from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import hmac
import re
import threading
import time

from fastapi import APIRouter, HTTPException, Path, Request, Response

from ..services.investigation_service import InvestigationNotFound
from ..services.report_data_service import (
    InvestigationReportDataService,
    ReportSnapshotError,
)
from ..services.report_pdf_service import (
    MAX_REPORT_PDF_BYTES,
    ReportPdfError,
    ReportPdfTooLarge,
    render_investigation_report,
)

router = APIRouter(prefix="/api/investigations", tags=["investigation-reports"])

MAX_REQUEST_BODY_BYTES = 1_024
REPORT_REQUESTS_PER_MINUTE = 10
MAX_CONCURRENT_REPORTS = 2
_RATE_WINDOW_SECONDS = 60.0
_rate_lock = threading.Lock()
_rate_requests: dict[str, deque[float]] = defaultdict(deque)
_generation_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REPORTS)
_report_lock_guard = threading.Lock()
_report_locks: dict[str, tuple[asyncio.Lock, int]] = {}


def _register_report_lock(investigation_id: str) -> asyncio.Lock:
    with _report_lock_guard:
        entry = _report_locks.get(investigation_id)
        if entry is None:
            lock, users = asyncio.Lock(), 0
        else:
            lock, users = entry
        _report_locks[investigation_id] = (lock, users + 1)
        return lock


def _unregister_report_lock(investigation_id: str, lock: asyncio.Lock) -> None:
    with _report_lock_guard:
        registered_lock, users = _report_locks[investigation_id]
        if registered_lock is not lock:
            return
        if users == 1:
            del _report_locks[investigation_id]
        else:
            _report_locks[investigation_id] = (lock, users - 1)


def _authorize_report_request(request: Request) -> str:
    expected_token = request.app.state.settings.api_bearer_token
    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="Investigation report downloads require API_BEARER_TOKEN configuration.",
        )

    provided = request.headers.get("Authorization", "")
    expected = f"Bearer {expected_token}"
    if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return hashlib.sha256(expected_token.encode("utf-8")).hexdigest()


def _check_rate_limit(identity: str) -> int | None:
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SECONDS
    with _rate_lock:
        requests = _rate_requests[identity]
        while requests and requests[0] <= cutoff:
            requests.popleft()
        if len(requests) >= REPORT_REQUESTS_PER_MINUTE:
            return max(1, int(requests[0] + _RATE_WINDOW_SECONDS - now))
        requests.append(now)
        if len(_rate_requests) > 1_000:
            expired = [
                key for key, values in _rate_requests.items()
                if not values or values[-1] <= cutoff
            ]
            for key in expired:
                _rate_requests.pop(key, None)
    return None


async def _validate_empty_body(request: Request) -> None:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc
        if declared_length < 0:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")
        if declared_length > MAX_REQUEST_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Report requests cannot exceed 1 KB.")

    body_length = 0
    async for chunk in request.stream():
        body_length += len(chunk)
        if body_length > MAX_REQUEST_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Report requests cannot exceed 1 KB.")
    if body_length:
        raise HTTPException(
            status_code=400,
            detail="Report generation does not accept a request body.",
        )


def _safe_filename(investigation_id: str) -> str:
    identifier = re.sub(r"[^A-Za-z0-9_-]", "", investigation_id)[:80]
    return f"TRUSTRAIL-investigation-{identifier}.pdf"


@router.post("/{investigation_id}/report", response_class=Response)
async def generate_investigation_report(
    request: Request,
    investigation_id: str = Path(..., min_length=5, max_length=200),
) -> Response:
    identity = _authorize_report_request(request)
    retry_after = _check_rate_limit(identity)
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Report generation rate limit exceeded.",
            headers={"Retry-After": str(retry_after)},
        )
    await _validate_empty_body(request)
    report_lock = _register_report_lock(investigation_id)
    try:
        async with report_lock:
            if not _generation_slots.acquire(blocking=False):
                raise HTTPException(
                    status_code=429,
                    detail="Report generation is busy; retry shortly.",
                    headers={"Retry-After": "2"},
                )
            try:
                data_service = InvestigationReportDataService(
                    request.app.state.neo4j,
                    request.app.state.detection_engine,
                    request.app.state.settings.max_graph_depth,
                )
                snapshot, snapshot_hash, persist_snapshot = await data_service.get_snapshot(
                    investigation_id,
                )
                generated_at = datetime.now(timezone.utc).isoformat()
                pdf = await asyncio.to_thread(
                    render_investigation_report,
                    snapshot,
                    generated_at,
                )
                if len(pdf) > MAX_REPORT_PDF_BYTES:
                    raise ReportPdfTooLarge("Generated report PDF exceeds the allowed size.")
                await data_service.record_generated(snapshot, snapshot_hash, persist_snapshot)
            except InvestigationNotFound:
                raise
            except ReportPdfTooLarge as exc:
                raise HTTPException(status_code=413, detail="Generated report exceeds the allowed size.") from exc
            except (ReportSnapshotError, ReportPdfError) as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Investigation report generation failed.",
                ) from exc
            finally:
                _generation_slots.release()
    finally:
        _unregister_report_lock(investigation_id, report_lock)

    filename = _safe_filename(investigation_id)
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store, private",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "sandbox",
        "Referrer-Policy": "no-referrer",
        "X-Report-Status": "partial" if snapshot.partial else "complete",
    }
    return Response(content=pdf, media_type="application/pdf", headers=headers)
