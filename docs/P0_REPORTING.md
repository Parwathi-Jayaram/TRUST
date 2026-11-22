# TRUSTRAIL AI Investigation Reports

## What the feature does

An authorized shared-bearer holder can generate a PDF for the currently selected investigation from the Investigations page. The frontend calls:

```http
POST /api/investigations/{investigation_id}/report
Authorization: Bearer <API_BEARER_TOKEN>
```

The request has no body. A successful response is an `application/pdf` attachment. `X-Report-Status` is `complete` or `partial`; a partial report includes source availability and limitation notes in the document.

The first successful generation captures and persists a bounded, validated evidence snapshot. Later downloads reuse that snapshot rather than silently refreshing graph data. A failed PDF render does not persist a first snapshot or record a successful-generation audit entry. The endpoint records successful generations in the investigation audit history as `backend_api`.

## Source handling and limitations

- Investigation fields and attached evidence come from the existing investigation APIs/services.
- Graph entities, relationships, and bounded paths come from the existing graph service; no graph edges are invented.
- Per-event risk uses the existing Member 4 threat/scoring service. The report does not implement a second scoring algorithm.
- No Member 3 intelligence provider or investigation-level AI-summary provider exists in the checked-out backend. Both sections are explicitly marked unavailable; no findings or narrative are fabricated.
- Missing risk, graph, evidence, and provenance are marked unavailable/empty/unknown rather than inferred.
- Backend-provided `is_synthetic` metadata is retained. A synthetic fixture report is labeled synthetic; it is not evidence of a real attack.
- The disclaimer states that automated results assist human review and do not confirm malicious activity or compromise.
- The current shared bearer has no analyst identity or investigation ownership. Any bearer holder can request any investigation report; per-user authorization and cross-user isolation are not provided.
- Live Neo4j connectivity and a report based on a real investigation must be verified in the target environment before presenting a live integration demo.

## Local configuration

1. Install backend dependencies from the repository root:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
   ```

2. Set a strong `API_BEARER_TOKEN` in the backend environment (for example, in the ignored `backend\.env`). Never commit the token. Configure valid Neo4j settings if using the live graph.
3. Configure the frontend access gate with `VITE_API_AUTH_REQUIRED=true` in the frontend environment and use the same bearer token at the access gate. The button is hidden until a token is present.
4. Start the backend from the repository root:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
   ```

5. In another terminal, start the frontend:

   ```powershell
   Set-Location frontend
   npm run dev
   ```

## Demonstration

1. Sign in through the configured API access gate.
2. Open **Investigations** and select an existing investigation or create one using backend-returned event/entity IDs.
3. Select **Download report**. The button is disabled while generation is in progress; errors appear in the investigation view. A partial-report status appears when a source is unavailable.
4. Open the downloaded PDF and confirm the investigation ID, provenance, source statuses, graph evidence, risk status, limitations, and disclaimer.

For a direct API check in PowerShell, use the investigation ID from the backend and keep the token out of command history where possible:

```powershell
$headers = @{ Authorization = "Bearer $env:API_BEARER_TOKEN" }
Invoke-WebRequest `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/investigations/INV-REPLACE-WITH-ID/report" `
  -Headers $headers `
  -OutFile ".\investigation-report.pdf"
```

The endpoint limits the request body to 1 KB and rejects non-empty bodies, caps PDF output at 5 MB, allows at most 10 requests per bearer per minute per backend process, and limits concurrent generation to two requests per process. Repeated requests for one investigation are serialized to preserve a single captured snapshot. The route returns generic report errors rather than internal filesystem paths or stack traces. Multi-worker deployments need a shared rate/concurrency store for global enforcement.

## Verification commands

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests\test_investigation_report_routes.py -q
.\.venv\Scripts\python.exe -m pytest backend\tests -q
Set-Location frontend
node --test tests/integrationData.test.js
npm run build
```

The focused report tests use the in-memory synthetic fixture adapter and parse the generated PDF with pypdf. Passing them verifies the synthetic/local code path only; it does not establish live Neo4j, Member 3, or investigation-level AI availability.
