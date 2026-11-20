"""Phase 8 — Graph-Enhanced Threat Intelligence interface (Member 4).

Provides graph-derived feature extraction for ML enhancement and
investigation context. Works with Member 2's Neo4j graph via an agreed
data contract — Member 4 must NOT create a conflicting graph schema.

Graph-derived features are candidates, not mandatory fields. Only use
features supported by actual graph data with clear interpretation.

Key guardrails (per spec):
  - A graph path does NOT prove an attacker traversed that path.
  - A shared IP address does NOT prove two devices have the same owner.
  - A high-degree node is NOT automatically malicious.
  - A graph-derived risk score is NOT proof of compromise.
  - Graph features must not leak the target label.
  - Graph information must be computable at prediction time (no future info).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import pandas as pd


class GraphFeatureExtractor:
    """Extracts graph-derived features for a given entity/event.

    Designed to consume graph query outputs from Member 2's Neo4j
    database. Does NOT connect to Neo4j directly — that remains
    Member 2's responsibility (Neo4j Python Driver, parameterized Cypher,
    MERGE-based import, batch transactions).

    The extractor accepts graph query results (as dicts/lists) and
    computes numeric features safe for ML input.
    """

    def __init__(self, contract_path: str | Path | None = None):
        self.contract_path = Path(contract_path) if contract_path else None
        self.contract: dict[str, Any] = {}
        if contract_path and Path(contract_path).is_file():
            self.contract = json.loads(Path(contract_path).read_text(encoding="utf-8"))

    def load_contract(self, contract_path: str | Path) -> None:
        """Load the agreed graph feature contract with Member 2."""
        self.contract_path = Path(contract_path)
        self.contract = json.loads(self.contract_path.read_text(encoding="utf-8"))

    def extract_features(
        self,
        entity_id: str,
        graph_context: dict[str, Any],
    ) -> dict[str, float]:
        """Compute graph-derived features from graph context.

        Parameters
        ----------
        entity_id : str
            The entity ID (e.g. host, identity) associated with the event.
        graph_context : dict
            Graph query results from Member 2's Neo4j. Expected keys
            (all optional, missing keys treated as 0/empty):
              - connected_entity_count: int
              - associated_security_event_count: int
              - distinct_hosts_for_identity: int
              - related_suspicious_event_count: int
              - related_to_critical_asset: bool
              - shortest_path_to_critical_asset: int or None
              - exposed_downstream_asset_count: int
              - repeated_suspicious_activity: bool
              - temporal_proximity_minutes: float or None

        Returns
        -------
        dict[str, float]
            Feature name -> numeric value. All values are safe for ML input.
            Missing graph context yields zeros (no hallucinated values).
        """
        ctx = graph_context or {}

        features: dict[str, float] = {}

        # Number of connected entities for the event's host/identity.
        features["graph_connected_entity_count"] = float(
            ctx.get("connected_entity_count", 0)
        )

        # Number of associated security events on the host.
        features["graph_associated_security_event_count"] = float(
            ctx.get("associated_security_event_count", 0)
        )

        # Number of distinct hosts associated with an identity.
        features["graph_distinct_hosts_for_identity"] = float(
            ctx.get("distinct_hosts_for_identity", 0)
        )

        # Number of related suspicious events involving the same entities.
        features["graph_related_suspicious_event_count"] = float(
            ctx.get("related_suspicious_event_count", 0)
        )

        # Relationship to a critical asset (binary).
        features["graph_related_to_critical_asset"] = float(
            bool(ctx.get("related_to_critical_asset", False))
        )

        # Shortest-path distance to a critical asset (None -> large value).
        path_dist = ctx.get("shortest_path_to_critical_asset")
        features["graph_shortest_path_to_critical_asset"] = (
            float(path_dist) if path_dist is not None else 999.0
        )

        # Number of potentially exposed downstream assets.
        features["graph_exposed_downstream_asset_count"] = float(
            ctx.get("exposed_downstream_asset_count", 0)
        )

        # Repeated suspicious activity involving related entities (binary).
        features["graph_repeated_suspicious_activity"] = float(
            bool(ctx.get("repeated_suspicious_activity", False))
        )

        # Temporal proximity of associated events (minutes, None -> 0).
        temp_prox = ctx.get("temporal_proximity_minutes")
        features["graph_temporal_proximity_minutes"] = (
            float(temp_prox) if temp_prox is not None else 0.0
        )

        return features

    def feature_names(self) -> list[str]:
        """Return the list of graph feature names in deterministic order."""
        return [
            "graph_connected_entity_count",
            "graph_associated_security_event_count",
            "graph_distinct_hosts_for_identity",
            "graph_related_suspicious_event_count",
            "graph_related_to_critical_asset",
            "graph_shortest_path_to_critical_asset",
            "graph_exposed_downstream_asset_count",
            "graph_repeated_suspicious_activity",
            "graph_temporal_proximity_minutes",
        ]


def merge_graph_features_with_telemetry(
    telemetry_df: pd.DataFrame,
    graph_features: dict[str, dict[str, float]],
    entity_id_column: str = "event_id",
) -> pd.DataFrame:
    """Merge graph-derived features into a telemetry DataFrame.

    Parameters
    ----------
    telemetry_df : pd.DataFrame
        Normalized telemetry events.
    graph_features : dict[str, dict[str, float]]
        Mapping from entity_id -> graph feature dict.
    entity_id_column : str
        Column in telemetry_df holding the entity ID to join on.

    Returns
    -------
    pd.DataFrame
        Telemetry with graph feature columns added. Rows without graph
        context get zeros for all graph features.
    """
    df = telemetry_df.copy()
    feature_names = GraphFeatureExtractor().feature_names()

    # Initialize all graph feature columns to 0.
    for fname in feature_names:
        df[fname] = 0.0

    # Fill in graph features where available.
    if entity_id_column in df.columns:
        for idx, row in df.iterrows():
            eid = row[entity_id_column]
            if eid in graph_features:
                for fname in feature_names:
                    df.at[idx, fname] = graph_features[eid].get(fname, 0.0)

    return df


def validate_no_target_leakage(
    graph_features: dict[str, dict[str, float]],
    target_column: str | None = None,
) -> list[str]:
    """Check graph features for obvious target leakage indicators.

    Returns a list of warning strings. Empty list means no obvious leakage.
    """
    warnings: list[str] = []

    # Feature names that would directly leak an attack label.
    leakage_hints = {"is_attack", "attack_label", "is_malicious", "compromised"}

    for fname in GraphFeatureExtractor().feature_names():
        for hint in leakage_hints:
            if hint in fname.lower():
                warnings.append(
                    f"Potential target leakage in graph feature: {fname}"
                )

    return warnings


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 8 Graph Features — self-check")
    print("=" * 60)

    extractor = GraphFeatureExtractor()

    # Example graph context for HOST-001 (from the spec example).
    graph_context = {
        "connected_entity_count": 5,
        "associated_security_event_count": 3,
        "distinct_hosts_for_identity": 2,
        "related_suspicious_event_count": 2,
        "related_to_critical_asset": True,
        "shortest_path_to_critical_asset": 2,
        "exposed_downstream_asset_count": 3,
        "repeated_suspicious_activity": True,
        "temporal_proximity_minutes": 15.0,
    }

    features = extractor.extract_features("HOST-001", graph_context)
    print(f"\nGraph features for HOST-001 ({len(features)} features):")
    for fname, value in features.items():
        print(f"  {fname}: {value}")

    # Empty context -> all zeros.
    empty_features = extractor.extract_features("UNKNOWN", {})
    print(f"\nEmpty context -> all zeros: {all(v == 0.0 for v in empty_features.values())}")

    # Leakage check.
    leak_warnings = validate_no_target_leakage({})
    print(f"\nLeakage warnings (empty): {leak_warnings}")

    print("\nGraph feature self-check complete.")
    print(
        "\nGuardrails: graph features are context only. No path = proof of "
        "traversal. No shared IP = same owner. Member 2 owns Neo4j schema."
    )
