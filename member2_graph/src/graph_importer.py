
import argparse
import json
from pathlib import Path

from neo4j.time import DateTime

from member2_graph.src.graph_connection import Neo4jConnection

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA = ROOT / "data" / "graph_fixture"
BATCH_SIZE = 500

RELATIONSHIP_QUERIES = {
    "AUTHENTICATED_TO": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:AUTHENTICATED_TO {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
    "COMMUNICATES_WITH": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:COMMUNICATES_WITH {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
    "RUNS": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:RUNS {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
    "DEPENDS_ON": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:DEPENDS_ON {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
    "HAS_VULNERABILITY": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:HAS_VULNERABILITY {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
    "INVOLVES": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:INVOLVES {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
    "SUPPORTED_BY": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:SUPPORTED_BY {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
    "OBSERVED_ON": """
        MATCH (s:GraphNode {id: row.source_id})
        MATCH (t:GraphNode {id: row.target_id})
        MERGE (s)-[r:OBSERVED_ON {relationship_id: row.relationship_id}]->(t)
        SET r += row.properties
    """,
}


def read_jsonl(path):
    with path.open("r", encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def chunks(records, size=BATCH_SIZE):
    for index in range(0, len(records), size):
        yield records[index:index + size]


def node_properties(record, id_field):
    properties = dict(record)
    properties["id"] = record[id_field]

    for key in ("event_time", "observed_at"):
        value = properties.get(key)
        if value:
            properties[key] = DateTime.from_iso_format(
                value.replace("Z", "+00:00")
            )

    return properties


def create_schema(session):
    session.run("""
        CREATE CONSTRAINT graph_node_id IF NOT EXISTS
        FOR (n:GraphNode) REQUIRE n.id IS UNIQUE
    """).consume()


def import_entities(session, records):
    query = """
        UNWIND $rows AS row
        MERGE (n:GraphNode:Entity {id: row.id})
        SET n += row.properties
    """
    for batch in chunks(records):
        rows = [
            {"id": r["id"], "properties": node_properties(r, "id")}
            for r in batch
        ]
        session.execute_write(lambda tx: tx.run(query, rows=rows).consume())


def import_events(session, records):
    query = """
        UNWIND $rows AS row
        MERGE (n:GraphNode:SecurityEvent {id: row.id})
        SET n += row.properties
    """
    for batch in chunks(records):
        rows = [
            {
                "id": r["event_id"],
                "properties": node_properties(r, "event_id")
            }
            for r in batch
        ]
        session.execute_write(lambda tx: tx.run(query, rows=rows).consume())


def import_evidence(session, records):
    query = """
        UNWIND $rows AS row
        MERGE (n:GraphNode:Evidence {id: row.id})
        SET n += row.properties
    """
    for batch in chunks(records):
        rows = [
            {
                "id": r["evidence_id"],
                "properties": node_properties(r, "evidence_id")
            }
            for r in batch
        ]
        session.execute_write(lambda tx: tx.run(query, rows=rows).consume())



def import_relationships(session, records, valid_ids):
    grouped = {}

    for record in records:
        rel_type = record["relationship_type"]

        if rel_type not in RELATIONSHIP_QUERIES:
            raise ValueError(f"Unsupported relationship type: {rel_type}")

        if record["source_id"] not in valid_ids:
            raise ValueError(f"Missing source node: {record['source_id']}")

        if record["target_id"] not in valid_ids:
            raise ValueError(f"Missing target node: {record['target_id']}")

        grouped.setdefault(rel_type, []).append(record)

    for rel_type, query in RELATIONSHIP_QUERIES.items():
        query = "UNWIND $rows AS row\n" + query

        for batch in chunks(grouped.get(rel_type, [])):
            rows = [
                {
                    "source_id": r["source_id"],
                    "target_id": r["target_id"],
                    "relationship_id": r["relationship_id"],
                    "properties": {
                        k: v for k, v in r.items()
                        if k not in (
                            "source_id",
                            "target_id",
                            "relationship_id",
                            "relationship_type"
                        )
                    }
                }
                for r in batch
            ]

            session.execute_write(
                lambda tx, q=query, data=rows:
                    tx.run(q, rows=data).consume()
            )



def run_import(data_dir):
    entities = read_jsonl(data_dir / "entities.jsonl")
    events = read_jsonl(data_dir / "events.jsonl")
    evidence = read_jsonl(data_dir / "evidence.jsonl")
    relationships = read_jsonl(data_dir / "relationships.jsonl")

    valid_ids = (
        {r["id"] for r in entities}
        | {r["event_id"] for r in events}
        | {r["evidence_id"] for r in evidence}
    )

    if len(valid_ids) != len(entities) + len(events) + len(evidence):
        raise ValueError("Duplicate node IDs found across input files.")

    with Neo4jConnection() as connection:
        with connection.driver.session(
            database=connection.database
        ) as session:
            create_schema(session)
            import_entities(session, entities)
            import_events(session, events)
            import_evidence(session, evidence)
            import_relationships(session, relationships, valid_ids)

    print("Import completed successfully.")
    print(f"Entities: {len(entities)}")
    print(f"Events: {len(events)}")
    print(f"Evidence: {len(evidence)}")
    print(f"Relationships: {len(relationships)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Import TRUSTRAIL graph JSONL files into Neo4j Aura."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA
    )
    args = parser.parse_args()
    run_import(args.data_dir)
