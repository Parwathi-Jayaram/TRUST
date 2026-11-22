import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()
MAX_ALLOWED_GRAPH_DEPTH = 6


@dataclass(frozen=True)
class Settings:
    neo4j_uri: str
    neo4j_username: str
    neo4j_password: str
    neo4j_database: str
    cors_origins: tuple[str, ...]
    max_graph_depth: int
    neo4j_query_timeout_seconds: float = 30.0
    api_bearer_token: str = ""
    app_env: str = "development"
    demo_fallback: bool = True


def get_settings() -> Settings:
    origins = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    max_graph_depth = int(os.getenv("MAX_GRAPH_DEPTH", "4"))
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    demo_fallback_value = os.getenv(
        "DEMO_FALLBACK",
        "true" if app_env != "production" else "false",
    ).strip().lower()
    if demo_fallback_value not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError("DEMO_FALLBACK must be true or false.")
    if not 1 <= max_graph_depth <= MAX_ALLOWED_GRAPH_DEPTH:
        raise ValueError(
            f"MAX_GRAPH_DEPTH must be between 1 and {MAX_ALLOWED_GRAPH_DEPTH}."
        )
    try:
        neo4j_query_timeout_seconds = float(
            os.getenv("NEO4J_QUERY_TIMEOUT_SECONDS", "30")
        )
    except ValueError as exc:
        raise ValueError("NEO4J_QUERY_TIMEOUT_SECONDS must be numeric.") from exc
    if not 1 <= neo4j_query_timeout_seconds <= 120:
        raise ValueError(
            "NEO4J_QUERY_TIMEOUT_SECONDS must be between 1 and 120."
        )
    return Settings(
        neo4j_uri=os.getenv("NEO4J_URI", ""),
        neo4j_username=os.getenv("NEO4J_USERNAME", ""),
        neo4j_password=os.getenv("NEO4J_PASSWORD", ""),
        neo4j_database=os.getenv("NEO4J_DATABASE", "neo4j"),
        cors_origins=tuple(origin.strip() for origin in origins.split(",") if origin.strip()),
        max_graph_depth=max_graph_depth,
        neo4j_query_timeout_seconds=neo4j_query_timeout_seconds,
        api_bearer_token=os.getenv("API_BEARER_TOKEN", ""),
        app_env=app_env,
        demo_fallback=demo_fallback_value in {"true", "1", "yes"},
    )
