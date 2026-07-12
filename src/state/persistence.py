"""SQLite persistence layer for the attack graph."""

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import networkx as nx

from src.state.schemas import ExploitAttempt
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class PersistenceManager:
    """Handles saving and loading the attack graph using SQLite."""

    def __init__(self, db_path: str = "runs/pentest_state.db") -> None:
        """Initialize the database connection and create tables."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create the necessary tables if they don't exist."""
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                # Table for the overall graph state
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS graph_state (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        data TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                # Table for exploit attempts history
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS exploit_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target_service_id TEXT NOT NULL,
                        module_used TEXT NOT NULL,
                        payload TEXT,
                        result TEXT,
                        session_id TEXT,
                        error_type TEXT,
                        raw_error TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                conn.commit()

    def save_graph(self, graph: nx.DiGraph) -> None:
        """Serialize and save the NetworkX graph to SQLite."""
        try:
            data = nx.node_link_data(graph)
            json_data = json.dumps(data)
            with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO graph_state (id, data, updated_at)
                        VALUES (1, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(id) DO UPDATE SET 
                            data=excluded.data,
                            updated_at=CURRENT_TIMESTAMP
                        """,
                        (json_data,),
                    )
                    conn.commit()
            logger.debug("Successfully saved graph state to database.")
        except Exception as e:
            logger.error(
                "Failed to save graph state", extra={"extra_data": {"error": str(e)}}
            )

    def load_graph(self) -> nx.DiGraph | None:
        """Load and deserialize the NetworkX graph from SQLite."""
        try:
            with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT data FROM graph_state WHERE id = 1")
                    row = cursor.fetchone()
                    if row:
                        data = json.loads(row[0])
                        logger.debug("Successfully loaded graph state from database.")
                        return nx.node_link_graph(data)
        except Exception as e:
            logger.error(
                "Failed to load graph state", extra={"extra_data": {"error": str(e)}}
            )
        return None

    def record_exploit_attempt(self, attempt: ExploitAttempt) -> None:
        """Save a record of an exploit attempt."""
        try:
            with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO exploit_attempts 
                        (target_service_id, module_used, payload, result, session_id, error_type, raw_error, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            attempt.target_service_id,
                            attempt.module_used,
                            attempt.payload,
                            attempt.result,
                            attempt.session_id,
                            attempt.error_type,
                            attempt.raw_error,
                            attempt.timestamp,
                        ),
                    )
                    conn.commit()
        except Exception as e:
            logger.error(
                "Failed to record exploit attempt",
                extra={"extra_data": {"error": str(e)}},
            )
