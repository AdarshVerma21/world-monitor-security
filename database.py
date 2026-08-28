import sqlite3
from datetime import datetime
from typing import Any, Dict, List


DB_NAME = "world_monitor.db"


def get_connection():
    """
    Create a SQLite database connection.
    """
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    """
    Create the scan history table if it does not already exist.
    """
    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            risk_rating TEXT DEFAULT 'Informational',
            findings_count INTEGER DEFAULT 0,
            http_status INTEGER,
            response_time REAL,
            scan_time TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


def save_scan(result: Dict[str, Any]) -> int:
    """
    Save a completed security assessment.
    """

    import json

    risk = result.get("risk") or {}

    target = result.get("target", "Unknown")
    risk_score = risk.get("score", 0)
    risk_rating = risk.get("rating", "Informational")

    findings = result.get("findings") or []
    findings_count = len(findings)

    http_status = result.get("status_code")

    if http_status is None:
        http_status = result.get("status")

    response_time = result.get("response_time")

    if response_time is None:
        response_time = result.get("response_time_ms")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    result_json = json.dumps(
        result,
        ensure_ascii=False,
        default=str
    )

    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO scan_history (
            target,
            risk_score,
            risk_rating,
            findings_count,
            http_status,
            response_time,
            scan_time,
            result_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target,
            risk_score,
            risk_rating,
            findings_count,
            http_status,
            response_time,
            scan_time,
            result_json,
        ),
    )

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id


def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Return the most recent scans.
    """

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            target,
            risk_score,
            risk_rating,
            findings_count,
            http_status,
            response_time,
            scan_time
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_scan(scan_id: int) -> Dict[str, Any] | None:
    """
    Return a complete saved scan.
    """

    import json

    connection = get_connection()

    row = connection.execute(
        """
        SELECT *
        FROM scan_history
        WHERE id = ?
        """,
        (scan_id,),
    ).fetchone()

    connection.close()

    if row is None:
        return None

    data = dict(row)

    try:
        data["result"] = json.loads(data["result_json"])
    except Exception:
        data["result"] = {}

    return data


def delete_scan(scan_id: int) -> bool:
    """
    Delete one scan from history.
    """

    connection = get_connection()

    cursor = connection.execute(
        """
        DELETE FROM scan_history
        WHERE id = ?
        """,
        (scan_id,),
    )

    connection.commit()
    connection.close()

    return cursor.rowcount > 0


def clear_history():
    """
    Delete all saved scan history.
    """

    connection = get_connection()

    connection.execute(
        "DELETE FROM scan_history"
    )

    connection.commit()
    connection.close()


def get_history_statistics() -> Dict[str, Any]:
    """
    Return basic statistics for the dashboard.
    """

    connection = get_connection()

    total = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM scan_history
        """
    ).fetchone()["count"]

    average_risk = connection.execute(
        """
        SELECT AVG(risk_score) AS average
        FROM scan_history
        """
    ).fetchone()["average"]

    critical = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM scan_history
        WHERE risk_rating = 'Critical'
        """
    ).fetchone()["count"]

    high = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM scan_history
        WHERE risk_rating = 'High'
        """
    ).fetchone()["count"]

    medium = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM scan_history
        WHERE risk_rating = 'Medium'
        """
    ).fetchone()["count"]

    low = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM scan_history
        WHERE risk_rating = 'Low'
        """
    ).fetchone()["count"]

    connection.close()

    return {
        "total_scans": total,
        "average_risk": round(average_risk or 0, 2),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# Initialize database automatically
init_database()