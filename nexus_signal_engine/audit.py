"""Audit trail logging system for Nexus Signal Engine."""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import sqlite3
import logging
from dataclasses import dataclass
from enum import Enum
import threading
from pathlib import Path
import hashlib
from filelock import FileLock

logger = logging.getLogger(__name__)

class AuditEventType(str, Enum):
    """Types of events that can be audited."""
    AUTH = "authentication"
    ACCESS = "access"
    DATA = "data"
    CONFIG = "configuration"
    SECURITY = "security"
    SYSTEM = "system"

class AuditAction(str, Enum):
    """Actions that can be audited."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    ANALYZE = "analyze"
    CONFIGURE = "configure"
    EXPORT = "export"

@dataclass
class AuditEvent:
    """Represents a single audit event."""
    timestamp: datetime
    event_type: AuditEventType
    action: AuditAction
    user: str
    resource: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    status: str = "success"
    error_message: Optional[str] = None

class AuditTrail:
    """Manages audit logging and retrieval."""
    
    def __init__(self, db_path: str = "audit.db"):
        self.db_path = Path(db_path)
        self.lock = FileLock(f"{db_path}.lock")
        self._init_db()
        self._setup_logging()
    
    def _init_db(self):
        """Initialize the audit database."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS audit_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            action TEXT NOT NULL,
                            user TEXT NOT NULL,
                            resource TEXT NOT NULL,
                            details TEXT NOT NULL,
                            ip_address TEXT,
                            session_id TEXT,
                            status TEXT NOT NULL,
                            error_message TEXT,
                            integrity_hash TEXT NOT NULL
                        )
                    """)
                    
                    # Create indexes
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                        ON audit_events(timestamp)
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_audit_user
                        ON audit_events(user)
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_audit_type_action
                        ON audit_events(event_type, action)
                    """)
                    
                    conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Failed to initialize audit database: {e}")
                raise
    
    def _setup_logging(self):
        """Set up audit-specific logging."""
        handler = logging.FileHandler("audit.log")
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - AUDIT: %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    def _calculate_integrity_hash(self, event: AuditEvent) -> str:
        """Calculate integrity hash for audit event."""
        event_data = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "action": event.action.value,
            "user": event.user,
            "resource": event.resource,
            "details": event.details,
            "ip_address": event.ip_address,
            "session_id": event.session_id,
            "status": event.status,
            "error_message": event.error_message
        }
        return hashlib.sha256(
            json.dumps(event_data, sort_keys=True).encode()
        ).hexdigest()
    
    def log_event(self, event: AuditEvent):
        """Log an audit event."""
        with self.lock:
            try:
                integrity_hash = self._calculate_integrity_hash(event)
                
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO audit_events (
                            timestamp, event_type, action, user,
                            resource, details, ip_address, session_id,
                            status, error_message, integrity_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.timestamp.isoformat(),
                        event.event_type.value,
                        event.action.value,
                        event.user,
                        event.resource,
                        json.dumps(event.details),
                        event.ip_address,
                        event.session_id,
                        event.status,
                        event.error_message,
                        integrity_hash
                    ))
                    conn.commit()
                
                logger.info(
                    f"Audit event logged: {event.event_type.value}/"
                    f"{event.action.value} by {event.user}"
                )
                
            except Exception as e:
                logger.error(f"Failed to log audit event: {e}")
                raise
    
    def query_events(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        event_type: Optional[AuditEventType] = None,
        action: Optional[AuditAction] = None,
        user: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 1000
    ) -> List[AuditEvent]:
        """Query audit events with filters."""
        query = "SELECT * FROM audit_events WHERE 1=1"
        params = []
        
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date.isoformat())
        
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date.isoformat())
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        if action:
            query += " AND action = ?"
            params.append(action.value)
        
        if user:
            query += " AND user = ?"
            params.append(user)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(query, params)
                    
                    events = []
                    for row in cursor:
                        events.append(AuditEvent(
                            timestamp=datetime.fromisoformat(row["timestamp"]),
                            event_type=AuditEventType(row["event_type"]),
                            action=AuditAction(row["action"]),
                            user=row["user"],
                            resource=row["resource"],
                            details=json.loads(row["details"]),
                            ip_address=row["ip_address"],
                            session_id=row["session_id"],
                            status=row["status"],
                            error_message=row["error_message"]
                        ))
                    
                    return events
                    
            except Exception as e:
                logger.error(f"Failed to query audit events: {e}")
                raise
    
    def verify_integrity(self, event_id: int) -> bool:
        """Verify the integrity of an audit event."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(
                        "SELECT * FROM audit_events WHERE id = ?",
                        (event_id,)
                    )
                    row = cursor.fetchone()
                    
                    if not row:
                        return False
                    
                    stored_hash = row["integrity_hash"]
                    event = AuditEvent(
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        event_type=AuditEventType(row["event_type"]),
                        action=AuditAction(row["action"]),
                        user=row["user"],
                        resource=row["resource"],
                        details=json.loads(row["details"]),
                        ip_address=row["ip_address"],
                        session_id=row["session_id"],
                        status=row["status"],
                        error_message=row["error_message"]
                    )
                    
                    calculated_hash = self._calculate_integrity_hash(event)
                    return stored_hash == calculated_hash
                    
            except Exception as e:
                logger.error(f"Failed to verify audit event integrity: {e}")
                return False