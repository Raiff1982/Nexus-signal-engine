"""Compliance reporting module for Nexus Signal Engine."""

from typing import Dict, List, Optional
from datetime import datetime, timedelta, UTC
import json
import csv
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ComplianceStandard(str, Enum):
    """Supported compliance standards."""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    PCI = "pci"
    CUSTOM = "custom"

class ComplianceLevel(str, Enum):
    """Compliance violation severity levels."""
    INFO = "info"
    WARNING = "warning"
    VIOLATION = "violation"
    CRITICAL = "critical"

@dataclass
class ComplianceEvent:
    """Represents a single compliance-related event."""
    timestamp: datetime
    standard: ComplianceStandard
    level: ComplianceLevel
    description: str
    context: Dict
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None

class ComplianceManager:
    """Manages compliance monitoring and reporting."""
    
    def __init__(self, report_dir: str = "compliance_reports"):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)
        self.events: List[ComplianceEvent] = []
        self._setup_logging()
    
    def _setup_logging(self):
        """Set up compliance-specific logging."""
        handler = logging.FileHandler(
            self.report_dir / "compliance.log"
        )
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    def log_event(
        self,
        standard: ComplianceStandard,
        level: ComplianceLevel,
        description: str,
        context: Dict
    ):
        """Log a compliance event."""
        event = ComplianceEvent(
            timestamp=datetime.now(UTC),
            standard=standard,
            level=level,
            description=description,
            context=context
        )
        
        self.events.append(event)
        logger.log(
            logging.WARNING if level in (ComplianceLevel.VIOLATION, ComplianceLevel.CRITICAL)
            else logging.INFO,
            f"Compliance {level}: {description}"
        )
    
    def resolve_event(
        self,
        event: ComplianceEvent,
        resolution: str
    ):
        """Mark a compliance event as resolved."""
        event.resolution = resolution
        event.resolved_at = datetime.now(UTC)
        
        logger.info(
            f"Resolved compliance event: {event.description} - {resolution}"
        )
    
    def generate_report(
        self,
        standard: Optional[ComplianceStandard] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format: str = "json"
    ) -> str:
        """Generate a compliance report."""
        # Filter events
        filtered_events = self.events
        
        if standard:
            filtered_events = [
                e for e in filtered_events
                if e.standard == standard
            ]
        
        if start_date:
            filtered_events = [
                e for e in filtered_events
                if e.timestamp >= start_date
            ]
            
        if end_date:
            filtered_events = [
                e for e in filtered_events
                if e.timestamp <= end_date
            ]
        
        # Generate report filename
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        standard_name = standard.value if standard else "all"
        filename = f"compliance_report_{standard_name}_{timestamp}"
        
        if format == "json":
            report_path = self.report_dir / f"{filename}.json"
            with open(report_path, "w") as f:
                json.dump(
                    [asdict(e) for e in filtered_events],
                    f,
                    default=str,
                    indent=2
                )
        elif format == "csv":
            report_path = self.report_dir / f"{filename}.csv"
            with open(report_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp",
                    "Standard",
                    "Level",
                    "Description",
                    "Context",
                    "Resolution",
                    "Resolved At"
                ])
                for event in filtered_events:
                    writer.writerow([
                        event.timestamp,
                        event.standard.value,
                        event.level.value,
                        event.description,
                        json.dumps(event.context),
                        event.resolution or "",
                        event.resolved_at or ""
                    ])
        else:
            raise ValueError(f"Unsupported report format: {format}")
        
        logger.info(f"Generated compliance report: {report_path}")
        return str(report_path)
    
    def get_compliance_status(
        self,
        standard: Optional[ComplianceStandard] = None
    ) -> Dict:
        """Get current compliance status summary."""
        now = datetime.now(UTC)
        thirty_days_ago = now - timedelta(days=30)
        
        events = [
            e for e in self.events
            if e.timestamp >= thirty_days_ago
        ]
        
        if standard:
            events = [e for e in events if e.standard == standard]
        
        total_events = len(events)
        open_violations = len([
            e for e in events
            if not e.resolved_at and e.level in (ComplianceLevel.VIOLATION, ComplianceLevel.CRITICAL)
        ])
        
        return {
            "status": "compliant" if open_violations == 0 else "non_compliant",
            "total_events": total_events,
            "open_violations": open_violations,
            "events_by_level": {
                level.value: len([e for e in events if e.level == level])
                for level in ComplianceLevel
            },
            "last_updated": now.isoformat()
        }