from datetime import datetime
from typing import Optional

from config import CAIRO_TZ

from services.alert_manager import AlertManager
from services.splunk_forwarder import SplunkForwarder
from services.threat_scorer import ThreatScorer
from services.vpn_detection import VPNDetector


class AppState:
    def __init__(self) -> None:
        self.started_at = datetime.now(CAIRO_TZ)
        self.alert_manager = AlertManager()
        self.threat_scorer: Optional[ThreatScorer] = None
        self.vpn_detector: Optional[VPNDetector] = None
        self.splunk_forwarder: Optional[SplunkForwarder] = None
        self.llm_service: Optional["LLMService"] = None


app_state = AppState()
