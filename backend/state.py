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
        self.pre_session_model = None  # VotingClassifier (LR + GradientBoost)

    def _load_pre_session_model(self, model_path: str) -> None:
        import logging
        import os
        _logger = logging.getLogger(__name__)
        try:
            if os.path.exists(model_path):
                import joblib
                self.pre_session_model = joblib.load(model_path)
                _logger.info("Pre-session ML model loaded from %s", model_path)
            else:
                _logger.warning("Pre-session model not found at %s", model_path)
        except Exception as exc:
            _logger.warning("Failed to load pre-session model: %s", exc)


app_state = AppState()
