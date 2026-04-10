from __future__ import annotations

import os
from typing import Any

import joblib
import numpy as np
from cachetools import TTLCache

from ai.feature_extractor import extract_features


class ThreatScorer:
    def __init__(self, model_path: str, ttl_seconds: int = 300) -> None:
        self.model_path = model_path
        self.cache: TTLCache = TTLCache(maxsize=10000, ttl=ttl_seconds)
        self.pipeline = self._load_pipeline()

    def _load_pipeline(self) -> Any:
        if os.path.exists(self.model_path):
            return joblib.load(self.model_path)
        return None

    async def score(self, session: Any, profile: Any, multi_protocol: bool = False, known_bad_ip: bool = False) -> tuple[float, int]:
        ip_key = str(getattr(profile, "ip", ""))
        if ip_key and ip_key in self.cache:
            cached = self.cache[ip_key]
            return cached[0], cached[1]

        if self.pipeline is None:
            result = (0.0, 0)
            if ip_key:
                self.cache[ip_key] = result
            return result

        features = np.array([extract_features(session, profile, multi_protocol, known_bad_ip)])
        probabilities = self.pipeline.predict_proba(features)[0]
        score = float(np.dot(probabilities, np.array([0.0, 0.25, 0.5, 0.75, 1.0])))
        level = int(self.pipeline.predict(features)[0])

        result = (score, level)
        if ip_key:
            self.cache[ip_key] = result
        return result
