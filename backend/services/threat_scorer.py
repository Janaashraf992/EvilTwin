from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import joblib
import numpy as np
from cachetools import TTLCache

from ai.feature_extractor import extract_features

logger = logging.getLogger(__name__)


class ThreatScorer:
    def __init__(self, model_path: str, ttl_seconds: int = 300) -> None:
        self.model_path = model_path
        self.cache: TTLCache = TTLCache(maxsize=10000, ttl=ttl_seconds)
        self.pipeline = self._load_pipeline()
        self._executor = ThreadPoolExecutor(max_workers=2)

    def _load_pipeline(self) -> Any:
        if os.path.exists(self.model_path):
            logger.info("Loading ML model from %s", self.model_path)
            try:
                return joblib.load(self.model_path)
            except Exception as exc:
                logger.error(
                    "Failed to load model from %s: %s – retraining a compatible model",
                    self.model_path,
                    exc,
                )
                return self._retrain()
        logger.error("Model file not found at %s – training a new model", self.model_path)
        return self._retrain()

    def _retrain(self) -> Any:
        try:
            from ai.train import train_model

            pipeline = train_model()
            try:
                joblib.dump(pipeline, self.model_path)
            except Exception as dump_exc:
                logger.warning("Could not persist retrained model to %s: %s", self.model_path, dump_exc)
            return pipeline
        except Exception as exc:
            logger.error("Model retraining failed: %s – all threat scores will be 0", exc)
            return None

    def _cache_key(self, ip_key: str, session: Any) -> str:
        session_id = str(getattr(session, "id", ""))
        cmd_count = len(getattr(session, "commands", []) or [])
        return f"{ip_key}:{session_id}:{cmd_count}"

    def _score_sync(self, ip_key: str, session: Any, profile: Any, multi_protocol: bool, known_bad_ip: bool) -> tuple[float, int]:
        cache_key = self._cache_key(ip_key, session)
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            return cached[0], cached[1]

        if self.pipeline is None:
            result = (0.0, 0)
            self.cache[cache_key] = result
            return result

        features = np.array([extract_features(session, profile, multi_protocol, known_bad_ip)])
        probabilities = self.pipeline.predict_proba(features)[0]
        score = float(np.dot(probabilities, np.array([0.0, 0.25, 0.5, 0.75, 1.0])))
        level = int(self.pipeline.predict(features)[0])

        logger.debug("Scored %s -> score=%.3f level=%d (cmds=%d multi=%s bad=%s)",
                      str(getattr(profile, "ip", "")), score, level,
                      len(getattr(session, "commands", []) or []),
                      multi_protocol, known_bad_ip)

        result = (score, level)
        self.cache[cache_key] = result
        return result

    async def score(self, session: Any, profile: Any, multi_protocol: bool = False, known_bad_ip: bool = False) -> tuple[float, int]:
        ip_key = str(getattr(profile, "ip", ""))

        cache_key = self._cache_key(ip_key, session)
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            return cached[0], cached[1]

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            self._score_sync,
            ip_key,
            session,
            profile,
            multi_protocol,
            known_bad_ip,
        )

    def close(self) -> None:
        self._executor.shutdown(wait=False)
