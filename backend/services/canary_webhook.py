import hashlib
import hmac
import time
from collections import OrderedDict
from threading import Lock


class _NonceCache:
    """Thread-safe LRU cache for nonce deduplication."""

    def __init__(self, maxsize: int = 10_000) -> None:
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._maxsize = maxsize
        self._lock = Lock()

    def seen(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._cache:
                return True
            self._cache[nonce] = time.time()
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)
            return False


_nonce_cache = _NonceCache()


def validate_canary_signature(
    payload: bytes,
    signature: str,
    secret: str,
    timestamp: float | None = None,
    tolerance_seconds: int = 300,
) -> bool:
    """Validate HMAC-SHA256 signature with optional replay protection.

    Args:
        payload: Raw request body bytes.
        signature: Hex-encoded HMAC-SHA256 from the webhook sender.
        secret: Shared HMAC secret.
        timestamp: Unix epoch from the webhook payload (replay protection).
        tolerance_seconds: Maximum allowed age in seconds.
    """
    if not signature:
        return False

    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False

    # Replay protection: reject stale or duplicate payloads
    if timestamp is not None:
        age = abs(time.time() - timestamp)
        if age > tolerance_seconds:
            return False

    # Nonce = signature itself (unique per payload)
    if _nonce_cache.seen(signature):
        return False

    return True
