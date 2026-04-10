from services.canary_webhook import validate_canary_signature


def test_canary_signature_validation():
    secret = "supersecret"
    payload = b'{"token_id":"abc"}'

    import hashlib
    import hmac

    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    assert validate_canary_signature(payload, sig, secret)
    assert not validate_canary_signature(payload, "bad", secret)
