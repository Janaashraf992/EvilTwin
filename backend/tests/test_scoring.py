from services.threat_scorer import ThreatScorer


class DummySession:
    commands = [{"command": "ls"}]
    credentials_tried = []
    start_time = None
    end_time = None
    malware_hashes = []


class DummyProfile:
    ip = "10.0.0.1"
    vpn_detected = False


def test_scorer_fallback_without_model(tmp_path):
    scorer = ThreatScorer(str(tmp_path / "missing.pkl"))
    import asyncio

    score, level = asyncio.run(scorer.score(DummySession(), DummyProfile()))
    assert score == 0.0
    assert level == 0
