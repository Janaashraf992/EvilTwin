import json
import types

from controller import FlowController


class FakeReq:
    def __init__(self, body=None):
        self.body = body
        self.json = body or {}


class FakeApp:
    def __init__(self):
        self.suspicious_ips = {"10.0.1.10": 9999999999}
        self.datapaths = {}


def test_flow_controller_get_and_post_and_delete():
    app = FakeApp()
    controller = FlowController(FakeReq(), None, {"eviltwin_app": app})

    get_response = controller.list_flows(FakeReq())
    body = json.loads(get_response.body)
    assert "10.0.1.10" in body

    post_response = controller.add_flow(FakeReq(body={"ip": "10.0.1.11", "duration": 120}))
    assert post_response.status == 200
    assert "10.0.1.11" in app.suspicious_ips

    delete_response = controller.del_flow(FakeReq(), ip="10.0.1.10")
    assert delete_response.status == 200
    assert "10.0.1.10" not in app.suspicious_ips


def test_query_threat_score_parses_json(monkeypatch):
    import controller as controller_module

    class FakeResponse:
        status = 200

        def read(self):
            return b'{"threat_level": 3}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout):
        return FakeResponse()

    monkeypatch.setattr(controller_module.urllib.request, "urlopen", fake_urlopen)

    stub = types.SimpleNamespace(backend_url="http://backend:8000")
    result = controller_module.EvilTwinController.query_threat_score(stub, "10.0.1.10")
    assert result["threat_level"] == 3
