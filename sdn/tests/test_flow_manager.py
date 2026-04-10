from flow_manager import FlowManager


class FakeParser:
    def OFPMatch(self, **kwargs):
        return {"match": kwargs}

    def OFPActionSetField(self, **kwargs):
        return {"set": kwargs}

    def OFPActionOutput(self, port):
        return {"output": port}

    def OFPInstructionActions(self, instruction_type, actions):
        return {"instruction_type": instruction_type, "actions": actions}

    def OFPFlowMod(self, **kwargs):
        return {"flow_mod": kwargs}


class FakeOfproto:
    OFPIT_APPLY_ACTIONS = 4
    OFPFF_SEND_FLOW_REM = 1
    OFPFC_DELETE = 3
    OFPP_ANY = 0xFFFFFFFF
    OFPG_ANY = 0xFFFFFFFF


class FakeDatapath:
    def __init__(self):
        self.ofproto = FakeOfproto()
        self.ofproto_parser = FakeParser()
        self.sent = []

    def send_msg(self, msg):
        self.sent.append(msg)


class FakeLogger:
    def info(self, *args, **kwargs):
        return None


def test_install_and_remove_flow():
    dp = FakeDatapath()
    manager = FlowManager(FakeLogger())

    manager.install_redirect_flow(dp, "10.0.1.10", "10.0.2.10", 2)
    manager.remove_flow(dp, "10.0.1.10")

    assert len(dp.sent) == 2
    first = dp.sent[0]["flow_mod"]
    assert first["priority"] == 200
    assert first["idle_timeout"] == 300
