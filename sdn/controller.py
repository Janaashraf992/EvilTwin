from __future__ import annotations

# pyright: reportMissingImports=false

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

try:
    from ryu.app import wsgi
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.lib.packet import ethernet, ipv4, packet
    from ryu.ofproto import ofproto_v1_3
except ModuleNotFoundError:
    class _NoOpWSGI:
        class ControllerBase:
            def __init__(self, req, link, data, **config):
                pass

        class WSGIApplication:
            def register(self, controller, data):
                return None

        @staticmethod
        def route(*args, **kwargs):
            def _decorator(fn):
                return fn

            return _decorator

        class Response:
            def __init__(self, status=200, body="", content_type="application/json"):
                self.status = status
                self.body = body
                self.content_type = content_type

    class _NoOpAppManager:
        class RyuApp:
            def __init__(self, *args, **kwargs):
                import logging

                self.logger = logging.getLogger(__name__)

    class _NoOpOFPEvent:
        EventOFPSwitchFeatures = object
        EventOFPPacketIn = object

    def set_ev_cls(*args, **kwargs):
        def _decorator(fn):
            return fn

        return _decorator

    CONFIG_DISPATCHER = object()
    MAIN_DISPATCHER = object()

    class _NoOpEthernet:
        ethernet = object

    class _NoOpIPv4:
        ipv4 = object

    class _NoOpPacket:
        class Packet:
            def __init__(self, data):
                self.data = data

            def get_protocol(self, _):
                return None

    class _NoOpProto:
        OFP_VERSION = 0x04

    wsgi = _NoOpWSGI()
    app_manager = _NoOpAppManager()
    ofp_event = _NoOpOFPEvent()
    ethernet = _NoOpEthernet()
    ipv4 = _NoOpIPv4()
    packet = _NoOpPacket()
    ofproto_v1_3 = _NoOpProto()

from flow_manager import FlowManager


class FlowController(wsgi.ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data["eviltwin_app"]

    @wsgi.route("flows", "/flows", methods=["GET"])
    def list_flows(self, req, **kwargs):
        body = {
            ip: {"expires_at": expiry}
            for ip, expiry in self.app.suspicious_ips.items()
            if expiry > time.time()
        }
        return wsgi.Response(content_type="application/json", body=json.dumps(body))

    @wsgi.route("flows", "/flows", methods=["POST"])
    def add_flow(self, req, **kwargs):
        data = req.json if req.body else {}
        ip = data.get("ip")
        duration = int(data.get("duration", 300))
        if not ip:
            return wsgi.Response(status=400, body="missing ip")
        self.app.suspicious_ips[ip] = time.time() + duration
        return wsgi.Response(content_type="application/json", body=json.dumps({"status": "ok", "ip": ip}))

    @wsgi.route("flows", "/flows/{ip}", methods=["DELETE"])
    def del_flow(self, req, **kwargs):
        ip = kwargs["ip"]
        self.app.suspicious_ips.pop(ip, None)
        for dp in self.app.datapaths.values():
            self.app.flow_manager.remove_flow(dp, ip)
        return wsgi.Response(content_type="application/json", body=json.dumps({"status": "removed", "ip": ip}))


class EvilTwinController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": wsgi.WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.suspicious_ips: dict[str, float] = {}
        self.datapaths: dict[int, Any] = {}

        self.backend_url = os.getenv("BACKEND_URL", "http://backend:8000")
        self.honeypot_ip = os.getenv("HONEYPOT_IP", "10.0.2.10")
        self.threshold = int(os.getenv("THREAT_REDIRECT_THRESHOLD", "2"))

        self.flow_manager = FlowManager(self.logger)

        wsgi_app = kwargs["wsgi"]
        wsgi_app.register(FlowController, {"eviltwin_app": self})

    def query_threat_score(self, ip: str) -> dict[str, Any]:
        try:
            req = urllib.request.Request(f"{self.backend_url}/score/{ip}", method="GET")
            with urllib.request.urlopen(req, timeout=2) as response:
                if response.status != 200:
                    return {"threat_level": 0}
                payload = response.read().decode("utf-8")
                return json.loads(payload)
        except Exception:
            return {"threat_level": 0}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapaths[ev.msg.datapath.id] = ev.msg.datapath

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            now = time.time()
            expiry = self.suspicious_ips.get(src_ip, 0)
            if expiry < now:
                self.suspicious_ips.pop(src_ip, None)
                level = self.query_threat_score(src_ip).get("threat_level", 0)
                if level >= self.threshold:
                    self.suspicious_ips[src_ip] = now + 300
                    self.flow_manager.install_redirect_flow(datapath, src_ip, self.honeypot_ip, out_port)

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)
