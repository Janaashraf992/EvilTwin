from __future__ import annotations

# pyright: reportMissingImports=false

import os
import time
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

    @wsgi.route("sdns", "/sdns/flows", methods=["POST"])
    def add_sdns_flow(self, req, **kwargs):
        """Called by gateway after pre-session decision.
        Body: {"ip": "10.0.1.10", "target": "real"|"honeypot", "duration": 300}
        """
        import json as _json
        data = _json.loads(req.body) if req.body else {}
        ip = data.get("ip")
        target = data.get("target")
        duration = int(data.get("duration", 300))
        if not ip or not target:
            return wsgi.Response(status=400, body="missing ip or target")

        # Resolve target to IP
        if target == "honeypot":
            target_ip = self.app.honeypot_ip
        elif target == "real":
            target_ip = self.app.real_server_ip
        else:
            target_ip = target  # raw IP string

        # Store routing
        self.app.routing_table[ip] = {
            "target_ip": target_ip,
            "target": target,
            "expires_at": __import__("time").time() + duration,
        }

        # Install flows on all connected switches
        for dpid, dp in list(self.app.datapaths.items()):
            out_port = self.app._lookup_out_port(dpid, target_ip)
            if out_port is not None:
                self.app.flow_manager.install_redirect_flow(
                    dp, ip, target_ip, out_port
                )

        return wsgi.Response(
            content_type="application/json",
            body=_json.dumps({
                "status": "ok",
                "ip": ip,
                "target": target,
                "target_ip": target_ip,
            }),
        )

    @wsgi.route("sdns", "/sdns/routes/{ip}", methods=["GET"])
    def get_sdns_route(self, req, **kwargs):
        """Check routing for an IP."""
        import json as _json
        ip = kwargs["ip"]
        route = self.app.routing_table.get(ip)
        if route:
            return wsgi.Response(
                content_type="application/json",
                body=_json.dumps(route),
            )
        return wsgi.Response(
            status=404,
            content_type="application/json",
            body=_json.dumps({"ip": ip, "routed": False}),
        )

    @wsgi.route("sdns", "/sdns/flows", methods=["GET"])
    def list_sdns_flows(self, req, **kwargs):
        import json as _json
        body = {
            ip: {"target": v["target"], "target_ip": v["target_ip"]}
            for ip, v in self.app.routing_table.items()
        }
        return wsgi.Response(content_type="application/json", body=_json.dumps(body))

    @wsgi.route("sdns", "/sdns/flows/{ip}", methods=["DELETE"])
    def del_sdns_flow(self, req, **kwargs):
        import json as _json
        ip = kwargs["ip"]
        self.app.routing_table.pop(ip, None)
        for dp in self.app.datapaths.values():
            self.app.flow_manager.remove_flow(dp, ip)
        return wsgi.Response(
            content_type="application/json",
            body=_json.dumps({"status": "removed", "ip": ip}),
        )


class EvilTwinController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": wsgi.WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.routing_table: dict[str, dict] = {}
        self.datapaths: dict[int, Any] = {}

        self.backend_url = os.getenv("BACKEND_URL", "http://backend:8000")
        self.honeypot_ip = os.getenv("HONEYPOT_IP", "10.0.2.10")
        self.real_server_ip = os.getenv("REAL_SERVER_IP", "10.0.1.100")
        self.threshold = int(os.getenv("THREAT_REDIRECT_THRESHOLD", "2"))

        self.flow_manager = FlowManager(self.logger)

        wsgi_app = kwargs["wsgi"]
        wsgi_app.register(FlowController, {"eviltwin_app": self})

    def _lookup_out_port(self, dpid: int, target_ip: str) -> int | None:
        """Find the switch port connected to target_ip.
        Uses learned MAC-to-port mapping from packet_in_handler.
        Falls back to OFPP_FLOOD if port unknown (OVS will learn it).
        """
        ports = self.mac_to_port.get(dpid, {})
        # Any known port is better than nothing — OVS learning handles the rest
        for _mac, port in ports.items():
            if port != 0:
                return port
        return None  # caller should fall back to FLOOD

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

        # Learn MAC-to-port mapping
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        # Check routing table for this source IP
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            now = time.time()
            route = self.routing_table.get(src_ip)
            if route:
                if route["expires_at"] < now:
                    self.routing_table.pop(src_ip, None)
                else:
                    target_port = self._lookup_out_port(dpid, route["target_ip"])
                    if target_port is not None:
                        self.flow_manager.install_redirect_flow(
                            datapath, src_ip, route["target_ip"], target_port
                        )

        # Normal forwarding
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)
