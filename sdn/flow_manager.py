# pyright: reportMissingImports=false

try:
    from ryu.lib.packet import ether_types
except ModuleNotFoundError:
    class _EtherTypes:
        ETH_TYPE_IP = 0x0800

    ether_types = _EtherTypes()


class FlowManager:
    def __init__(self, logger) -> None:
        self.logger = logger

    def install_redirect_flow(
        self, datapath, src_ip: str, target_ip: str, out_port: int
    ) -> None:
        """Install OpenFlow rule: redirect ALL traffic from src_ip to target_ip.

        Rewrites ipv4_dst for every packet from src_ip.
        Return traffic flows normally (L2 learning on OVS handles it).
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
        )
        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionOutput(out_port),
        ]
        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=200,
            match=match,
            instructions=instructions,
            idle_timeout=300,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )
        datapath.send_msg(mod)
        self.logger.info(
            "Redirect flow: src=%s → dst-rewrite→%s port=%d",
            src_ip, target_ip, out_port,
        )

    def remove_flow(self, datapath, src_ip: str) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=200,
            match=match,
        )
        datapath.send_msg(mod)
        self.logger.info("Removed redirect flow src=%s", src_ip)
