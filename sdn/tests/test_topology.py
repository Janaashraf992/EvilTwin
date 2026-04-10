"""
Mininet test topology for EvilTwin SDN redirection.

Topology:
    h1 (attacker)  -- 10.0.1.10
    h2 (server)    -- 10.0.1.20
    h3 (honeypot)  -- 10.0.2.10

    All connected to switch s1, controlled by Ryu on localhost:6633.

The test verifies that a suspicious IP's traffic is redirected to the
honeypot IP by the EvilTwin controller.

Requires: mininet, openvswitch-switch, and ryu-manager running.
"""
from __future__ import annotations

import subprocess
import time

try:
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.log import setLogLevel
    HAS_MININET = True
except ImportError:
    HAS_MININET = False


def create_topology() -> "Mininet":
    """Create a 3-host Mininet topology connected to a remote Ryu controller."""
    net = Mininet(controller=RemoteController, switch=OVSSwitch)
    net.addController("c0", ip="127.0.0.1", port=6633)

    s1 = net.addSwitch("s1")

    h1 = net.addHost("h1", ip="10.0.1.10/24")  # attacker
    h2 = net.addHost("h2", ip="10.0.1.20/24")  # real server
    h3 = net.addHost("h3", ip="10.0.2.10/24")  # honeypot

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    return net


def test_normal_connectivity(net: "Mininet") -> bool:
    """Verify that h1 can reach h2 (normal forwarding)."""
    h1 = net.get("h1")
    result = h1.cmd("ping -c 1 -W 2 10.0.1.20")
    return "1 received" in result


def test_honeypot_redirect(net: "Mininet") -> bool:
    """
    After the SDN controller marks h1 as suspicious, traffic
    originally destined for h2 should be redirected to h3 (honeypot).

    This test:
    1. Sends a ping from h1 → h2
    2. Checks that h3 (honeypot) receives the traffic via tcpdump
    """
    h1 = net.get("h1")
    h3 = net.get("h3")

    # Start tcpdump on honeypot to capture redirected packets
    h3.cmd("tcpdump -c 1 -w /tmp/capture.pcap icmp &")
    time.sleep(1)

    # Send traffic from attacker to server
    h1.cmd("ping -c 3 -W 2 10.0.1.20")
    time.sleep(2)

    # Check if honeypot received the redirected traffic
    result = h3.cmd("tcpdump -r /tmp/capture.pcap 2>/dev/null | wc -l")
    packet_count = int(result.strip()) if result.strip().isdigit() else 0

    return packet_count > 0


def run_tests() -> None:
    """Run the full Mininet test suite."""
    if not HAS_MININET:
        print("SKIP: Mininet not installed")
        return

    setLogLevel("warning")
    net = create_topology()

    try:
        net.start()
        print("Topology started: h1=attacker, h2=server, h3=honeypot")
        time.sleep(2)

        # Test 1: Normal connectivity
        print("\n[TEST 1] Normal connectivity (h1 → h2)...")
        if test_normal_connectivity(net):
            print("  ✓ PASS: h1 can reach h2")
        else:
            print("  ✗ FAIL: h1 cannot reach h2")

        # Test 2: Honeypot redirect
        # (requires the Ryu controller to have marked h1 as suspicious)
        print("\n[TEST 2] Honeypot redirect (h1 → h2 redirected to h3)...")
        # Mark h1 as suspicious via the SDN REST API
        try:
            subprocess.run(
                [
                    "curl", "-s", "-X", "POST",
                    "http://127.0.0.1:8080/flows",
                    "-H", "Content-Type: application/json",
                    "-d", '{"ip": "10.0.1.10", "duration": 60}',
                ],
                timeout=5,
                capture_output=True,
            )
            time.sleep(1)
        except Exception as e:
            print(f"  Warning: Could not mark IP via REST API: {e}")

        if test_honeypot_redirect(net):
            print("  ✓ PASS: traffic redirected to honeypot")
        else:
            print("  ✗ FAIL: no traffic reached honeypot")

    finally:
        net.stop()
        print("\nTopology stopped.")


if __name__ == "__main__":
    run_tests()
