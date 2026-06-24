from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
import os

RYU_IP = os.environ.get("RYU_IP", "127.0.0.1")
RYU_PORT = int(os.environ.get("RYU_PORT", "6633"))


def run_topology() -> None:
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    net.addController("c0", ip=RYU_IP, port=RYU_PORT)
    s1 = net.addSwitch("s1")

    h1 = net.addHost("h1", ip="10.0.1.10")   # attacker
    h2 = net.addHost("h2", ip="10.0.1.20")   # normal user
    h3 = net.addHost("h3", ip="10.0.2.10")   # honeypot (Cowrie + Dionaea)
    h4 = net.addHost("h4", ip="10.0.1.1")    # gateway (SSH proxy + SDN notifier)
    h5 = net.addHost("h5", ip="10.0.1.100")  # real banner server (dummy)

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)

    net.start()
    print("=" * 60)
    print("Mininet topology started:")
    print("  h1 (%s) = attacker" % h1.IP())
    print("  h2 (%s) = normal user" % h2.IP())
    print("  h3 (%s) = honeypot (Cowrie + Dionaea)" % h3.IP())
    print("  h4 (%s) = gateway (SSH proxy)" % h4.IP())
    print("  h5 (%s) = real banner server" % h5.IP())
    print("  Ryu controller at %s:%s" % (RYU_IP, RYU_PORT))
    print("=" * 60)
    CLI(net)
    net.stop()


if __name__ == "__main__":
    run_topology()
