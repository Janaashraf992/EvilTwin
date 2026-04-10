from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


def run_topology() -> None:
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    c0 = net.addController("c0", ip="127.0.0.1", port=6633)
    s1 = net.addSwitch("s1")

    h1 = net.addHost("h1", ip="10.0.1.10")
    h2 = net.addHost("h2", ip="10.0.1.20")
    h3 = net.addHost("h3", ip="10.0.2.10")

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.start()
    print("Mininet topology started with attacker h1, server h2, honeypot h3")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    run_topology()
