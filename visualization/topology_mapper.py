"""
visualization/topology_mapper.py — NetworkX Topology
Builds a live graph. Exports JSON for D3.js in the web dashboard.
"""
import networkx as nx
from collections import defaultdict
from typing import Dict
import config
from utils.logger import get_logger
log = get_logger(__name__)


class TopologyMapper:
    def __init__(self, gateway: str = config.GATEWAY):
        self.gateway = gateway
        self.G       = nx.Graph()
        self._pkt_counts: Dict[tuple, int] = defaultdict(int)
        self.G.add_node(gateway, label="Gateway/Router", node_type="router", mac="N/A", vendor="N/A")

    def add_device(self, device) -> None:
        ip = device.ip if hasattr(device, "ip") else device.get("ip")
        if not ip or ip == self.gateway:
            return
        self.G.add_node(
            ip,
            label     = getattr(device, "hostname", ip) or ip,
            node_type = "device",
            mac       = getattr(device, "mac", "N/A"),
            vendor    = getattr(device, "vendor", "Unknown"),
        )
        if not self.G.has_edge(self.gateway, ip):
            self.G.add_edge(self.gateway, ip, packets=0)
        log.debug("Topology: added %s", ip)

    def record_traffic(self, src: str, dst: str) -> None:
        if src in self.G and dst in self.G:
            if self.G.has_edge(src, dst):
                self.G[src][dst]["packets"] += 1
            else:
                self.G.add_edge(src, dst, packets=1)

    def to_d3_json(self) -> dict:
        nodes = [{"id": n, "label": d.get("label", n),
                  "type": d.get("node_type", "device"),
                  "mac": d.get("mac", "N/A"), "vendor": d.get("vendor", "Unknown")}
                 for n, d in self.G.nodes(data=True)]
        links = [{"source": u, "target": v, "packets": d.get("packets", 0)}
                 for u, v, d in self.G.edges(data=True)]
        return {"nodes": nodes, "links": links}

    def save_image(self, filepath: str = "topology.png") -> bool:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            pos   = nx.spring_layout(self.G, seed=42)
            types = nx.get_node_attributes(self.G, "node_type")
            routers = [n for n, t in types.items() if t == "router"]
            devices = [n for n, t in types.items() if t == "device"]
            plt.figure(figsize=(12, 8), facecolor="#0d1117")
            ax = plt.gca(); ax.set_facecolor("#0d1117")
            nx.draw_networkx_edges(self.G, pos, edge_color="#30363d", width=1.5, ax=ax)
            nx.draw_networkx_nodes(self.G, pos, nodelist=routers, node_color="#f85149", node_size=600, ax=ax)
            nx.draw_networkx_nodes(self.G, pos, nodelist=devices, node_color="#58a6ff", node_size=300, ax=ax)
            nx.draw_networkx_labels(self.G, pos, font_color="#c9d1d9", font_size=8, ax=ax)
            plt.title("Network Topology", color="#c9d1d9")
            plt.tight_layout()
            plt.savefig(filepath, dpi=150, facecolor="#0d1117")
            plt.close()
            log.info("Topology image saved: %s", filepath)
            return True
        except Exception as e:
            log.error("Topology image error: %s", e)
            return False
