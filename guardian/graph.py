"""[2] Dependency graph: who pulls in whom, and the path from the app to any package."""
from __future__ import annotations

import networkx as nx

from .discover import Inventory

ROOT = ""


class DepGraph:
    def __init__(self, inv: Inventory):
        self.inv = inv
        g = nx.DiGraph()
        g.add_node(ROOT, label=f"{inv.app_name}@{inv.app_version}")
        for key, c in inv.components.items():
            g.add_node(key, label=c.label)
        for parent, child, kind in inv.edges:
            g.add_edge(parent, child, kind=kind)
        self.g = g
        # BFS predecessor tree from the root gives shortest dependency paths
        self._pred = dict(nx.bfs_predecessors(g, ROOT))
        # Production closure: everything reachable from the app's runtime dependencies.
        # This is what `npm install --production` (used in the Dockerfile) actually installs.
        prod_roots = [b for a, b, kind in inv.edges
                      if a == ROOT and kind in ("dependencies", "optionalDependencies")]
        prod: set[str] = set(prod_roots)
        for r in prod_roots:
            prod |= nx.descendants(g, r)
        for k, c in inv.components.items():
            c.dev = k not in prod

    def label(self, key: str) -> str:
        return self.g.nodes[key]["label"]

    def shortest_path(self, key: str) -> list[str]:
        if key == ROOT:
            return [ROOT]
        if key not in self._pred:
            return []  # orphan / not reachable from the app
        path = [key]
        while path[-1] != ROOT:
            path.append(self._pred[path[-1]])
        return list(reversed(path))

    def paths(self, key: str, limit: int = 3) -> list[list[str]]:
        """Up to `limit` distinct paths root -> key (shortest first), as labels."""
        out: list[list[str]] = []
        sp = self.shortest_path(key)
        if sp:
            out.append(sp)
        # Extra paths: via other direct parents' shortest paths
        for parent in self.g.predecessors(key):
            if len(out) >= limit:
                break
            pp = self.shortest_path(parent)
            if pp and pp + [key] not in out:
                out.append(pp + [key])
        return [[self.label(k) for k in p] for p in out]

    def direct_introducers(self, key: str) -> list[str]:
        """Which direct dependencies of the app (transitively) bring this package in."""
        anc = nx.ancestors(self.g, key) | {key}
        return sorted(
            self.inv.components[k].label
            for k in anc
            if k in self.inv.components and self.inv.components[k].direct
        )

    def stats(self) -> dict:
        comps = self.inv.components.values()
        depth = {k: len(self.shortest_path(k)) - 1 for k in self.inv.components}
        return {
            "total_components": len(self.inv.components),
            "unique_name_versions": len({c.label for c in comps}),
            "direct": sum(1 for c in comps if c.direct),
            "transitive": sum(1 for c in comps if not c.direct),
            "runtime": sum(1 for c in comps if not c.dev),
            "runtime_unique_name_versions": len({c.label for c in comps if not c.dev}),
            "dev_only": sum(1 for c in comps if c.dev),
            "edges": self.g.number_of_edges(),
            "max_depth": max(depth.values()) if depth else 0,
            "unreachable": sum(1 for d in depth.values() if d < 0),
            "with_install_scripts": sum(1 for c in comps if c.has_install_script),
        }

    def subgraph_for(self, keys: set[str]) -> dict:
        """vis-network friendly nodes/edges covering every path root -> keys."""
        nodes: set[str] = {ROOT}
        for k in keys:
            nodes.update(self.shortest_path(k))
        # add direct deps so the picture shows the top level
        nodes.update(k for k, c in self.inv.components.items() if c.direct)
        sub = self.g.subgraph(nodes)
        return {
            "nodes": [
                {
                    "id": n,
                    "label": self.label(n),
                    "root": n == ROOT,
                    "direct": n != ROOT and self.inv.components[n].direct,
                    "dev": n != ROOT and self.inv.components[n].dev,
                    "flagged": n in keys,
                }
                for n in sub.nodes
            ],
            "edges": [{"from": a, "to": b} for a, b in sub.edges],
        }
