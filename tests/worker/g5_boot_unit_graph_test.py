from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "deploy" / "systemd"
MARKER = "/var/lib/open-card/upgrade-in-progress"
SAFE_TARGET = "open-card-upgrade-safe.target"
RECOVERY_UNIT = "open-card-upgrade-recover.service"
FINALIZER_UNIT = "open-card-upgrade-finalize.service"
DOWNSTREAM_UNITS = (
    "open-card-buildkit.service",
    "open-card-caddy.service",
    "open-card-server.service",
    "open-card-agent.service",
    "open-card-edge.service",
)


def read(relative: str) -> str:
    return (SYSTEMD / relative).read_text(encoding="utf-8")


def graph_edges(fragments: dict[str, str]) -> dict[str, set[str]]:
    edges = {name: set() for name in fragments}
    for name, contents in fragments.items():
        for line in contents.splitlines():
            if line.startswith("After="):
                for dependency in line.removeprefix("After=").split():
                    if dependency in edges:
                        edges[dependency].add(name)
            if line.startswith("Before="):
                for dependent in line.removeprefix("Before=").split():
                    if dependent in edges:
                        edges[name].add(dependent)
    return edges


def has_cycle(edges: dict[str, set[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(visit(child) for child in edges[node]):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in edges)


class BootUnitGraphTests(unittest.TestCase):
    def test_boot_safe_graph_is_static_acyclic_and_marker_gated(self) -> None:
        recovery = read(RECOVERY_UNIT)
        target = read(SAFE_TARGET)
        finalizer = read(FINALIZER_UNIT)
        edge_drop_in = read("open-card-edge.service.d/10-upgrade-marker.conf")

        self.assertNotIn("[Install]", recovery)
        self.assertNotIn("[Install]", finalizer)
        self.assertEqual(
            edge_drop_in,
            f"[Unit]\nConditionPathExists=!{MARKER}\n",
        )
        self.assertNotIn("ConditionPathExists=", read("open-card-edge.service"))

        self.assertIn(f"Before={SAFE_TARGET}\n", recovery)
        self.assertIn(f"After={SAFE_TARGET}\n", finalizer)
        self.assertIn(f"ConditionPathExists={MARKER}\n", recovery)
        self.assertIn(f"ConditionPathExists={MARKER}\n", finalizer)
        self.assertIn(
            "ExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover-prepare --pending\n",
            recovery,
        )
        self.assertIn(
            "ExecStart=/opt/open-card/upgrade-tools/open-card-upgrade recover-finalize --pending\n",
            finalizer,
        )
        for contents in (recovery, finalizer):
            self.assertIn(
                "ReadWritePaths=/opt/open-card /var/lib/open-card /run/lock /etc/open-card /etc/systemd/system\n",
                contents,
            )
            self.assertNotIn("/bin/sh", contents)

        required_by = " ".join(DOWNSTREAM_UNITS)
        before = " ".join((*DOWNSTREAM_UNITS, FINALIZER_UNIT))
        self.assertIn(f"Requires={RECOVERY_UNIT}\n", target)
        self.assertIn(f"Wants={FINALIZER_UNIT}\n", target)
        self.assertIn(f"After={RECOVERY_UNIT}\n", target)
        self.assertIn(f"Before={before}\n", target)
        self.assertIn("[Install]\n", target)
        self.assertIn("WantedBy=multi-user.target\n", target)
        self.assertIn(f"RequiredBy={required_by}\n", target)
        self.assertNotIn("Before=open-card-edge.service", finalizer)

        fragments = {
            RECOVERY_UNIT: recovery,
            SAFE_TARGET: target,
            FINALIZER_UNIT: finalizer,
            **{name: read(name) for name in DOWNSTREAM_UNITS},
        }
        self.assertFalse(has_cycle(graph_edges(fragments)))


if __name__ == "__main__":
    unittest.main()
