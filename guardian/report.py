"""Render the human-readable HTML report (single self-contained file, works offline)."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

HERE = Path(__file__).parent
TEMPLATES = HERE / "templates"
VIS = HERE / "static" / "vis-network.min.js"


def write_html(report: dict, graph: dict, path: Path) -> Path:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    vis_js = VIS.read_text(encoding="utf-8").replace("</script", "<\\/script") if VIS.exists() else ""
    html = env.get_template("report.html.j2").render(report=report, graph=graph, vis_js=vis_js)
    path.write_text(html, encoding="utf-8")
    return path
