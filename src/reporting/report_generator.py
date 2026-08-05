"""Report Generator — HTML and Markdown reports from the attack graph.

Reads the NetworkX attack graph and SQLite persistence layer, then produces
structured penetration test reports in HTML, Markdown, and JSON formats,
covering:
- Discovered hosts and services
- Exploit attempts and outcomes (with CVE cross-references)
- Session details and privilege levels
- CVE candidates mapped to services
- Post-mortem summaries for failed attempts
- Exploit timeline (chronological, from SQLite) — Week 19–20
- Network topology diagram (D3-style node-edge JSON in HTML) — Week 19–20

Owner: Vedant (Member C) — Week 17–22 deliverable
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.state.attack_graph import AttackGraph
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _node_color(node_type: str) -> str:
    """Return a CSS hex color for a given node type."""
    colors = {
        "host": "#4A90D9",
        "service": "#5BAD6F",
        "cve": "#E8963A",
        "session": "#D94A4A",
        "web_endpoint": "#A860D0",
        "failure": "#888888",
    }
    return colors.get(node_type, "#AAAAAA")


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Generates HTML and Markdown pentest reports from the attack graph.

    Args:
        attack_graph: The :class:`~src.state.attack_graph.AttackGraph` to
            read data from.
        output_dir: Directory where report files will be written.
            Created if it does not exist.
        run_id: Unique identifier for this pentest run, used in filenames.
    """

    def __init__(
        self,
        attack_graph: AttackGraph,
        output_dir: str = "runs/reports",
        run_id: str = "report",
    ) -> None:
        """Initialise ReportGenerator."""
        self._graph = attack_graph
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._run_id = run_id

    # ── Public API ────────────────────────────────────────────────

    def generate_html(self) -> str:
        """Generate an HTML report and write it to disk.

        Returns:
            Absolute path to the written HTML file.
        """
        data = self._collect_graph_data()
        html_content = self._render_html(data)

        out_path = self._output_dir / f"{self._run_id}.html"
        out_path.write_text(html_content, encoding="utf-8")
        logger.info("HTML report written to %s", out_path)
        return str(out_path)

    def generate_markdown(self) -> str:
        """Generate a Markdown report and write it to disk.

        Returns:
            Absolute path to the written Markdown file.
        """
        data = self._collect_graph_data()
        md_content = self._render_markdown(data)

        out_path = self._output_dir / f"{self._run_id}.md"
        out_path.write_text(md_content, encoding="utf-8")
        logger.info("Markdown report written to %s", out_path)
        return str(out_path)

    def generate_json(self) -> str:
        """Generate a machine-readable JSON report and write it to disk.

        Returns:
            Absolute path to the written JSON file.
        """
        data = self._collect_graph_data()
        out_path = self._output_dir / f"{self._run_id}.json"
        out_path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("JSON report written to %s", out_path)
        return str(out_path)

    def generate_all(self) -> dict[str, str]:
        """Generate HTML, Markdown, and JSON reports.

        Returns:
            Dict mapping format name → file path.
        """
        return {
            "html": self.generate_html(),
            "markdown": self.generate_markdown(),
            "json": self.generate_json(),
            "timeline": self.generate_timeline_json(),
        }

    def generate_timeline_json(self) -> str:
        """Generate a chronological exploit timeline JSON file.

        Reads exploit attempt records from SQLite persistence in timestamp
        order and enriches them with CVE and session data from the graph.

        Returns:
            Absolute path to the written timeline JSON file.
        """
        timeline = self._build_exploit_timeline()
        out_path = self._output_dir / f"{self._run_id}_timeline.json"
        out_path.write_text(
            json.dumps(timeline, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("Timeline JSON written to %s", out_path)
        return str(out_path)

    # ── Data collection ───────────────────────────────────────────

    def _collect_graph_data(self) -> dict[str, Any]:
        """Extract all relevant data from the attack graph.

        Returns:
            A structured dictionary with hosts, services, CVEs, sessions,
            and failure nodes.
        """
        g = self._graph.graph
        hosts: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        cves: list[dict[str, Any]] = []
        sessions: list[dict[str, Any]] = []
        web_endpoints: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []

        for node_id, data in g.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            enriched = dict(data)
            enriched["node_id"] = node_id

            if node_type == "host":
                hosts.append(enriched)
            elif node_type == "service":
                services.append(enriched)
            elif node_type == "cve":
                cves.append(enriched)
            elif node_type == "session":
                sessions.append(enriched)
            elif node_type == "web_endpoint":
                web_endpoints.append(enriched)
            elif node_type == "failure":
                failures.append(enriched)

        # Collect exploit attempt edges
        exploit_edges: list[dict[str, Any]] = []
        for src, dst, edge_data in g.edges(data=True):
            if edge_data.get("type") == "exploit_attempt":
                exploit_edges.append(
                    {
                        "source": src,
                        "target": dst,
                        "result": edge_data.get("result", "unknown"),
                        "module": edge_data.get("module", ""),
                        "error_type": edge_data.get("error_type", ""),
                        "post_mortem": edge_data.get("post_mortem", ""),
                    }
                )

        return {
            "run_id": self._run_id,
            "generated_at": _utc_now_str(),
            "summary": {
                "total_hosts": len(hosts),
                "total_services": len(services),
                "total_cves": len(cves),
                "total_sessions": len(sessions),
                "total_web_endpoints": len(web_endpoints),
                "total_exploit_attempts": len(exploit_edges),
                "successful_exploits": sum(
                    1 for e in exploit_edges if e["result"] == "success"
                ),
            },
            "hosts": hosts,
            "services": services,
            "cves": sorted(cves, key=lambda x: x.get("cvss_score", 0.0), reverse=True),
            "sessions": sessions,
            "web_endpoints": web_endpoints,
            "exploit_attempts": exploit_edges,
            "failures": failures,
            "timeline": self._build_exploit_timeline(),
            "topology": self._build_topology_data(),
        }

    # ── Timeline builder (Week 19–20) ─────────────────────────────────

    def _build_exploit_timeline(self) -> list[dict[str, Any]]:
        """Build a chronological exploit timeline from the SQLite database.

        Reads all exploit attempt records ordered by timestamp, then enriches
        each entry with any CVE references from the attack graph.

        Returns:
            List of timeline event dicts, newest last.
        """
        try:
            records = self._graph.get_exploit_attempts()
        except Exception as exc:
            logger.warning("Could not read exploit attempts: %s", exc)
            records = []

        # Also include post-mortems for failed attempts
        try:
            post_mortems = self._graph.get_post_mortems()
        except Exception as exc:
            logger.warning("Could not read post-mortems: %s", exc)
            post_mortems = []

        # Build a fast lookup: target_service_id → list of CVE IDs
        cve_lookup: dict[str, list[str]] = {}
        for node_id, data in self._graph.graph.nodes(data=True):
            if data.get("node_type") == "cve":
                # Find services that have an edge to this CVE
                for pred in self._graph.graph.predecessors(node_id):
                    cve_lookup.setdefault(pred, []).append(
                        data.get("cve_id", node_id)
                    )

        # Build a fast lookup: module_used + target_service → post-mortem hypothesis
        pm_lookup: dict[str, str] = {}
        for pm in post_mortems:
            key = f"{pm.get('module_used', '')}::{pm.get('target_service', '')}"
            pm_lookup[key] = pm.get("hypothesis", "")

        timeline: list[dict[str, Any]] = []
        for rec in records:
            service_id = rec.get("target_service_id", "")
            module = rec.get("module_used", "")
            result = rec.get("result", "unknown")
            pm_key = f"{module}::{service_id}"
            event: dict[str, Any] = {
                "timestamp": rec.get("timestamp", ""),
                "module": module,
                "service": service_id,
                "payload": rec.get("payload", ""),
                "result": result,
                "session_id": rec.get("session_id", ""),
                "error_type": rec.get("error_type", ""),
                "cves": cve_lookup.get(service_id, []),
                "post_mortem": pm_lookup.get(pm_key, ""),
            }
            timeline.append(event)

        # Sort by timestamp (ISO string sort works for ISO-8601)
        timeline.sort(key=lambda e: e.get("timestamp", ""))
        return timeline

    # ── Topology builder (Week 19–20) ─────────────────────────────────

    def _build_topology_data(self) -> dict[str, Any]:
        """Serialise the attack graph as a node-link structure for visualisation.

        Returns:
            Dict with ``nodes`` and ``edges`` keys suitable for D3.js rendering.
        """
        g = self._graph.graph
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        for node_id, data in g.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            nodes.append({
                "id": node_id,
                "type": node_type,
                "label": (
                    data.get("ip")
                    or data.get("cve_id")
                    or data.get("session_id")
                    or data.get("url")
                    or node_id.split(":")[-1][:24]
                ),
                "color": _node_color(node_type),
            })

        for src, dst, edge_data in g.edges(data=True):
            edges.append({
                "source": src,
                "target": dst,
                "type": edge_data.get("type", ""),
                "result": edge_data.get("result", ""),
            })

        return {"nodes": nodes, "edges": edges}

    # ── HTML renderer ──────────────────────────────────────────────

    def _render_html(self, data: dict[str, Any]) -> str:
        """Render the collected data as an HTML string."""
        s = data["summary"]
        run_id = html.escape(data["run_id"])
        generated = html.escape(data["generated_at"])

        def _td(value: object) -> str:
            return f"<td>{html.escape(str(value))}</td>"

        def _tr(*values: object) -> str:
            return "<tr>" + "".join(_td(v) for v in values) + "</tr>"

        # ── Services table ────────────────────────────────────────
        svc_rows = ""
        for svc in data["services"]:
            svc_rows += _tr(
                svc.get("host_ip", ""),
                svc.get("port", ""),
                svc.get("protocol", ""),
                svc.get("name", ""),
                svc.get("product", ""),
                svc.get("version", ""),
                svc.get("state", ""),
            )

        # ── CVE table ─────────────────────────────────────────────
        cve_rows = ""
        for cve in data["cves"]:
            score = cve.get("cvss_score", 0.0)
            sev = (
                "🔴 Critical"
                if score >= 9
                else (
                    "🟠 High" if score >= 7 else "🟡 Medium" if score >= 4 else "🟢 Low"
                )
            )
            cve_rows += _tr(
                cve.get("cve_id", ""),
                f"{score:.1f}",
                sev,
                cve.get("description", "")[:120]
                + ("…" if len(cve.get("description", "")) > 120 else ""),
            )

        # ── Session table ─────────────────────────────────────────
        sess_rows = ""
        for sess in data["sessions"]:
            priv = sess.get("privilege", "user")
            badge = "🔑 root" if priv == "root" else "👤 user"
            sess_rows += _tr(
                sess.get("session_id", ""),
                sess.get("host_ip", ""),
                badge,
                sess.get("shell_type", ""),
                sess.get("opened_at", ""),
            )

        # ── Exploit attempts table ─────────────────────────────────
        exp_rows = ""
        for exp in data["exploit_attempts"]:
            result = exp.get("result", "unknown")
            icon = "✅" if result == "success" else "❌"
            exp_rows += _tr(
                exp.get("source", ""),
                exp.get("module", ""),
                f"{icon} {result}",
                exp.get("error_type", ""),
            )

        # ── Timeline table ────────────────────────────────────────
        timeline_rows = ""
        for event in data.get("timeline", []):
            res = event.get("result", "unknown")
            icon = "✅" if res == "success" else "❌"
            cve_str = ", ".join(event.get("cves", []))
            ts = event.get("timestamp", "")[:19].replace("T", " ")
            timeline_rows += _tr(
                ts,
                event.get("module", ""),
                event.get("service", ""),
                f"{icon} {res}",
                cve_str,
                event.get("error_type", ""),
            )


        # ── Topology JSON for inline script ────────────────────────────
        topology = data.get("topology", {"nodes": [], "edges": []})
        topo_json = html.escape(json.dumps(topology))

        pwned = s["successful_exploits"] > 0
        status_badge = (
            '<span class="badge success">PWNED ✅</span>'
            if pwned
            else '<span class="badge failure">NOT COMPROMISED ❌</span>'
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PenTest Report — {run_id}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117; color: #c9d1d9; line-height: 1.6;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
    h1 {{ font-size: 2rem; color: #58a6ff; margin-bottom: 0.25rem; }}
    h2 {{ font-size: 1.2rem; color: #8b949e; font-weight: 400; margin-bottom: 2rem; }}
    h3 {{
      font-size: 1rem; color: #58a6ff; margin: 2rem 0 0.75rem;
      border-bottom: 1px solid #21262d; padding-bottom: 0.4rem;
    }}
    .summary-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 1rem; margin: 1.5rem 0;
    }}
    .card {{
      background: #161b22; border: 1px solid #21262d;
      border-radius: 8px; padding: 1rem; text-align: center;
    }}
    .card .value {{ font-size: 2rem; font-weight: 700; color: #58a6ff; }}
    .card .label {{
      font-size: 0.8rem; color: #8b949e;
      text-transform: uppercase; letter-spacing: 0.05em;
    }}
    .badge {{
      display: inline-block; padding: 0.35em 0.75em;
      border-radius: 20px; font-weight: 700; font-size: 0.85rem;
    }}
    .badge.success {{ background: #196c2e; color: #3fb950; }}
    .badge.failure {{ background: #6e1414; color: #f85149; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th {{
      background: #161b22; color: #8b949e; text-align: left;
      padding: 0.6rem 0.8rem; border-bottom: 2px solid #21262d;
    }}
    td {{
      padding: 0.5rem 0.8rem; border-bottom: 1px solid #21262d; vertical-align: top;
    }}
    tr:hover td {{ background: #161b22; }}
    .meta {{ font-size: 0.8rem; color: #8b949e; margin-top: 0.5rem; }}
    .status-row {{ display: flex; align-items: center; gap: 1rem; margin: 1rem 0; }}
    #topology-canvas {{
      width: 100%; height: 340px; background: #0d1117;
      border: 1px solid #21262d; border-radius: 8px; margin: 0.75rem 0;
      position: relative; overflow: hidden;
    }}
    .topo-node {{
      position: absolute; border-radius: 50%;
      width: 14px; height: 14px; transform: translate(-50%, -50%);
      display: flex; align-items: center; justify-content: center;
    }}
    .topo-label {{
      position: absolute; font-size: 9px; color: #8b949e;
      white-space: nowrap; pointer-events: none; transform: translate(-50%, 100%);
    }}
  </style>
</head>
<body>
<div class="container">
  <h1>🔐 PrivacyAware-PenAgent Report</h1>
  <h2>Run: {run_id}</h2>
  <div class="status-row">
    {status_badge}
    <span class="meta">Generated: {generated}</span>
  </div>

  <h3>📊 Summary</h3>
  <div class="summary-grid">
    <div class="card">
      <div class="value">{s['total_hosts']}</div><div class="label">Hosts</div>
    </div>
    <div class="card">
      <div class="value">{s['total_services']}</div><div class="label">Services</div>
    </div>
    <div class="card">
      <div class="value">{s['total_cves']}</div><div class="label">CVEs</div>
    </div>
    <div class="card">
      <div class="value">{s['total_sessions']}</div><div class="label">Sessions</div>
    </div>
    <div class="card">
      <div class="value">{s['total_exploit_attempts']}</div>
      <div class="label">Exploit Attempts</div>
    </div>
    <div class="card">
      <div class="value" style="color:#3fb950">{s['successful_exploits']}</div>
      <div class="label">Successful</div>
    </div>
  </div>

  <h3>🗇 Network Topology</h3>
  <div id="topology-canvas"></div>
  <script>
  (function() {{
    var topo = JSON.parse(decodeURIComponent('{topo_json}'));
    var canvas = document.getElementById('topology-canvas');
    var W = canvas.offsetWidth || 900, H = canvas.offsetHeight || 340;
    var n = topo.nodes.length;
    if (n === 0) {{ canvas.innerHTML = '<p style="color:#8b949e;padding:1rem">No topology data — run recon first.</p>'; return; }}
    var positions = topo.nodes.map(function(node, i) {{
      var angle = (2 * Math.PI * i) / n;
      return {{ x: W/2 + (W * 0.38) * Math.cos(angle), y: H/2 + (H * 0.38) * Math.sin(angle) }};
    }});
    var svg = '<svg width="' + W + '" height="' + H + '" style="position:absolute;top:0;left:0">';
    topo.edges.forEach(function(e) {{
      var si = topo.nodes.findIndex(function(n) {{ return n.id === e.source; }});
      var ti = topo.nodes.findIndex(function(n) {{ return n.id === e.target; }});
      if (si < 0 || ti < 0) return;
      var color = e.result === 'success' ? '#3fb950' : (e.result === 'failure' ? '#f85149' : '#30363d');
      svg += '<line x1="' + positions[si].x + '" y1="' + positions[si].y + '" x2="' + positions[ti].x + '" y2="' + positions[ti].y + '" stroke="' + color + '" stroke-width="1.5" stroke-opacity="0.6"/>';
    }});
    topo.nodes.forEach(function(node, i) {{
      var p = positions[i];
      svg += '<circle cx="' + p.x + '" cy="' + p.y + '" r="7" fill="' + node.color + '" stroke="#21262d" stroke-width="1.5"/>';
      svg += '<text x="' + p.x + '" y="' + (p.y + 18) + '" fill="#8b949e" font-size="9" text-anchor="middle">' + (node.label || '').substring(0, 20) + '</text>';
    }});
    svg += '</svg>';
    canvas.innerHTML = svg;
  }})();
  </script>

  <h3>🖵 Discovered Services</h3>
  <table>
    <thead>
      <tr>
        <th>Host IP</th><th>Port</th><th>Proto</th><th>Service</th>
        <th>Product</th><th>Version</th><th>State</th>
      </tr>
    </thead>
    <tbody>
      {svc_rows if svc_rows else '<tr><td colspan="7">No services</td></tr>'}
    </tbody>
  </table>

  <h3>🎯 CVE Candidates</h3>
  <table>
    <thead>
      <tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Description</th></tr>
    </thead>
    <tbody>
      {cve_rows if cve_rows else '<tr><td colspan="4">No CVEs</td></tr>'}
    </tbody>
  </table>

  <h3>📅 Exploit Timeline</h3>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th><th>Module</th><th>Service</th>
        <th>Result</th><th>CVEs</th><th>Error</th>
      </tr>
    </thead>
    <tbody>
      {timeline_rows if timeline_rows else '<tr><td colspan="6" style="color:#8b949e">No exploit attempts recorded — graph is empty or recon only.</td></tr>'}
    </tbody>
  </table>

  <h3>💥 Exploit Attempts</h3>
  <table>
    <thead>
      <tr><th>Source</th><th>Module</th><th>Result</th><th>Error</th></tr>
    </thead>
    <tbody>
      {exp_rows if exp_rows else '<tr><td colspan="4">No exploits</td></tr>'}
    </tbody>
  </table>

  <h3>🐚 Active Sessions</h3>
  <table>
    <thead>
      <tr>
        <th>Session ID</th><th>Host IP</th><th>Privilege</th>
        <th>Shell Type</th><th>Opened At</th>
      </tr>
    </thead>
    <tbody>
      {sess_rows if sess_rows else '<tr><td colspan="5">No sessions</td></tr>'}
    </tbody>
  </table>
</div>
</body>
</html>
"""


    # ── Markdown renderer ─────────────────────────────────────────


    def _render_markdown(self, data: dict[str, Any]) -> str:
        """Render the collected data as a Markdown string."""
        s = data["summary"]
        lines: list[str] = []

        lines += [
            "# PrivacyAware-PenAgent — Penetration Test Report",
            "",
            f"**Run ID:** `{data['run_id']}`  ",
            f"**Generated:** {data['generated_at']}  ",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Hosts discovered | {s['total_hosts']} |",
            f"| Services discovered | {s['total_services']} |",
            f"| CVE candidates | {s['total_cves']} |",
            f"| Sessions obtained | {s['total_sessions']} |",
            f"| Exploit attempts | {s['total_exploit_attempts']} |",
            f"| Successful exploits | **{s['successful_exploits']}** |",
            "",
        ]

        # Services
        lines += ["## Discovered Services", ""]
        if data["services"]:
            lines += [
                "| Host IP | Port | Protocol | Service | Product | Version | State |",
                "|---------|------|----------|---------|---------|---------|-------|",
            ]
            for svc in data["services"]:
                lines.append(
                    f"| {svc.get('host_ip', '')} | {svc.get('port', '')} "
                    f"| {svc.get('protocol', '')} | {svc.get('name', '')} "
                    f"| {svc.get('product', '')} | {svc.get('version', '')} "
                    f"| {svc.get('state', '')} |"
                )
        else:
            lines.append("*No services discovered.*")
        lines.append("")

        # CVEs
        lines += ["## CVE Candidates", ""]
        if data["cves"]:
            lines += [
                "| CVE ID | CVSS | Description |",
                "|--------|------|-------------|",
            ]
            for cve in data["cves"]:
                desc = cve.get("description", "")[:100]
                lines.append(
                    f"| {cve.get('cve_id', '')} "
                    f"| {cve.get('cvss_score', 0):.1f} "
                    f"| {desc} |"
                )
        else:
            lines.append("*No CVEs mapped.*")
        lines.append("")

        # Exploit timeline (chronological — Week 19–20)
        lines += ["## Exploit Timeline", ""]
        timeline = data.get("timeline", [])
        if timeline:
            lines += [
                "| Timestamp | Module | Service | Result | CVEs | Error |",
                "|-----------|--------|---------|--------|------|-------|",
            ]
            for event in timeline:
                icon = "✅" if event.get("result") == "success" else "❌"
                ts = event.get("timestamp", "")[:19].replace("T", " ")
                cves = ", ".join(event.get("cves", []))
                lines.append(
                    f"| {ts} "
                    f"| `{event.get('module', '')}` "
                    f"| {event.get('service', '')} "
                    f"| {icon} {event.get('result', '')} "
                    f"| {cves} "
                    f"| {event.get('error_type', '')} |"
                )
        else:
            lines.append("*No exploit attempts recorded.*")
        lines.append("")

        # Exploit attempts (edge summary)
        lines += ["## Exploit Attempts (Graph Edges)", ""]
        if data["exploit_attempts"]:
            lines += [
                "| Module | Result | Error Type | Post-mortem |",
                "|--------|--------|-----------|-------------|",
            ]
            for exp in data["exploit_attempts"]:
                icon = "✅" if exp.get("result") == "success" else "❌"
                pm = (exp.get("post_mortem") or "")[:80]
                lines.append(
                    f"| `{exp.get('module', '')}` "
                    f"| {icon} {exp.get('result', '')} "
                    f"| {exp.get('error_type', '')} "
                    f"| {pm} |"
                )
        else:
            lines.append("*No exploit graph edges recorded.*")
        lines.append("")

        # Failure post-mortems (Week 19–20)
        lines += ["## Failure Post-Mortems", ""]
        failures = data.get("failures", [])
        if failures:
            lines += [
                "| Module | Error Type | Hypothesis |",
                "|--------|------------|------------|",
            ]
            for fail in failures:
                hypo = (fail.get("hypothesis") or "")[:120]
                lines.append(
                    f"| `{fail.get('module', '')}` "
                    f"| {fail.get('error_type', '')} "
                    f"| {hypo} |"
                )
        else:
            lines.append("*No failure post-mortems recorded.*")
        lines.append("")

        # Sessions
        lines += ["## Active Sessions", ""]
        if data["sessions"]:
            lines += [
                "| Session ID | Host IP | Privilege | Shell Type |",
                "|-----------|---------|-----------|-----------|",
            ]
            for sess in data["sessions"]:
                lines.append(
                    f"| {sess.get('session_id', '')} "
                    f"| {sess.get('host_ip', '')} "
                    f"| **{sess.get('privilege', '')}** "
                    f"| {sess.get('shell_type', '')} |"
                )
        else:
            lines.append("*No sessions obtained.*")
        lines.append("")

        lines.append("---")
        lines.append(
            f"*Report generated by PrivacyAware-PenAgent — {data['generated_at']}*"
        )

        return "\n".join(lines)
