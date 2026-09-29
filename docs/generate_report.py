#!/usr/bin/env python3
"""
generate_report.py — STIG compliance report generator
Project: ansible-stig-hardening (Full Sail P&P7, term 2609)
Author:  Charles Tull

Reads the results of the Ansible STIG hardening run and produces a single
self-contained HTML report (stig-report.html) summarizing which DISA STIGs
were applied across both droplets and their pass/fail status.

Usage:
    python3 generate_report.py                    # uses sample data below
    python3 generate_report.py results.json       # uses your own results file
    python3 generate_report.py results.json out.html

Expected results.json shape:
{
  "generated": "2026-09-28T22:00:00",
  "hosts": ["TullC-2609-STIG1", "TullC-2609-STIG2"],
  "controls": [
    {"id": "RHEL-08-010020", "severity": "high",
     "title": "FIPS mode enabled",
     "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
    ...
  ]
}
"""

import json
import sys
from datetime import datetime

# --- Sample data -------------------------------------------------------------
# Used when no results file is passed. Replace by running the playbook with a
# JSON callback and feeding that file in, or edit these to match your run.
SAMPLE = {
    "generated": datetime.now().isoformat(timespec="seconds"),
    "hosts": ["TullC-2609-STIG1", "TullC-2609-STIG2"],
    "controls": [
        {"id": "RHEL-08-010020", "severity": "high",
         "title": "Enable FIPS mode for cryptographic modules",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010030", "severity": "medium",
         "title": "Encrypt all local disk partitions",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010040", "severity": "medium",
         "title": "Display Standard Mandatory DoD Notice at ssh login",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010121", "severity": "medium",
         "title": "Password-protect the GRUB 2 bootloader",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010130", "severity": "medium",
         "title": "Use SHA-512 for shadow password hashing",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010160", "severity": "medium",
         "title": "Set pam_faillock deny threshold and lockout time",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010200", "severity": "medium",
         "title": "Terminate idle SSH sessions (ClientAliveCountMax)",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010290", "severity": "high",
         "title": "Disable weak MACs in the SSH daemon",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010300", "severity": "high",
         "title": "Disable weak ciphers in the SSH daemon",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010371", "severity": "medium",
         "title": "Prevent install of packages without a repo GPG signature",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010380", "severity": "medium",
         "title": "Require authentication for single-user mode",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-010550", "severity": "medium",
         "title": "Disable direct root login over SSH",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-020035", "severity": "medium",
         "title": "Lock accounts after 35 days of inactivity",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-020080", "severity": "medium",
         "title": "Enforce a minimum 15-character password length",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-020230", "severity": "medium",
         "title": "Set password minimum lifetime to 1 day",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-030000", "severity": "high",
         "title": "Enable and start the auditd service",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-030181", "severity": "medium",
         "title": "Audit successful/unsuccessful use of setuid programs",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "warn"}},
        {"id": "RHEL-08-030601", "severity": "medium",
         "title": "Enable Linux Audit rules on boot via GRUB",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-040021", "severity": "medium",
         "title": "Disable the kernel core dump service (kdump)",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-040090", "severity": "medium",
         "title": "Enable firewalld and restrict to allowed services",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-040100", "severity": "high",
         "title": "Deny all incoming traffic by default at the host firewall",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-040139", "severity": "medium",
         "title": "Remove the telnet server package",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-040180", "severity": "medium",
         "title": "Remove the tftp server package",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-040280", "severity": "medium",
         "title": "Disable Ctrl-Alt-Del burst action / reboot",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
        {"id": "RHEL-08-040370", "severity": "medium",
         "title": "Disable the USB storage kernel module",
         "results": {"TullC-2609-STIG1": "pass", "TullC-2609-STIG2": "pass"}},
    ],
}

STATUS_ORDER = {"fail": 0, "warn": 1, "pass": 2}


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def tally(data):
    """Return {status: count} across every host/control result cell."""
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for control in data["controls"]:
        for status in control["results"].values():
            counts[status] = counts.get(status, 0) + 1
    return counts


def rows(data):
    hosts = data["hosts"]
    out = []
    for c in sorted(data["controls"], key=lambda x: x["id"]):
        cells = "".join(
            f'<td class="cell {c["results"].get(h, "na")}">'
            f'{c["results"].get(h, "n/a")}</td>'
            for h in hosts
        )
        out.append(
            f'<tr>'
            f'<td class="mono">{c["id"]}</td>'
            f'<td><span class="sev sev-{c["severity"]}">{c["severity"]}</span></td>'
            f'<td class="title">{c["title"]}</td>'
            f'{cells}'
            f'</tr>'
        )
    return "\n".join(out)


def render(data):
    hosts = data["hosts"]
    counts = tally(data)
    total = sum(counts.values())
    passed = counts.get("pass", 0)
    pct = round(passed / total * 100) if total else 0
    host_headers = "".join(f'<th class="host mono">{h}</th>' for h in hosts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>STIG Compliance Report — ansible-stig-hardening</title>
<style>
  :root {{
    --bg: #0d1117;
    --panel: #131a24;
    --panel-2: #1a2330;
    --line: #24303f;
    --ink: #e6edf3;
    --muted: #8b98a9;
    --teal: #1fe0c4;
    --teal-dim: #0f8f7f;
    --pass: #1fe0c4;
    --warn: #e3b341;
    --fail: #f2607a;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--ink);
    font-family: var(--sans); line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{ max-width: 1040px; margin: 0 auto; padding: 48px 24px 80px; }}

  header {{ border-bottom: 1px solid var(--line); padding-bottom: 28px; margin-bottom: 36px; }}
  .kicker {{ font-family: var(--mono); color: var(--teal); font-size: 13px; letter-spacing: .04em; }}
  h1 {{ font-size: 30px; margin: 10px 0 6px; font-weight: 650; letter-spacing: -0.01em; }}
  .sub {{ color: var(--muted); font-size: 14px; }}
  .sub .mono {{ font-family: var(--mono); color: var(--ink); }}

  .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 32px 0 40px; }}
  .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 18px 20px; }}
  .card .n {{ font-family: var(--mono); font-size: 30px; font-weight: 600; line-height: 1; }}
  .card .l {{ color: var(--muted); font-size: 12px; margin-top: 8px; }}
  .card.pct .n {{ color: var(--teal); }}
  .card.pass .n {{ color: var(--pass); }}
  .card.warn .n {{ color: var(--warn); }}
  .card.fail .n {{ color: var(--fail); }}

  .bar {{ height: 8px; border-radius: 6px; background: var(--panel-2); overflow: hidden; display: flex; margin-bottom: 40px; }}
  .bar i {{ display: block; height: 100%; }}
  .bar .p {{ background: var(--pass); }}
  .bar .w {{ background: var(--warn); }}
  .bar .f {{ background: var(--fail); }}

  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  thead th {{
    text-align: left; color: var(--muted); font-weight: 500; font-size: 12px;
    padding: 0 12px 12px; border-bottom: 1px solid var(--line);
  }}
  thead th.host {{ text-align: center; color: var(--ink); }}
  tbody td {{ padding: 11px 12px; border-bottom: 1px solid var(--panel-2); vertical-align: middle; }}
  tbody tr:hover td {{ background: var(--panel); }}
  .mono {{ font-family: var(--mono); font-size: 13px; }}
  .title {{ color: var(--ink); }}

  .sev {{ font-family: var(--mono); font-size: 11px; padding: 2px 8px; border-radius: 20px; border: 1px solid; }}
  .sev-high {{ color: var(--fail); border-color: color-mix(in srgb, var(--fail) 45%, transparent); }}
  .sev-medium {{ color: var(--warn); border-color: color-mix(in srgb, var(--warn) 45%, transparent); }}
  .sev-low {{ color: var(--muted); border-color: var(--line); }}

  td.cell {{ text-align: center; font-family: var(--mono); font-size: 12px; font-weight: 600; }}
  td.pass {{ color: var(--pass); }}
  td.warn {{ color: var(--warn); }}
  td.fail {{ color: var(--fail); }}
  td.na {{ color: var(--muted); }}

  footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--line);
            color: var(--muted); font-size: 12px; font-family: var(--mono); }}

  @media (max-width: 720px) {{
    .cards {{ grid-template-columns: repeat(2, 1fr); }}
    .title {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="kicker">ansible-stig-hardening · term 2609</div>
    <h1>DISA STIG Compliance Report</h1>
    <div class="sub">
      RHEL-8 STIG baseline applied to
      <span class="mono">{hosts[0]}</span> and
      <span class="mono">{hosts[-1]}</span> via a single Ansible playbook.
    </div>
  </header>

  <div class="cards">
    <div class="card pct"><div class="n">{pct}%</div><div class="l">Overall compliance</div></div>
    <div class="card pass"><div class="n">{passed}</div><div class="l">Checks passing</div></div>
    <div class="card warn"><div class="n">{counts.get('warn', 0)}</div><div class="l">Warnings</div></div>
    <div class="card fail"><div class="n">{counts.get('fail', 0)}</div><div class="l">Failing</div></div>
  </div>

  <div class="bar">
    <i class="p" style="width:{passed / total * 100 if total else 0}%"></i>
    <i class="w" style="width:{counts.get('warn', 0) / total * 100 if total else 0}%"></i>
    <i class="f" style="width:{counts.get('fail', 0) / total * 100 if total else 0}%"></i>
  </div>

  <table>
    <thead>
      <tr>
        <th>STIG ID</th>
        <th>Severity</th>
        <th>Control</th>
        {host_headers}
      </tr>
    </thead>
    <tbody>
      {rows(data)}
    </tbody>
  </table>

  <footer>
    Generated {data['generated']} · {len(data['controls'])} controls · {len(hosts)} hosts ·
    Charles Tull · Full Sail University
  </footer>
</div>
</body>
</html>"""


def main():
    args = sys.argv[1:]
    data = load(args[0]) if args else SAMPLE
    out_path = args[1] if len(args) > 1 else "stig-report.html"
    html = render(data)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    counts = tally(data)
    total = sum(counts.values())
    print(f"Wrote {out_path}")
    print(f"  {counts.get('pass', 0)}/{total} checks passing "
          f"({round(counts.get('pass', 0) / total * 100) if total else 0}%), "
          f"{counts.get('warn', 0)} warn, {counts.get('fail', 0)} fail")


if __name__ == "__main__":
    main()
