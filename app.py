"""Authorized, low-impact reconnaissance workflow for one confirmed domain scope."""

from __future__ import annotations

import asyncio
import http.client
import io
import ipaddress
import json
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from html import escape as html_escape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import dns.resolver
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from docx import Document
from docx.shared import Pt, RGBColor
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
ASSET_DIR = PUBLIC_DIR / "assets"
MAX_HOSTS = 4
MAX_CT_NAMES = 20
MAX_URLS = 60
MAX_JS_FILES = 3
MAX_PATH_PROBES = 8
MAX_CRAWL_PAGES = 8
MAX_HTTP_REQUESTS = 1 + 2 + MAX_PATH_PROBES + (MAX_CRAWL_PAGES - 1) + MAX_JS_FILES
PATH_PROBE_LIST = (
    "/.well-known/security.txt",
    "/security.txt",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/api-docs",
    "/login",
    "/admin",
)
MAX_BODY_BYTES = 180_000
MAX_EXPORT_BYTES = 2_000_000
SOCKET_TIMEOUT = 2.5
REQUEST_SPACING_SECONDS = 0.25
USER_AGENT = "PyramidRecon/0.1 (+authorized, low-impact assessment)"

PHASES = [
    (0, "Scope & Setup", "Permission and scope confirmation"),
    (1, "Passive Recon & OSINT", "Certificate transparency lookup"),
    (2, "Subdomain Discovery", "Public DNS resolution"),
    (3, "Live Host Verification", "One homepage request to the confirmed root domain"),
    (4, "Technology Fingerprinting", "Analyze the observed page and response headers"),
    (5, "Content & Directory Discovery", "Read site indexes and check a fixed path list"),
    (6, "URL & Endpoint Discovery", "Archive lookup and bounded same-host crawling"),
    (7, "JavaScript Analysis", "Inspect up to three same-scope JavaScript files"),
    (8, "Parameter Discovery", "Inventory parameter names without values"),
    (9, "Passive Security Review", "Review observed security configuration indicators"),
]

# Tool names come from the user's Recon for Web Application checklist. The
# reference lists several independent Go/Rust/Python programs; this Python app
# uses bounded native equivalents where practical and reports exactly which
# external programs are present or deliberately not invoked.
TOOL_CATALOG = [
    {"phase": 0, "tool": "Go", "mode": "reference prerequisite", "binary": "go", "integration": "Not required by this Python backend."},
    {"phase": 0, "tool": "Python 3 / pipx", "mode": "runtime", "integration": "Python runs the backend; pipx is not required."},
    {"phase": 0, "tool": "Git / curl / wget", "mode": "reference prerequisite", "integration": "Not invoked by scan jobs."},
    {"phase": 1, "tool": "Censys", "mode": "passive provider", "integration": "API credentials and provider adapter are not configured."},
    {"phase": 1, "tool": "Shodan", "mode": "passive provider", "integration": "API credentials and provider adapter are not configured."},
    {"phase": 1, "tool": "DNSDumpster", "mode": "online service", "integration": "Manual service; no automated lookup is made."},
    {"phase": 1, "tool": "Whois", "mode": "registration lookup", "integration": "No third-party WHOIS service is queried."},
    {"phase": 1, "tool": "ViewDNS", "mode": "online service", "integration": "Manual service; no automated lookup is made."},
    {"phase": 1, "tool": "crt.sh", "mode": "passive CT lookup", "integration": "Integrated; bounded certificate-transparency lookup."},
    {"phase": 1, "tool": "dnspython", "mode": "DNS records", "integration": "Integrated; A/AAAA/MX/NS/TXT metadata."},
    {"phase": 2, "tool": "Subfinder", "mode": "passive CLI", "binary": "subfinder", "optional_runner": True, "integration": "Runs passive enumeration only when installed locally."},
    {"phase": 2, "tool": "dnsx", "mode": "DNS resolution", "integration": "dnspython performs bounded A/AAAA resolution; dnsx binary is not required."},
    {"phase": 2, "tool": "Amass", "mode": "passive CLI", "binary": "amass", "optional_runner": True, "integration": "Runs enum --passive only when installed locally."},
    {"phase": 2, "tool": "Puredns", "mode": "active DNS brute force", "binary": "puredns", "integration": "Not invoked; wordlist brute force is outside this low-impact profile."},
    {"phase": 2, "tool": "MassDNS", "mode": "bulk DNS scanner", "binary": "massdns", "integration": "Not invoked; high-volume resolver is outside this profile."},
    {"phase": 3, "tool": "httpx", "mode": "HTTP probing", "binary": "pd-httpx", "integration": "Python makes a single pinned root homepage GET; ProjectDiscovery httpx is not invoked."},
    {"phase": 3, "tool": "gowitness", "mode": "screenshots", "binary": "gowitness", "integration": "Not invoked; no screenshots or report server are created."},
    {"phase": 4, "tool": "Wappalyzer", "mode": "browser extension", "integration": "Not queried by the backend."},
    {"phase": 4, "tool": "WhatWeb", "mode": "technology fingerprinting", "binary": "whatweb", "integration": "Bounded Python header/HTML fingerprint hints are used instead."},
    {"phase": 4, "tool": "BuiltWith", "mode": "passive provider", "integration": "API credentials and provider adapter are not configured."},
    {"phase": 5, "tool": "ffuf", "mode": "directory fuzzing", "binary": "ffuf", "integration": "Not invoked; replaced with eight fixed, low-rate GET checks."},
    {"phase": 5, "tool": "feroxbuster", "mode": "recursive directory scan", "binary": "feroxbuster", "integration": "Not invoked; no recursion or wordlist brute force."},
    {"phase": 5, "tool": "dirsearch", "mode": "directory scan", "binary": "dirsearch", "integration": "Not invoked; no wordlist brute force."},
    {"phase": 6, "tool": "Katana", "mode": "web crawler", "binary": "katana", "integration": "A Python same-host crawler is capped at eight HTML pages."},
    {"phase": 6, "tool": "gau", "mode": "historical URL lookup", "binary": "gau", "integration": "Wayback CDX lookup is integrated; gau binary is not invoked."},
    {"phase": 6, "tool": "waybackurls", "mode": "historical URL lookup", "binary": "waybackurls", "integration": "Wayback CDX lookup is integrated; binary is not invoked."},
    {"phase": 6, "tool": "hakrawler", "mode": "web crawler", "binary": "hakrawler", "integration": "The capped Python same-host crawler is used instead."},
    {"phase": 7, "tool": "SecretFinder", "mode": "JavaScript pattern scan", "binary": "SecretFinder", "integration": "Python pattern checks run on at most three same-host JS files; values are redacted."},
    {"phase": 7, "tool": "jsluice", "mode": "JavaScript static analysis", "binary": "jsluice", "integration": "Python URL/secret pattern extraction is used instead."},
    {"phase": 8, "tool": "Arjun", "mode": "active parameter probing", "binary": "arjun", "integration": "Not invoked; no hidden-parameter payloads are sent."},
    {"phase": 8, "tool": "ParamSpider", "mode": "historical parameter lookup", "binary": "paramspider", "integration": "Parameter names are extracted from observed and archived URLs."},
    {"phase": 9, "tool": "Nuclei", "mode": "template vulnerability scanner", "binary": "nuclei", "integration": "Templates are not run; Phase 9 reviews observed configuration only."},
    {"phase": 9, "tool": "SQLMap", "mode": "SQL injection / extraction", "binary": "sqlmap", "integration": "Not invoked; injection and database extraction are disabled."},
    {"phase": 9, "tool": "Ghauri", "mode": "SQL injection / extraction", "binary": "ghauri", "integration": "Not invoked; injection and database extraction are disabled."},
    {"phase": 9, "tool": "Dalfox", "mode": "XSS payload scanner", "binary": "dalfox", "integration": "Not invoked; injection payloads are disabled."},
    {"phase": 9, "tool": "Nmap", "mode": "port / service scanner", "binary": "nmap", "integration": "Not invoked; network port scanning is outside this profile."},
]

PHASE_TOOL_EXECUTION = {
    0: ["Python domain validation", "authorization and provider-consent gate"],
    1: ["crt.sh certificate-transparency lookup", "dnspython A/AAAA/MX/NS/TXT metadata"],
    2: ["dnspython public A/AAAA resolver", "Subfinder passive CLI when installed", "Amass passive CLI when installed"],
    3: ["pinned Python HTTPS/HTTP homepage request"],
    4: ["Python HTMLParser and response-header fingerprints"],
    5: ["robots.txt and sitemap.xml", "eight fixed same-root GET checks (no wordlist)"],
    6: ["Wayback CDX passive URL lookup", "Python crawler capped at eight same-host HTML pages"],
    7: ["Python endpoint/credential-pattern review with secret values redacted"],
    8: ["Python parameter-name extraction from observed and archived URLs"],
    9: ["passive response-header and redacted-JavaScript review"],
}

app = FastAPI(
    title="Pyramid Recon",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)


class ScanRequest(BaseModel):
    domain: str = Field(min_length=4, max_length=253)
    authorization_confirmed: bool
    provider_consent: bool


def _export_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or not isinstance(report.get("domain"), str):
        raise HTTPException(status_code=422, detail="A final report with a domain is required.")
    if not isinstance(report.get("summary"), dict) or not isinstance(report.get("phase_reports"), list):
        raise HTTPException(status_code=422, detail="The report is missing its summary or phase reports.")
    if len(report["phase_reports"]) > len(PHASES):
        raise HTTPException(status_code=422, detail="The report contains too many phase records.")
    return report


async def _read_export_request(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_EXPORT_BYTES:
        raise HTTPException(status_code=413, detail="The report is too large to export.")
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="The export request must contain valid JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="The export request must be a JSON object.")
    return _export_report(body.get("report"))


def _export_filename(report: dict[str, Any], extension: str) -> str:
    safe_domain = re.sub(r"[^A-Za-z0-9.-]+", "-", report["domain"]).strip(".-")[:180] or "report"
    return f"pyramid-recon-{safe_domain}-{datetime.now(timezone.utc):%Y-%m-%d}.{extension}"


def _report_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value if value is not None else "—")


def _pdf_escape(value: Any) -> str:
    # The built-in PDF font covers Western text. Keep arbitrary target-supplied
    # Unicode from breaking a report; the DOCX export preserves full Unicode.
    raw = str(value).encode("latin-1", "replace").decode("latin-1")
    safe = "".join(char if char == "\n" or 32 <= ord(char) <= 126 or 160 <= ord(char) <= 255 else "?" for char in raw)
    return html_escape(safe)


def _build_pdf(report: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=48,
        leftMargin=48,
        topMargin=48,
        bottomMargin=48,
        title=f"Pyramid Recon - {report['domain']}",
        author="Pyramid Recon",
    )
    base = getSampleStyleSheet()
    title_style = ParagraphStyle("ReconTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=19, leading=24, textColor=colors.HexColor("#143c47"), alignment=TA_LEFT)
    heading_style = ParagraphStyle("ReconHeading", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=colors.HexColor("#146e65"), spaceBefore=12, spaceAfter=5)
    body_style = ParagraphStyle("ReconBody", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=colors.HexColor("#263b42"), spaceAfter=5)
    code_style = ParagraphStyle("ReconCode", parent=body_style, fontName="Courier", fontSize=7.5, leading=10, leftIndent=8, wordWrap="CJK")
    story: list[Any] = [Paragraph("Pyramid Recon - Final Report", title_style), Spacer(1, 8)]
    summary = report["summary"]
    rows = [
        ["Domain", report["domain"]],
        ["Overall status", summary.get("overall_status", "unknown")],
        ["Phases completed / reported", f"{summary.get('phases_completed', 0)} / {summary.get('phases_reported', 0)}"],
        ["Live hosts", str(summary.get("live_hosts", 0))],
        ["URLs collected", str(summary.get("urls_collected", 0))],
        ["Items for manual review", str(summary.get("findings_for_manual_review", 0))],
        ["Created", str(report.get("created_at", "—"))],
    ]
    table = Table([[Paragraph(_pdf_escape(cell), body_style) for cell in row] for row in rows], colWidths=[155, 330], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f2f1")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#263b42")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c7d7d9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([table, Paragraph("Scope and limitations", heading_style)])
    for note in summary.get("limitations", []):
        story.append(Paragraph("- " + _pdf_escape(note), body_style))

    story.append(Paragraph("Final findings", heading_style))
    findings = report.get("final_findings", [])
    if findings:
        for finding in findings:
            story.append(Paragraph(
                f"<b>{_pdf_escape(str(finding.get('severity', 'review')).upper())}: {_pdf_escape(finding.get('title', 'Review item'))}</b><br/>"
                f"Asset: {_pdf_escape(finding.get('asset', '-'))}<br/>"
                f"{_pdf_escape(finding.get('evidence', 'Manual review required.'))}<br/>"
                f"Confidence: {_pdf_escape(finding.get('confidence', ''))}",
                body_style,
            ))
    else:
        story.append(Paragraph("No Phase 9 findings were produced in this run.", body_style))

    story.append(Paragraph("Phase-by-phase reports", heading_style))
    for phase in report.get("phase_reports", []):
        if not isinstance(phase, dict):
            continue
        story.append(Paragraph(
            f"Phase {_pdf_escape(phase.get('phase', '?'))} - {_pdf_escape(phase.get('name', 'Unnamed phase'))}",
            heading_style,
        ))
        story.append(Paragraph(
            f"Status: {_pdf_escape(phase.get('status', 'unknown'))} - "
            f"Duration: {_pdf_escape(phase.get('duration_ms', '-'))} ms<br/>"
            f"Purpose: {_pdf_escape(phase.get('purpose', '-'))}<br/>"
            f"Analysis: {_pdf_escape(phase.get('analysis', '-'))}<br/>"
            f"Tools: {_pdf_escape(', '.join(map(str, phase.get('tools_used', []))))}",
            body_style,
        ))
        if phase.get("warnings"):
            story.append(Paragraph("Warnings: " + _pdf_escape("; ".join(map(str, phase["warnings"]))), body_style))
        output_text = _report_value(phase.get("outputs", {}))
        for line in output_text.splitlines() or ["{}"]:
            story.append(Paragraph(_pdf_escape(line) or "&nbsp;", code_style))
    doc.build(story)
    return buffer.getvalue()


def _build_docx(report: dict[str, Any]) -> bytes:
    document = Document()
    document.core_properties.title = f"Pyramid Recon — {report['domain']}"
    document.core_properties.author = "Pyramid Recon"
    document.add_heading("Pyramid Recon — Final Report", 0)
    document.add_paragraph(f"Domain: {report['domain']}")
    document.add_paragraph(f"Created: {report.get('created_at', '—')}")
    summary = report["summary"]
    table = document.add_table(rows=0, cols=2)
    table.style = "Light Shading Accent 1"
    summary_rows = [
        ("Overall status", summary.get("overall_status", "unknown")),
        ("Phases completed / reported", f"{summary.get('phases_completed', 0)} / {summary.get('phases_reported', 0)}"),
        ("Live hosts", summary.get("live_hosts", 0)),
        ("URLs collected", summary.get("urls_collected", 0)),
        ("Items for manual review", summary.get("findings_for_manual_review", 0)),
    ]
    for label, value in summary_rows:
        cells = table.add_row().cells
        cells[0].text = str(label)
        cells[1].text = str(value)
    document.add_heading("Scope and limitations", level=1)
    for note in summary.get("limitations", []):
        document.add_paragraph(str(note), style="List Bullet")
    document.add_heading("Final findings", level=1)
    findings = report.get("final_findings", [])
    if findings:
        for finding in findings:
            document.add_heading(f"{str(finding.get('severity', 'review')).upper()}: {finding.get('title', 'Review item')}", level=2)
            document.add_paragraph(f"Asset: {finding.get('asset', '—')}")
            document.add_paragraph(str(finding.get("evidence", "Manual review required.")))
            document.add_paragraph(f"Confidence: {finding.get('confidence', '')}")
    else:
        document.add_paragraph("No Phase 9 findings were produced in this run.")
    document.add_heading("Phase-by-phase reports", level=1)
    for phase in report.get("phase_reports", []):
        if not isinstance(phase, dict):
            continue
        document.add_heading(f"Phase {phase.get('phase', '?')} — {phase.get('name', 'Unnamed phase')}", level=2)
        document.add_paragraph(f"Status: {phase.get('status', 'unknown')} · Duration: {phase.get('duration_ms', '—')} ms")
        document.add_paragraph(f"Purpose: {phase.get('purpose', '—')}")
        document.add_paragraph(f"Analysis: {phase.get('analysis', '—')}")
        document.add_paragraph(f"Tools used / policy: {', '.join(map(str, phase.get('tools_used', [])))}")
        for warning in phase.get("warnings", []):
            document.add_paragraph(f"Warning: {warning}", style="List Bullet")
        output = document.add_paragraph()
        run = output.add_run(_report_value(phase.get("outputs", {})))
        run.font.name = "Consolas"
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor(55, 75, 83)
    stream = io.BytesIO()
    document.save(stream)
    return stream.getvalue()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    return response


# Vercel serves public/ files from its static CDN and may omit them from the
# Python function bundle. Keep the mount for local development when present.
if ASSET_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=ASSET_DIR), name="assets")


@app.get("/", include_in_schema=False)
def home():
    index_file = PUBLIC_DIR / "index.html"
    if index_file.is_file():
        return FileResponse(index_file, media_type="text/html")
    return JSONResponse({"error": "The interface is served by the deployment static host."}, status_code=404)


@app.get("/favicon.svg", include_in_schema=False)
def favicon():
    favicon_file = PUBLIC_DIR / "favicon.svg"
    if favicon_file.is_file():
        return FileResponse(favicon_file, media_type="image/svg+xml")
    return JSONResponse({"error": "The interface is served by the deployment static host."}, status_code=404)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "Pyramid Recon", "phases": len(PHASES), "tools": len(TOOL_CATALOG), "mode": "authorized-root, passive-first"}


@app.get("/api/tools")
def list_tools():
    return {
        "runtime": {"python": platform.python_version(), "platform": platform.system()},
        "phases": len(PHASES),
        "tools": tool_inventory(),
        "limits": {"max_http_requests": MAX_HTTP_REQUESTS, "request_spacing_seconds": REQUEST_SPACING_SECONDS, "max_path_probes": MAX_PATH_PROBES, "max_crawl_pages": MAX_CRAWL_PAGES, "max_js_files": MAX_JS_FILES},
    }


@app.post("/api/report/pdf")
async def export_pdf(request: Request):
    report = await _read_export_request(request)
    data = _build_pdf(report)
    filename = _export_filename(report, "pdf")
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


@app.post("/api/report/docx")
async def export_docx(request: Request):
    report = await _read_export_request(request)
    data = _build_docx(report)
    filename = _export_filename(report, "docx")
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_domain(value: str) -> str:
    raw = value.strip().rstrip(".")
    if not raw or any(c in raw for c in "/:@?#\\") or any(c.isspace() for c in raw):
        raise ValueError("Enter a domain name only, without a URL or path.")
    try:
        domain = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The domain name is not valid.") from exc
    if len(domain) > 253 or "." not in domain:
        raise ValueError("Enter a fully qualified public domain name.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not accepted; enter a verified domain name.")
    labels = domain.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise ValueError("The domain name contains an invalid label.")
    return domain


def in_scope(host: str, root_domain: str) -> bool:
    normalized = host.rstrip(".").lower()
    return normalized == root_domain or normalized.endswith("." + root_domain)


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.3
    resolver.lifetime = 2.2
    return resolver


def resolve_public_addresses(host: str) -> list[str]:
    resolver = _resolver()
    addresses: set[str] = set()
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, record_type, lifetime=2.2, search=False)
            for record in answer:
                address = ipaddress.ip_address(record.address)
                if not address.is_global or address.is_multicast or address.is_reserved:
                    raise ValueError("The domain resolves to a non-public address.")
                addresses.add(address.compressed)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
    return sorted(addresses)


def _public_dns_record_summary(domain: str) -> dict[str, Any]:
    resolver = _resolver()
    summary: dict[str, Any] = {}
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answer = resolver.resolve(domain, record_type, lifetime=2.2, search=False)
            records = [record.to_text()[:300] for record in answer]
        except Exception:
            records = []
        if record_type in ("A", "AAAA"):
            public_values: list[str] = []
            omitted = 0
            for value in records:
                try:
                    address = ipaddress.ip_address(value)
                    if address.is_global and not address.is_multicast and not address.is_reserved:
                        public_values.append(address.compressed)
                    else:
                        omitted += 1
                except ValueError:
                    omitted += 1
            summary[record_type] = {"count": len(public_values), "values": public_values[:8], "non_public_omitted": omitted}
        elif record_type == "TXT":
            categories: set[str] = set()
            for value in records:
                lowered = value.lower()
                if "v=spf1" in lowered:
                    categories.add("SPF")
                elif "v=dmarc1" in lowered:
                    categories.add("DMARC")
                elif "v=dkim1" in lowered or "_domainkey" in lowered:
                    categories.add("DKIM")
                else:
                    categories.add("other public TXT record")
            summary[record_type] = {"count": len(records), "categories": sorted(categories), "values_returned": False}
        else:
            summary[record_type] = {"count": len(records), "values": records[:8]}
    return summary


def _host_addresses(host: str, expected_scope: str | None) -> list[str]:
    if expected_scope is not None and not in_scope(host, expected_scope):
        raise ValueError("The host is outside the confirmed scope.")
    if expected_scope is None and host not in {"crt.sh", "web.archive.org"}:
        raise ValueError("Outbound provider access is restricted.")
    addresses = resolve_public_addresses(host)
    if not addresses:
        raise OSError("The host has no public DNS address.")
    return addresses


def tool_inventory() -> list[dict[str, Any]]:
    """Return the reference checklist with honest local availability signals."""
    inventory: list[dict[str, Any]] = []
    for source in TOOL_CATALOG:
        item = dict(source)
        binary = item.pop("binary", None)
        item.pop("optional_runner", None)
        if binary:
            item["installed"] = shutil.which(binary) is not None
            item["availability"] = "installed" if item["installed"] else "not installed"
        elif item["tool"] in {"crt.sh", "dnspython"}:
            item["installed"] = True
            item["availability"] = "integrated"
        elif item["tool"] == "Python 3 / pipx":
            item["installed"] = True
            item["availability"] = f"Python {sys.version_info.major}.{sys.version_info.minor} runtime"
        else:
            item["installed"] = None
            item["availability"] = "manual / not configured"
        inventory.append(item)
    return inventory


def _run_optional_passive_enumerator(tool: str, domain: str) -> dict[str, Any]:
    """Run only fixed passive commands; never accepts user-supplied arguments."""
    executable = shutil.which(tool)
    if not executable:
        return {"tool": tool, "status": "not_installed", "hosts": [], "host_count": 0}
    if tool == "subfinder":
        command = [executable, "-d", domain, "-silent"]
    elif tool == "amass":
        command = [executable, "enum", "-passive", "-d", domain]
    else:
        return {"tool": tool, "status": "not_enabled", "hosts": [], "host_count": 0}
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        names: set[str] = set()
        for line in completed.stdout.splitlines()[:1000]:
            candidate = line.strip().lower().lstrip("*.").rstrip(".")
            try:
                candidate = normalize_domain(candidate)
            except ValueError:
                continue
            if in_scope(candidate, domain):
                names.add(candidate)
            if len(names) >= MAX_CT_NAMES:
                break
        ordered = sorted(names)
        return {
            "tool": tool,
            "status": "completed" if completed.returncode == 0 else "nonzero_exit",
            "hosts": ordered,
            "host_count": len(ordered),
            "exit_code": completed.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"tool": tool, "status": "timed_out", "hosts": [], "host_count": 0}
    except OSError as exc:
        return {"tool": tool, "status": "failed", "hosts": [], "host_count": 0, "error": type(exc).__name__}


def safe_get(host: str, path: str, *, expected_scope: str | None = None, max_bytes: int = MAX_BODY_BYTES) -> dict[str, Any]:
    """Make one bounded HTTP GET to a pinned public IP. Redirects are never followed."""
    if not path.startswith("/") or "\r" in path or "\n" in path or len(path) > 2048:
        raise ValueError("Invalid request path.")
    addresses = _host_addresses(host, expected_scope)
    last_error: Exception | None = None
    for address in addresses[:2]:
        sock: socket.socket | None = None
        try:
            ip = ipaddress.ip_address(address)
            family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            destination = (address, 443, 0, 0) if ip.version == 6 else (address, 443)
            try:
                sock.connect(destination)
                scheme = "https"
            except OSError:
                sock.close()
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(SOCKET_TIMEOUT)
                destination = (address, 80, 0, 0) if ip.version == 6 else (address, 80)
                sock.connect(destination)
                scheme = "http"
            if scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                sock.settimeout(SOCKET_TIMEOUT)
            port = 443 if scheme == "https" else 80
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: text/html,application/json,text/plain,*/*\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii", "strict")
            sock.sendall(request)
            response = http.client.HTTPResponse(sock)
            response.begin()
            headers = {key.lower(): value[:500] for key, value in response.getheaders() if key.lower() in {
                "content-type", "server", "x-powered-by", "strict-transport-security", "content-security-policy",
                "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "location",
                "last-modified", "content-length",
            }}
            body = response.read(max_bytes + 1)
            truncated = len(body) > max_bytes
            body = body[:max_bytes]
            response.close()
            return {
                "url": f"{scheme}://{host}{path}",
                "scheme": scheme,
                "status_code": response.status,
                "headers": headers,
                "body": body.decode("utf-8", "replace"),
                "truncated": truncated,
                "address": address,
            }
        except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError, ValueError) as exc:
            last_error = exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    raise OSError(type(last_error).__name__ if last_error else "NetworkError")


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.generators: list[str] = []
        self._seen_links: set[str] = set()
        self._seen_scripts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "a" and values.get("href"):
            value = values["href"] or ""
            if value not in self._seen_links and len(self.links) < 100:
                self.links.append(value)
                self._seen_links.add(value)
        if tag.lower() == "script" and values.get("src"):
            value = values["src"] or ""
            if value not in self._seen_scripts and len(self.scripts) < 30:
                self.scripts.append(value)
                self._seen_scripts.add(value)
        if tag.lower() == "meta" and values.get("name", "").lower() == "generator" and values.get("content"):
            self.generators.append((values["content"] or "")[:120])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and sum(len(part) for part in self.title_parts) < 300:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part)[:240]


def parse_page(body: str) -> PageParser:
    parser = PageParser()
    try:
        parser.feed(body)
    except Exception:
        pass
    return parser


def redact_query_values(url: str) -> str:
    """Keep parameter names for inventory while preventing query values from entering reports."""
    parts = urlsplit(url)
    bounded_query = "&".join(parts.query.split("&")[:40])
    names = [name for name, _ in parse_qsl(bounded_query, keep_blank_values=True, max_num_fields=40)]
    safe_netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, safe_netloc, parts.path or "/", urlencode([(name, "") for name in names]), ""))


def make_report(
    phase: int,
    started: float,
    status: str,
    input_from: int | None,
    input_payload: Any,
    analysis: str,
    outputs: dict[str, Any],
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "name": PHASES[phase][1],
        "purpose": PHASES[phase][2],
        "status": status,
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(timespec="seconds"),
        "finished_at": utc_now(),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "input": {"from_phase": input_from, "report": input_payload},
        "analysis": analysis,
        "tools_used": PHASE_TOOL_EXECUTION[phase],
        "outputs": outputs,
        "warnings": warnings or [],
    }


def handoff_report(report: dict[str, Any]) -> dict[str, Any]:
    """Forward the previous phase's complete useful report without nesting its history."""
    return {
        "phase": report["phase"],
        "name": report["name"],
        "purpose": report["purpose"],
        "status": report["status"],
        "started_at": report["started_at"],
        "finished_at": report["finished_at"],
        "duration_ms": report["duration_ms"],
        "analysis": report["analysis"],
        "outputs": report["outputs"],
        "warnings": report["warnings"],
    }


def phase0(ctx: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    started = time.monotonic()
    domain = ctx["domain"]
    request: ScanRequest = ctx["request"]
    if not request.authorization_confirmed:
        return make_report(0, started, "blocked", None, {"domain": domain}, "The authorization attestation was not confirmed.", {"scope": domain}, ["Confirm that you own the domain or have written authorization for this assessment."])
    if not request.provider_consent:
        return make_report(0, started, "blocked", None, {"domain": domain}, "The external data-source disclosure was not accepted.", {"scope": domain}, ["Consent is required because passive lookups may share the domain with crt.sh, the Internet Archive, and configured passive enumeration sources."])
    ctx["scope_confirmed"] = True
    return make_report(0, started, "completed", None, {"domain": domain, "authorization_confirmed": True, "provider_consent": True}, "The domain syntax, authorization attestation, and external-provider consent passed.", {
        "root_domain": domain,
        "scope_rule": f"Direct HTTP requests are limited to the confirmed root domain {domain}; discovered subdomains remain passive inventory only.",
        "authorization": "The user confirmed ownership or written authorization in the interface.",
        "provider_disclosure": "The domain may be queried through crt.sh and the Internet Archive; installed Subfinder or Amass passive sources may also receive the domain. DNS queries go to the configured resolver.",
        "optional_passive_cli": {"subfinder_installed": shutil.which("subfinder") is not None, "amass_installed": shutil.which("amass") is not None},
        "limits": {"max_hosts": MAX_HOSTS, "max_http_requests": MAX_HTTP_REQUESTS, "max_path_probes": MAX_PATH_PROBES, "max_crawl_pages": MAX_CRAWL_PAGES, "max_js_files": MAX_JS_FILES, "request_spacing_seconds": REQUEST_SPACING_SECONDS, "redirects_followed": 0, "scan_concurrency": 1, "direct_http_scope": "confirmed root host only"},
    })


def phase1(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    domain = ctx["domain"]
    warnings: list[str] = []
    names: set[str] = {domain}
    try:
        path = "/?" + urlencode({"q": f"%.{domain}", "output": "json"})
        response = safe_get("crt.sh", path, max_bytes=500_000)
        if response["status_code"] >= 400:
            raise OSError("Provider returned an error response")
        rows = json.loads(response["body"] or "[]")
        if not isinstance(rows, list):
            raise ValueError("Unexpected provider response")
        for row in rows:
            if not isinstance(row, dict):
                continue
            for value in (row.get("name_value", ""), row.get("common_name", "")):
                for candidate in str(value).splitlines():
                    name = candidate.strip().lower().lstrip("*.").rstrip(".")
                    try:
                        name = normalize_domain(name)
                    except ValueError:
                        continue
                    if in_scope(name, domain):
                        names.add(name)
                    if len(names) >= MAX_CT_NAMES:
                        break
                if len(names) >= MAX_CT_NAMES:
                    break
            if len(names) >= MAX_CT_NAMES:
                break
    except Exception as exc:
        warnings.append(f"Certificate-transparency lookup unavailable ({type(exc).__name__}); continuing with the confirmed root domain.")
    dns_records = _public_dns_record_summary(domain)
    ordered = [domain] + sorted(name for name in names if name != domain)
    return make_report(1, started, "completed_with_warnings" if warnings else "completed", 0, handoff_report(previous), "Analyzed Phase 0's confirmed scope and collected certificate-transparency hostnames, discarding entries outside the root-domain suffix.", {
        "provider": "crt.sh",
        "provider_shared_domain": domain,
        "dns_record_summary": dns_records,
        "candidate_subdomains": ordered[:MAX_CT_NAMES],
        "candidate_count": len(ordered[:MAX_CT_NAMES]),
    }, warnings)


def phase2(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    domain = ctx["domain"]
    external_runs = [
        _run_optional_passive_enumerator("subfinder", domain),
        _run_optional_passive_enumerator("amass", domain),
    ]
    candidates = list(previous["outputs"].get("candidate_subdomains", [domain]))
    for run in external_runs:
        candidates.extend(run.get("hosts", []))
    selected = [domain] + [host for host in candidates if host != domain and in_scope(host, domain)]
    selected = list(dict.fromkeys(selected))[:MAX_HOSTS]
    resolved: list[dict[str, Any]] = []
    for host in selected:
        try:
            addresses = resolve_public_addresses(host)
            if addresses:
                resolved.append({"host": host, "addresses": addresses})
        except ValueError:
            continue
        except Exception:
            continue
    warnings = [] if resolved else ["No public DNS addresses were found in the confirmed scope; active phases will have no host targets."]
    ctx["resolved_hosts"] = resolved
    return make_report(2, started, "completed" if resolved else "completed_with_warnings", 1, handoff_report(previous), "Analyzed Phase 1's candidate list, optionally merged passive Subfinder/Amass results when those binaries are installed, then resolved a small deduplicated set through public DNS. Puredns wordlist brute force and direct HTTP to discovered subdomains are not run.", {
        "resolved_hosts": resolved,
        "resolved_count": len(resolved),
        "passive_cli_runs": external_runs,
        "cap": MAX_HOSTS,
    }, warnings)


def phase3(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    hosts: list[dict[str, Any]] = []
    errors: list[str] = []
    for item in previous["outputs"].get("resolved_hosts", [])[:MAX_HOSTS]:
        host = item["host"]
        if host != ctx["domain"]:
            continue
        try:
            page = safe_get(host, "/", expected_scope=ctx["domain"], max_bytes=MAX_BODY_BYTES)
            parsed = parse_page(page["body"])
            summary = {key: value for key, value in page.items() if key != "body"}
            summary["title"] = parsed.title
            hosts.append(summary)
            ctx.setdefault("homepages", {})[host] = {"page": page, "parsed": parsed}
        except Exception as exc:
            errors.append(f"{host}: {type(exc).__name__}")
    warnings = ["Some public hosts did not respond within the low-impact request timeout."] if errors else []
    ctx["live_hosts"] = hosts
    return make_report(3, started, "completed_with_warnings" if errors else "completed", 2, handoff_report(previous), "Analyzed Phase 2 DNS results and sent at most one bounded homepage GET to the confirmed root domain. Discovered subdomains were not contacted; redirects were not followed.", {
        "live_hosts": hosts,
        "live_count": len(hosts),
        "not_responding": errors,
    }, warnings)


def phase4(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    technologies: list[dict[str, Any]] = []
    for host in ctx.get("live_hosts", []):
        name = urlsplit(host["url"]).hostname or ""
        home = ctx.get("homepages", {}).get(name)
        if not home:
            continue
        headers = host.get("headers", {})
        text = home["page"].get("body", "").lower()
        detected: list[str] = []
        server = headers.get("server")
        powered = headers.get("x-powered-by")
        if server:
            detected.append(f"Server header: {server}")
        if powered:
            detected.append(f"X-Powered-By: {powered}")
        for needle, label in (("wp-content", "WordPress"), ("/ _next/".replace(" ", ""), "Next.js"), ("__next_data__", "Next.js"), ("drupal-settings-json", "Drupal"), ("joomla!", "Joomla"), ("ng-version", "Angular"), ("data-reactroot", "React")):
            if needle in text and label not in detected:
                detected.append(label)
        generator = home["parsed"].generators[:3]
        detected.extend(f"Generator: {value}" for value in generator)
        technologies.append({"host": name, "signals": detected[:10], "confidence": "fingerprint hints; verify manually"})
    ctx["technologies"] = technologies
    return make_report(4, started, "completed", 3, handoff_report(previous), "Analyzed Phase 3's root-page capture and compared response headers, generator metadata, and a small set of HTML fingerprints; no exploit or intrusive probe was sent.", {"technology_inventory": technologies})


def phase5(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    root = ctx["domain"]
    robots_result: dict[str, Any] | None = None
    sitemap_result: dict[str, Any] | None = None
    warnings: list[str] = []
    try:
        robots_result = safe_get(root, "/robots.txt", expected_scope=root, max_bytes=40_000)
    except Exception as exc:
        warnings.append(f"robots.txt was not retrieved ({type(exc).__name__}).")
    try:
        time.sleep(REQUEST_SPACING_SECONDS)
        sitemap_result = safe_get(root, "/sitemap.xml", expected_scope=root, max_bytes=100_000)
    except Exception as exc:
        warnings.append(f"sitemap.xml was not retrieved ({type(exc).__name__}).")
    paths: set[str] = set()
    disallowed_paths: set[str] = set()
    if robots_result and robots_result["status_code"] < 400:
        for line in robots_result["body"].splitlines():
            key, _, value = line.partition(":")
            directive = key.strip().lower()
            if directive in ("allow", "disallow") and value.strip().startswith("/"):
                paths.add(value.strip()[:400])
                if directive == "disallow":
                    disallowed_paths.add(value.strip()[:400])
    probe_results: list[dict[str, Any]] = []
    for path in PATH_PROBE_LIST:
        if any(rule and path.startswith(rule) for rule in disallowed_paths):
            probe_results.append({"path": path, "status": "skipped_by_robots"})
            continue
        try:
            time.sleep(REQUEST_SPACING_SECONDS)
            response = safe_get(root, path, expected_scope=root, max_bytes=8_000)
            probe_results.append({
                "path": path,
                "status": "checked",
                "http_status": response["status_code"],
                "content_type": response["headers"].get("content-type", "")[:120],
            })
        except Exception as exc:
            probe_results.append({"path": path, "status": "unavailable", "error": type(exc).__name__})
    sitemap_urls: list[str] = []
    if sitemap_result and sitemap_result["status_code"] < 400:
        for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", sitemap_result["body"], re.I | re.S):
            candidate = loc.strip()[:1000]
            parsed = urlsplit(candidate)
            if parsed.scheme in ("http", "https") and parsed.hostname and in_scope(parsed.hostname, root):
                sitemap_urls.append(redact_query_values(candidate))
                if len(sitemap_urls) >= MAX_URLS:
                    break
    paths_sorted = sorted(paths)[:50]
    ctx["robots_paths"] = paths_sorted
    ctx["robots_disallowed_paths"] = sorted(disallowed_paths)[:50]
    ctx["sitemap_urls"] = list(dict.fromkeys(sitemap_urls))[:MAX_URLS]
    return make_report(5, started, "completed_with_warnings" if warnings else "completed", 4, handoff_report(previous), "Analyzed Phase 4's hints, read the root robots.txt and sitemap.xml, then checked a fixed list of at most eight common paths with serial GET requests. No wordlist, recursive brute force, redirects, or robots-disallowed paths are used.", {
        "robots_status": robots_result["status_code"] if robots_result else None,
        "robots_paths": paths_sorted,
        "sitemap_status": sitemap_result["status_code"] if sitemap_result else None,
        "sitemap_urls": ctx["sitemap_urls"],
        "fixed_path_checks": probe_results,
        "path_check_cap": MAX_PATH_PROBES,
    }, warnings)


def phase6(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    urls: set[str] = set(ctx.get("sitemap_urls", []))
    warnings: list[str] = []
    archive_urls: list[str] = []
    archive_path = "/cdx/search/cdx?" + urlencode({
        "url": f"{ctx['domain']}/*",
        "output": "json",
        "fl": "original",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": "50",
    })
    try:
        archive_response = safe_get("web.archive.org", archive_path, max_bytes=100_000)
        if archive_response["status_code"] < 400:
            archive_rows = json.loads(archive_response["body"] or "[]")
            if isinstance(archive_rows, list):
                for row in archive_rows[1:]:
                    raw_url = row[0] if isinstance(row, list) and row else ""
                    parts = urlsplit(str(raw_url))
                    if parts.scheme in ("http", "https") and parts.hostname and in_scope(parts.hostname, ctx["domain"]):
                        archive_urls.append(redact_query_values(urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))))
                    if len(archive_urls) >= MAX_URLS:
                        break
        else:
            warnings.append(f"Internet Archive returned HTTP {archive_response['status_code']}.")
    except Exception as exc:
        warnings.append(f"Internet Archive lookup unavailable ({type(exc).__name__}).")
    urls.update(archive_urls)

    fetched_pages: list[dict[str, Any]] = []
    for host, home in ctx.get("homepages", {}).items():
        if host == ctx["domain"]:
            fetched_pages.append({"url": home["page"]["url"], "page": home["page"], "parsed": home["parsed"]})
    queue: list[str] = list(urls)
    for host, home in ctx.get("homepages", {}).items():
        base_url = home["page"]["url"]
        for link in home["parsed"].links:
            candidate = urljoin(base_url, link.strip())
            parts = urlsplit(candidate)
            if parts.scheme not in ("http", "https") or not parts.hostname or not in_scope(parts.hostname, ctx["domain"]):
                continue
            if parts.username or parts.password:
                continue
            candidate = redact_query_values(urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, "")))
            urls.add(candidate[:1500])
            queue.append(candidate[:1500])
            if len(urls) >= MAX_URLS:
                break

    robots_disallowed = ctx.get("robots_disallowed_paths", [])
    visited_paths = {"/"}
    crawl_requests = 1 if fetched_pages else 0
    crawl_errors: list[str] = []
    for candidate in queue:
        if crawl_requests >= MAX_CRAWL_PAGES:
            break
        parts = urlsplit(candidate)
        if parts.scheme not in ("http", "https") or parts.hostname != ctx["domain"] or parts.username or parts.password:
            continue
        path = parts.path or "/"
        if path in visited_paths or any(path.startswith(rule) for rule in robots_disallowed if rule):
            continue
        if re.search(r"\.(?:png|jpe?g|gif|svg|css|woff2?|ttf|ico|pdf|zip)$", path, re.I):
            continue
        visited_paths.add(path)
        crawl_requests += 1
        time.sleep(REQUEST_SPACING_SECONDS)
        try:
            page = safe_get(ctx["domain"], path, expected_scope=ctx["domain"], max_bytes=MAX_BODY_BYTES)
            urls.add(page["url"])
            if page["status_code"] < 400 and "text/html" in page["headers"].get("content-type", "").lower():
                parsed = parse_page(page["body"])
                fetched_pages.append({"url": page["url"], "page": page, "parsed": parsed})
                for link in parsed.links:
                    linked = urlsplit(urljoin(page["url"], link.strip()))
                    if linked.scheme in ("http", "https") and linked.hostname == ctx["domain"] and not linked.username and not linked.password:
                        urls.add(urlunsplit((linked.scheme, linked.netloc, linked.path or "/", "", "")))
                        queue.append(urlunsplit((linked.scheme, linked.netloc, linked.path or "/", linked.query, "")))
        except Exception as exc:
            crawl_errors.append(type(exc).__name__)
    ctx["crawled_pages"] = fetched_pages
    ctx["archive_urls"] = list(dict.fromkeys(archive_urls))[:MAX_URLS]
    safe_urls = sorted(urls)[:MAX_URLS]
    ctx["urls"] = safe_urls
    if crawl_errors:
        warnings.append("Some same-scope crawl requests failed within the short request timeout.")
    return make_report(6, started, "completed_with_warnings" if warnings else "completed", 5, handoff_report(previous), "Analyzed Phase 5's report, collected same-scope links, queried the Internet Archive CDX endpoint for historical URLs, and crawled at most eight HTML pages on the exact root host. Forms were not submitted; redirects and off-scope URLs were not followed.", {
        "urls": safe_urls,
        "url_count": len(safe_urls),
        "historical_urls": ctx["archive_urls"],
        "pages_crawled": len(fetched_pages),
        "page_requests": crawl_requests,
        "crawl_page_cap": MAX_CRAWL_PAGES,
        "sources": ["homepage links", "sitemap.xml", "Internet Archive CDX"],
        "forms_submitted": False,
    }, warnings)


SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password|private[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{12,})")
URL_PATTERN = re.compile(r"(?:(?:https?:)?//[^\s'\"`<>]+|/(?:api|v[0-9]+|graphql|auth|oauth|admin|search|users|account)[A-Za-z0-9_?&=./-]*)", re.I)


def phase7(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    root = ctx["domain"]
    scripts: list[tuple[str, str]] = []
    seen_scripts: set[str] = set()
    for page_record in ctx.get("crawled_pages", []):
        page_url = page_record["url"]
        host = urlsplit(page_url).hostname or ""
        if host != root:
            continue
        for source in page_record["parsed"].scripts:
            absolute = urljoin(page_url, source)
            parts = urlsplit(absolute)
            if parts.scheme not in ("http", "https") or parts.hostname != root or parts.query or absolute in seen_scripts:
                continue
            scripts.append((host, absolute))
            seen_scripts.add(absolute)
            if len(scripts) >= MAX_JS_FILES:
                break
        if len(scripts) >= MAX_JS_FILES:
            break
    endpoint_hints: set[str] = set()
    secret_hints: list[dict[str, str]] = []
    fetched_count = 0
    for host, absolute in scripts:
        parts = urlsplit(absolute)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        try:
            time.sleep(REQUEST_SPACING_SECONDS)
            response = safe_get(host, path, expected_scope=root, max_bytes=MAX_BODY_BYTES)
            if response["status_code"] >= 400:
                continue
            fetched_count += 1
            source_text = response["body"]
            for match in URL_PATTERN.findall(source_text):
                candidate = urljoin(absolute, match)
                url_parts = urlsplit(candidate)
                if url_parts.hostname and in_scope(url_parts.hostname, root) and url_parts.scheme in ("http", "https"):
                    endpoint_hints.add(redact_query_values(urlunsplit((url_parts.scheme, url_parts.netloc, url_parts.path, url_parts.query, "")))[:1000])
            for match in SECRET_PATTERN.finditer(source_text):
                secret_hints.append({"script": path[:300], "category": match.group(1).lower(), "value": "[REDACTED]"})
                if len(secret_hints) >= 20:
                    break
        except Exception:
            continue
    outputs = {
        "javascript_files_reviewed": fetched_count,
        "endpoint_hints": sorted(endpoint_hints)[:MAX_URLS],
        "possible_secret_indicators": secret_hints,
        "secret_values_returned": False,
    }
    ctx["js_findings"] = outputs
    warnings = ["No same-host JavaScript file was available to inspect."] if not fetched_count else []
    return make_report(7, started, "completed_with_warnings" if warnings else "completed", 6, handoff_report(previous), "Analyzed Phase 6's URL inventory and inspected at most three same-host JavaScript files. Endpoint clues are scope-filtered; credential-like values are never returned.", outputs, warnings)


SENSITIVE_PARAMETER = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|session|cookie|signature)")


def phase8(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    entries: dict[str, set[str]] = {}
    candidates = list(ctx.get("urls", [])) + list(ctx.get("js_findings", {}).get("endpoint_hints", []))
    for value in candidates:
        parts = urlsplit(value)
        if not parts.hostname or not in_scope(parts.hostname, ctx["domain"]):
            continue
        path = parts.path or "/"
        endpoint = f"{parts.scheme}://{parts.netloc}{path}"
        for name, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=40):
            clean_name = re.sub(r"[^A-Za-z0-9_.-]", "", name)[:80]
            if clean_name:
                entries.setdefault(endpoint, set()).add(clean_name)
    inventory = [
        {"endpoint": endpoint, "parameter_names": sorted(names), "sensitive_name_present": any(SENSITIVE_PARAMETER.search(name) for name in names)}
        for endpoint, names in sorted(entries.items())
    ][:MAX_URLS]
    ctx["parameter_inventory"] = inventory
    return make_report(8, started, "completed", 7, handoff_report(previous), "Analyzed Phase 7's URL and JavaScript hints; collected parameter names only, without sending test payloads or storing parameter values.", {
        "parameter_inventory": inventory,
        "endpoint_count": len(inventory),
        "parameter_values_collected": False,
    })


def phase9(ctx: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    findings: list[dict[str, str]] = []
    for host in ctx.get("live_hosts", []):
        headers = host.get("headers", {})
        hostname = urlsplit(host["url"]).hostname or "unknown"
        if host.get("scheme") == "https" and not headers.get("strict-transport-security"):
            findings.append({"severity": "low", "title": "HSTS header not observed", "asset": hostname, "evidence": "The homepage response did not include Strict-Transport-Security.", "confidence": "indicator; review deployment policy"})
        for key, label in (("content-security-policy", "Content Security Policy"), ("x-content-type-options", "X-Content-Type-Options"), ("x-frame-options", "X-Frame-Options"), ("referrer-policy", "Referrer-Policy")):
            if not headers.get(key):
                findings.append({"severity": "info", "title": f"{label} header not observed", "asset": hostname, "evidence": f"The homepage response did not include {label}.", "confidence": "informational; verify whether the control is configured elsewhere"})
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if re.search(r"\d+\.\d+", server + " " + powered):
            findings.append({"severity": "info", "title": "Version-like server detail exposed", "asset": hostname, "evidence": "A response header contains a version-like string.", "confidence": "informational; exact value omitted"})
    for indicator in ctx.get("js_findings", {}).get("possible_secret_indicators", []):
        findings.append({"severity": "review", "title": "Credential-like JavaScript pattern", "asset": indicator["script"], "evidence": f"Pattern category: {indicator['category']}; matched value redacted.", "confidence": "possible false positive; rotate only after manual validation"})
    ctx["findings"] = findings
    warnings = ["This phase checks response configuration only; it does not run exploit or injection tests."]
    return make_report(9, started, "completed_with_warnings", 8, handoff_report(previous), "Analyzed Phase 8's parameter inventory and the prior observed headers and redacted JavaScript indicators. No exploit, credential guessing, port scan, or data extraction was run.", {
        "findings": findings,
        "finding_count": len(findings),
        "automated_exploitation": False,
    }, warnings)


PHASE_RUNNERS = [phase0, phase1, phase2, phase3, phase4, phase5, phase6, phase7, phase8, phase9]


def final_result(job_id: str, domain: str, reports: list[dict[str, Any]]) -> dict[str, Any]:
    status = "completed" if len(reports) == len(PHASES) and all(report["status"] in ("completed", "completed_with_warnings") for report in reports) else "blocked" if reports and reports[-1]["status"] == "blocked" else "partial"
    findings = reports[-1].get("outputs", {}).get("findings", []) if reports and reports[-1]["phase"] == 9 else []
    summary = {
        "domain": domain,
        "overall_status": status,
        "phases_reported": len(reports),
        "phases_completed": sum(report["status"] in ("completed", "completed_with_warnings") for report in reports),
        "findings_for_manual_review": len(findings),
        "live_hosts": len(reports[3].get("outputs", {}).get("live_hosts", [])) if len(reports) > 3 else 0,
        "urls_collected": len(reports[6].get("outputs", {}).get("urls", [])) if len(reports) > 6 else 0,
        "limitations": [
            "No wordlist brute force, vulnerability exploitation, injection payloads, port scanning, password guessing, or data extraction.",
            "Each run uses one bounded request to the Python backend; reports are saved in this browser only.",
            "After explicit consent, passive lookups may share the domain with crt.sh, the Internet Archive, and configured Subfinder/Amass providers.",
        ],
    }
    return {"job_id": job_id, "domain": domain, "created_at": utc_now(), "summary": summary, "phase_reports": reports, "final_findings": findings}


@app.post("/api/scan")
async def scan(request: Request, payload: ScanRequest):
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)
    job_id = str(uuid.uuid4())
    ctx: dict[str, Any] = {"domain": domain, "request": payload}

    async def events():
        reports: list[dict[str, Any]] = []
        previous: dict[str, Any] | None = None
        for index, runner in enumerate(PHASE_RUNNERS):
            if index and await request.is_disconnected():
                return
            if index > 0 and not ctx.get("scope_confirmed"):
                break
            try:
                report = await asyncio.to_thread(runner, ctx, previous)
            except Exception as exc:
                started = time.monotonic()
                report = make_report(index, started, "failed", previous["phase"] if previous else None, handoff_report(previous) if previous else {"domain": domain}, "The phase stopped after an unexpected error.", {}, [f"Safe error category: {type(exc).__name__}."])
            reports.append(report)
            previous = report
            yield json.dumps({"type": "phase", "report": report}, ensure_ascii=False, separators=(",", ":")) + "\n"
            if report["status"] in ("blocked", "failed"):
                break
        result = final_result(job_id, domain, reports)
        if not await request.is_disconnected():
            yield json.dumps({"type": "final", "report": result}, ensure_ascii=False, separators=(",", ":")) + "\n"

    return StreamingResponse(events(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

