# Pyramid Recon

বাংলা-প্রথম, Python-ভিত্তিক local-first web reconnaissance dashboard। একটি domain-এর DNS TXT ownership proof ও অনুমতির সম্মতি যাচাই করে Phase 0 → 9 ধারাবাহিকভাবে চালায়। প্রতিটি phase-এর input, analysis, report ও output আলাদা দেখায়; আগের সম্পূর্ণ report পরের phase-এর input হয়। শেষে final synthesis JSON হিসেবে download করা যায়।

## Phase chain

0. Scope & Setup
1. Passive Recon & OSINT — crt.sh certificate-transparency query
2. Subdomain Discovery — public DNS resolution
3. Live Host Verification — one bounded homepage GET to the verified root domain only
4. Technology Fingerprinting — observed response/page hints
5. Content & Directory Discovery — root `robots.txt` and `sitemap.xml` only
6. URL & Endpoint Discovery — same-scope homepage links and sitemap entries
7. JavaScript Analysis — at most three same-host JS files; sensitive values redacted
8. Parameter Discovery — names only; values and test payloads are not sent
9. Vulnerability Review — passive response-header indicators for human review

## Run locally

Requires Python 3.11 or newer locally (Vercel builds use Python 3.12). On Windows, double-click `start_local.bat`; it creates a project-local `.venv`, installs only the packages in `requirements.txt`, starts the Python server on loopback, and opens the dashboard in your browser. Keep the terminal open while using the dashboard and press **Ctrl+C** there to stop it. It does not install packages globally or install the separate Nmap/Nuclei-style tools from the reference project.

To start it manually on any platform:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run_local.py
```

The launcher selects an available `127.0.0.1` port and opens it automatically. The dashboard is reachable only from this PC. Add the generated TXT record at `_webrecon.<domain>` with value `recon-verification=<token>`, wait for DNS propagation, then confirm authorization and provider sharing in the UI. The domain is sent to crt.sh only after the explicit provider consent.

## Deploy to Vercel

The repository exports a FastAPI app from `app.py`, includes dependencies in `requirements.txt`, and configures a bounded 120-second function duration. Connect the GitHub repository to Vercel or run `vercel` from this directory. Vercel's FastAPI preset serves the app; static files live under `public/`.

## Storage and job model

The workflow executes as one serial, streaming request. Vercel does not keep an application database for this MVP. Phase and final reports are saved in the visitor's browser `localStorage` and can be downloaded as JSON. Clear browser site data or use **History clear** to remove saved reports.

## Scope and safety

- One TXT-verified root domain per run; certificate-transparency subdomains are inventory only and are never contacted over HTTP.
- Maximum four DNS names, three same-host JavaScript files, bounded timeouts and response sizes.
- DNS results must be public IP addresses. Connections are pinned to a resolved public address; redirects are never followed.
- Query parameter values are stripped from reports; JavaScript files with query strings are skipped.
- No port scanning, path brute force, form submission, payload injection, exploitation, password guessing, WAF evasion, database dump, or data extraction.
- Phase 9 records configuration indicators, not confirmed vulnerabilities. A human must validate findings.
- Use only on assets you own or have written authorization to assess.

## Files

- `app.py` — FastAPI endpoints, DNS proof, safe fetcher, serial orchestrator, and phase reports.
- `public/` — responsive UI, phase stream, pyramid and favicon.
- `outputs/` — initial Bengali build instruction and full-size pyramid concept.
- `vercel.json` — security headers and execution cap.
