# Python-ভিত্তিক Web Recon Tool — Build Instruction

## উদ্দেশ্য

একটি online web application তৈরি করো যেখানে ব্যবহারকারী একটি domain, তার সুনির্দিষ্ট অনুমোদিত scope, এবং assessment-এর লিখিত অনুমতির তথ্য দিয়ে Phase 0–9 ধারাবাহিকভাবে চালাতে পারবেন। প্রতিটি ধাপ আগের ধাপ সফল হলে শুরু হবে। Tool-টি ফলাফল সংরক্ষণ করে একটি পাঠযোগ্য report তৈরি করবে। এটি কেবল নিজের বা লিখিত অনুমতি থাকা asset-এর জন্য।

## Pyramid ও phase map

উপরের স্তর থেকে নিচের স্তর পর্যন্ত এই ক্রমটি বজায় রাখো:

| Phase | কাজ | প্রধান output |
|---|---|---|
| **0 — Scope & Setup** | অনুমতি, domain allowlist, সীমা, tool ও provider readiness যাচাই | অনুমোদিত scope ও job configuration |
| **1 — Passive Recon & OSINT** | public domain, DNS, ASN, registration ও passive-source তথ্য | passive intelligence |
| **2 — Subdomain Discovery** | passive discovery; প্রয়োজন হলে অনুমোদিত, নিয়ন্ত্রিত DNS checks | subdomain inventory |
| **3 — Live Host Verification** | scope-এর মধ্যে HTTP/HTTPS host ও response metadata যাচাই | live-host list, status/title |
| **4 — Technology Fingerprinting** | framework, CMS, server ও client technology শনাক্ত | technology inventory |
| **5 — Content & Directory Discovery** | সীমিত rate-এ অনুমোদিত host-এর public path আবিষ্কার | path/content inventory |
| **6 — URL & Endpoint Discovery** | public archive ও scope-সীমাবদ্ধ crawl থেকে URL সংগ্রহ | deduplicated URL/endpoint list |
| **7 — JavaScript Analysis** | JS file থেকে endpoint clue ও সম্ভাব্য secret শনাক্ত; report-এ secret redact | JS findings, redacted indicators |
| **8 — Parameter Discovery** | URL ও endpoint-এর parameter inventory তৈরি | endpoint-parameter map |
| **9 — Vulnerability Scanning** | সীমিত rate-এ অনুমোদিত asset-এ non-destructive checks | যাচাই-অপেক্ষমাণ finding ও evidence |

Phase 0 হবে pyramid-এর ছোট শীর্ষে, Phase 9 হবে চওড়া নিচের ভিত্তিতে। [Pyramid image](recon-phases-pyramid.svg)

## প্রস্তাবিত architecture

```text
Browser UI → FastAPI → Job queue → Python worker (serial Phase 0–9)
                                      ├─ Tool/provider adapters
                                      ├─ Per-phase artifacts
                                      └─ PostgreSQL + report storage
```

- **UI:** responsive dashboard; domain, exact allowlist, permission reference, provider নির্বাচন, rate limit ও run mode দেখাবে। প্রতিটি phase-এর queued/running/completed/failed/skipped অবস্থা, সময়, ফলাফলের সংখ্যা এবং log দেখাবে।
- **API:** Python **FastAPI** দিয়ে job তৈরি, status পড়া, result download এবং cancel endpoint দাও।
- **Orchestrator:** প্রতিটি phase-কে আলাদা Python function/adapter হিসেবে লেখো। Job-এর মধ্যে concurrency `1` রাখো; `0 → 1 → … → 9` ক্রমে চালাও। একটি phase fail, timeout, scope breach বা stop request পেলে পরের phase চালাবে না।
- **Queue/worker:** ছোট MVP-তে FastAPI background worker চলতে পারে; দীর্ঘ job-এর জন্য Redis-ভিত্তিক **RQ** বা Celery worker ব্যবহার করো। Worker-কে আলাদা container-এ, resource/time limit-সহ চালাও।
- **Storage:** PostgreSQL-এ job, scope, phase status, finding metadata এবং audit event রাখো। বড় JSON/log/report আলাদা object/file storage-এ রাখো।
- **Adapters:** একেকটি বাইরের tool/API-র জন্য ছোট adapter লিখো; version, timeout, exit status, structured output এবং error আলাদা করে ধরো। Python `subprocess` ব্যবহার করলে argument list দাও—`shell=True` নয়।
- **Secrets:** provider API key environment/secret store-এ রাখো; UI response, logs বা report-এ key কখনও ফেরত দিও না। সম্ভাব্য credential/secret report-এ redact করে শুধু অবস্থান ও masked hint দেখাও।

## Serial job-এর আচরণ

1. ব্যবহারকারী domain ও exact scope জমা দিলে Phase 0 validation চালাও। Root domain, অনুমোদিত subdomain, বাদ দেওয়া host, অনুমতির মেয়াদ, request rate এবং contact/stop তথ্য সংরক্ষণ করো।
2. Scope/authorization যাচাই না হলে job `blocked` করে থামাও; কোনো active request পাঠিও না।
3. প্রতিটি phase-এর input আগের phase-এর saved artifact থেকে নাও। Duplicate বাদ দাও এবং ফলাফলে source/provenance রাখো।
4. Phase শুরু হওয়ার আগে scope পুনরায় যাচাই করো; redirect বা discovered subdomain স্বয়ংক্রিয়ভাবে allowlist-এ যোগ করো না। নতুন asset-কে review queue-তে দেখাও।
5. প্রতি phase-এ timeout, low configurable rate limit, request cap এবং cancel/pause support রাখো। `429`, repeated `5xx`, explicit deny/stop, scope mismatch বা resource limit হলে সঙ্গে সঙ্গে থামাও।
6. প্রতিটি phase শেষে summary ও artifact লিখে status update দাও। ব্যর্থ হলে error ও অসম্পূর্ণ artifact সংরক্ষণ করে পরের phase skip করো। ব্যবহারকারী resume করলে failed phase থেকেই শুরু করো।
7. সব ধাপ শেষে executive summary, asset inventory, phase-by-phase findings, redacted evidence, timestamps, tool versions ও limitations-সহ HTML/JSON report তৈরি করো।

## নিরাপত্তা ও অনুমতির নিয়ম

- Tool-টি **শুধু লিখিত অনুমতি থাকা scope**-এ কাজ করবে। Authorization record ও allowlist ছাড়া Phase 3 বা তার পরের active phase শুরু করা যাবে না।
- UI-তে স্পষ্টভাবে দেখাও কোন online provider-কে domain পাঠানো হবে; provider বেছে নেওয়া ও data-sharing সম্মতি ছাড়া সেই API call করবে না।
- User input-কে arbitrary URL fetch করার সুযোগ দিও না। Domain normalize/validate করো; private, loopback, link-local, reserved address ও metadata endpoint-এ worker-এর network access বন্ধ রাখো; DNS resolve/redirect-এর পরেও scope যাচাই করো।
- Rate limit, request budget, worker egress allowlist, timeout এবং immutable audit log server-side প্রয়োগ করো। Browser-side check-কে security control হিসেবে ধরো না।
- MVP-তে exploitation, SQL/database dump, password guessing, stealth/evasion, WAF bypass, persistence বা data extraction থাকবে না। Vulnerability scanner-এ non-destructive template/category allowlist দাও; high-impact check default-এ বন্ধ রাখো। Finding-কে “সম্ভাব্য” হিসেবে দেখাও, human verification চাইবে।
- CSRF protection, authentication, per-user job isolation, authorization checks, encrypted secrets, safe report download এবং retention/delete policy যোগ করো।

## MVP acceptance criteria

- একটি domain দিয়ে job তৈরি হয় এবং Phase 0–9 strict serial order-এ দৃশ্যমান হয়।
- Authorization/scope ছাড়া active scan অসম্ভব; allowlist-এর বাইরের host-এ request যায় না।
- প্রতিটি phase-এর status, timing, error, tool/provider source এবং artifact UI-তে দেখা যায়।
- Fail/cancel হলে পরের ধাপ শুরু হয় না; resume করলে সঠিক phase থেকে চলে।
- Report-এ API key/secret প্রকাশ পায় না এবং findings-কে যাচাই-অপেক্ষমাণ হিসেবে চিহ্নিত করা হয়।

## Build prompt

> উপরের specification অনুযায়ী Python দিয়ে একটি secure, online web application তৈরি করো। FastAPI backend, responsive dashboard, serial Phase 0–9 orchestrator, pluggable provider/tool adapters, durable job status, PostgreSQL persistence, audit log এবং HTML/JSON report implement করো। Phase 0-তে authorization ও exact allowlist যাচাই বাধ্যতামূলক করো; active network phase-এর আগে এবং প্রতিটি redirect/discovered host-এ scope re-check করো। প্রতিটি phase-এর timeout, rate/request cap, cancel/pause, structured artifact ও failure handling রাখো। MVP-তে non-destructive reconnaissance ও conservative vulnerability checks-এ সীমাবদ্ধ থাকো; exploit, credential guessing, WAF bypass, database dump বা data extraction implement কোরো না। Provider-এ domain পাঠানোর আগে UI-তে provider disclosure/consent দাও, API key secret store-এ রাখো, এবং report/log-এ sensitive value redact করো।

## Source note

এই phase map খোলা **“Recon for Web Application”** পেজের Phase 0–9 checklist থেকে সাজানো। পেজের “Quick Reference” অংশে phase numbering আলাদা করে ৫ ধাপে মিশিয়ে দেওয়া, তাই নতুন tool-এ উপরের পূর্ণ checklist-কে canonical sequence হিসেবে ধরো।
