# ACS Domain Checker (PowerShell)

Single-file PowerShell local web app (UI + JSON API) that inspects DNS records commonly involved in Azure Communication Services (ACS) email domain verification, plus helpful email/DNS signals (MX, DMARC, DKIM, CNAME).

## What it checks

- **ACS readiness (primary):** root TXT contains `ms-domain-verification`
- **Also shows:**
  - **SPF**: root TXT starting with `v=spf1`
  - **MX**: records + resolved A/AAAA for each MX host + provider hint
  - **DMARC**: `_dmarc.<domain>` TXT
  - **DKIM (ACS selectors):** `selector1-azurecomm-prod-net._domainkey.<domain>` TXT, `selector2-...`
  - **CNAME**: root CNAME (informational)

## Endpoints

- `/` (UI)
- `/dns` (aggregated status)
- `/api/base`, `/api/mx`, `/api/dmarc`, `/api/dkim`, `/api/cname`

All endpoints accept `?domain=<domain>`.

## Requirements

- PowerShell 7+ (recommended). Windows PowerShell 5.1 should work on Windows.
- A browser.
- DNS resolution:
  - Uses `Resolve-DnsName` when available, otherwise falls back to DNS-over-HTTPS (DoH).

## Quick start

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\acs-domain-checker.ps1
```

Open `http://localhost:8080`

Different port:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\acs-domain-checker.ps1 -Port 8090
```

## DNS resolver options

```powershell
# Auto (default): Resolve-DnsName if present, else DoH
pwsh -File .\acs-domain-checker.ps1 -DnsResolver Auto

# Force system resolver (requires Resolve-DnsName)
pwsh -File .\acs-domain-checker.ps1 -DnsResolver System

# Force DoH (optionally set endpoint)
pwsh -File .\acs-domain-checker.ps1 -DnsResolver DoH -DohEndpoint https://cloudflare-dns.com/dns-query
```

You can also set:
- `ACS_DNS_RESOLVER` = `Auto` | `System` | `DoH`
- `ACS_DNS_DOH_ENDPOINT` = DoH endpoint URL

## API examples

```powershell
Invoke-RestMethod "http://localhost:8080/dns?domain=example.com"
Invoke-RestMethod "http://localhost:8080/api/base?domain=example.com"
Invoke-RestMethod "http://localhost:8080/api/mx?domain=example.com"
Invoke-RestMethod "http://localhost:8080/api/dmarc?domain=example.com"
Invoke-RestMethod "http://localhost:8080/api/dkim?domain=example.com"
Invoke-RestMethod "http://localhost:8080/api/cname?domain=example.com"
```

## Networking / safety notes

- **Windows / HttpListener mode:** binds to `http://+:<port>/` (LAN-accessible if firewall allows).
- **Non-Windows:** binds to `localhost` only (and may use a TcpListener fallback).

If you want local-only access on Windows, change the prefix to `http://localhost:$Port/` (or `http://127.0.0.1:$Port/`).

## Troubleshooting

- **Access denied / URL reservation** (Windows):
  ```powershell
  netsh http add urlacl url=http://+:8080/ user=$env:USERNAME
  ```
- **DNS lookups fail/time out:**
  - Try `-DnsResolver DoH` (or set `ACS_DNS_RESOLVER=DoH`)
  - Verify the domain exists and the machine can reach DNS/HTTPS

## Repo layout

- `acs-domain-checker.ps1` — single-file server + UI + API

## License

MIT