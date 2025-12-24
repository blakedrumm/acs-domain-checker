# ACS Domain Checker (PowerShell)

A single-file PowerShell web app that checks a domain’s DNS records for Azure Communication Services (ACS) email domain verification readiness, plus common email/DNS signals (MX, DMARC, DKIM, CNAME).

It serves a local UI and a small JSON API.

## Features

- **ACS readiness**: detects `ms-domain-verification` TXT record and an SPF record (`v=spf1`).
- **Email/DNS checks**:
  - MX lookup + basic provider hint (Microsoft 365 / Google / Proofpoint / Mimecast / Zoho / Unknown)
  - DMARC (`_dmarc.<domain>`)
  - DKIM (common selectors)
  - CNAME (basic lookup)
- **Web UI**: light/dark mode, shareable `?domain=` link, per-field copy buttons, recent-history chips, screenshot-to-clipboard.
- **JSON endpoints**: `/api/base`, `/api/mx`, `/api/dmarc`, `/api/dkim`, `/api/cname`, and `/dns`.

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+ on Windows
- DNS tooling: `Resolve-DnsName` (Windows)
- A browser for the UI

## Quick start

Run:

    pwsh -NoProfile -ExecutionPolicy Bypass -File .\acs-domain-checker.ps1

Open:

- `http://localhost:8080`

To use a different port:

    pwsh -NoProfile -ExecutionPolicy Bypass -File .\acs-domain-checker.ps1 -Port 8090

## API usage

All endpoints accept `?domain=<domain>`.

### Examples:

    Invoke-RestMethod "http://localhost:8080/dns?domain=example.com"
    Invoke-RestMethod "http://localhost:8080/api/base?domain=example.com"
    Invoke-RestMethod "http://localhost:8080/api/mx?domain=example.com"
    Invoke-RestMethod "http://localhost:8080/api/dmarc?domain=example.com"
    Invoke-RestMethod "http://localhost:8080/api/dkim?domain=example.com"
    Invoke-RestMethod "http://localhost:8080/api/cname?domain=example.com"

## Notes on networking / safety

By default the script binds the listener to `http://+:<port>/` (all interfaces). That’s convenient for LAN testing, but it also means other machines may be able to reach the UI/API if your firewall allows it.

If you want **local-only** access, change the listener prefix to `http://localhost:$Port/` (or `http://127.0.0.1:$Port/`).

## Troubleshooting

- **Access denied / URL reservation** when starting the listener:
  - Try running the shell as Administrator, or reserve the URL:

        netsh http add urlacl url=http://+:8080/ user=%USERNAME%

- **DNS lookups fail**:
  - Confirm the machine has DNS access and the domain exists.

## Repo layout

- `acs-domain-checker.ps1` — single-file server + UI + API.

## License

MIT