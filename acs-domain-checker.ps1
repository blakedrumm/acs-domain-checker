<#!
.SYNOPSIS
  Local web UI + REST API to inspect DNS records used for Azure Communication Services (ACS) domain verification.

.DESCRIPTION
  Starts an HTTP listener (default: http://localhost:8080) that serves a single-page web UI and several JSON endpoints.
  The tool helps validate whether a domain appears ready for ACS verification by checking for:
  - Root TXT records (SPF + ms-domain-verification)
  - MX records (with resolved IPv4/IPv6 addresses where available)
  - DMARC, DKIM, and CNAME

  Endpoints:
  - /            : Web UI
  - /dns         : Aggregated DNS status JSON
  - /api/base    : Root TXT/SPF/ACS TXT JSON
  - /api/mx      : MX (plus A/AAAA resolution details) JSON
  - /api/dmarc   : DMARC JSON
  - /api/dkim    : DKIM JSON
  - /api/cname   : CNAME JSON

.PARAMETER Port
  TCP port to listen on. Default is 8080.

.EXAMPLE
  # Start on the default port
  .\acs-domain-checker.ps1

.EXAMPLE
  # Start on a different port
  .\acs-domain-checker.ps1 -Port 8090

.NOTES
  Author: Blake Drumm (blakedrumm@microsoft.com)
  Date created: December 26th, 2025
  This script is intended for local troubleshooting. Ensure the chosen port is allowed by your firewall policy.

  Cross-platform notes:
  - On Linux/macOS, the listener binds to localhost only.
  - If `Resolve-DnsName` is unavailable, DNS lookups fall back to DNS-over-HTTPS (DoH).
    Override the DoH endpoint by setting `ACS_DNS_DOH_ENDPOINT` (default: Cloudflare).
#>

param(
  [int]$Port = 8080,
  [ValidateSet('Auto','System','DoH')]
  [string]$DnsResolver = 'Auto',
  [string]$DohEndpoint
)

Add-Type -AssemblyName System.Net

# ------------------- CONFIG / STARTUP -------------------
# This script hosts a tiny local web server:
# - `GET /` serves an embedded single-page HTML UI.
# - `GET /api/*` returns individual DNS checks.
# - `GET /dns` returns an aggregated "readiness" JSON payload.
#
# DNS resolver selection is exposed via `-DnsResolver`:
# - Auto   : use `Resolve-DnsName` if available, else DoH.
# - System : force `Resolve-DnsName` (Windows/PowerShell with DnsClient module).
# - DoH    : force DNS-over-HTTPS via `Invoke-RestMethod`.

$script:DnsResolverMode = $DnsResolver

# RunspacePool copies function *definitions* but not script-scoped variables.
# Use env vars for settings that must be visible inside request handler runspaces.
$env:ACS_DNS_RESOLVER = $DnsResolver

if ([string]::IsNullOrWhiteSpace($DohEndpoint)) {
  if (-not [string]::IsNullOrWhiteSpace($env:ACS_DNS_DOH_ENDPOINT)) {
    $DohEndpoint = $env:ACS_DNS_DOH_ENDPOINT
  }
}
if (-not [string]::IsNullOrWhiteSpace($DohEndpoint)) {
  $env:ACS_DNS_DOH_ENDPOINT = $DohEndpoint
}

$serverMode = 'HttpListener'
$listener = $null
$tcpListener = $null

$displayUrl = "http://localhost:$Port"

try {
  $listener = [System.Net.HttpListener]::new()

  # HttpListener on Windows supports wildcard prefixes (http://+:port/) which enables LAN access.
  # On non-Windows, HttpListener support/permissions vary; bind to localhost to keep it simple.
  $prefix = if ($IsWindows) { "http://+:$Port/" } else { "http://localhost:$Port/" }
  $listener.Prefixes.Add($prefix)
  $listener.Start()
}
catch {
  # HttpListener is not consistently supported on Linux/macOS; fall back to a simple TcpListener server.
  if (-not $IsWindows) {
    $serverMode = 'TcpListener'
  } else {
    throw
  }
}

if ($serverMode -eq 'TcpListener') {
  $tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
  $tcpListener.Start()
}

Write-Information -InformationAction Continue -MessageData "ACS Domain Verification Checker running at $displayUrl"

function Write-Json {
    param(
    $Context,
    [object]$Object,
    [int]$StatusCode = 200
    )

    # Serialize to JSON and write to the current response type.
    # The script can run in 2 server modes:
    # - HttpListener: native `HttpListenerContext`/`HttpListenerResponse` objects
    # - TcpListener : a minimal compatibility layer that mimics a subset of those APIs
    $json  = $Object | ConvertTo-Json -Depth 8
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)

  if ($Context.Response -is [System.Net.HttpListenerResponse]) {
    $Context.Response.ContentType = "application/json; charset=utf-8"
    $Context.Response.StatusCode  = $StatusCode
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
    return
  }

  # TcpListener fallback response
  $Context.Response.ContentType = "application/json; charset=utf-8"
  $Context.Response.StatusCode  = $StatusCode
  $Context.Response.ContentLength64 = $bytes.Length
  $Context.Response.SendBody($bytes)
}

function Write-Html {
    param(
        $Context,
        [string]$Html
    )

    # Serve the embedded SPA HTML. (All dynamic data is fetched from JSON endpoints.)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Html)

    if ($Context.Response -is [System.Net.HttpListenerResponse]) {
      $Context.Response.ContentType = "text/html; charset=utf-8"
      $Context.Response.StatusCode  = 200
      $Context.Response.ContentLength64 = $bytes.Length
      $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
      $Context.Response.OutputStream.Close()
      return
    }

    # TcpListener fallback response
    $Context.Response.ContentType = "text/html; charset=utf-8"
    $Context.Response.StatusCode  = 200
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.SendBody($bytes)
}

function Resolve-DohName {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [ValidateSet('A','AAAA','CNAME','MX','TXT')]
    [string]$Type
  )

  # DNS-over-HTTPS resolver.
  # Returns objects shaped similarly to `Resolve-DnsName` output so downstream code can stay uniform.
  $endpoint = $env:ACS_DNS_DOH_ENDPOINT
  if ([string]::IsNullOrWhiteSpace($endpoint)) {
    $endpoint = 'https://cloudflare-dns.com/dns-query'
    $env:ACS_DNS_DOH_ENDPOINT = $endpoint
  }

  $uri = "{0}?name={1}&type={2}" -f $endpoint, ([uri]::EscapeDataString($Name)), $Type

  # Cloudflare-style DoH JSON response (RFC 8484 compatible JSON format).
  $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ accept = 'application/dns-json' } -TimeoutSec 10 -ErrorAction Stop
  if ($null -eq $resp -or $null -eq $resp.Answer) { return $null }

  $answers = @($resp.Answer)
  if (-not $answers) { return $null }

  switch ($Type) {
    'TXT' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        $data = $data.Trim()
        if ($data.StartsWith('"') -and $data.EndsWith('"') -and $data.Length -ge 2) {
          $data = $data.Substring(1, $data.Length - 2)
        }
        $data = $data -replace '\\"','"'
        [pscustomobject]@{ Strings = @($data) }
      }
    }
    'MX' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        $parts = $data.Trim() -split '\s+', 2
        if ($parts.Count -ne 2) { continue }
        $pref = 0
        [int]::TryParse($parts[0], [ref]$pref) | Out-Null
        [pscustomobject]@{ Preference = $pref; NameExchange = $parts[1] }
      }
    }
    'CNAME' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ CanonicalName = $data.Trim() }
      }
    }
    'A' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ IPAddress = $data.Trim(); IP4Address = $data.Trim() }
      }
    }
    'AAAA' {
      foreach ($a in $answers) {
        $data = [string]$a.data
        if ([string]::IsNullOrWhiteSpace($data)) { continue }
        [pscustomobject]@{ IPAddress = $data.Trim(); IP6Address = $data.Trim() }
      }
    }
  }
}

function ResolveSafely {
    param(
        [string]$Name,
        [string]$Type,
        [switch]$ThrowOnError
    )
    # One stop DNS lookup wrapper:
    # - picks System vs DoH vs Auto
    # - optionally throws (when the caller wants to surface DNS failures)
    try {
        $mode = $env:ACS_DNS_RESOLVER
        if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'Auto' }

        switch ($mode) {
          'DoH' {
            return (Resolve-DohName -Name $Name -Type $Type)
          }
          'System' {
            $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
            if (-not $cmd) {
              throw "DnsResolver=System requires Resolve-DnsName (DnsClient module)."
            }
            return (Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
          }
          default {
            # Auto
            $cmd = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
            if ($cmd) {
              return (Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
            }
            return (Resolve-DohName -Name $Name -Type $Type)
          }
        }
    } catch {
        if ($ThrowOnError) { throw }
        $null
    }
}

function Get-DnsIpString {
  param(
    [Parameter(ValueFromPipeline = $true)]
    [object]$Record
  )

  begin {
    $results = [System.Collections.Generic.List[string]]::new()
  }

  process {
    if ($null -eq $Record) { return }

    $value = $null

    # Resolve-DnsName outputs vary by PS/DnsClient version: IP4Address/IP6Address are common,
    # and some versions expose an AliasProperty named IPAddress.
    $props = $Record.PSObject.Properties
    if ($props.Match('IPAddress').Count -gt 0) { $value = $Record.IPAddress }
    elseif ($props.Match('IP4Address').Count -gt 0) { $value = $Record.IP4Address }
    elseif ($props.Match('IP6Address').Count -gt 0) { $value = $Record.IP6Address }
    elseif ($Record -is [System.Net.IPAddress]) { $value = $Record.ToString() }

    foreach ($v in @($value)) {
      $s = [string]$v
      if (-not [string]::IsNullOrWhiteSpace($s)) {
        $results.Add($s.Trim())
      }
    }
  }

  end {
    $results | Select-Object -Unique
  }
}

function ConvertTo-NormalizedDomain {
  param([string]$Raw)

  # Normalize user input into a plain domain name:
  # - accepts: domain, email address, or URL
  # - strips: wildcard prefix and surrounding dots
  # - outputs: lowercase domain

  $domain = if ($null -eq $Raw) { "" } else { [string]$Raw }
  $domain = $domain.Trim()
  if ([string]::IsNullOrWhiteSpace($domain)) { return "" }

  # If user provided an email address, take everything after the last '@'
  $at = $domain.LastIndexOf("@")
  if ($at -ge 0 -and $at -lt ($domain.Length - 1)) {
    $domain = $domain.Substring($at + 1)
  }

  # If user provided a URL, extract hostname
  if ($domain -match '^(?i)https?://') {
    try {
      $domain = ([Uri]$domain).Host
    } catch {
      $null = $_
    }
  }

  # Remove wildcard prefix and surrounding dots/spaces
  $domain = $domain -replace '^\*\.', ''
  $domain = $domain.Trim().Trim('.')

  return $domain.ToLowerInvariant()
}

function Test-DomainName {
  param([string]$Domain)

  # Lightweight validation to avoid:
  # - obviously invalid domains
  # - path/query injection through the query string

  if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }

  $d = $Domain.Trim().ToLowerInvariant()
  if ($d.Length -gt 253) { return $false }
  if ($d -notmatch '^[a-z0-9.-]+$') { return $false }
  if ($d.Contains('..')) { return $false }
  if ($d.StartsWith('-') -or $d.EndsWith('-')) { return $false }

  $labels = $d.Split('.')
  if ($labels.Count -lt 2) { return $false }
  foreach ($label in $labels) {
    if ([string]::IsNullOrWhiteSpace($label)) { return $false }
    if ($label.Length -gt 63) { return $false }
    if ($label.StartsWith('-') -or $label.EndsWith('-')) { return $false }
  }
  return $true
}

function Write-RequestLog {
  param(
    $Context,
    [string]$Action,
    [string]$Domain
  )

  # Log incoming request context (useful when the listener is exposed on LAN on Windows).
  $userAgent = $Context.Request.UserAgent
  $remoteIp  = $Context.Request.RemoteEndPoint.Address.ToString()
  $isLocal   = $false

  if (
    $remoteIp -eq "::1" -or
    $remoteIp -like "127.*" -or
    $remoteIp -like "10.*" -or
    $remoteIp -like "192.168.*" -or
    $remoteIp -match "^172\.(1[6-9]|2[0-9]|3[0-1])\."
  ) {
    $isLocal = $true
  }

  $netType = if ($isLocal) { "Local Network" } else { "Public Network" }
  Write-Information -InformationAction Continue -MessageData "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] $Action for '$Domain'"
  Write-Information -InformationAction Continue -MessageData "  From: $remoteIp ($netType)"
  Write-Information -InformationAction Continue -MessageData "  Browser: $userAgent"
}

function Get-DnsBaseStatus {
  param([string]$Domain)

  # Base/root TXT checks.
  # - Collect all root TXT strings.
  # - Detect SPF (v=spf1...) and ACS verification token (ms-domain-verification...).

  $spf        = $null
  $acsTxt     = $null
  $txtRecords = @()
  $dnsFailed  = $false
  $dnsError   = $null

  try {
    $records = ResolveSafely $Domain "TXT" -ThrowOnError
    foreach ($r in $records) {
      $joined = ($r.Strings -join "").Trim()
      if ($joined) { $txtRecords += $joined }
    }
  } catch {
    $dnsFailed = $true
    $dnsError  = $_.Exception.Message
  }

  if (-not $dnsFailed) {
    foreach ($t in $txtRecords) {
      if (-not $spf    -and $t -match '(?i)^v=spf1')                { $spf    = $t }
      if (-not $acsTxt -and $t -match '(?i)ms-domain-verification') { $acsTxt = $t }
    }
  }

  $spfPresent = -not $dnsFailed -and [bool]$spf
  $acsPresent = -not $dnsFailed -and [bool]$acsTxt

  [pscustomobject]@{
    domain     = $Domain
    dnsFailed  = $dnsFailed
    dnsError   = $dnsError

    spfPresent = $spfPresent
    spfValue   = $spf
    acsPresent = $acsPresent
    acsValue   = $acsTxt

    txtRecords = $txtRecords
  }
}

function Get-DnsMxStatus {
  param([string]$Domain)

  # MX checks.
  # - Resolve MX records.
  # - Guess the mail provider based on the lowest-preference MX host.
  # - Resolve A/AAAA for each MX host to show concrete IP targets.

  $mxRecords         = @()
  $mxRecordsDetailed = @()
  $mxProvider        = $null
  $mxProviderHint    = $null

  if ($mx = ResolveSafely $Domain "MX") {
    $mxSorted = $mx | Sort-Object Preference, NameExchange

    $primaryMx = $null
    try { $primaryMx = ($mxSorted | Select-Object -First 1 -ExpandProperty NameExchange) } catch { $primaryMx = $null }

    if ($primaryMx) {
      $mxHost = $primaryMx.ToString().Trim().ToLowerInvariant()
      switch -Regex ($mxHost) {
        'mail\.protection\.outlook\.com\.?$' {
          $mxProvider = 'Microsoft 365 / Exchange Online'
          $mxProviderHint = 'MX points to Exchange Online Protection (EOP).'
          break
        }
        'aspmx\.l\.google\.com\.?$|\.aspmx\.l\.google\.com\.?$|google\.com\.?$' {
          $mxProvider = 'Google Workspace / Gmail'
          $mxProviderHint = 'MX points to Google mail exchangers.'
          break
        }
        '(^|\.)mx\.cloudflare\.net\.?$' {
          $mxProvider = 'Cloudflare Email Routing'
          $mxProviderHint = 'MX points to Cloudflare (mx.cloudflare.net).'
          break
        }
        'pphosted\.com\.?$' {
          $mxProvider = 'Proofpoint'
          $mxProviderHint = 'MX points to Proofpoint-hosted mail.'
          break
        }
        'mimecast\.com\.?$' {
          $mxProvider = 'Mimecast'
          $mxProviderHint = 'MX points to Mimecast.'
          break
        }
        'zoho\.com\.?$' {
          $mxProvider = 'Zoho Mail'
          $mxProviderHint = 'MX points to Zoho Mail.'
          break
        }
        default {
          $mxProvider = 'Unknown'
          $mxProviderHint = 'Provider not recognized from MX hostname.'
        }
      }
    }

    foreach ($m in $mxSorted) {
      $mxRecords += "$($m.NameExchange) (Priority $($m.Preference))"

      $ipv4 = @()
      $ipv6 = @()

      if ($aRecs = ResolveSafely $m.NameExchange "A") {
        $ipv4 += $aRecs | Get-DnsIpString
      }
      if ($aaaaRecs = ResolveSafely $m.NameExchange "AAAA") {
        $ipv6 += $aaaaRecs | Get-DnsIpString
      }

      if (-not $ipv4 -and -not $ipv6) {
        $mxRecordsDetailed += [pscustomobject]@{
          Hostname = $m.NameExchange
          Priority = $m.Preference
          Type = "N/A"
          IPAddress = "(none found)"
        }
      } else {
        foreach ($ip in $ipv4) {
          $mxRecordsDetailed += [pscustomobject]@{
            Hostname = $m.NameExchange
            Priority = $m.Preference
            Type = "IPv4"
            IPAddress = $ip
          }
        }
        foreach ($ip in $ipv6) {
          $mxRecordsDetailed += [pscustomobject]@{
            Hostname = $m.NameExchange
            Priority = $m.Preference
            Type = "IPv6"
            IPAddress = $ip
          }
        }
      }
    }
  }

  [pscustomobject]@{
    domain            = $Domain
    mxRecords         = $mxRecords
    mxRecordsDetailed = $mxRecordsDetailed
    mxProvider        = $mxProvider
    mxProviderHint    = $mxProviderHint
  }
}

function Get-DnsDmarcStatus {
  param([string]$Domain)

  # DMARC is a TXT record at `_dmarc.<domain>`.

  $dmarc = $null
  if ($dm = ResolveSafely "_dmarc.$Domain" "TXT") {
    foreach ($r in $dm) {
      $j = ($r.Strings -join "").Trim()
      if ($j -match '(?i)^v=dmarc') { $dmarc = $j }
    }
  }

  [pscustomobject]@{ domain = $Domain; dmarc = $dmarc }
}

function Get-DnsDkimStatus {
  param([string]$Domain)

  # ACS guidance expects these two DKIM selector TXT records.

  $dkim1 = $null
  if ($d1 = ResolveSafely "selector1-azurecomm-prod-net._domainkey.$Domain" "TXT") {
    $dkim1 = (($d1.Strings -join "") -replace '\s+', '').Trim()
  }

  $dkim2 = $null
  if ($d2 = ResolveSafely "selector2-azurecomm-prod-net._domainkey.$Domain" "TXT") {
    $dkim2 = (($d2.Strings -join "") -replace '\s+', '').Trim()
  }

  [pscustomobject]@{ domain = $Domain; dkim1 = $dkim1; dkim2 = $dkim2 }
}

function Get-DnsCnameStatus {
  param([string]$Domain)

  # Root CNAME check (not required for ACS verification; included as guidance).

  $cname = $null
  if ($cn = ResolveSafely $Domain "CNAME") {
    $cname = $cn.CanonicalName
  }

  [pscustomobject]@{ domain = $Domain; cname = $cname }
}

function Get-AcsDnsStatus {
    param([string]$Domain)

  # Aggregated status used by the UI.
  # Combines the individual checks + generates human-friendly guidance strings.

  $base  = Get-DnsBaseStatus  -Domain $Domain
  $mx    = Get-DnsMxStatus    -Domain $Domain
  $dmarc = Get-DnsDmarcStatus -Domain $Domain
  $dkim  = Get-DnsDkimStatus  -Domain $Domain
  $cname = Get-DnsCnameStatus -Domain $Domain

  # ACS domain verification readiness is primarily based on the ms-domain-verification TXT record.
  # Other checks (SPF/MX/DMARC/DKIM/CNAME) are useful guidance but not required for ACS verification.
  $acsReady = (-not $base.dnsFailed) -and $base.acsPresent

    # Guidance
    $guidance = New-Object System.Collections.Generic.List[string]

    if ($base.dnsFailed) {
        $guidance.Add("DNS TXT lookup failed or timed out. Other DNS records may still resolve.")
    } else {
      if (-not $base.spfPresent) { $guidance.Add("SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent).") }
      if (-not $base.acsPresent) { $guidance.Add("ACS ms-domain-verification TXT is missing. Add the value from the Azure portal.") }
      if (-not $mx.mxRecords)    { $guidance.Add("No MX records detected. Mail flow will not function until MX records are configured.") }
      if (-not $dmarc.dmarc)     { $guidance.Add("DMARC is missing. Add a _dmarc.$Domain TXT record to reduce spoofing risk.") }
      if (-not $dkim.dkim1)      { $guidance.Add("DKIM selector1 (selector1-azurecomm-prod-net) is missing.") }
      if (-not $dkim.dkim2)      { $guidance.Add("DKIM selector2 (selector2-azurecomm-prod-net) is missing.") }
      if (-not $cname.cname)     { $guidance.Add("Root CNAME is not configured. Validate this is expected for your scenario.") }

      # Provider-aware hints
      if ($mx.mxProvider -and $mx.mxProvider -ne 'Unknown') {
        $guidance.Add("Detected MX provider: $($mx.mxProvider)")
      }
      if ($mx.mxProvider -eq 'Microsoft 365 / Exchange Online' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)spf\.protection\.outlook\.com')) {
        $guidance.Add("Your MX indicates Microsoft 365, but SPF does not include spf.protection.outlook.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Google Workspace / Gmail' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)_spf\.google\.com')) {
        $guidance.Add("Your MX indicates Google Workspace, but SPF does not include _spf.google.com. Verify your SPF includes the correct provider include.")
      }
      if ($mx.mxProvider -eq 'Zoho Mail' -and $base.spfPresent -and ($base.spfValue -notmatch '(?i)include:zoho\.com')) {
        $guidance.Add("Your MX indicates Zoho, but SPF does not include include:zoho.com. Verify your SPF includes the correct provider include.")
      }
        if ($acsReady)        { $guidance.Add("This domain appears ready for Azure Communication Services domain verification.") }
    }

    [pscustomobject]@{
        domain     = $Domain
      resolver   = $env:ACS_DNS_RESOLVER
      dohEndpoint = $(if ($env:ACS_DNS_RESOLVER -eq 'DoH' -or ($env:ACS_DNS_RESOLVER -eq 'Auto' -and -not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue))) { $env:ACS_DNS_DOH_ENDPOINT } else { $null })
        dnsFailed  = $base.dnsFailed
        dnsError   = $base.dnsError

        spfPresent = $base.spfPresent
        spfValue   = $base.spfValue
        acsPresent = $base.acsPresent
        acsValue   = $base.acsValue

        txtRecords = $base.txtRecords
        acsReady   = $acsReady

        mxRecords         = $mx.mxRecords
        mxRecordsDetailed = $mx.mxRecordsDetailed
        mxProvider        = $mx.mxProvider
        mxProviderHint    = $mx.mxProviderHint

        dmarc      = $dmarc.dmarc
        dkim1      = $dkim.dkim1
        dkim2      = $dkim.dkim2
        cname      = $cname.cname

        guidance   = $guidance
    }
}

# ------------------- HTML / UI -------------------
# The UI is embedded as a here-string for easy, single-file distribution.
# It calls the JSON endpoints in this script and renders results client-side.
#
# Note: The UI references a CDN script (`html2canvas`) only for screenshot/export.

$htmlPage = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure Communication Services - Domain Verification Checker</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">

<style>
:root {
  --bg: #f4f6fb;
  --fg: #111827;
  --card-bg: #ffffff;
  --border: #e0e3ee;
  --status: #555555;
  --input-border: #c3c7d6;
  --button-bg: #2f80ed;
  --button-fg: #ffffff;
  --button-bg-secondary: #ffffff;
  --button-fg-secondary: #111827;
  --button-border-secondary: #c3c7d6;
  --code-bg: #0b1220;
  --code-fg: #c3d5ff;
}

.dark {
  --bg: #020617;
  --fg: #e5e7eb;
  --card-bg: #020617;
  --border: #1f2937;
  --status: #9ca3af;
  --input-border: #4b5563;
  --button-bg: #1d4ed8;
  --button-fg: #f9fafb;
  --button-bg-secondary: #111827;
  --button-fg-secondary: #e5e7eb;
  --button-border-secondary: #4b5563;
  --code-bg: #020617;
  --code-fg: #e5e7eb;
}

/* Hide marked buttons while screenshot is taken */
.screenshot-mode .hide-on-screenshot {
  visibility: hidden !important;
}

*, *::before, *::after {
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  margin: 0;
  padding: 32px 24px;
  background: var(--bg);
  color: var(--fg);
  transition: 0.25s background-color ease-in-out;
}

.search-box, .card, input, button, .code, .mx-table, .history-chip {
  transition: 0.25s background-color ease-in-out;
}

.container {
  width: 100%;
  max-width: 1100px;
  margin: 0 auto;
}

h1 {
  font-size: 22px;
  margin: 0 0 18px 0;
}

.top-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.top-bar button {
  padding: 6px 10px;
  font-size: 12px;
  border-radius: 4px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
}

.top-bar button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.search-box {
  background: var(--card-bg);
  border-radius: 8px;
  border: 1px solid var(--border);
  width: 100%;
  max-width: 760px;
  padding: 18px;
  margin: 0 auto 20px auto;
}

.search-box h1 {
  margin: 0 0 12px 0;
  font-size: 22px;
  font-weight: 700;
  text-align: center;
}

.search-box h2 {
  margin: 0 0 12px 0;
  font-size: 16px;
  font-weight: 600;
}

.input-row {
  display: flex;
  gap: 8px;
}

input[type=text] {
  flex: 1;
  height: 38px;
  padding: 8px 10px;
  line-height: 20px;
  border-radius: 4px;
  border: 1px solid var(--input-border);
  font-size: 14px;
  background: var(--card-bg);
  color: var(--fg);
}

button.primary {
  height: 38px;
  padding: 8px 14px;
  background: var(--button-bg);
  color: var(--button-fg);
  border-radius: 4px;
  border: none;
  cursor: pointer;
  font-size: 14px;
}

button.primary:disabled {
  opacity: 0.7;
  cursor: default;
}

#status {
  font-size: 13px;
  color: var(--status);
  min-height: 18px;
  margin-bottom: 10px;
  text-align: center;
}

.status-divider {
  margin: 10px auto 8px auto;
  width: min(860px, 100%);
  border-top: 1px solid var(--border);
}

.status-header {
  width: 100%;
  margin: 0 0 10px 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  text-align: center;
}

.status-header .title {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--fg);
}

.status-header .hint {
  font-size: 12px;
  color: var(--status);
}

.status-summary {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  justify-content: center;
  gap: 6px;
  width: min(860px, 100%);
  margin: 0 auto;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--card-bg);
}

.status-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.status-pills {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 6px;
  flex-wrap: wrap;
}

.status-name {
  font-size: 12px;
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.status-pill {
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  border: 1px solid var(--border);
  padding: 3px 10px;
  white-space: nowrap;
}

.cards {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.card {
  background: var(--card-bg);
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: 12px 14px;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
  flex-wrap: wrap;
}

.tag {
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 999px;
}

.tag-pass {
  background: #e1f7e6;
  color: #137333;
}

.tag-fail {
  background: #fde2e2;
  color: #c5221f;
}

.tag-info {
  background: #e1ecff;
  color: #214a9b;
}

.code {
  background: var(--code-bg);
  color: var(--code-fg);
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 12px;
  padding: 8px 10px;
  border-radius: 6px;
  white-space: pre-wrap;
  word-break: break-word;
}

.mx-table {
  width: 100%;
  border-collapse: collapse;
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 12px;
  background: var(--code-bg);
  color: var(--code-fg);
  border-radius: 6px;
  overflow: hidden;
}

.mx-table th {
  background: var(--border);
  color: var(--fg);
  padding: 6px 10px;
  text-align: left;
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.mx-table td {
  padding: 6px 10px;
  border-top: 1px solid var(--border);
}

.mx-table tr:first-child td {
  border-top: none;
}

ul.guidance {
  margin: 0;
  padding-left: 18px;
  font-size: 13px;
}

ul.guidance li {
  margin-bottom: 4px;
}

.copy-btn {
  padding: 4px 8px;
  font-size: 11px;
  border-radius: 4px;
  border: 1px solid var(--button-border-secondary);
  background: var(--button-bg-secondary);
  color: var(--button-fg-secondary);
  cursor: pointer;
}

/* --- New UI Polish --- */
.spinner {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 2px solid rgba(255,255,255,0.3);
  border-radius: 50%;
  border-top-color: #fff;
  animation: spin 1s ease-in-out infinite;
  margin-left: 6px;
  vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }

.input-wrapper {
  position: relative;
  flex: 1;
  display: flex;
}
.input-wrapper input {
  width: 100%;
  padding-right: 30px;
}
.clear-btn {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--status);
  font-size: 16px;
  cursor: pointer;
  padding: 0;
  display: none;
}
.clear-btn:hover { color: var(--fg); }

.history {
  margin-top: 12px;
  font-size: 12px;
  color: var(--status);
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}

.history-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 8px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--button-bg-secondary);
  will-change: transform;
}

.history-item {
  cursor: pointer;
  text-decoration: underline;
  color: var(--button-bg);
}
.history-item:hover { color: var(--fg); }

.history-remove {
  border: none;
  background: transparent;
  color: var(--status);
  cursor: pointer;
  font-size: 12px;
  line-height: 1;
  padding: 0;
}
.history-remove:hover { color: var(--fg); }

.card a {
  color: var(--button-bg);
}
.card a:hover {
  color: var(--fg);
}

.card-header { cursor: pointer; user-select: none; }
.card-header button:hover { opacity: 0.8; }
.card-content { display: block; }
.card-content.collapsed { display: none; }
.chevron {
  display: inline-block;
  transition: transform 0.2s;
  margin-right: 6px;
  font-size: 10px;
}
.card-header.collapsed-header .chevron { transform: rotate(-90deg); }

.footer {
  margin-top: 40px;
  text-align: center;
  font-size: 12px;
  color: var(--status);
  border-top: 1px solid var(--border);
  padding-top: 20px;
}

@media (max-width: 640px) {
  body { padding: 16px 12px; }
  .container { max-width: 100%; }
  .search-box { max-width: 100%; }
  .input-row { flex-direction: column; }
  .input-wrapper { width: 100%; }
  .input-row button:not(.search-box #clearBtn) { width: 100%; }
  .mx-table { display: block; overflow-x: auto; white-space: nowrap; }
  .top-bar button { width: 100%; height: 43px; }
}

@media print {
  body { padding: 0; background: #ffffff; color: #000000; }
  .top-bar, .history, .hide-on-screenshot, #clearBtn { display: none !important; }
  .search-box { max-width: 100%; margin: 0 0 12px 0; }
  .card { break-inside: avoid; }
  .code, .mx-table { background: #ffffff; color: #000000; border: 1px solid #d1d5db; }
  .mx-table th { background: #f3f4f6; color: #000000; }
}
</style>

<!-- html2canvas for screenshot capture -->
<script src="https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"></script>
<script>
(function() {
  try {
    var local = localStorage.getItem('acsTheme');
    var support = window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (local === 'dark' || (!local && support)) {
      document.documentElement.classList.add('dark');
    }
  } catch (e) {}
})();
</script>
</head>

<body>

<div class="container">

<div class="top-bar">
  <button id="themeToggleBtn" type="button" class="hide-on-screenshot" onclick="toggleTheme()">Dark mode &#x1F319;</button>
  <button id="copyLinkBtn" type="button" class="hide-on-screenshot" onclick="copyShareLink()">Copy link &#x1F517;</button>
  <button id="screenshotBtn" type="button" class="hide-on-screenshot" onclick="screenshotPage()">Copy page screenshot &#x1F4F8;</button>
  <button id="downloadBtn" type="button" class="hide-on-screenshot" onclick="downloadReport()" style="display:none;">Download JSON &#x1F4E5;</button>
</div>

<div class="search-box">
  <img src="data:image/png;base64,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" alt="ACS Logo" style="height: 64px; display: block; margin: 0 auto 12px auto;">
  <h1>Azure Communication Services<br/>Domain Verification Checker</h1>
  <div class="input-row">
    <div class="input-wrapper">
      <input id="domainInput" type="text" placeholder="example.com" oninput="toggleClearBtn()" />
      <button id="clearBtn" class="clear-btn" type="button" onclick="clearInput()">&#x2715;</button>
    </div>
    <button id="lookupBtn" class="primary hide-on-screenshot" type="button" onclick="lookup()">Lookup</button>
  </div>
  <div id="history" class="history"></div>
</div>
<div id="status"></div>
<div id="results" class="cards"></div>

<div class="footer">
  ACS Domain Verification Checker v1.0 &bull; Generated by PowerShell &bull; <a href="#" onclick="window.scrollTo(0,0); return false;" style="color:inherit;">Back to Top</a>
</div>

</div>

<script>
let lastResult = null;
const HISTORY_KEY = "acsDomainHistory";

let screenshotStatusToken = 0;

let activeLookup = { runId: 0, controllers: [] };

function cancelInflightLookup() {
  for (const c of (activeLookup.controllers || [])) {
    try { c.abort(); } catch {}
  }
  activeLookup.controllers = [];
}

function normalizeDomain(raw) {
  raw = (raw === null || raw === undefined) ? "" : String(raw);
  raw = raw.trim();

  // If user pasted an email, use the part after @
  const at = raw.lastIndexOf("@");
  if (at > -1 && at < raw.length - 1) {
    raw = raw.slice(at + 1);
  }

  // If user pasted a URL, extract hostname
  try {
    if (/^https?:\/\//i.test(raw)) {
      raw = new URL(raw).hostname;
    }
  } catch {
    // ignore
  }

  // Remove wildcard prefix and surrounding dots/spaces
  raw = raw.replace(/^\*\./, "");
  raw = raw.replace(/^\.+/, "").replace(/\.+$/, "");

  return raw.toLowerCase();
}

function isValidDomain(domain) {
  domain = (domain === null || domain === undefined) ? "" : String(domain);
  domain = domain.trim();
  if (!domain) return false;

  // Basic charset + structure checks (lenient, supports punycode)
  if (domain.length > 253) return false;
  if (!/^[a-z0-9.-]+$/.test(domain)) return false;
  if (domain.includes("..")) return false;
  if (domain.startsWith("-") || domain.endsWith("-")) return false;

  const labels = domain.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!label) return false;
    if (label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return true;
}

function toggleClearBtn() {
  const input = document.getElementById("domainInput");
  const btn = document.getElementById("clearBtn");
  if (btn) btn.style.display = input.value ? "block" : "none";
}

function clearInput() {
  const input = document.getElementById("domainInput");
  input.value = "";
  input.focus();
  toggleClearBtn();
}

function readHistoryItems() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const items = raw ? JSON.parse(raw) : [];
    return Array.isArray(items) ? items.map(String) : [];
  } catch {
    return [];
  }
}

function writeHistoryItems(items) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
}

function captureHistoryChipRects(container) {
  const rects = new Map();
  if (!container) return rects;
  const chips = container.querySelectorAll('.history-chip[data-domain]');
  for (const chip of chips) {
    const key = (chip.getAttribute('data-domain') || '').toLowerCase();
    if (!key) continue;
    rects.set(key, chip.getBoundingClientRect());
  }
  return rects;
}

function playHistoryFlip(container, beforeRects) {
  if (!container || !beforeRects || beforeRects.size === 0) return;

  const chips = container.querySelectorAll('.history-chip[data-domain]');
  for (const chip of chips) {
    const key = (chip.getAttribute('data-domain') || '').toLowerCase();
    if (!key) continue;

    const first = beforeRects.get(key);
    if (!first) continue;

    const last = chip.getBoundingClientRect();
    const dx = first.left - last.left;
    const dy = first.top - last.top;
    if (dx === 0 && dy === 0) continue;

    chip.style.transition = 'transform 0s';
    chip.style.transform = `translate(${dx}px, ${dy}px)`;
    chip.getBoundingClientRect();

    chip.style.transition = 'transform 180ms ease';
    chip.style.transform = '';

    const cleanup = () => {
      chip.style.transition = '';
      chip.style.transform = '';
      chip.removeEventListener('transitionend', cleanup);
    };
    chip.addEventListener('transitionend', cleanup);
    setTimeout(cleanup, 250);
  }
}

function promoteHistory(domain, animate) {
  const d = (domain === null || domain === undefined) ? "" : String(domain).trim();
  if (!d) return;

  const current = readHistoryItems();
  const lower = d.toLowerCase();
  let next = current.filter(i => String(i).toLowerCase() !== lower);
  next.unshift(d);
  if (next.length > 5) next = next.slice(0, 5);

  const changed =
    current.length !== next.length ||
    current.some((v, idx) => String(v).toLowerCase() !== String(next[idx]).toLowerCase());
  if (!changed) return;

  const container = document.getElementById('history');
  const before = animate ? captureHistoryChipRects(container) : null;

  writeHistoryItems(next);
  renderHistory(next);

  if (animate) {
    requestAnimationFrame(() => playHistoryFlip(container, before));
  }
}

function loadHistory() {
  try {
    renderHistory(readHistoryItems());
  } catch (e) { console.error(e); }
}

function saveHistory(domain) {
  try {
    promoteHistory(domain, false);
  } catch (e) { console.error(e); }
}

function renderHistory(items) {
  const container = document.getElementById("history");
  if (!items || items.length === 0) {
    container.innerHTML = "";
    return;
  }
  const chips = items.map(d => {
    const text = (d === null || d === undefined) ? "" : String(d);
    const safe = escapeHtml(text);
    const key = escapeHtml(text.toLowerCase());
    const arg = JSON.stringify(text);
    return `<span class="history-chip" data-domain="${key}">
      <span class="history-item" onclick='runHistory(${arg})'>${safe}</span>
      <button type="button" class="history-remove" title="Remove" aria-label="Remove" onclick='event.stopPropagation(); removeHistory(${arg})'>&#x2715;</button>
    </span>`;
  }).join(" ");
  container.innerHTML = "Recent: " + chips;
}

function removeHistory(domain) {
  const d = (domain === null || domain === undefined) ? "" : String(domain);
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return;
    let items = JSON.parse(raw);
    items = (items || []).filter(i => String(i).toLowerCase() !== d.toLowerCase());
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
    renderHistory(items);
  } catch (e) { console.error(e); }
}

function runHistory(domain) {
  promoteHistory(domain, true);
  document.getElementById("domainInput").value = domain;
  toggleClearBtn();
  lookup();
}

function downloadReport() {
  if (!lastResult) return;
  const json = JSON.stringify(lastResult, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "acs-check-" + lastResult.domain + ".json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function toggleCard(header) {
  header.classList.toggle("collapsed-header");
  const content = header.nextElementSibling;
  if (content) {
    content.classList.toggle("collapsed");
  }

  // If the MX card is being collapsed, also hide the additional details and reset the button label.
  const isNowCollapsed = header.classList.contains("collapsed-header") || (content && content.classList.contains("collapsed"));
  if (isNowCollapsed) {
    const mxDetails = document.getElementById("mxDetails");
    if (mxDetails && header.parentElement && header.parentElement.contains(mxDetails)) {
      mxDetails.style.display = "none";
      const btns = header.querySelectorAll("button");
      for (const b of btns) {
        const t = (b.textContent || "").trim();
        if (t.startsWith("Additional Details")) {
          b.textContent = "Additional Details +";
          break;
        }
      }
    }
  }
}

function setStatus(html) {
  document.getElementById("status").innerHTML = html;
}

function escapeHtml(text) {
  text = (text === null || text === undefined) ? "" : String(text);
  return text.replace(/[&<>\"]/g, function(ch) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;"
    }[ch];
  });
}

function buildTestSummaryHtml(r) {
  const loaded = (r && r._loaded) ? r._loaded : {};
  const errors = (r && r._errors) ? r._errors : {};

  const classForState = (state) => {
    switch (state) {
      case "pass": return "tag-pass";
      case "fail": return "tag-fail";
      case "error": return "tag-fail";
      case "pending": return "tag-info";
      case "optional": return "tag-info";
      case "unavailable": return "tag-info";
      default: return "tag-info";
    }
  };

  const checks = [];
  const add = (name, state, isOptional = false) => checks.push({ name, state, isOptional });

  // ACS Readiness (derived from base)
  if (!loaded.base && !errors.base) {
    add("ACS Readiness", "pending");
  } else if (errors.base) {
    add("ACS Readiness", "error");
  } else if (r.dnsFailed) {
    add("ACS Readiness", "fail");
  } else {
    add("ACS Readiness", r.acsReady ? "pass" : "fail");
  }

  // Domain (base lookup sanity)
  if (!loaded.base && !errors.base) {
    add("Domain", "pending");
  } else if (errors.base) {
    add("Domain", "error");
  } else {
    add("Domain", r.dnsFailed ? "fail" : "pass");
  }

  // SPF + ACS TXT + root TXT list depend on base
  if (!loaded.base && !errors.base) {
    add("SPF (root TXT)", "pending");
    add("ACS TXT", "pending");
    add("TXT Records", "pending");
  } else if (errors.base) {
    add("SPF (root TXT)", "error");
    add("ACS TXT", "error");
    add("TXT Records", "error");
  } else if (r.dnsFailed) {
    add("SPF (root TXT)", "unavailable", true);
    add("ACS TXT", "fail");
    add("TXT Records", "unavailable", true);
  } else {
    add("SPF (root TXT)", r.spfPresent ? "pass" : "fail", true);
    add("ACS TXT", r.acsPresent ? "pass" : "fail");
    const hasTxt = Array.isArray(r.txtRecords) && r.txtRecords.length > 0;
    add("TXT Records", hasTxt ? "pass" : "fail", true);
  }

  // MX
  if (!loaded.mx && !errors.mx) {
    add("MX", "pending");
  } else if (errors.mx) {
    add("MX", "error");
  } else {
    const hasMx = Array.isArray(r.mxRecords) && r.mxRecords.length > 0;
    add("MX", hasMx ? "pass" : "fail", true);
  }

  // DMARC
  if (!loaded.dmarc && !errors.dmarc) {
    add("DMARC", "pending");
  } else if (errors.dmarc) {
    add("DMARC", "error");
  } else {
    add("DMARC", r.dmarc ? "pass" : "fail", true);
  }

  // DKIM selectors
  if (!loaded.dkim && !errors.dkim) {
    add("DKIM1", "pending");
    add("DKIM2", "pending");
  } else if (errors.dkim) {
    add("DKIM1", "error");
    add("DKIM2", "error");
  } else {
    add("DKIM1", r.dkim1 ? "pass" : "fail", true);
    add("DKIM2", r.dkim2 ? "pass" : "fail", true);
  }

  // CNAME
  if (!loaded.cname && !errors.cname) {
    add("CNAME", "pending");
  } else if (errors.cname) {
    add("CNAME", "error");
  } else {
    add("CNAME", r.cname ? "pass" : "fail", true);
  }

  const pills = checks.map(c => {
    const name = escapeHtml(c.name);
    const status = escapeHtml(String(c.state).toUpperCase());
    const optionalBadge = c.isOptional ? `<span class="tag ${classForState('optional')} status-pill">OPTIONAL</span>` : "";
    return `<div class="status-row"><span class="status-name">${name}</span><span class="status-pills">${optionalBadge}<span class="tag ${classForState(c.state)} status-pill">${status}</span></span></div>`;
  });

  return `
    <div class="status-divider"></div>
    <div class="status-summary">
      <div class="status-header">
        <div class="title">Check Summary</div>
        <div class="hint">Only <strong>ACS TXT</strong> is required for ACS domain verification. Items marked <strong>OPTIONAL</strong> are best-practice checks.</div>
      </div>
      ${pills.join("")}
    </div>
  `;
}

function applyTheme(theme) {
  const root = document.documentElement;
  const btn  = document.getElementById("themeToggleBtn");
  if (theme === "dark") {
    root.classList.add("dark");
    if (btn) btn.innerHTML = "Light mode &#x2600;&#xFE0F;";
  } else {
    root.classList.remove("dark");
    if (btn) btn.innerHTML = "Dark mode &#x1F319;";
  }
  localStorage.setItem("acsTheme", theme);
}

function toggleTheme() {
  const isDark = document.documentElement.classList.contains("dark");
  applyTheme(isDark ? "light" : "dark");
}

function copyShareLink() {
  const btn = document.getElementById("copyLinkBtn");
  if (!navigator.clipboard) {
    setStatus("Clipboard API not available in this browser.");
    return;
  }

  const input = document.getElementById("domainInput");
  const domain = normalizeDomain(input ? input.value : "");
  const url = new URL(window.location.href);
  if (domain && isValidDomain(domain)) {
    url.searchParams.set("domain", domain);
  } else {
    url.searchParams.delete("domain");
  }

  navigator.clipboard.writeText(url.toString())
    .then(() => {
      if (btn) {
        const original = btn.innerHTML;
        btn.innerHTML = "Copied! &#x2714;";
        setTimeout(() => { btn.innerHTML = original; }, 2000);
      } else {
        setStatus("Link copied to clipboard.");
      }
    })
    .catch(() => setStatus("Failed to copy link to clipboard."));
}

function copyField(btn, key) {
  // Support legacy call (key only)
  let button = btn;
  let fieldKey = key;
  if (typeof btn === 'string') {
     fieldKey = btn;
     button = null;
  }

  const el = document.getElementById("field-" + fieldKey);
  if (!el) {
    setStatus("Nothing to copy for " + escapeHtml(fieldKey) + ".");
    return;
  }

  let text = el.innerText || el.textContent || "";

  // If MX additional details are open, include them in the copied text.
  if (fieldKey === "mx") {
    const mxDetails = document.getElementById("mxDetails");
    if (mxDetails) {
      const display = (window.getComputedStyle ? getComputedStyle(mxDetails).display : mxDetails.style.display);
      if (display && display !== "none") {
        const detailsText = (mxDetails.innerText || mxDetails.textContent || "").trim();
        if (detailsText) {
          text = (String(text || "").trimEnd() + "\n\n--- Additional Details ---\n" + detailsText).trim();
        }
      }
    }
  }
  if (!navigator.clipboard) {
    setStatus("Clipboard API not available in this browser.");
    return;
  }
  navigator.clipboard.writeText(text)
    .then(() => {
      if (button && button.tagName === "BUTTON") {
        const originalText = button.innerHTML;
        button.innerHTML = "Copied! &#x2714;";
        setTimeout(() => { button.innerHTML = originalText; }, 2000);
      } else {
        setStatus("Copied " + escapeHtml(fieldKey) + " to clipboard.");
      }
    })
    .catch(() => setStatus("Failed to copy " + escapeHtml(fieldKey) + " to clipboard."));
}

function screenshotPage() {
  if (!window.html2canvas || !navigator.clipboard || typeof ClipboardItem === "undefined") {
    setStatus("Screenshot clipboard support is not available in this browser.");
    return;
  }

  const statusEl = document.getElementById("status");
  const previousStatusHtml = statusEl ? statusEl.innerHTML : "";
  const myToken = ++screenshotStatusToken;

  // Capture only the container div instead of the entire body
  const container = document.querySelector(".container");
  if (!container) {
    setStatus("Container not found for screenshot.");
    return;
  }

  html2canvas(container, {
    backgroundColor: getComputedStyle(document.body).backgroundColor,
    onclone: (clonedDoc) => {
      // Hide marked buttons in the cloned DOM only (prevents visible flashing)
      clonedDoc.body.classList.add("screenshot-mode");
    }
  }).then(canvas => {
    canvas.toBlob(blob => {
      if (!blob) {
        setStatus("Failed to capture screenshot.");
        return;
      }
      const item = new ClipboardItem({ "image/png": blob });
      navigator.clipboard.write([item])
        .then(() => {
          setStatus("Screenshot copied to clipboard.");
          setTimeout(() => {
            if (myToken !== screenshotStatusToken) return;
            const el = document.getElementById("status");
            if (el && el.innerHTML === "Screenshot copied to clipboard.") {
              el.innerHTML = previousStatusHtml;
            }
          }, 2500);
        })
        .catch(() => setStatus("Failed to copy screenshot to clipboard."));
    });
  }).catch(() => {
    setStatus("Screenshot capture failed.");
  });
}

function lookup() {
  const input = document.getElementById("domainInput");
  const btn   = document.getElementById("lookupBtn");
  const screenshotBtn = document.getElementById("screenshotBtn");
  const dlBtn = document.getElementById("downloadBtn");
  const domain = normalizeDomain(input.value);
  input.value = domain;
  toggleClearBtn();

  if (!domain) {
    setStatus("Please enter a domain.");
    return;
  }

  if (!isValidDomain(domain)) {
    setStatus("Please enter a valid domain name (example: example.com).");
    return;
  }

  // Cancel any previous lookup's requests and start a new run
  const runId = ++activeLookup.runId;
  cancelInflightLookup();

  // Clear previous results and hide download button
  document.getElementById("results").innerHTML = "";
  setStatus("");
  if (dlBtn) dlBtn.style.display = "none";

  const url = new URL(window.location.href);
  url.searchParams.set("domain", domain);
  window.history.replaceState({}, "", url);

  // Keep Lookup clickable so another click can cancel/restart
  btn.disabled = false;
  if (screenshotBtn) screenshotBtn.disabled = true;
  btn.innerHTML = 'Checking <span class="spinner"></span>';
  // setStatus("Checking " + escapeHtml(domain) + " &#x23F3;");

  function parseHttpError(r, bodyText) {
    const details = (bodyText || "").trim();
    return `HTTP ${r.status}${r.statusText ? " " + r.statusText : ""}${details ? ": " + details : ""}`;
  }

  async function fetchJson(path) {
    const controller = new AbortController();
    activeLookup.controllers.push(controller);
    try {
      const r = await fetch(path + "?domain=" + encodeURIComponent(domain), { signal: controller.signal });
      if (!r.ok) {
        let body = "";
        try { body = await r.text(); } catch {}
        throw new Error(parseHttpError(r, body));
      }
      return r.json();
    } finally {
      // Remove controller to avoid leaks
      activeLookup.controllers = (activeLookup.controllers || []).filter(c => c !== controller);
    }
  }

  function ensureResultObject() {
    if (!lastResult || typeof lastResult !== "object") {
      lastResult = {};
    }
    if (!lastResult._loaded) {
      lastResult._loaded = { base: false, mx: false, dmarc: false, dkim: false, cname: false };
    }
    if (!lastResult._errors) {
      lastResult._errors = {};
    }
  }

  function buildGuidance(r) {
    const guidance = [];
    const loaded = r._loaded || {};

    if (loaded.base && r.dnsFailed) {
      guidance.push("DNS TXT lookup failed or timed out. Other DNS records may still resolve.");
      return guidance;
    }

    if (loaded.base) {
      if (!r.spfPresent) guidance.push("SPF is missing. Add v=spf1 include:spf.protection.outlook.com -all (or provider equivalent). ");
      if (!r.acsPresent) guidance.push("ACS ms-domain-verification TXT is missing. Add the value from the Azure portal.");
    }

    if (loaded.mx) {
      const mxList = (r.mxRecords || []);
      if (!mxList || mxList.length === 0) {
        guidance.push("No MX records detected. Mail flow will not function until MX records are configured.");
      }
      if (r.mxProvider && r.mxProvider !== "Unknown") {
        guidance.push("Detected MX provider: " + r.mxProvider);
      }
    }

    if (loaded.dmarc && !r.dmarc) {
      guidance.push("DMARC is missing. Add a _dmarc." + (r.domain || "") + " TXT record to reduce spoofing risk.");
    }

    if (loaded.dkim) {
      if (!r.dkim1) guidance.push("DKIM selector1 (selector1-azurecomm-prod-net) is missing.");
      if (!r.dkim2) guidance.push("DKIM selector2 (selector2-azurecomm-prod-net) is missing.");
    }

    if (loaded.cname && !r.cname) {
      guidance.push("Root CNAME is not configured. Validate this is expected for your scenario.");
    }

    if (loaded.base && loaded.mx && r.mxProvider === "Microsoft 365 / Exchange Online" && r.spfPresent && r.spfValue && !/spf\.protection\.outlook\.com/i.test(r.spfValue)) {
      guidance.push("Your MX indicates Microsoft 365, but SPF does not include spf.protection.outlook.com. Verify your SPF includes the correct provider include.");
    }
    if (loaded.base && loaded.mx && r.mxProvider === "Google Workspace / Gmail" && r.spfPresent && r.spfValue && !/_spf\.google\.com/i.test(r.spfValue)) {
      guidance.push("Your MX indicates Google Workspace, but SPF does not include _spf.google.com. Verify your SPF includes the correct provider include.");
    }
    if (loaded.base && loaded.mx && r.mxProvider === "Zoho Mail" && r.spfPresent && r.spfValue && !/include:zoho\.com/i.test(r.spfValue)) {
      guidance.push("Your MX indicates Zoho, but SPF does not include include:zoho.com. Verify your SPF includes the correct provider include.");
    }

    if (loaded.base && r.acsReady) {
      guidance.push("This domain appears ready for Azure Communication Services domain verification.");
    }

    return guidance;
  }

  function recomputeDerived(r) {
    const loaded = r._loaded || {};
    if (loaded.base) {
      r.acsReady = (!r.dnsFailed) && !!r.spfPresent && !!r.acsPresent;
    } else {
      r.acsReady = false;
    }
    r.guidance = buildGuidance(r);
  }

  ensureResultObject();
  lastResult = {
    domain,
    _loaded: { base: false, mx: false, dmarc: false, dkim: false, cname: false },
    _errors: {},
    guidance: [],
    acsReady: false
  };
  recomputeDerived(lastResult);
  render(lastResult);

  const requests = [
    { key: "base",  path: "/api/base"  },
    { key: "mx",    path: "/api/mx"    },
    { key: "dmarc", path: "/api/dmarc" },
    { key: "dkim",  path: "/api/dkim"  },
    { key: "cname", path: "/api/cname" }
  ];

  let savedHistory = false;
  let downloadShown = false;

  const tasks = requests.map(async ({ key, path }) => {
    try {
      const data = await fetchJson(path);

      // Ignore late results from older runs
      if (runId !== activeLookup.runId) return;

      ensureResultObject();
      Object.assign(lastResult, data);
      lastResult._loaded[key] = true;
      delete lastResult._errors[key];

      if (!downloadShown) {
        const dlBtn2 = document.getElementById("downloadBtn");
        if (dlBtn2) dlBtn2.style.display = "inline-block";
        downloadShown = true;
      }

      if (!savedHistory && key === "base") {
        saveHistory(domain);
        savedHistory = true;
      }

      recomputeDerived(lastResult);
      render(lastResult);
    } catch (err) {
      if (err && err.name === "AbortError") return;
      if (runId !== activeLookup.runId) return;

      const reason = (err && err.message) ? err.message : String(err);
      ensureResultObject();
      lastResult._loaded[key] = true;
      lastResult._errors[key] = reason;
      recomputeDerived(lastResult);
      render(lastResult);
    }
  });

  Promise.allSettled(tasks)
    .catch(() => {})
    .finally(() => {
      if (runId !== activeLookup.runId) return;
      btn.disabled = false;
      if (screenshotBtn) screenshotBtn.disabled = false;
      btn.innerHTML = "Lookup";
    });
}

function card(title, value, label, cls, key, showCopy = true) {
  return `
  <div class="card">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      ${label ? `<span class="tag ${cls}">${label}</span>` : ""}
      <strong>${title}</strong>
      ${showCopy ? `<button type="button" class="copy-btn hide-on-screenshot" style="margin-left: auto;" onclick="event.stopPropagation(); copyField(this, '${key}')">Copy</button>` : ""}
    </div>
    <div id="field-${key}" class="code card-content">${escapeHtml(value || "No Records Available.")}</div>
  </div>`;
}

// Toggle for MX additional details
function toggleMxDetails(element) {
  const el = document.getElementById("mxDetails");
  if (!el) return;

  // If the MX card is collapsed, expand it first and force details open.
  const header = element && element.closest ? element.closest(".card-header") : null;
  const content = header ? header.nextElementSibling : null;
  const isCollapsed = !!(header && header.classList && header.classList.contains("collapsed-header")) ||
                      !!(content && content.classList && content.classList.contains("collapsed"));
  if (isCollapsed && header) {
    toggleCard(header);
    el.style.display = "block";
    element.textContent = 'Additional Details -';
    return;
  }

  const current = el.style.display;
  const isOpen = (!current || current === "none");
  if (isOpen) {
    element.textContent = 'Additional Details -';
  } else {
    element.textContent = 'Additional Details +';
  }
  el.style.display = isOpen ? "block" : "none";
}

function render(r) {
  const loaded = (r && r._loaded) ? r._loaded : {};
  const errors = (r && r._errors) ? r._errors : {};
  const allLoaded = !!(loaded.base && loaded.mx && loaded.dmarc && loaded.dkim && loaded.cname);
  const anyError = !!(errors && Object.keys(errors).length > 0);

  let statusText = "";

  if (!allLoaded) {
    statusText = "Checking " + escapeHtml(r.domain || "") + " &#x23F3;";
  } else if (anyError) {
    statusText = "Done. Some checks failed &#x274C;";
  } else if (loaded.base && r.dnsFailed) {
    // CHANGED: use &mdash; instead of literal em dash
    statusText = "TXT lookup failed &#x274C; &mdash; other DNS records may still resolve.";
  } else if (r.acsReady) {
    statusText = "Done. Ready to have domain verified with ACS &#x2705;";
  } else {
    statusText = "Done. Not ready to have domain verified with ACS &#x274C;";
  }

  setStatus(statusText + buildTestSummaryHtml(r));

  const cards = [];

  const basePending = !loaded.base && !errors.base;
  const baseError = !!errors.base;

  cards.push(card(
    "ACS Readiness",
    basePending
      ? "Waiting for base TXT lookup..."
      : (baseError
        ? (errors.base || "Base lookup failed.")
        : (r.acsReady
          ? "Domain appears ready for Azure Communication Services verification."
          : "Domain is missing one or more ACS records."
        )
      ),
    basePending ? "LOADING" : (baseError ? "ERROR" : (r.acsReady ? "ACS READY" : "NOT READY")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (r.acsReady ? "tag-pass" : "tag-fail")),
    "acsReadiness",
    false
  ));

  cards.push(card(
    "Domain",
    r.domain,
    basePending ? "PENDING" : (baseError ? "ERROR" : (r.dnsFailed ? "DNS ERROR" : "LOOKED UP")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : "tag-info"),
    "domain",
    false
  ));

  cards.push(card(
    "SPF (root TXT)",
    loaded.base ? r.spfValue : (baseError ? (errors.base || "Error") : "Loading..."),
    basePending ? "LOADING" : (baseError ? "ERROR" : (r.spfPresent ? "PASS" : "OPTIONAL")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (r.spfPresent ? "tag-pass" : "tag-info")),
    "spf"
  ));

  cards.push(card(
    "ACS Domain Verification TXT",
    loaded.base ? r.acsValue : (baseError ? (errors.base || "Error") : "Loading..."),
    basePending ? "LOADING" : (baseError ? "ERROR" : (r.acsPresent ? "PASS" : "MISSING")),
    basePending ? "tag-info" : (baseError ? "tag-fail" : (r.acsPresent ? "tag-pass" : "tag-fail")),
    "acsTxt"
  ));

  cards.push(card(
    "TXT Records (root)",
    loaded.base ? (r.txtRecords || []).join("\n") : (baseError ? (errors.base || "Error") : "Loading..."),
    basePending ? "LOADING" : (baseError ? "ERROR" : "INFO"),
    basePending ? "tag-info" : (baseError ? "tag-fail" : "tag-info"),
    "txtRecords",
    false
  ));

  if (!loaded.mx && !errors.mx) {
    cards.push(card(
      "MX Records",
      "Loading...",
      "LOADING",
      "tag-info",
      "mx",
      false
    ));
  } else if (errors.mx) {
    cards.push(card(
      "MX Records",
      errors.mx,
      "ERROR",
      "tag-fail",
      "mx",
      false
    ));
  } else {
    // MX card with "Additional Details" toggle on the right
    const ipv4Records = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "IPv4");
    const ipv6Records = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "IPv6");
    const noIpRecords = (r.mxRecordsDetailed || []).filter(rec => rec.Type === "N/A");
    
    let mxDetailsContent = "";
    
    if (ipv4Records.length > 0) {
      const ipv4Rows = ipv4Records.map(record => 
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");
      
      mxDetailsContent += `<div style="margin-bottom: 12px;">
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">IPv4 Addresses</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Priority</th>
              <th>IP Address</th>
            </tr>
          </thead>
          <tbody>${ipv4Rows}</tbody>
        </table>
      </div>`;
    }
    
    if (ipv6Records.length > 0) {
      const ipv6Rows = ipv6Records.map(record => 
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");
      
      mxDetailsContent += `<div style="margin-bottom: 12px;">
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">IPv6 Addresses</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Priority</th>
              <th>IP Address</th>
            </tr>
          </thead>
          <tbody>${ipv6Rows}</tbody>
        </table>
      </div>`;
    }
    
    if (noIpRecords.length > 0) {
      const noIpRows = noIpRecords.map(record => 
        `<tr>
          <td>${escapeHtml(record.Hostname)}</td>
          <td>${escapeHtml(String(record.Priority))}</td>
          <td>${escapeHtml(record.IPAddress)}</td>
        </tr>`
      ).join("");
      
      mxDetailsContent += `<div>
        <div style="font-weight: 600; margin-bottom: 6px; font-size: 13px;">No IP Addresses Found</div>
        <table class="mx-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Priority</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>${noIpRows}</tbody>
        </table>
      </div>`;
    }
    
    if (!mxDetailsContent) {
      mxDetailsContent = '<div class="code">No additional MX details available.</div>';
    }

    cards.push(`
  <div class="card">
    <div class="card-header" onclick="toggleCard(this)">
      <span class="chevron">&#x25BC;</span>
      <span class="tag tag-info">INFO</span>
      <strong>MX Records</strong>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              style="margin-left: auto;"
              onclick="event.stopPropagation(); toggleMxDetails(this)">
        Additional Details +
      </button>
      <button type="button"
              class="copy-btn hide-on-screenshot"
              onclick="event.stopPropagation(); copyField(this, 'mx')">
        Copy
      </button>
    </div>
    <div class="card-content">
      ${r.mxProvider ? `<div class="code" style="margin-bottom:6px;">Detected provider: ${escapeHtml(r.mxProvider)}${r.mxProviderHint ? " — " + escapeHtml(r.mxProviderHint) : ""}</div>` : ""}
      <div id="field-mx" class="code">${escapeHtml((r.mxRecords || []).join("\n") || "No Records Available.")}</div>
      <div id="mxDetails" style="margin-top:6px; display:none;">${mxDetailsContent}</div>
    </div>
  </div>
    `);
  }

  cards.push(card(
    "DMARC",
    loaded.dmarc ? r.dmarc : (errors.dmarc ? errors.dmarc : "Loading..."),
    (!loaded.dmarc && !errors.dmarc) ? "LOADING" : (errors.dmarc ? "ERROR" : (r.dmarc ? "PASS" : "OPTIONAL")),
    (!loaded.dmarc && !errors.dmarc) ? "tag-info" : (errors.dmarc ? "tag-fail" : (r.dmarc ? "tag-pass" : "tag-info")),
    "dmarc"
  ));

  // include full selector host with domain in title
  cards.push(card(
    `DKIM1 (selector1-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim1 : (errors.dkim ? errors.dkim : "Loading..."),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim1 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim1 ? "tag-pass" : "tag-info")),
    "dkim1"
  ));

  cards.push(card(
    `DKIM2 (selector2-azurecomm-prod-net._domainkey.${r.domain || ""})`,
    loaded.dkim ? r.dkim2 : (errors.dkim ? errors.dkim : "Loading..."),
    (!loaded.dkim && !errors.dkim) ? "LOADING" : (errors.dkim ? "ERROR" : (r.dkim2 ? "PASS" : "OPTIONAL")),
    (!loaded.dkim && !errors.dkim) ? "tag-info" : (errors.dkim ? "tag-fail" : (r.dkim2 ? "tag-pass" : "tag-info")),
    "dkim2"
  ));

  cards.push(card(
    "CNAME",
    loaded.cname ? r.cname : (errors.cname ? errors.cname : "Loading..."),
    (!loaded.cname && !errors.cname) ? "LOADING" : (errors.cname ? "ERROR" : (r.cname ? "PASS" : "OPTIONAL")),
    (!loaded.cname && !errors.cname) ? "tag-info" : (errors.cname ? "tag-fail" : (r.cname ? "tag-pass" : "tag-info")),
    "cname"
  ));

  const guidanceItems = (r.guidance || []).map(g => "<li>" + escapeHtml(g) + "</li>").join("");
  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">READINESS TIPS</span>
        <strong>Guidance &#x1F4A1;</strong>
      </div>
      <div id="field-guidance" class="card-content">
        <ul class="guidance">
          ${guidanceItems || "<li>No additional guidance.</li>"}
        </ul>
      </div>
    </div>
  `);

  cards.push(`
    <div class="card">
      <div class="card-header" onclick="toggleCard(this)">
        <span class="chevron">&#x25BC;</span>
        <span class="tag tag-info">DOCS</span>
        <strong>Helpful Links</strong>
      </div>
      <div class="card-content">
        <ul class="guidance">
          <li><a href="https://learn.microsoft.com/search/?terms=Azure%20Communication%20Services%20email%20domain%20verification" target="_blank" rel="noopener">ACS email domain verification</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=SPF%20record" target="_blank" rel="noopener">SPF record basics</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=DMARC%20record" target="_blank" rel="noopener">DMARC record basics</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=DKIM%20record" target="_blank" rel="noopener">DKIM record basics</a></li>
          <li><a href="https://learn.microsoft.com/search/?terms=MX%20record" target="_blank" rel="noopener">MX record basics</a></li>
        </ul>
      </div>
    </div>
  `);

  document.getElementById("results").innerHTML = cards.join("");
}

document.getElementById("domainInput").addEventListener("keyup", function (e) {
  if (e.key === "Enter") {
    lookup();
  }
});

// Theme + query-domain initialization
window.addEventListener("load", function () {
  // 1. Check for saved theme
  // 2. If none, check system preference (Dark vs Light)
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const defaultTheme = systemPrefersDark ? "dark" : "light";
  
  const savedTheme = localStorage.getItem("acsTheme") || defaultTheme;
  
  applyTheme(savedTheme);
  loadHistory();

  const params = new URLSearchParams(window.location.search);
  const d = params.get("domain");
  if (d) {
    document.getElementById("domainInput").value = d;
    toggleClearBtn();
    lookup();
  }
});
</script>

</body>
</html>
'@

# ------------------- MAIN LOOP -------------------
# Request handling uses a RunspacePool to process multiple HTTP requests concurrently.
# This keeps the UI responsive while DNS lookups are in flight.

$maxConcurrentRequests = 64

# Per-domain throttling: only one lookup per domain at a time.
# This prevents a single browser from hammering DNS (e.g., repeated refreshes) for the same domain.

$domainLocks = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Threading.SemaphoreSlim]]::new([System.StringComparer]::OrdinalIgnoreCase)

$functionNames = @(
  'Write-Json','Write-Html',
  'Resolve-DohName','ResolveSafely','Get-DnsIpString','ConvertTo-NormalizedDomain','Test-DomainName','Write-RequestLog',
  'Get-DnsBaseStatus','Get-DnsMxStatus','Get-DnsDmarcStatus','Get-DnsDkimStatus','Get-DnsCnameStatus',
  'Get-AcsDnsStatus'
)

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
foreach ($name in $functionNames) {
  # Copy function *definitions* into the runspace pool so handler runspaces can call them.
  $def = (Get-Command $name -CommandType Function -ErrorAction Stop).Definition
  $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $def))
}

$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxConcurrentRequests, $iss, $Host)
$pool.Open()

$inflight = New-Object System.Collections.Generic.List[object]

function Invoke-InflightCleanup {
  # Reap completed async PowerShell invocations to avoid unbounded memory growth.
  for ($i = $inflight.Count - 1; $i -ge 0; $i--) {
    $item = $inflight[$i]
    if ($item.Async.IsCompleted) {
      try { $item.Ps.EndInvoke($item.Async) } catch { $null = $_ }
      $item.Ps.Dispose()
      $inflight.RemoveAt($i)
    }
  }
}

$handlerScript = @'
param($ctx, $htmlPage, $domainLocks)

$path = $ctx.Request.Url.AbsolutePath

# This script block runs inside the RunspacePool for each incoming request.
# Inputs:
# - $ctx         : the request/response context (HttpListenerContext or TcpListener shim)
# - $htmlPage    : the embedded SPA HTML (string)
# - $domainLocks : shared dictionary of per-domain semaphores

function Get-DomainSemaphore([string]$domain) {
  # Get/create a per-domain semaphore so concurrent requests for the same domain serialize.
  $sem = $null
  if (-not $domainLocks.TryGetValue($domain, [ref]$sem)) {
    $newSem = [System.Threading.SemaphoreSlim]::new(1, 1)
    if ($domainLocks.TryAdd($domain, $newSem)) {
      $sem = $newSem
    } else {
      $null = $domainLocks.TryGetValue($domain, [ref]$sem)
    }
  }
  return $sem
}

try {
  # 1) Serve the UI
  if ($path -eq "/" -or $path -eq "/index.html") {
    Write-Html -Context $ctx -Html $htmlPage
    return
  }

  # 2) Serve individual API endpoints (/api/*)
  if ($path -in @("/api/base","/api/mx","/api/dmarc","/api/dkim","/api/cname")) {
    $domainRaw = $ctx.Request.QueryString["domain"]
    $domain    = ConvertTo-NormalizedDomain $domainRaw

    Write-RequestLog -Context $ctx -Action "API $path" -Domain $domain

    if ([string]::IsNullOrWhiteSpace($domain)) {
      Write-Json -Context $ctx -Object @{ error = "Missing domain parameter." } -StatusCode 400
      return
    }
    if (-not (Test-DomainName -Domain $domain)) {
      Write-Json -Context $ctx -Object @{ error = "Invalid domain parameter." } -StatusCode 400
      return
    }

    # Serialize work for this domain, do the lookup, then release.
    $sem = Get-DomainSemaphore -domain $domain
    $null = $sem.Wait()
    try {
      switch ($path) {
        "/api/base"  { Write-Json -Context $ctx -Object (Get-DnsBaseStatus  -Domain $domain) }
        "/api/mx"    { Write-Json -Context $ctx -Object (Get-DnsMxStatus    -Domain $domain) }
        "/api/dmarc" { Write-Json -Context $ctx -Object (Get-DnsDmarcStatus -Domain $domain) }
        "/api/dkim"  { Write-Json -Context $ctx -Object (Get-DnsDkimStatus  -Domain $domain) }
        "/api/cname" { Write-Json -Context $ctx -Object (Get-DnsCnameStatus -Domain $domain) }
        default       { Write-Json -Context $ctx -Object @{ error = "Unknown endpoint." } -StatusCode 404 }
      }
    }
    finally {
      try { $null = $sem.Release() } catch {}
    }
    return
  }

  # 3) Serve the aggregated endpoint used by the UI (/dns)
  if ($path -eq "/dns") {
    $domainRaw = $ctx.Request.QueryString["domain"]
    $domain    = ConvertTo-NormalizedDomain $domainRaw

    Write-RequestLog -Context $ctx -Action "DNS Lookup" -Domain $domain

    if ([string]::IsNullOrWhiteSpace($domain)) {
      Write-Json -Context $ctx -Object @{ error = "Missing domain parameter."; acsReady = $false } -StatusCode 400
      return
    }
    if (-not (Test-DomainName -Domain $domain)) {
      Write-Json -Context $ctx -Object @{ error = "Invalid domain parameter."; acsReady = $false } -StatusCode 400
      return
    }

    # Serialize work for this domain, do the lookup, then release.
    $sem = Get-DomainSemaphore -domain $domain
    $null = $sem.Wait()
    try {
      $result = Get-AcsDnsStatus -Domain $domain
      Write-Json -Context $ctx -Object $result
    }
    finally {
      try { $null = $sem.Release() } catch {}
    }
    return
  }

  $ctx.Response.StatusCode = 404
  $ctx.Response.StatusDescription = "Not Found"
  $ctx.Response.Close()
}
catch {
  # Last-resort error handler: attempt to return a JSON error payload.
  try { Write-Json -Context $ctx -Object @{ error = $_.Exception.Message } -StatusCode 500 } catch {}
  try { $ctx.Response.Close() } catch {}
}
'@

try {
  function ConvertFrom-QueryString {
    param([string]$Query)
    # Minimal query-string parser used by the TcpListener fallback.
    $nvc = [System.Collections.Specialized.NameValueCollection]::new()
    if ([string]::IsNullOrWhiteSpace($Query)) { return $nvc }
    $q = $Query.TrimStart('?')
    if ([string]::IsNullOrWhiteSpace($q)) { return $nvc }
    foreach ($pair in ($q -split '&')) {
      if ([string]::IsNullOrWhiteSpace($pair)) { continue }
      $kv = $pair -split '=', 2
      $k = ($kv[0] -replace '\+',' ')
      $k = [uri]::UnescapeDataString($k)
      $v = ''
      if ($kv.Count -gt 1) {
        $v = ($kv[1] -replace '\+',' ')
        $v = [uri]::UnescapeDataString($v)
      }
      $nvc.Add($k, $v)
    }
    return $nvc
  }

  function New-TcpContext {
    param(
      [Parameter(Mandatory = $true)]
      [System.Net.Sockets.TcpClient]$Client,
      [Parameter(Mandatory = $true)]
      [string]$RawTarget,
      [Parameter(Mandatory = $true)]
      [hashtable]$Headers
    )

    $remote = $Client.Client.RemoteEndPoint
    $ua = if ($Headers.ContainsKey('user-agent')) { [string]$Headers['user-agent'] } else { $null }

    $pathOnly = $RawTarget
    $query = ''
    $qm = $RawTarget.IndexOf('?')
    if ($qm -ge 0) {
      $pathOnly = $RawTarget.Substring(0, $qm)
      $query = $RawTarget.Substring($qm)
    }

    $url = [uri]::new("http://localhost:$Port$pathOnly$query")
    $qs = ConvertFrom-QueryString -Query $query

    $networkStream = $Client.GetStream()

    # TcpListener fallback response object.
    # It exposes a subset of `HttpListenerResponse`-like properties and a `SendBody()` method.
    $resp = [pscustomobject]@{
      StatusCode = 200
      StatusDescription = 'OK'
      ContentType = 'text/plain; charset=utf-8'
      ContentLength64 = [int64]0
      _client = $Client
      _stream = $networkStream
      _sent = $false
    }

    $resp | Add-Member -MemberType ScriptMethod -Name SendBody -Value {
      param([byte[]]$Bytes)
      if ($this._sent) {
        try { $this._client.Close() } catch { }
        return
      }

      $statusText = if ([string]::IsNullOrWhiteSpace($this.StatusDescription)) { 'OK' } else { $this.StatusDescription }
      $headers = "HTTP/1.1 {0} {1}\r\nContent-Type: {2}\r\nContent-Length: {3}\r\nConnection: close\r\n\r\n" -f $this.StatusCode, $statusText, $this.ContentType, $Bytes.Length
      $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)

      try {
        $this._stream.Write($headerBytes, 0, $headerBytes.Length)
        if ($Bytes.Length -gt 0) {
          $this._stream.Write($Bytes, 0, $Bytes.Length)
        }
        $this._stream.Flush()
      } finally {
        $this._sent = $true
        try { $this._stream.Dispose() } catch { }
        try { $this._client.Close() } catch { }
      }
    } | Out-Null

    $resp | Add-Member -MemberType ScriptMethod -Name Close -Value {
      if ($this._sent) {
        try { $this._client.Close() } catch { }
        return
      }
      $this.SendBody([byte[]]@())
    } | Out-Null

    $req = [pscustomobject]@{
      Url = $url
      QueryString = $qs
      UserAgent = $ua
      RemoteEndPoint = $remote
    }

    return [pscustomobject]@{ Request = $req; Response = $resp }
  }

  function Read-TcpHttpRequest {
    param(
      [Parameter(Mandatory = $true)]
      [System.Net.Sockets.TcpClient]$Client
    )

    # Extremely small HTTP/1.1 request reader (GET only).
    # We only need the request line + headers to route GET requests and read query strings.
    $stream = $Client.GetStream()
    $reader = [System.IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 8192, $true)
    $line1 = $reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line1)) { return $null }

    $parts = $line1 -split '\s+'
    if ($parts.Count -lt 2) { return $null }

    $method = $parts[0].Trim().ToUpperInvariant()
    $target = $parts[1].Trim()

    $headers = @{}
    while ($true) {
      $line = $reader.ReadLine()
      if ($null -eq $line) { break }
      if ($line -eq '') { break }
      $idx = $line.IndexOf(':')
      if ($idx -le 0) { continue }
      $hName = $line.Substring(0, $idx).Trim().ToLowerInvariant()
      $hValue = $line.Substring($idx + 1).Trim()
      $headers[$hName] = $hValue
    }

    return [pscustomobject]@{ Method = $method; Target = $target; Headers = $headers }
  }

  if ($serverMode -eq 'HttpListener') {
    # Primary server mode: HttpListener (best supported on Windows).
    while ($listener.IsListening) {
      try {
        $contextTask = $listener.GetContextAsync()
        while (-not $contextTask.AsyncWaitHandle.WaitOne(200)) {
          # allow Ctrl+C / stop processing
        }

        if (-not $listener.IsListening) { break }

        $ctx = $contextTask.GetAwaiter().GetResult()

        # Run the handler in the RunspacePool so multiple requests can be processed concurrently.
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks)

        $async = $ps.BeginInvoke()
        $inflight.Add([pscustomobject]@{ Ps = $ps; Async = $async })

        Invoke-InflightCleanup
      }
      catch [System.Net.HttpListenerException] {
        break
      }
    }
  }
  else {
    # Fallback server mode: TcpListener (for platforms where HttpListener is unavailable).
    # Only GET is supported here; it's enough for the SPA + JSON endpoints.
    while ($true) {
      $acceptTask = $tcpListener.AcceptTcpClientAsync()
      while (-not $acceptTask.AsyncWaitHandle.WaitOne(200)) {
        # allow Ctrl+C / stop processing
      }

      $client = $acceptTask.GetAwaiter().GetResult()
      if ($null -eq $client) { continue }

      $req = $null
      try {
        $req = Read-TcpHttpRequest -Client $client
        if ($null -eq $req) {
          try { $client.Close() } catch { }
          continue
        }

        if ($req.Method -ne 'GET') {
          $ctx = New-TcpContext -Client $client -RawTarget ($req.Target) -Headers $req.Headers
          $ctx.Response.StatusCode = 405
          $ctx.Response.StatusDescription = 'Method Not Allowed'
          $ctx.Response.ContentType = 'text/plain; charset=utf-8'
          $ctx.Response.SendBody([Text.Encoding]::UTF8.GetBytes('Method Not Allowed'))
          continue
        }

        $ctx = New-TcpContext -Client $client -RawTarget ($req.Target) -Headers $req.Headers

        # Run the same handler script used by HttpListener.
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($handlerScript).AddArgument($ctx).AddArgument($htmlPage).AddArgument($domainLocks)

        $async = $ps.BeginInvoke()
        $inflight.Add([pscustomobject]@{ Ps = $ps; Async = $async })

        Invoke-InflightCleanup
      }
      catch {
        try { $client.Close() } catch { }
      }
    }
  }
}
catch {
  Write-Error -ErrorRecord $_
}
finally {
  # Graceful shutdown: stop listeners and dispose runspaces.
  try { if ($listener -and $listener.IsListening) { $listener.Stop() } } catch { $null = $_ }
  try { if ($tcpListener) { $tcpListener.Stop() } } catch { $null = $_ }
  Invoke-InflightCleanup
  foreach ($item in @($inflight)) { try { $item.Ps.Dispose() } catch { $null = $_ } }
  try { $pool.Close(); $pool.Dispose() } catch { $null = $_ }
  Write-Information -InformationAction Continue -MessageData "Server stopped."
}