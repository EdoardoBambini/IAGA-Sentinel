#requires -Version 5.1
<#
.SYNOPSIS
    IAGA Sentinel live demo driver: 3 real verdicts + offline receipt proof.

.DESCRIPTION
    Drives three real seeded scenarios through the live governance pipeline
    (Allow -> Review -> Block), paced so the dashboard Live feed is watchable,
    and asserts each verdict so a non-deterministic take can never be recorded.

    All three beats share one sessionId, so their signed receipts form a single
    hash-chained run. The driver then exports that run and verifies it offline
    with iaga-verify (no server, no DB, no network) - twice: against the key
    embedded in the export, then against the same key pinned explicitly.

    Nothing is faked: every verdict comes from POST /v1/inspect on the running
    server, and the scenario payloads are fetched live from the server itself.

.PARAMETER BaseUrl
    Server base URL (default http://localhost:4010).

.PARAMETER SessionId
    Fixed sessionId used as the receipt run_id, grouping all three beats into
    one hash-chained run.

.PARAMETER PauseSec
    Seconds to pause between beats so each verdict lands on camera (default 5).

.PARAMETER ChainFile
    Output path for the exported receipt chain (default chain.json, gitignored).

.EXAMPLE
    .\scripts\demo_run.ps1
#>
[CmdletBinding()]
param(
    [string]$BaseUrl   = 'http://localhost:4010',
    [string]$SessionId = 'demo-session-iaga',
    [int]   $PauseSec  = 5,
    [string]$ChainFile = 'chain.json'
)

$ErrorActionPreference = 'Stop'

# replay reads the demo DB relative to the working directory, and chain.json is
# written here too, so run from the repo root (same CWD as the server).
$RepoRoot  = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$IagaExe   = Join-Path $RepoRoot 'target\release\iaga.exe'
$VerifyExe = Join-Path $RepoRoot 'target\release\iaga-verify.exe'
$ChainPath = Join-Path $RepoRoot $ChainFile

function Write-Banner {
    param([string]$Text, [string]$Fg = 'White', [string]$Bg = 'DarkCyan')
    $width = 64
    $pad = [Math]::Max(0, $width - $Text.Length)
    Write-Host ''
    Write-Host (' ' * ($width + 2)) -BackgroundColor $Bg
    Write-Host (' ' + $Text + (' ' * $pad)) -ForegroundColor $Fg -BackgroundColor $Bg
    Write-Host (' ' * ($width + 2)) -BackgroundColor $Bg
    Write-Host ''
}

function Write-Verdict {
    param([string]$Decision, [int]$Score)
    switch ($Decision.ToLower()) {
        'allow'  { Write-Banner ("VERDICT: ALLOW    risk=$Score") 'Black' 'Green' }
        'review' { Write-Banner ("VERDICT: REVIEW   risk=$Score   (human-in-the-loop)") 'Black' 'Yellow' }
        'block'  { Write-Banner ("VERDICT: BLOCK    risk=$Score   (action denied)") 'White' 'Red' }
        default  { Write-Banner ("VERDICT: $($Decision.ToUpper())   risk=$Score") 'White' 'DarkGray' }
    }
}

function Select-Beat {
    param($Scenarios, [int]$StepNum, [string]$TitleNeedle)
    $hit = $Scenarios | Where-Object { $_.step -eq "Step $StepNum" } | Select-Object -First 1
    if ($null -eq $hit) {
        $hit = $Scenarios | Where-Object { $_.title -like "*$TitleNeedle*" } | Select-Object -First 1
    }
    if ($null -eq $hit) { throw "Could not locate beat: Step $StepNum / '$TitleNeedle'" }
    return $hit
}

Write-Banner 'IAGA SENTINEL  -  LIVE GOVERNANCE  (one signed session)' 'White' 'DarkBlue'
Write-Host ("Server  : {0}" -f $BaseUrl)
Write-Host ("Session : {0}   (all 3 beats chain into one run, run_id = <agentId>:{0})" -f $SessionId)

# Determinism guard: reset adaptive risk weights to defaults. In open mode the
# request authenticates as implicit admin, so no token is needed. The driver
# never calls /v1/risk/feedback, so weights stay at defaults for the whole run.
try {
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/risk/weights/reset" -TimeoutSec 5 | Out-Null
    Write-Host 'Weights : reset to defaults (determinism guard).' -ForegroundColor DarkGray
} catch {
    Write-Host ("Weights : reset skipped ({0}); a fresh server already uses defaults." -f $_.Exception.Message) -ForegroundColor DarkYellow
}

# Pull the real seeded scenarios from the running server (source of truth).
$scenarios = Invoke-RestMethod -Uri "$BaseUrl/v1/demo/scenarios" -TimeoutSec 10

$beats = @(
    @{ N = 1; Expect = 'allow';  Beat = (Select-Beat $scenarios 1 'repository inspection') },
    @{ N = 2; Expect = 'review'; Beat = (Select-Beat $scenarios 2 'secret injection') },
    @{ N = 3; Expect = 'block';  Beat = (Select-Beat $scenarios 3 'Destructive') }
)

$failures = 0

foreach ($b in $beats) {
    $beat = $b.Beat
    Write-Banner ("BEAT {0}/3   ABOUT TO: {1}    | expected: {2}" -f $b.N, $beat.title, $b.Expect.ToUpper()) 'White' 'DarkCyan'

    # Round-trip the server's own request object and only inject the shared
    # sessionId, so every field name stays exactly as the product emits it.
    $req = $beat.request
    if (($req.PSObject.Properties.Name -contains 'metadata') -and $req.metadata) {
        $req.metadata | Add-Member -NotePropertyName sessionId -NotePropertyValue $SessionId -Force
    } else {
        $req | Add-Member -NotePropertyName metadata -NotePropertyValue @{ sessionId = $SessionId } -Force
    }

    $body = $req | ConvertTo-Json -Depth 12
    $resp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/inspect" -ContentType 'application/json' -Body $body -TimeoutSec 15

    $decision = "$($resp.decision)"
    $score    = [int]$resp.risk.score
    Write-Verdict $decision $score

    Write-Host '  Why:' -ForegroundColor DarkGray
    foreach ($reason in @($resp.risk.reasons | Select-Object -First 4)) {
        Write-Host ("    - {0}" -f $reason) -ForegroundColor DarkGray
    }
    if ($resp.reviewRequestId) {
        Write-Host ("  reviewRequestId    : {0}" -f $resp.reviewRequestId) -ForegroundColor DarkGray
    }
    Write-Host ("  auditEvent.eventId : {0}" -f $resp.auditEvent.eventId) -ForegroundColor DarkGray

    if ($decision.ToLower() -ne $b.Expect) {
        Write-Host ("  ASSERTION FAILED: expected {0}, got {1}. Determinism broken." -f $b.Expect.ToUpper(), $decision.ToUpper()) -ForegroundColor Red
        $failures++
    }

    if ($b.N -lt 3) {
        Write-Host ("  ... pausing {0}s (watch the dashboard Live feed) ..." -f $PauseSec) -ForegroundColor DarkGray
        Start-Sleep -Seconds $PauseSec
    }
}

if ($failures -gt 0) {
    Write-Banner ("STOP: {0} verdict assertion(s) failed - do NOT use this take." -f $failures) 'White' 'Red'
    exit 1
}

# Let the final receipt commit before reading it back.
Start-Sleep -Seconds 2

# ── Money shot: export the signed chain and verify it offline ──
Write-Banner 'MONEY SHOT  -  OFFLINE PROOF (no server, no DB, just a file + a key)' 'White' 'DarkMagenta'

Write-Host ("> iaga replay {0} --export {1}" -f $SessionId, $ChainFile) -ForegroundColor Cyan
$exportOut = & $IagaExe replay $SessionId --export $ChainPath
if ($LASTEXITCODE -ne 0) {
    Write-Banner 'EXPORT FAILED' 'White' 'Red'
    $exportOut | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    exit 1
}
$exportOut | ForEach-Object { Write-Host $_ -ForegroundColor Green }

$chain  = Get-Content $ChainPath -Raw | ConvertFrom-Json
$pubHex = $chain.signer_verifying_key
$runId  = $chain.run_id
$count  = @($chain.receipts).Count
Write-Host ''
Write-Host ("  run_id   : {0}" -f $runId) -ForegroundColor White
Write-Host ("  receipts : {0}   (seq 0,1,2 = Allow, Review, Block)" -f $count) -ForegroundColor White
Write-Host ("  pub key  : {0}" -f $pubHex) -ForegroundColor DarkGray
Write-Host ''

# Verify against the key embedded in the export (prints a self-asserted warning).
Write-Host ("> iaga-verify {0}" -f $ChainFile) -ForegroundColor Cyan
& $VerifyExe $ChainPath | ForEach-Object { Write-Host $_ -ForegroundColor Green }
$embeddedExit = $LASTEXITCODE

# Verify against the PINNED public key (authenticates authorship, no warning).
Write-Host ''
Write-Host ("> iaga-verify {0} --key {1}" -f $ChainFile, $pubHex) -ForegroundColor Cyan
$pinnedOut = & $VerifyExe $ChainPath --key $pubHex
$pinnedExit = $LASTEXITCODE
$pinnedOut | ForEach-Object { Write-Host $_ -ForegroundColor Green }

if (($embeddedExit -eq 0) -and ($pinnedExit -eq 0)) {
    Write-Banner ("CHAIN OK   run_id={0}   receipts={1}   terminal verdict = BLOCK" -f $runId, $count) 'Black' 'Green'
    Write-Host '  Verified offline: no network, no server, no DB - just this file + the public key.' -ForegroundColor Green
    Write-Host '  The terminal receipt cryptographically attests the BLOCK.' -ForegroundColor Green
} else {
    Write-Banner ("VERIFY FAILED  (embedded exit={0}, pinned exit={1})" -f $embeddedExit, $pinnedExit) 'White' 'Red'
    exit 1
}
