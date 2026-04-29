# secured-claude installer - Windows (PowerShell 5+)
#
#   irm https://gitlab.com/benoit.besson/secured-claude/-/raw/main/install.ps1 | iex
#
# Per ADR-0015. Mirror of install.sh (Mac/Linux) for Windows. Both call
# the same `pipx install secured-claude` — the difference is the prereq
# detection + install hints.

[CmdletBinding()]
param (
    [string] $IndexUrl = $env:SC_INDEX_URL,
    [string] $ProjectId = $env:SC_PROJECT_ID,
    [string] $Version = $env:SC_VERSION,
    [switch] $Local = $env:SC_LOCAL -eq '1',
    [switch] $SkipDocker = $env:SC_NO_DOCKER -eq '1'
)

$ErrorActionPreference = 'Stop'

function Write-Step    { param($Msg) Write-Host "`n:: $Msg" -ForegroundColor DarkGray }
function Write-Info    { param($Msg) Write-Host "$([char]0x2713) $Msg" -ForegroundColor Green }
function Write-Warn    { param($Msg) Write-Host "$([char]0x26A0) $Msg" -ForegroundColor Yellow }
function Stop-WithFail { param($Msg) Write-Host "$([char]0x2717) $Msg" -ForegroundColor Red ; exit 1 }

# ---------------------------------------------------------------------------
# 1. OS / arch
# ---------------------------------------------------------------------------

Write-Step "OS / arch detection"
$arch = $env:PROCESSOR_ARCHITECTURE
Write-Info "Windows $arch"

# ---------------------------------------------------------------------------
# 2. Python >= 3.11
# ---------------------------------------------------------------------------

Write-Step "Python >= 3.11"
$py = (Get-Command python -ErrorAction SilentlyContinue) -as [System.Management.Automation.CommandInfo]
if (-not $py) {
    Stop-WithFail "python not found. Install via : winget install Python.Python.3.13"
}
$pyver = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$pyok = & python -c "import sys; print(1 if sys.version_info >= (3, 11) else 0)"
if ($pyok -ne '1') {
    Stop-WithFail "python $pyver found, but >= 3.11 required. Install via : winget install Python.Python.3.13"
}
Write-Info "python $pyver"

# ---------------------------------------------------------------------------
# 3. Docker
# ---------------------------------------------------------------------------

if (-not $SkipDocker) {
    Write-Step "Docker (running)"
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithFail "docker not found. Install Docker Desktop : https://docs.docker.com/desktop/install/windows-install/"
    }
    try {
        $null = & docker info 2>&1
        Write-Info "docker $(docker version --format '{{.Server.Version}}' 2>$null)"
    } catch {
        Stop-WithFail "docker daemon not running. Start Docker Desktop and re-run."
    }
} else {
    Write-Warn "skipping Docker checks (SC_NO_DOCKER=1)"
}

# ---------------------------------------------------------------------------
# 4. pipx
# ---------------------------------------------------------------------------

Write-Step "pipx"
if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
    Write-Info "pipx not found, installing via 'python -m pip install --user pipx'"
    & python -m pip install --user --quiet pipx
    & python -m pipx ensurepath
    # Refresh PATH for this session
    $userBin = "$env:APPDATA\Python\Python$($pyver -replace '\.','')\Scripts"
    if (Test-Path $userBin) {
        $env:Path = "$userBin;$env:Path"
    }
    if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
        Stop-WithFail "pipx still not on PATH after install. Restart PowerShell and re-run."
    }
}
Write-Info "pipx $(pipx --version 2>$null)"

# ---------------------------------------------------------------------------
# 5. Install secured-claude
# ---------------------------------------------------------------------------

Write-Step "secured-claude"
if ($Local) {
    $repoRoot = Split-Path -Path $PSCommandPath -Parent
    Write-Info "installing from local source : $repoRoot"
    & pipx install --force $repoRoot
} else {
    if (-not $ProjectId) { $ProjectId = '81740556' }
    if (-not $IndexUrl)  { $IndexUrl  = "https://gitlab.com/api/v4/projects/$ProjectId/packages/pypi/simple" }
    $spec = if ($Version) { "secured-claude==$Version" } else { "secured-claude" }
    Write-Info "installing $spec from $IndexUrl"
    try {
        & pipx install --force --index-url $IndexUrl $spec
    } catch {
        Write-Warn "GitLab Package Registry install failed. If this repo has no published version yet, run with -Local."
        throw
    }
}

if (-not (Get-Command secured-claude -ErrorAction SilentlyContinue)) {
    Stop-WithFail "secured-claude not on PATH after install. Run 'python -m pipx ensurepath' and restart PowerShell."
}
Write-Info "$(secured-claude version)"

# ---------------------------------------------------------------------------
# 6. Pre-pull Docker images
# ---------------------------------------------------------------------------

if (-not $SkipDocker) {
    Write-Step "pre-pull Docker images (one-time, ~600 MB)"
    try {
        & docker pull cerbos/cerbos:0.42.0 | Out-Null
        Write-Info "cerbos/cerbos:0.42.0 cached"
    } catch {
        Write-Warn "cerbos image pull failed (continuing - will be retried on 'secured-claude up')"
    }
}

# ---------------------------------------------------------------------------
# 7. Doctor
# ---------------------------------------------------------------------------

Write-Step "doctor"
try {
    & secured-claude doctor
} catch {
    Write-Warn "doctor reported issue(s) ; review above."
}

# ---------------------------------------------------------------------------
# 8. Next steps
# ---------------------------------------------------------------------------

Write-Host @"

──────────────────────────────────────────────────────────────────────
secured-claude is installed.

Next steps :

  1. Get an Anthropic API key
       https://console.anthropic.com/settings/keys

  2. Set the env var
       `$env:ANTHROPIC_API_KEY = "sk-ant-..."

  3. Start the secured stack
       secured-claude up

  4. Run a Claude Code session
       secured-claude run "hello"

  5. Inspect the audit trail
       secured-claude audit

  6. Run the security audit (proves the policy gates fire)
       bash bin/security-audit.sh   # in WSL2, or use audit-demo subcommand

Documentation : https://gitlab.com/benoit.besson/secured-claude
Threat model :  https://gitlab.com/benoit.besson/secured-claude/-/blob/main/SECURITY.md
──────────────────────────────────────────────────────────────────────
"@
