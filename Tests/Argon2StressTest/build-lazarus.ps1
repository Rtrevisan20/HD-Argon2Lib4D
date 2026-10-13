<#
  Compila o teste de estresse (Argon2StressTest) com FreePascal/Lazarus.

  E o equivalente de .\build.ps1 (que usa o Delphi) para quem prefere
  o FPC/Lazarus. Nao depende da IDE.

  Uso:
    .\build-lazarus.ps1                     # compila via lazbuild
    .\build-lazarus.ps1 -Run -Quick         # compila e roda --quick
    .\build-lazarus.ps1 -Compiler fpc       # usa o fpc.exe direto (sem lazbuild)
    .\build-lazarus.ps1 -Cpu x86_64 -Os win64

  O executavel sai em .\Argon2StressTest.exe (o mesmo caminho do alvo do .lpi).
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('lazbuild', 'fpc')]
    [string]$Compiler = 'lazbuild',
    [string]$Cpu = '',
    [string]$Os = '',
    [switch]$Run,
    [switch]$Quick,
    [string[]]$TestArgs = @()
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lpi  = Join-Path $here 'Argon2StressTest.lpi'
$dpr  = Join-Path $here 'Argon2StressTest.dpr'
$src  = (Resolve-Path (Join-Path $here '..\..\src')).Path
$exe  = Join-Path $here 'Argon2StressTest.exe'

function Find-Lazbuild {
    $c = Get-Command 'lazbuild.exe' -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $candidates = @('C:\lazarus\lazbuild.exe')
    if ($env:LAZARUS_DIR) { $candidates += (Join-Path $env:LAZARUS_DIR 'lazbuild.exe') }
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    throw 'Nao encontrei lazbuild.exe. Instale o Lazarus ou ajuste o PATH.'
}

function Find-Fpc {
    $c = Get-Command 'fpc.exe' -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    if ($env:FPC -and (Test-Path $env:FPC)) { return $env:FPC }
    $found = @()
    foreach ($r in @('C:\lazarus\fpc')) {
        if (Test-Path $r) {
            $found += Get-ChildItem -Path $r -Recurse -Filter 'fpc.exe' -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        }
    }
    if ($found.Count -eq 0) {
        throw 'Nao encontrei fpc.exe. Instale o FPC ou ajuste o PATH.'
    }
    # ordem decrescente do caminho -> versao mais recente primeiro
    $best = @($found | Sort-Object -Descending)
    return $best[0]
}

if ($Compiler -eq 'lazbuild') {
    $lazbuild = Find-Lazbuild
    Write-Host '== Compilando (lazbuild) ==' -ForegroundColor Cyan
    Write-Host "   $lazbuild"
    $lazArgs = @('--build-all')
    if ($Cpu) { $lazArgs += "--cpu=$Cpu" }
    if ($Os)  { $lazArgs += "--os=$Os" }
    $lazArgs += $lpi
    & $lazbuild @lazArgs
} else {
    $fpc = Find-Fpc
    Write-Host '== Compilando (fpc) ==' -ForegroundColor Cyan
    Write-Host "   $fpc"
    $lib = Join-Path $here 'lib\fpc'
    New-Item -ItemType Directory -Force $lib | Out-Null
    & $fpc -vw -O2 "-Fu$src" "-FU$lib" "-FE$here" $dpr
}
if ($LASTEXITCODE -ne 0) {
    throw "Falha ao compilar (exit $LASTEXITCODE)."
}
Write-Host "   OK -> $exe" -ForegroundColor Green

if ($Run) {
    Write-Host "== Executando $exe ==" -ForegroundColor Cyan
    $argList = @()
    if ($Quick) { $argList += '--quick' }
    $argList += $TestArgs
    & $exe @argList
    exit $LASTEXITCODE
}
