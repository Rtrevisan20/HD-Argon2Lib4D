<#
  Compila o teste de estresse (Argon2StressTest) para Win32 e/ou Win64.

  Uso:
    .\build.ps1                       # compila Win32 + Win64
    .\build.ps1 -Platform Win64       # so Win64
    .\build.ps1 -Run -Quick           # compila (Win64), roda --quick

  Nao depende da IDE: localiza o dcc32/dcc64 mais recente do Delphi.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Win32', 'Win64', 'Both')]
    [string]$Platform = 'Both',
    [switch]$Run,
    [switch]$Quick,
    [string[]]$TestArgs = @()
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dpr  = Join-Path $here 'Argon2StressTest.dpr'
$src  = (Resolve-Path (Join-Path $here '..\..\src')).Path

function Find-Compiler([string]$name) {
    $roots = @(
        'C:\Program Files (x86)\Embarcadero\Studio',
        'C:\Program Files\Embarcadero\Studio'
    )
    $found = @()
    foreach ($r in $roots) {
        if (Test-Path $r) {
            $found += Get-ChildItem -Path $r -Recurse -Filter $name -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        }
    }
    if ($found.Count -eq 0) {
        throw "Nao encontrei $name. Instale o Delphi ou ajuste o PATH."
    }
    # maior caminho = versao mais recente do Studio
    return ($found | Sort-Object -Descending)[0]
}

function Build-One([string]$plat) {
    $dcc = Find-Compiler $(if ($plat -eq 'Win32') { 'dcc32.exe' } else { 'dcc64.exe' })
    $out = Join-Path $here $plat
    New-Item -ItemType Directory -Force $out | Out-Null
    Write-Host "== Compilando $plat ==" -ForegroundColor Cyan
    Write-Host "   $dcc"
    & $dcc -B "-U$src" "-E$out" $dpr
    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao compilar $plat (exit $LASTEXITCODE)."
    }
    $exe = Join-Path $out 'Argon2StressTest.exe'
    Write-Host "   OK -> $exe" -ForegroundColor Green
    return $exe
}

$exes = @()
switch ($Platform) {
    'Win32' { $exes += Build-One 'Win32' }
    'Win64' { $exes += Build-One 'Win64' }
    'Both'  { $exes += Build-One 'Win32'; $exes += Build-One 'Win64' }
}

if ($Run) {
    $exe = $exes[-1]
    Write-Host "== Executando $exe ==" -ForegroundColor Cyan
    $testArgList = @()
    if ($Quick) { $testArgList += '--quick' }
    $testArgList += $TestArgs
    & $exe @testArgList
    exit $LASTEXITCODE
}
