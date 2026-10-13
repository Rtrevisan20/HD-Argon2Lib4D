<#
  Compila (com FreePascal/Lazarus) e roda o teste de estresse em varios perfis,
  gravando um relatorio por perfil. E o equivalente de .\run-tests.ps1, mas
  usando o binario do FPC/Lazarus (x86_64-win64) em vez do Delphi.

  Uso:
    .\run-tests-lazarus.ps1                            # perfis quick + big
    .\run-tests-lazarus.ps1 -Profiles quick,default,big
    .\run-tests-lazarus.ps1 -NoBuild                   # so roda (exe ja compilado)
    .\run-tests-lazarus.ps1 -Compiler fpc              # compila com fpc.exe direto

  Perfis:
    quick    -> --quick        m ate 16 MiB          (~10 s)
    default  -> (sem args)     m ate 1 GiB           (~2-3 min)
    big      -> --big          m ate 4 GiB (64-bit)  (~5-6 min)

  Retorna 0 se todos os perfis passarem, 1 se algum falhar.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('lazbuild', 'fpc')]
    [string]$Compiler = 'lazbuild',
    [string]$Profiles = 'quick,big',
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $here 'build-lazarus.ps1'

$profileList = @($Profiles -split '\s*,\s*' | Where-Object { $_ -ne '' })
foreach ($prof in $profileList) {
    if ($prof -notin @('quick', 'default', 'big')) {
        throw "Perfil invalido: '$prof'. Use quick, default e/ou big."
    }
}
if ($profileList.Count -eq 0) { throw 'Informe ao menos um perfil (-Profiles quick,big).' }

if (-not $NoBuild) {
    & $build -Compiler $Compiler
}

function Get-ProfileArgs([string]$profile) {
    switch ($profile) {
        'quick' { @('--quick') }
        'big'   { @('--big') }
        default { @() }
    }
}

$exe = Join-Path $here 'Argon2StressTest.exe'
if (-not (Test-Path $exe)) {
    throw "Nao encontrei $exe. Compile com .\build-lazarus.ps1."
}

$results = @()
foreach ($prof in $profileList) {
    $report = Join-Path $here "stress-report-$prof-fpc.txt"
    $pargs  = @(Get-ProfileArgs $prof) + "--report=$report"

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host " PERFIL '$prof'  |  FPC/Lazarus (x86_64-win64)" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $exe @pargs
    $code = $LASTEXITCODE
    $sw.Stop()

    $results += [pscustomobject]@{
        Profile = $prof
        Exit    = $code
        Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Report  = "stress-report-$prof-fpc.txt"
    }
}

Write-Host ''
Write-Host '===== RESUMO =====' -ForegroundColor Cyan
$results | Format-Table -AutoSize

$failed = @($results | Where-Object { $_.Exit -ne 0 })
if ($failed.Count -eq 0) {
    Write-Host 'TODOS OS PERFIS PASSARAM.' -ForegroundColor Green
    exit 0
} else {
    $names = ($failed | ForEach-Object { $_.Profile }) -join ', '
    Write-Host "FALHAS: $names" -ForegroundColor Red
    exit 1
}
