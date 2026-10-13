<#
  Calcula a "revisao de fonte" (hash) citada no aviso do README.

  Metodo (deterministico):
    SHA-256 sobre os bytes, na ordem:
      1) src\*.pas   (ordem alfabetica pelo nome do arquivo)
      2) Argon2StressTest.dpr
      3) Argon2StressGolden.inc
    Saida: os 12 primeiros digitos hexadecimais (minusculos).

  Serve para "carimbar" o fonte no momento em que os executaveis
  versionados (Win32/Win64) foram compilados. Se a saida mudar, os .exe
  precisam ser recompilados para continuarem coerentes com a revisao.

  Uso:
    .\source-rev.ps1
#>
#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = (Resolve-Path (Join-Path $here '..\..\src')).Path

$files = @()
$files += Get-ChildItem -Path $src -Filter '*.pas' -File |
    Sort-Object Name | Select-Object -ExpandProperty FullName
$files += (Join-Path $here 'Argon2StressTest.dpr')
$files += (Join-Path $here 'Argon2StressGolden.inc')

$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    foreach ($f in $files) {
        if (-not (Test-Path $f)) { throw "Arquivo nao encontrado: $f" }
        $bytes = [System.IO.File]::ReadAllBytes($f)
        if ($bytes.Length -gt 0) {
            [void]$sha.TransformBlock($bytes, 0, $bytes.Length, $null, 0)
        }
    }
    [void]$sha.TransformFinalBlock([byte[]]@(), 0, 0)
    $hex = -join ($sha.Hash | ForEach-Object { $_.ToString('x2') })
    Write-Output $hex.Substring(0, 12)
} finally {
    $sha.Dispose()
}
