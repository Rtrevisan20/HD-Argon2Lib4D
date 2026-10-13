# Teste de estresse — HD-Argon2Lib4D

> **Binários versionados.** Os executáveis em `Win32/` e `Win64/` foram
> compilados em **13/10/2026 11:20** a partir da revisão de fonte
> **`b7bce942f8d5`** (SHA-256 dos `src/*.pas` + `Argon2StressTest.dpr` +
> `Argon2StressGolden.inc`, calculada por `.\source-rev.ps1`). Servem para validar
> a Lib **sem compilar**, mas podem ficar desatualizados: **se você alterar o
> `src/` ou este teste, recompile** com `.\build.ps1` (ou `.\run-tests.ps1`) e
> recommite os `.exe` antes de confiar neles. A revisão `b7bce942f8d5` é a
> "impressão digital" do fonte no momento do build.

Programa console que exercita a biblioteca nativa de forma agressiva, cobrindo
correção, concorrência, memória grande e desempenho. É o equivalente, em Pascal,
ao `src/bench.c` + `src/test.c` da referência `phc-winner-argon2`, com alguns
testes extras (concorrência e determinismo).

## O que ele faz

| Seção | O que testa |
| ----- | ----------- |
| **A. Correção** | 120 vetores-ouro gerados pela referência C oficial (`oracle_grid.c`), conferidos **byte-a-byte** (`argon2i/d/id`, v16/v19, m=8..65536 KiB, t=1/3, p=1/2/4). |
| **B. Varredura + bench** | Espelha `src/bench.c`: `m = 2^10 .. 2^maxExp` KiB, threads `1/2/4/8`, os 3 tipos, `t=3`; mede tempo e o *speedup* `p=4` vs `p=1`. |
| **C. Determinismo** | Configurações com memória grande (até 64 MiB) executadas 2× — resultado tem de ser idêntico. |
| **D. Concorrência** | N threads externas calculando hashes ao mesmo tempo; cada tag é conferida contra o recomputo sequencial (valida reentrância / ausência de estado global mutável). |
| **E. Soak aleatório** | Centenas de combinações aleatórias (tipo, versão, m, t, p, tamanhos de pwd/salt/tag): `raw` determinístico, `encoded` + `verify` OK e `verify` com senha errada ⇒ `VERIFY_MISMATCH`. |
| **F. Erros + fachada** | `ARGON2_MEMORY_TOO_LITTLE`, `PWD_PTR_MISMATCH`, `SALT_TOO_SHORT`, `OUTPUT_TOO_SHORT`, `ENCODING_FAIL`, `INCORRECT_TYPE`, `DECODING_FAIL` e a fachada `THDArgon2` (`HashPassword`/`VerifyPassword`/`NeedsRehash`/`ErrorMessage`). |

Ao final imprime um resumo (`PASS`/`FAIL`/`SKIP`), grava `stress-report.txt` e
retorna **exit code 0** se não houver falhas (1 caso contrário) — pronto para CI.

## Como compilar e rodar

> **Binários prontos:** os executáveis já compilados ficam versionados em
> `Win32/` e `Win64/` — dá para validar a Lib **sem compilar nada**:
>
> ```powershell
> .\Win64\Argon2StressTest.exe --quick    # perfil rápido (~10 s)
> .\Win64\Argon2StressTest.exe            # default, varre até 1 GiB (~80 s)
> .\Win64\Argon2StressTest.exe --big      # até 4 GiB (~5,5 min)
> ```
>
> A revisão de fonte correspondente a estes binários pode ser recalculada com
> `.\source-rev.ps1`.

**Teste completo** (compila e roda vários perfis numa tacada só):

```powershell
# Win64: perfis quick + big (padrão)
.\run-tests.ps1

# inclui também o default (1 GiB)
.\run-tests.ps1 -Profiles quick,default,big

# Win32 + Win64
.\run-tests.ps1 -Platform Both
```

Cada perfil grava seu próprio relatório (`stress-report-<perfil>-<plat>.txt`) e o
script termina com um resumo e o exit code (0 = tudo passou).

Compilando/rodando manualmente, sem depender da IDE (localiza o `dcc32`/`dcc64`
mais recente do Delphi):

```powershell
# Win32 + Win64
.\build.ps1

# só Win64 e já executando
.\build.ps1 -Platform Win64 -Run

# perfil rápido (m até 16 MiB, soak 40, 2 threads)
.\build.ps1 -Platform Win64 -Run -Quick
```

Ou direto pelo compilador:

```powershell
& $env:BDS\bin\dcc64.exe -B -U..\..\src -E.\Win64 Argon2StressTest.dpr
.\Win64\Argon2StressTest.exe
```

Na IDE: abra `Group.groupproj` — o projeto `Argon2StressTest` já está no grupo.

### Com Lazarus / FreePascal (FPC)

O teste (e a Lib) também compilam com **FreePascal/Lazarus**, a partir dos mesmos
`src/*.pas` — sem alterar nada. Há duas formas, ambas sem depender da IDE:

```powershell
# via lazbuild (usa o projeto Argon2StressTest.lpi)
.\build-lazarus.ps1 -Run -Quick

# via fpc.exe direto (sem lazbuild)
.\build-lazarus.ps1 -Compiler fpc -Run -Quick

# teste completo (multi-perfil, um relatorio por perfil, exit code de CI)
.\run-tests-lazarus.ps1                       # perfis quick + big
.\run-tests-lazarus.ps1 -Profiles quick,default,big
.\run-tests-lazarus.ps1 -Compiler fpc         # compila com fpc.exe direto
```

Na IDE do Lazarus: abra `Argon2StressTest.lpi` (o projeto referencia `..\..\src`
e não exige que o pacote esteja instalado). O `build-lazarus.ps1` usa `lazbuild`
por padrão e cai para o `fpc` com `-Compiler fpc`. O `run-tests-lazarus.ps1` é o
equivalente FPC/Lazarus do `run-tests.ps1` (compila e roda os perfis numa tacada,
gravando `stress-report-<perfil>-fpc.txt`).

Validado com **FPC 3.2.2 / Lazarus 4.x** (x86_64-win64): `--quick` =
**6 PASS / 0 FAIL / 0 SKIP**, **sem avisos** de compilação.

## Opções

```
Argon2StressTest [opcoes]
  --quick            perfil rapido (m ate 16 MiB, soak 40, conc 2)
  --big              inclui memoria grande (m ate 4 GiB; exige 64-bit)
  --max-mib=N        memoria maxima da varredura em MiB (default 1024)
  --soak=N           numero de combinacoes aleatorias (default 100)
  --concurrency=N    threads externas simultaneas (default 4)
  --no-bench         pula a varredura/benchmark
  --no-concurrency   pula o teste de concorrencia
  --no-soak          pula o soak aleatorio
  --report=ARQ       arquivo de relatorio (default stress-report.txt)
  --pause            aguarda ENTER ao final
  --help             mostra esta ajuda
```

`--max-mib`/`--big` são automaticamente limitados ao máximo endereçável da
plataforma (`Argon2MaxMemory`); no Win32 a varredura vai até 2 GiB.

## Valores-ouro (seção A)

`Argon2StressGolden.inc` é **gerado** a partir da referência C (`oracle_grid.c`),
com `pwd = 16 × 0x01`, `salt = 16 × 0x02`, tag de 32 bytes:

```
cl /nologo /O2 /I include oracle_grid.c argon2.obj core.obj ref.obj \
   encoding.obj thread.obj blake2b.obj /Fe:oracle_grid.exe
oracle_grid.exe > golden.txt     # depois convertido para o .inc
```

Não edite o `.inc` à mão — ele é somente dados de referência.

## Resultado esperado

```
RESULTADO: 6 PASS, 0 FAIL, 0 SKIP   (por perfil)
ESTE TESTE DE ESTRESSE PASSOU (0 falhas)
```

Tempos numa máquina de 16 CPUs (Win64):

| Perfil | Memória varrida | Tempo aprox. |
| ------ | --------------- | ------------ |
| `quick` (`--quick`) | até 16 MiB | ~10 s |
| `default` (sem args) | até 1 GiB | ~80 s |
| `big` (`--big`) | até 4 GiB | ~5,5 min |

O perfil `big` já foi executado com sucesso até 4 GiB (156 execuções na
varredura, 0 falhas de alocação; 6 PASS / 0 FAIL / 0 SKIP).
