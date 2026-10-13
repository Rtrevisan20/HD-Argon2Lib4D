# HD-Argon2Lib4D

Porte **nativo** do [Argon2](https://github.com/P-H-C/phc-winner-argon2) para
**Pascal/Delphi** — implementação 100% em código Pascal, **sem DLL**. Compila em
**Delphi** (Win32/Win64) **e** em **FreePascal/Lazarus**.

Substituto drop-in do binding `libargon2.dll`: a mesma API pública (`argon2_hash`,
`argon2_verify`, `argon2_*_hash_encoded`, etc.) e ainda uma **fachada de uso
simples** (`THDArgon2`) para gerar e verificar senhas em poucas linhas.

## Por que Argon2

[Argon2](https://en.wikipedia.org/wiki/Argon2) é o vencedor da
[Password Hashing Competition](https://password-hashing.net/) de 2015 e a
recomendação da RFC 9106. Protege contra força bruta, GPU e ASIC por exigir
memória, tempo e paralelismo configuráveis. A variante padrão é o **Argon2id**.

- **Configurável:** memória, iterações (tempo) e paralelismo (threads).
- **Resistente:** difícil de acelerar com hardware especializado.
- **Variantes:**
  - `argon2d` — resiste a GPUs (ideal para criptomoedas).
  - `argon2i` — resiste a ataques de canal lateral.
  - `argon2id` — híbrido; recomendação padrão (RFC 9106).

O Argon2 é amplamente considerado superior a bcrypt e scrypt pela
configurabilidade e resistência a hardware avançado.

### Formato da string PHC

Por convenção o Argon2 produz uma string autoexplicativa:

```
$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
```

| Parte    | Significado            | Observações                                            |
| -------- | ---------------------- | ------------------------------------------------------ |
| argon2id | Algoritmo              | `argon2id`, `argon2i` ou `argon2d`                     |
| v=19     | Versão (decimal)       | `0x13` = 19 (v19); também suporta `v=16` (`0x10`)      |
| m=65536  | Memória em KiB         | `8*p` .. `0x7fffffff`; potência de 2 é recomendada     |
| t=3      | Iterações (tempo)      | 1 .. `0xffffffff`                                      |
| p=4      | Paralelismo (lanes)    | 1 .. `0x00ffffff`                                      |
| salt     | Salt em Base64 (sem `=`) | mínimo 8 bytes                                       |
| hash     | Hash em Base64 (sem `=`) | tamanho configurável (default 32)                    |

## Diferenças em relação ao binding DLL (`HDArgon2`)

- **Sem DLL:** nada para distribuir junto ao executável — tudo compila no binário.
- **Fachada com defaults sensatos** (`t=3`, `m=19 MiB`, `p=4`, salt 16, hash 32).
- **Salt criptograficamente seguro** via `BCryptGenRandom` (Windows) ou
  `/dev/urandom` (POSIX).
- **`VerifyPassword` auto-detecta** o tipo (`argon2i`/`argon2d`/`argon2id`)
  pelo prefixo da string.
- **`NeedsRehash`** para saber se um hash armazenado usa parâmetros antigos.

## Instalação

#### Via [boss](https://github.com/HashLoad/boss)

```sh
boss install github.com/Rtrevisan20/HD-Argon2Lib4D
```

#### Manual

Adicione a pasta `src` em _Project > Options > Delphi Compiler > Search path_:

```
../HD-Argon2Lib4D/src
```

#### Lazarus / FreePascal

Há um pacote Lazarus pronto: **`HDArgon2Lib4D.Package.lpk`** (registra as 7
units da Lib).

- **Na IDE do Lazarus:** _Package > Open Package File_ e abra o `.lpk`; depois
  _Use > Add to Project_ (ou `Project Inspector > Add > New Requirement`).
- **Sem IDE:** adicione a pasta `src` em _Project Options > Compiler Options >
  Paths > Other unit files_, ou compile o pacote na linha de comando:

  ```sh
  lazbuild HDArgon2Lib4D.Package.lpk
  ```

O `uses` é idêntico ao do Delphi. Há dois projetos Lazarus prontos, ambos
reaproveitando o **mesmo fonte** dos equivalentes Delphi:

- `Tests/Argon2StressTest/Argon2StressTest.lpi` — teste de estresse (veja
  `Tests/Argon2StressTest/README.md`);
- `Samples/Argon2Lib4DSample/Argon2Lib4DSample.lpi` — sample console
  (auto-teste, encode/verify e benchmark).

Para compilar pela linha de comando (sem IDE):

```sh
lazbuild Tests/Argon2StressTest/Argon2StressTest.lpi
lazbuild Samples/Argon2Lib4DSample/Argon2Lib4DSample.lpi
```

#### Uses

```delphi
uses
  HDArgon2Lib4D;          // uso simples (recomendado)
  // ou
  HDArgon2Lib4D.Api;      // API crua compatível com o binding DLL
```

## Uso simples (fachada `THDArgon2`)

```delphi
uses
  HDArgon2Lib4D;

// Gera a string PHC (salt aleatorio seguro automatico)
var Hash := THDArgon2.HashPassword('SuaSenhaSuperSegura');
// -> $argon2id$v=19$m=19456,t=3,p=4$....$....

// Verifica (aceita argon2i / argon2d / argon2id)
if THDArgon2.VerifyPassword(HashArmazenadoNoBanco, 'SuaSenhaSuperSegura') then
  ShowMessage('Senha correta')
else
  ShowMessage('Senha incorreta');

// Se os parametros mudaram, vale re-hashear no proximo login:
if THDArgon2.NeedsRehash(HashArmazenadoNoBanco) then
  HashArmazenadoNoBanco := THDArgon2.HashPassword('SuaSenhaSuperSegura');
```

### Propriedades da fachada

| Propriedade   | Default | Significado                          |
| ------------- | ------- | ------------------------------------ |
| `Iterations`  | `3`     | Iterações (tempo)                    |
| `Memory`      | `19456` | Memória em KiB (19 MiB)              |
| `Parallelism` | `4`     | Threads / lanes                      |
| `SaltLength`  | `16`    | Bytes de salt                        |
| `HashLength`  | `32`    | Bytes do hash                        |
| `Mode`        | `Argon2_id` | Variante (`Argon2_i`, `Argon2_d`) |

### Funções da fachada

```delphi
THDArgon2.HashPassword(const aPass: string): string;   // PHC + salt seguro
THDArgon2.HashRaw(const aPass: string): TBytes;        // tag binaria
THDArgon2.VerifyPassword(const aHash, aPass: string): Boolean;
THDArgon2.NeedsRehash(const aHash: string): Boolean;
THDArgon2.ErrorMessage(const aCode: Integer): string;
```

Erros levantam `EHDArgon2` (com a propriedade `Code` e a mensagem do Argon2).

## Uso avançado (API crua)

Mesma assinatura da referência C / do binding DLL:

```delphi
uses
  HDArgon2Lib4D.Types,
  HDArgon2Lib4D.Api;

var
  Salt: array[0..15] of Byte;
  Hash: array[0..31] of Byte;
  Enc : array[0..255] of AnsiChar;
  rc  : Integer;
begin
  // ...preencher Salt...
  rc := argon2id_hash_encoded(3, 65536, 4, PAnsiChar(AnsiString(Pwd)),
          Length(Pwd), @Salt[0], 16, 32, @Enc[0], SizeOf(Enc));
  if rc <> ARGON2_OK then
    raise Exception.Create(argon2_error_message(rc));
end;
```

Funções disponíveis: `argon2_hash`, `argon2_ctx`,
`argon2{i,d,id}_hash_raw`, `argon2{i,d,id}_hash_encoded`,
`argon2_verify` / `argon2{i,d,id}_verify` (+ `_ctx`),
`argon2_encodedlen`, `argon2_error_message`, `argon2_type2string`.

## Estrutura do projeto

```
src/
  HDArgon2Lib4D.Types.pas      tipos, constantes, helpers little-endian
  HDArgon2Lib4D.Blake2b.pas    BLAKE2b + blake2b_long
  HDArgon2Lib4D.Blamka.pas     fBlaMka, round G, fill_block
  HDArgon2Lib4D.Core.pas       nucleo (H0, fill_segment, threading)
  HDArgon2Lib4D.Encoding.pas   Base64 PHC + encode/decode
  HDArgon2Lib4D.Api.pas        API publica (drop-in da DLL)
  HDArgon2Lib4D.pas            fachada THDArgon2 (uso simples)
Samples/
  Argon2Lib4DSample/           demonstracao (auto-teste, encode/verify, bench)
    Argon2Lib4DSample.dpr      fonte console (Delphi + FPC)
    Argon2Lib4DSample.lpi      projeto Lazarus
Tests/
  Argon2StressTest/            teste de estresse (correcao, concorrencia, bench)
    Argon2StressTest.dpr       projeto console (Delphi + FPC)
    Argon2StressTest.lpi       projeto Lazarus
    Win32|Win64/               executaveis prontos (rodar sem compilar)
Argon2Lib4D.dpk / .dproj       pacote Delphi (Win32 + Win64)
HDArgon2Lib4D.Package.lpk      pacote Lazarus/FPC (registra as 7 units)
```

## Validacao

Implementacao validada **byte-a-byte** contra os vetores oficiais (KATs) do
`phc-winner-argon2`, para `argon2i`, `argon2d` e `argon2id` nas **versões v16
(`0x10`) e v19 (`0x13`)**, incluindo:

- tags finais (hu) e o _pre-hashing digest_ (H0);
- **dump completo da memória final** (32 blocos × 128 palavras por KAT);
- verificação `encode`/`verify`;
- execução mono-thread e multi-thread (paralelismo por lane com `TThread`).

### Portabilidade (Delphi + FreePascal/Lazarus)

A **mesma** implementação compila em **FreePascal 3.2.2 / Lazarus** (validado em
x86_64-win64), sem avisos: a fachada `THDArgon2` e o KAT do `argon2id` v19 são
conferidos byte-a-byte. Os `src/*.pas` trazem guardas `{$IFDEF FPC}` (diretiva
`{$MODE DELPHI}`, `uses` condicionais e códigos de aviso do FPC) que são
**ignoradas pelo Delphi** — o build Delphi permanece idêntico.

### Resultados dos testes

Tudo conferido contra a referencia C oficial (nunca so "auto-consistencia"):

| Verificação | Escopo | Resultado |
| ----------- | ------ | --------- |
| KATs oficiais | argon2i/d/id, v16 + v19 — tags, H0 e dump de memória | **12/12 PASS** |
| Vetores-ouro da ref. C | 120 configurações (m=8..65536 KiB, t=1/3, p=1/2/4) | **120/120 PASS** |
| Determinismo | configurações com memória grande executadas 2× | **4/4 PASS** |
| Concorrência | hashes em várias threads externas vs recomputo sequencial | **32/32 PASS** |
| Soak aleatório | 100 combinações (raw/encoded/verify) | **100/100 PASS** |
| Caminhos de erro + fachada | 12 casos | **12/12 PASS** |
| Benchmark até 4 GiB | varredura completa, p=1/2/4/8 | **156 execuções, 0 falhas** |

O teste de estresse termina sempre com **`6 PASS, 0 FAIL, 0 SKIP`**, tanto em
**Win32** quanto em **Win64**.

### Teste de estresse

O projeto `Tests/Argon2StressTest` vai além dos KATs: confere **120 vetores-ouro**
gerados pela referência C (byte-a-byte), varre `m` de 1 MiB até gigabytes com
`threads ∈ {1,2,4,8}`, verifica **determinismo**, faz **hashes concorrentes** em
várias threads externas (reentrância), roda um **soak aleatório** e valida os
caminhos de erro + a fachada. O perfil default varre até **1 GiB** (e `--big` até
**4 GiB**, já validado). Veja `Tests/Argon2StressTest/README.md`.

#### Binários prontos (sem compilar)

Os executáveis já compilados estão versionados no repositório:

```
Tests/Argon2StressTest/Win32/Argon2StressTest.exe    (32-bit)
Tests/Argon2StressTest/Win64/Argon2StressTest.exe    (64-bit, recomendado)
```

Basta executar:

```powershell
cd Tests\Argon2StressTest\Win64
.\Argon2StressTest.exe --quick     # perfil rapido (~10 s)
.\Argon2StressTest.exe             # default, varre ate 1 GiB (~80 s)
.\Argon2StressTest.exe --big       # ate 4 GiB (~5,5 min)
```

Para recompilar do zero (sem depender da IDE):

```powershell
cd Tests\Argon2StressTest
.\run-tests.ps1                       # compila e roda os perfis quick + big
.\build.ps1 -Platform Win64 -Run      # compila e roda o perfil default (1 GiB)
.\build-lazarus.ps1 -Run -Quick       # compila com Lazarus/FPC e roda --quick
.\run-tests-lazarus.ps1               # idem, mas o teste completo (FPC/Lazarus)
```

> Revisão de fonte dos binários versionados: **`b7bce942f8d5`**
> (13/10/2026 11:20), recalculável com `Tests\Argon2StressTest\source-rev.ps1`.

## Licença

O código original (`phc-winner-argon2`) é **CC0 1.0 / Apache 2.0**; a atribuição
é mantida nos cabeçalhos das units.

## Suporte

rtinformatica.ti@gmail.com
