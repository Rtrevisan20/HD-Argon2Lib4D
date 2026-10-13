{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)
program Argon2StressTest;

{******************************************************************************}
{  HD-Argon2Lib4D - Teste de estresse (stress/soak) da implementacao nativa.    }
{                                                                              }
{  Exercita a biblioteca de forma agressiva:                                    }
{    A. Grade de correcao  - 120 vetores-ouro da referencia C oficial           }
{       (argon2i/d/id, v16/v19, m=8..65536 KiB, t=1/3, p=1/2/4).                }
{    B. Varredura de parametros + benchmark (espelha src/bench.c da referencia): }
{       m = 2^10 .. 2^maxExp, threads 1/2/4/8, tipos i/d/id, t=3.                }
{    C. Determinismo sob estresse (memoria grande, 2 execucoes identicas).      }
{    D. Concorrencia: N threads externas calculando hashes ao mesmo tempo       }
{       (valida reentrancia / ausencia de estado global mutavel).               }
{    E. Soak aleatorio: milhares de combinacoes pequenas/medias.                  }
{    F. Caminhos de erro (parametros invalidos) e fachada THDArgon2.            }
{                                                                              }
{  Sem DLL: compila contra ../..\src. Relatorio gravado em stress-report.txt.    }
{******************************************************************************}

{$APPTYPE CONSOLE}
{$Q-}{$R-}

uses
{$IFDEF FPC}
  SysUtils, Classes, Windows,
{$ELSE}
  System.SysUtils,
  System.Classes,
  Winapi.Windows,
{$ENDIF}
  HDArgon2Lib4D.Types,
  HDArgon2Lib4D.Api,
  HDArgon2Lib4D;

type
  { Um vetor-ouro da referencia C (argon2_grid.c). }
  TGolden = record
    AType: TArgon2Type;
    Version: UInt32;
    MCost: UInt32;      // KiB
    TCost: UInt32;
    Parallelism: UInt32;
    TagLen: Integer;
    Tag: string;        // hex
  end;

{$I Argon2StressGolden.inc}

{ ---------------------------------------------------------------------------- }
{  Estado global do teste / relatorio                                          }
{ ---------------------------------------------------------------------------- }

var
  GReport: TStringList;
  GFail: Integer = 0;
  GPass: Integer = 0;
  GSkip: Integer = 0;
  GMaxExp: Integer = 20;        // memoria maxima: 2^20 KiB = 1 GiB
  GSoak: Integer = 100;
  GConcurrency: Integer = 4;
  GDoBench: Boolean = True;
  GDoConcurrency: Boolean = True;
  GDoSoak: Boolean = True;
  GPause: Boolean = False;
  GReportFile: string = 'stress-report.txt';

procedure Log(const s: string);
begin
  Writeln(s);
  if GReport <> nil then
    GReport.Add(s);
end;

procedure Pass(const name: string);
begin
  Inc(GPass);
  Log('  PASS  ' + name);
end;

procedure Fail(const name, detail: string);
begin
  Inc(GFail);
  Log('  FAIL  ' + name + '  -> ' + detail);
end;

function Hex(const p: PByte; const len: Integer): string;
const
  D: array [0 .. 15] of Char = '0123456789abcdef';
var
  i: Integer;
begin
  SetLength(Result, len * 2);
  for i := 0 to len - 1 do
  begin
    Result[2 * i + 1] := D[p[i] shr 4];
    Result[2 * i + 2] := D[p[i] and $0F];
  end;
end;

function TypeName(const t: TArgon2Type): string;
begin
  Result := string(AnsiString(argon2_type2string(t, False)));
end;

{ Cronometro portavel (milissegundos, alta resolucao). Substitui o
  System.Diagnostics.TStopwatch, que nao existe no FPC/Lazarus. }
var
  GQpcFreq: Int64 = 0;

function NowMs: Double;
var
  cnt: Int64;
begin
  if GQpcFreq = 0 then
    QueryPerformanceFrequency(GQpcFreq);
  QueryPerformanceCounter(cnt);
  Result := cnt * 1000.0 / GQpcFreq;
end;

{ Entradas deterministicas para o teste de concorrencia. }
procedure BuildInputs(const idx, it: Integer; var pwd, salt: TBytes);
var
  k: Integer;
begin
  SetLength(pwd, 16);
  for k := 0 to 15 do
    pwd[k] := Byte((idx * 31 + it * 7 + k * 13) and $FF);
  SetLength(salt, 16);
  for k := 0 to 15 do
    salt[k] := Byte((idx * 17 + it * 3 + k * 29 + 11) and $FF);
end;

{ Thread externa: calcula varios hashes em paralelo com outras iguais. }
type
  { Tipo nomeado (em vez de TArray<string>): o codetools do Lazarus nao
    interpreta genericos aqui e poluiria o editor com erro de sintaxe. }
  TStringArray = array of string;

  TStressWorker = class(TThread)
  private
    FIdx, FIters: Integer;
    FMode: TArgon2Type;
    FVersion, FMCost, FTCost, FParallelism: UInt32;
    FTags: TStringArray;
    FErr: Boolean;
    FErrMsg: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const AIdx, AIters: Integer; const AMode: TArgon2Type;
      const AVersion, AMCost, ATCost, AParallelism: UInt32);
    property Tags: TStringArray read FTags;
    property Err: Boolean read FErr;
    property ErrMsg: string read FErrMsg;
  end;

constructor TStressWorker.Create(const AIdx, AIters: Integer;
  const AMode: TArgon2Type;
  const AVersion, AMCost, ATCost, AParallelism: UInt32);
begin
  FIdx := AIdx;
  FIters := AIters;
  FMode := AMode;
  FVersion := AVersion;
  FMCost := AMCost;
  FTCost := ATCost;
  FParallelism := AParallelism;
  inherited Create(True);
  FreeOnTerminate := False;
end;

procedure TStressWorker.Execute;
var
  it, rc: Integer;
  pwd, salt: TBytes;
  hash: array [0 .. 63] of Byte;
begin
  try
    SetLength(FTags, FIters);
    for it := 0 to FIters - 1 do
    begin
      BuildInputs(FIdx, it, pwd, salt);
      rc := argon2_hash(FTCost, FMCost, FParallelism, @pwd[0], Length(pwd),
        @salt[0], Length(salt), @hash[0], 32, nil, 0, FMode, FVersion);
      if rc <> ARGON2_OK then
      begin
        FErr := True;
        FErrMsg := 'rc=' + IntToStr(rc);
        Exit;
      end;
      FTags[it] := Hex(@hash[0], 32);
    end;
  except
    on E: Exception do
    begin
      FErr := True;
      FErrMsg := E.ClassName + ': ' + E.Message;
    end;
  end;
end;

{ ---------------------------------------------------------------------------- }
{  A. Grade de correcao (vetores-ouro da referencia C)                         }
{ ---------------------------------------------------------------------------- }
procedure SectionGolden;
var
  i, rc: Integer;
  pwd, salt: TBytes;
  hash: array [0 .. 63] of Byte;
  bad: Integer;
begin
  Log('');
  Log('== A. Correcao: ' + IntToStr(GOLDEN_COUNT) +
    ' vetores-ouro da referencia C ==');
  SetLength(pwd, 16);
  for i := 0 to 15 do pwd[i] := 1;
  SetLength(salt, 16);
  for i := 0 to 15 do salt[i] := 2;

  bad := 0;
  for i := 0 to GOLDEN_COUNT - 1 do
  begin
    rc := argon2_hash(GOLDEN[i].TCost, GOLDEN[i].MCost, GOLDEN[i].Parallelism,
      @pwd[0], 16, @salt[0], 16, @hash[0], GOLDEN[i].TagLen, nil, 0,
      GOLDEN[i].AType, GOLDEN[i].Version);
    if rc <> ARGON2_OK then
    begin
      Inc(bad);
      Log(Format('  FAIL  #%d %s v%d m=%d t=%d p=%d -> rc=%d',
        [i, TypeName(GOLDEN[i].AType), GOLDEN[i].Version, GOLDEN[i].MCost,
         GOLDEN[i].TCost, GOLDEN[i].Parallelism, rc]));
      Continue;
    end;
    if not SameText(Hex(@hash[0], GOLDEN[i].TagLen), GOLDEN[i].Tag) then
    begin
      Inc(bad);
      Log(Format('  FAIL  #%d %s v%d m=%d t=%d p=%d -> tag divergente',
        [i, TypeName(GOLDEN[i].AType), GOLDEN[i].Version, GOLDEN[i].MCost,
         GOLDEN[i].TCost, GOLDEN[i].Parallelism]));
    end;
  end;

  if bad = 0 then
    Pass(IntToStr(GOLDEN_COUNT) + '/' + IntToStr(GOLDEN_COUNT) +
      ' vetores-ouro conferidos byte-a-byte')
  else
    Fail('grade de correcao', IntToStr(bad) + ' divergencia(s)');
end;

{ ---------------------------------------------------------------------------- }
{  B. Varredura de parametros + benchmark (espelho de src/bench.c)             }
{ ---------------------------------------------------------------------------- }
procedure SectionBench;
const
  PTHS: array [0 .. 3] of UInt32 = (1, 2, 4, 8);
var
  exp, pi, ti, k, rc: Integer;
  m, pth: UInt32;
  pwd, salt: TBytes;
  hash: array [0 .. 63] of Byte;
  types: array [0 .. 2] of TArgon2Type;
  t0: Double;
  ms, total, p1, p4: Double;
  line: string;
  skipped, ran, realFail: Integer;
begin
  Log('');
  Log('== B. Varredura de parametros + benchmark (t=3) ==');
  Log(Format('   maquina: %d CPUs | compilado %d-bit | m ate 2^%d KiB',
    [TThread.ProcessorCount, SizeOf(Pointer) * 8, GMaxExp]));

  types[0] := Argon2_i;
  types[1] := Argon2_d;
  types[2] := Argon2_id;
  { Entradas fixas como em src/bench.c da referencia: pwd = 16 x 0x00,
    salt = 16 x 0x01. }
  SetLength(pwd, 16);
  for k := 0 to 15 do pwd[k] := 0;
  SetLength(salt, 16);
  for k := 0 to 15 do salt[k] := 1;

  ran := 0;
  skipped := 0;
  realFail := 0;
  for exp := 10 to GMaxExp do
  begin
    m := UInt32(1) shl exp;
    for pi := 0 to High(PTHS) do
    begin
      pth := PTHS[pi];
      if UInt64(m) < UInt64(8) * pth then
        Continue;
      total := 0;
      line := '';
      p1 := 0;
      p4 := 0;
      for ti := 0 to 2 do
      begin
        t0 := NowMs;
        rc := argon2_hash(3, m, pth, @pwd[0], 16, @salt[0], 16, @hash[0], 32,
          nil, 0, types[ti], ARGON2_VERSION_13);
        if rc <> ARGON2_OK then
        begin
          { Falha de alocacao = limite da plataforma (ex.: Win32/32-bit):
            conta como SKIP, nao como falha de correcao. }
          if rc = ARGON2_MEMORY_ALLOCATION_ERROR then
          begin
            Inc(skipped);
            Inc(GSkip);
            line := line + Format('%s=SKIP-ALOC ',
              [TypeName(types[ti])]);
          end
          else
          begin
            Inc(realFail);
            line := line + Format('%s=ERRO(%d) ',
              [TypeName(types[ti]), rc]);
          end;
          Continue;
        end;
        Inc(ran);
        ms := NowMs - t0;
        total := total + ms;
        line := line + Format('%s=%.0f ', [TypeName(types[ti]), ms]);
        if pth = 1 then p1 := ms;
        if pth = 4 then p4 := ms;
      end;
      Log(Format('  m=%7d KiB (%5d MiB) p=%d : %s | total=%.0f ms',
        [m, m shr 10, pth, line, total]));
      if (pth = 4) and (p1 > 0) and (p4 > 0) then
        Log(Format('  %s speedup p=4 vs p=1: %.2fx', [TypeName(types[2]),
          p1 / p4]));
    end;
  end;

  if realFail = 0 then
    Pass(Format('benchmark concluido (%d execucoes, %d puladas por memoria)',
      [ran, skipped]))
  else
    Fail('benchmark', IntToStr(realFail) + ' erro(s) inesperado(s)');
end;

{ ---------------------------------------------------------------------------- }
{  C. Determinismo sob estresse (memoria grande)                               }
{ ---------------------------------------------------------------------------- }
procedure SectionDeterminism;
type
  TCfg = record
    Mode: TArgon2Type;
    Version, MCost, TCost, P: UInt32;
  end;
const
  CFGS: array [0 .. 3] of TCfg = (
    (Mode: Argon2_id; Version: 19; MCost: 65536; TCost: 3; P: 4),
    (Mode: Argon2_i;  Version: 19; MCost: 16384; TCost: 2; P: 1),
    (Mode: Argon2_d;  Version: 16; MCost: 4096;  TCost: 2; P: 2),
    (Mode: Argon2_id; Version: 16; MCost: 65536; TCost: 2; P: 4));
var
  i, rc: Integer;
  pwd, salt: TBytes;
  h1, h2: array [0 .. 63] of Byte;
  bad: Integer;
begin
  Log('');
  Log('== C. Determinismo sob estresse (2 execucoes identicas) ==');
  SetLength(pwd, 32);
  for i := 0 to 31 do pwd[i] := Byte(i);
  SetLength(salt, 16);
  for i := 0 to 15 do salt[i] := Byte(255 - i);

  bad := 0;
  for i := 0 to High(CFGS) do
  begin
    rc := argon2_hash(CFGS[i].TCost, CFGS[i].MCost, CFGS[i].P, @pwd[0], 32,
      @salt[0], 16, @h1[0], 32, nil, 0, CFGS[i].Mode, CFGS[i].Version);
    if rc <> ARGON2_OK then
    begin
      Inc(bad);
      Log(Format('  FAIL  cfg#%d rc=%d', [i, rc]));
      Continue;
    end;
    rc := argon2_hash(CFGS[i].TCost, CFGS[i].MCost, CFGS[i].P, @pwd[0], 32,
      @salt[0], 16, @h2[0], 32, nil, 0, CFGS[i].Mode, CFGS[i].Version);
    if (rc <> ARGON2_OK) or (Hex(@h1[0], 32) <> Hex(@h2[0], 32)) then
    begin
      Inc(bad);
      Log(Format('  FAIL  cfg#%d (%s m=%d t=%d p=%d) nao determinista',
        [i, TypeName(CFGS[i].Mode), CFGS[i].MCost, CFGS[i].TCost, CFGS[i].P]));
    end;
  end;
  if bad = 0 then
    Pass(IntToStr(Length(CFGS)) + '/' + IntToStr(Length(CFGS)) +
      ' configuracoes deterministicas')
  else
    Fail('determinismo', IntToStr(bad) + ' falha(s)');
end;

{ ---------------------------------------------------------------------------- }
{  D. Concorrencia (N threads externas)                                        }
{ ---------------------------------------------------------------------------- }
procedure SectionConcurrency;
const
  INNER_P = 4;
  ITERS = 8;
  MMEM = 8192;   // 8 MiB por hash
var
  workers: array of TStressWorker;
  i, it, rc: Integer;
  pwd, salt: TBytes;
  hash: array [0 .. 63] of Byte;
  bad: Integer;
begin
  Log('');
  Log(Format('== D. Concorrencia: %d threads externas x %d hashes ' +
    '(m=%d KiB, p=%d) ==', [GConcurrency, ITERS, MMEM, INNER_P]));

  SetLength(workers, GConcurrency);
  for i := 0 to GConcurrency - 1 do
    workers[i] := TStressWorker.Create(i, ITERS, Argon2_id,
      ARGON2_VERSION_13, MMEM, 3, INNER_P);

  for i := 0 to GConcurrency - 1 do
    workers[i].Start;
  for i := 0 to GConcurrency - 1 do
    workers[i].WaitFor;

  bad := 0;
  for i := 0 to GConcurrency - 1 do
  begin
    if workers[i].Err then
    begin
      Inc(bad);
      Log(Format('  FAIL  worker %d: %s', [i, workers[i].ErrMsg]));
      Continue;
    end;
    for it := 0 to ITERS - 1 do
    begin
      BuildInputs(i, it, pwd, salt);
      rc := argon2_hash(3, MMEM, INNER_P, @pwd[0], Length(pwd), @salt[0],
        Length(salt), @hash[0], 32, nil, 0, Argon2_id, ARGON2_VERSION_13);
      if (rc <> ARGON2_OK) or (Hex(@hash[0], 32) <> workers[i].Tags[it]) then
      begin
        Inc(bad);
        Log(Format('  FAIL  worker %d iter %d divergente (rc=%d)',
          [i, it, rc]));
      end;
    end;
  end;

  for i := 0 to GConcurrency - 1 do
    workers[i].Free;

  if bad = 0 then
    Pass(Format('%d hashes concorrentes conferidos contra recomputo sequencial',
      [GConcurrency * ITERS]))
  else
    Fail('concorrencia', IntToStr(bad) + ' divergencia(s)');
end;

{ ---------------------------------------------------------------------------- }
{  E. Soak aleatorio                                                           }
{ ---------------------------------------------------------------------------- }
procedure SectionSoak;
const
  M_LIST: array [0 .. 7] of UInt32 =
    (8, 16, 32, 64, 128, 256, 1024, 4096);
var
  it, rc, bad, pwdlen, saltlen, outlen, pi: Integer;
  mode: TArgon2Type;
  version, m, t, p: UInt32;
  pwd, salt, wrong: TBytes;
  raw1, raw2: array [0 .. 63] of Byte;
  enc: TBytes;
  encLen: NativeUInt;
  wrongRc: Integer;
begin
  Log('');
  Log(Format('== E. Soak aleatorio: %d combinacoes ==', [GSoak]));
  bad := 0;
  for it := 0 to GSoak - 1 do
  begin
    mode := TArgon2Type(Random(3));
    if Random(2) = 0 then version := ARGON2_VERSION_10
    else version := ARGON2_VERSION_13;
    p := UInt32(1 + Random(4));
    m := M_LIST[Random(Length(M_LIST))];
    if UInt64(m) < UInt64(8) * p then
      m := UInt32(8) * p;
    t := UInt32(1 + Random(4));
    pwdlen := Random(65);
    saltlen := 8 + Random(25);
    outlen := 4 + Random(61);

    SetLength(pwd, pwdlen);
    for pi := 0 to pwdlen - 1 do pwd[pi] := Random(256);
    SetLength(salt, saltlen);
    for pi := 0 to saltlen - 1 do salt[pi] := Random(256);

    rc := argon2_hash(t, m, p, Pointer(pwd), pwdlen, Pointer(salt), saltlen,
      @raw1[0], outlen, nil, 0, mode, version);
    if rc <> ARGON2_OK then
    begin
      Inc(bad);
      Log(Format('  FAIL  #%d raw rc=%d (%s m=%d t=%d p=%d)', [it, rc,
        TypeName(mode), m, t, p]));
      Continue;
    end;

    { Determinismo: recomputa e compara. }
    rc := argon2_hash(t, m, p, Pointer(pwd), pwdlen, Pointer(salt), saltlen,
      @raw2[0], outlen, nil, 0, mode, version);
    if (rc <> ARGON2_OK) or (Hex(@raw1[0], outlen) <> Hex(@raw2[0], outlen)) then
    begin
      Inc(bad);
      Log(Format('  FAIL  #%d nao determinista', [it]));
      Continue;
    end;

    { encoded + verify OK. }
    encLen := argon2_encodedlen(t, m, p, UInt32(saltlen), UInt32(outlen), mode);
    SetLength(enc, Integer(encLen) + 1);
    rc := argon2_hash(t, m, p, Pointer(pwd), pwdlen, Pointer(salt), saltlen,
      nil, outlen, PAnsiChar(@enc[0]), encLen, mode, version);
    if rc <> ARGON2_OK then
    begin
      Inc(bad);
      Log(Format('  FAIL  #%d encoded rc=%d', [it, rc]));
      Continue;
    end;
    rc := argon2_verify(PAnsiChar(@enc[0]), Pointer(pwd), pwdlen, mode);
    if rc <> ARGON2_OK then
    begin
      Inc(bad);
      Log(Format('  FAIL  #%d verify(senha certa) rc=%d', [it, rc]));
      Continue;
    end;

    { verify com senha errada -> VERIFY_MISMATCH }
    SetLength(wrong, pwdlen);
    if pwdlen > 0 then
      Move(pwd[0], wrong[0], pwdlen);
    if pwdlen > 0 then
      wrong[0] := wrong[0] xor $FF
    else
    begin
      SetLength(wrong, 1);
      wrong[0] := 1;
    end;
    wrongRc := argon2_verify(PAnsiChar(@enc[0]), Pointer(wrong), Length(wrong),
      mode);
    if wrongRc <> ARGON2_VERIFY_MISMATCH then
    begin
      Inc(bad);
      Log(Format('  FAIL  #%d verify(senha errada) rc=%d (esperado %d)',
        [it, wrongRc, ARGON2_VERIFY_MISMATCH]));
    end;
  end;

  if bad = 0 then
    Pass(IntToStr(GSoak) + ' combinacoes: raw/encoded/verify/determinismo OK')
  else
    Fail('soak', IntToStr(bad) + ' falha(s)');
end;

{ ---------------------------------------------------------------------------- }
{  F. Caminhos de erro + fachada THDArgon2                                     }
{ ---------------------------------------------------------------------------- }
procedure SectionErrors;
var
  pwd, salt: TBytes;
  out: array [0 .. 31] of Byte;
  enc: array [0 .. 31] of AnsiChar;
  rc: Integer;
  h: string;
  ok, bad: Integer;
  invalidType: Integer;
begin
  Log('');
  Log('== F. Caminhos de erro e fachada THDArgon2 ==');
  ok := 0;
  bad := 0;

  SetLength(pwd, 16);
  SetLength(salt, 16);

  rc := argon2_hash(2, 1, 1, @pwd[0], 16, @salt[0], 16, @out[0], 32, nil, 0,
    Argon2_id, ARGON2_VERSION_13);
  if rc = ARGON2_MEMORY_TOO_LITTLE then Inc(ok)
  else begin Inc(bad); Log(Format('  FAIL  memoria minima -> rc=%d', [rc])); end;

  rc := argon2_hash(2, 1024, 1, nil, 16, @salt[0], 16, @out[0], 32, nil, 0,
    Argon2_id, ARGON2_VERSION_13);
  if rc = ARGON2_PWD_PTR_MISMATCH then Inc(ok)
  else begin Inc(bad); Log(Format('  FAIL  pwd nil -> rc=%d', [rc])); end;

  rc := argon2_hash(2, 1024, 1, @pwd[0], 16, @salt[0], 1, @out[0], 32, nil, 0,
    Argon2_id, ARGON2_VERSION_13);
  if rc = ARGON2_SALT_TOO_SHORT then Inc(ok)
  else begin Inc(bad); Log(Format('  FAIL  salt curto -> rc=%d', [rc])); end;

  rc := argon2_hash(2, 1024, 1, @pwd[0], 16, @salt[0], 16, @out[0], 2, nil, 0,
    Argon2_id, ARGON2_VERSION_13);
  if rc = ARGON2_OUTPUT_TOO_SHORT then Inc(ok)
  else begin Inc(bad); Log(Format('  FAIL  outlen curto -> rc=%d', [rc])); end;

  { encoded com buffer pequeno -> ENCODING_FAIL }
  rc := argon2_hash(2, 1024, 1, @pwd[0], 16, @salt[0], 16, @out[0], 32,
    @enc[0], 4, Argon2_id, ARGON2_VERSION_13);
  if rc = ARGON2_ENCODING_FAIL then Inc(ok)
  else begin Inc(bad); Log(Format('  FAIL  enc pequeno -> rc=%d', [rc])); end;

  { tipo invalido via argon2_ctx }
  invalidType := 7;  { via variavel: evita warning de range no FPC }
  rc := argon2_hash(2, 1024, 1, @pwd[0], 16, @salt[0], 16, @out[0], 32, nil, 0,
    TArgon2Type(invalidType), ARGON2_VERSION_13);
  if rc = ARGON2_INCORRECT_TYPE then Inc(ok)
  else begin Inc(bad); Log(Format('  FAIL  tipo invalido -> rc=%d', [rc])); end;

  { verify com string invalida -> DECODING_FAIL }
  rc := argon2_verify('$argon2id$lixo', @pwd[0], 16, Argon2_id);
  if rc = ARGON2_DECODING_FAIL then Inc(ok)
  else begin Inc(bad); Log(Format('  FAIL  decode invalido -> rc=%d', [rc])); end;

  { fachada: hash -> verify ok/errado, NeedsRehash, ErrorMessage }
  THDArgon2.Mode := Argon2_id;
  THDArgon2.Iterations := 2;
  THDArgon2.Memory := 1024;
  THDArgon2.Parallelism := 1;
  h := THDArgon2.HashPassword('senha-de-teste');
  if THDArgon2.VerifyPassword(h, 'senha-de-teste') then Inc(ok)
  else begin Inc(bad); Log('  FAIL  fachada verify(certa)'); end;
  if not THDArgon2.VerifyPassword(h, 'outra-senha') then Inc(ok)
  else begin Inc(bad); Log('  FAIL  fachada verify(errada)'); end;
  if not THDArgon2.NeedsRehash(h) then Inc(ok)
  else begin Inc(bad); Log('  FAIL  fachada NeedsRehash=false'); end;
  THDArgon2.Iterations := 5;
  if THDArgon2.NeedsRehash(h) then Inc(ok)
  else begin Inc(bad); Log('  FAIL  fachada NeedsRehash=true'); end;
  if THDArgon2.ErrorMessage(ARGON2_VERIFY_MISMATCH) <> '' then Inc(ok)
  else begin Inc(bad); Log('  FAIL  fachada ErrorMessage vazio'); end;

  if bad = 0 then
    Pass(IntToStr(ok) + ' checagens de erro/fachada OK')
  else
    Fail('caminhos de erro', IntToStr(bad) + ' falha(s)');
end;

{ ---------------------------------------------------------------------------- }
{  Argumentos / ajuda                                                          }
{ ---------------------------------------------------------------------------- }
function MaxExpAllowed: Integer;
var
  maxMem: UInt32;
  e: Integer;
begin
  maxMem := Argon2MaxMemory;   // KiB
  e := 0;
  while (e < 40) and ((UInt64(1) shl (e + 1)) <= UInt64(maxMem)) do
    Inc(e);
  Result := e;
end;

procedure Usage;
begin
  Writeln('Uso: Argon2StressTest [opcoes]');
  Writeln('  --quick            perfil rapido (m ate 16 MiB, soak 40, conc 2)');
  Writeln('  --big              inclui memoria grande (m ate 4 GiB; exige 64-bit)');
  Writeln('  --max-mib=N        memoria maxima da varredura em MiB (default 1024)');
  Writeln('  --soak=N           numero de combinacoes aleatorias (default 100)');
  Writeln('  --concurrency=N    threads externas simultaneas (default 4)');
  Writeln('  --no-bench         pula a varredura/benchmark');
  Writeln('  --no-concurrency   pula o teste de concorrencia');
  Writeln('  --no-soak          pula o soak aleatorio');
  Writeln('  --report=ARQ       arquivo de relatorio (default stress-report.txt)');
  Writeln('  --pause            aguarda ENTER ao final');
  Writeln('  --help             mostra esta ajuda');
end;

function ParseArgs: Boolean;
var
  i: Integer;
  a, key, val: string;
  mib: Integer;

  function SplitArg(const s: string; var k, v: string): Boolean;
  var
    p: Integer;
  begin
    p := Pos('=', s);
    if p > 0 then
    begin
      k := Copy(s, 1, p - 1);
      v := Copy(s, p + 1, MaxInt);
      Result := True;
    end
    else
    begin
      k := s;
      v := '';
      Result := False;
    end;
  end;

begin
  Result := True;
  i := 1;
  while i <= ParamCount do
  begin
    a := ParamStr(i);
    SplitArg(a, key, val);
    if key = '--help' then
    begin
      Usage;
      Result := False;
      Exit;
    end
    else if key = '--quick' then
    begin
      GMaxExp := 14;
      GSoak := 40;
      GConcurrency := 2;
    end
    else if key = '--big' then
      GMaxExp := 22
    else if key = '--max-mib' then
    begin
      mib := StrToIntDef(val, 256);
      if mib < 1 then mib := 1;
      mib := mib * 1024;   // KiB
      GMaxExp := 0;
      while (GMaxExp < 31) and ((UInt64(1) shl (GMaxExp + 1)) <= UInt64(mib)) do
        Inc(GMaxExp);
    end
    else if key = '--soak' then
      GSoak := StrToIntDef(val, GSoak)
    else if key = '--concurrency' then
    begin
      GConcurrency := StrToIntDef(val, GConcurrency);
      if GConcurrency < 1 then GConcurrency := 1;
    end
    else if key = '--no-bench' then
      GDoBench := False
    else if key = '--no-concurrency' then
      GDoConcurrency := False
    else if key = '--no-soak' then
      GDoSoak := False
    else if key = '--report' then
      GReportFile := val
    else if key = '--pause' then
      GPause := True
    else
    begin
      Writeln('Opcao desconhecida: ', a);
      Usage;
      Result := False;
      Exit;
    end;
    Inc(i);
  end;
end;

{ ---------------------------------------------------------------------------- }
var
  maxAllowed: Integer;
  t0: Double;
begin
  if not ParseArgs then
  begin
    ExitCode := 2;
    Exit;
  end;

  GReport := TStringList.Create;
  Randomize;

  maxAllowed := MaxExpAllowed;
  if GMaxExp > maxAllowed then
  begin
    Writeln(Format('Aviso: 2^%d KiB excede o maximo desta plataforma (%d-bit, ' +
      '2^%d KiB). Reduzindo.', [GMaxExp, SizeOf(Pointer) * 8, maxAllowed]));
    GMaxExp := maxAllowed;
  end;

  Log('==================================================================');
  Log('  HD-Argon2Lib4D - Teste de estresse');
  Log('==================================================================');
  Log(Format('  Data        : %s', [DateTimeToStr(Now)]));
  Log(Format('  Plataforma  : %d-bit, %d CPUs',
    [SizeOf(Pointer) * 8, TThread.ProcessorCount]));
  Log(Format('  Benchmark   : %s (m ate 2^%d KiB)', [BoolToStr(GDoBench, True),
    GMaxExp]));
  Log(Format('  Concorrencia: %s (%d threads)',
    [BoolToStr(GDoConcurrency, True), GConcurrency]));
  Log(Format('  Soak        : %s (%d combinacoes)',
    [BoolToStr(GDoSoak, True), GSoak]));

  t0 := NowMs;

  SectionGolden;
  if GDoBench then SectionBench;
  SectionDeterminism;
  if GDoConcurrency then SectionConcurrency;
  if GDoSoak then SectionSoak;
  SectionErrors;

  Log('');
  Log('==================================================================');
  Log(Format('  RESULTADO: %d PASS, %d FAIL, %d SKIP em %.1f s',
    [GPass, GFail, GSkip, (NowMs - t0) / 1000.0]));
  if GFail = 0 then
    Log('  ESTE TESTE DE ESTRESSE PASSOU (0 falhas)')
  else
    Log(Format('  TESTE DE ESTRESSE FALHOU (%d falha(s))', [GFail]));
  Log('==================================================================');

  try
    GReport.SaveToFile(GReportFile);
    Writeln('Relatorio gravado em: ', ExpandFileName(GReportFile));
  except
    on E: Exception do
      Writeln('Aviso: nao foi possivel gravar o relatorio: ', E.Message);
  end;

  GReport.Free;

  if GFail = 0 then
    ExitCode := 0
  else
    ExitCode := 1;

  if GPause then
  begin
    Writeln('Pressione ENTER para sair...');
    Readln;
  end;
end.
