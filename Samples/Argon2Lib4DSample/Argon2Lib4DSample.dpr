{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)
program Argon2Lib4DSample;

{ Exemplo de uso da biblioteca nativa HD-Argon2Lib4D (sem argon2.dll).

  Demonstra:
    1. Auto-teste com vetores conhecidos (independe de qualquer DLL).
    2. argon2id_hash_encoded + argon2id_verify (senha certa/errada).
    3. argon2id_hash_raw (tag em hex).
    4. Benchmark (single-thread p=1 vs multi-thread p=4).

  Compile junto com os fontes: a search path do projeto aponta para ..\..\src. }

{$APPTYPE CONSOLE}

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

const
  SAMPLE_PWD = 'correct horse battery staple';

function BytesToHex(const b: array of Byte): string;
const
  Hex: array [0 .. 15] of Char = '0123456789abcdef';
var
  i: Integer;
begin
  SetLength(Result, Length(b) * 2);
  for i := 0 to High(b) do
  begin
    Result[2 * i + 1] := Hex[b[i] shr 4];
    Result[2 * i + 2] := Hex[b[i] and $0F];
  end;
end;

function StrToBytes(const s: string): TBytes;
begin
{$IFDEF FPC}
  Result := TEncoding.ANSI.GetBytes(UnicodeString(s));
{$ELSE}
  Result := TEncoding.ANSI.GetBytes(s);
{$ENDIF}
end;

function RandomSalt(const n: Integer): TBytes;
var
  i: Integer;
begin
  Result := nil;
  SetLength(Result, n);
  for i := 0 to n - 1 do
    Result[i] := Random(256);
end;

procedure Sep(const title: string);
begin
  Writeln;
  Writeln('== ', title, ' ==');
end;

{ 0. Uso simples via fachada (THDArgon2) - o jeito recomendado para senhas.
     Esconde contexto/buffers: gera salt aleatorio seguro e a string PHC. }
procedure DemoFacade;
var
  h: string;
  tag: TBytes;
begin
  THDArgon2.Iterations := 3;
  THDArgon2.Memory := 19456;
  THDArgon2.Parallelism := 4;

  h := THDArgon2.HashPassword(SAMPLE_PWD);
  Writeln('  encoded      : ', h);
  Writeln('  verify OK    : ', THDArgon2.VerifyPassword(h, SAMPLE_PWD));
  Writeln('  verify errado: ', THDArgon2.VerifyPassword(h, 'senhaErrada'));
  Writeln('  needs rehash : ', THDArgon2.NeedsRehash(h));

  tag := THDArgon2.HashRaw(SAMPLE_PWD);
  Writeln('  tag (32 bytes): ', BytesToHex(tag));
end;

{ 1. Vetores conhecidos (sem secret/ad), gerados pela referencia C oficial.
     pwd = 32 x 0x01, salt = 16 x 0x02, m=32, t=3, p=4, taglen=32. }
function KnownVectors: Integer;
const
  ExpId = '03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e';
  ExpI  = 'a9a7510e6db4d588ba3414cd0e094d480d683f97b9ccb612a544fe8ef65ba8e0';
  ExpD  = '9e34c31a47866ce0c30a90c69dd21022d5329a3b75f9c513722dd2541fe93a1a';

  function Run(const atype: TArgon2Type): string;
  var
    pwd: array [0 .. 31] of Byte;
    salt: array [0 .. 15] of Byte;
    hash: array [0 .. 31] of Byte;
    i, rc: Integer;
  begin
    for i := 0 to 31 do pwd[i] := 1;
    for i := 0 to 15 do salt[i] := 2;
    case atype of
      Argon2_i: rc := argon2i_hash_raw(3, 32, 4, @pwd[0], 32, @salt[0], 16, @hash[0], 32);
      Argon2_d: rc := argon2d_hash_raw(3, 32, 4, @pwd[0], 32, @salt[0], 16, @hash[0], 32);
    else
      rc := argon2id_hash_raw(3, 32, 4, @pwd[0], 32, @salt[0], 16, @hash[0], 32);
    end;
    if rc <> ARGON2_OK then
      Result := 'rc=' + IntToStr(rc)
    else
      Result := BytesToHex(hash);
  end;

  procedure Check(const name, got, want: string; var fails: Integer);
  begin
    if SameText(got, want) then
      Writeln('  ', name, ': PASS')
    else
    begin
      Inc(fails);
      Writeln('  ', name, ': FAIL got=', got, ' want=', want);
    end;
  end;

begin
  Result := 0;
  Check('argon2id_hash_raw', Run(Argon2_id), ExpId, Result);
  Check('argon2i_hash_raw ', Run(Argon2_i), ExpI, Result);
  Check('argon2d_hash_raw ', Run(Argon2_d), ExpD, Result);
end;

{ 2. Hash de senha com parametros (m=19 MiB, t=2, p=1) + verify. }
procedure DemoEncodeVerify;
var
  pwd, pwdWrong: TBytes;
  salt: TBytes;
  enc: array [0 .. 255] of AnsiChar;
  s: AnsiString;
  rc: Integer;
begin
  pwd := StrToBytes(SAMPLE_PWD);
  pwdWrong := StrToBytes('senhaErrada');
  salt := RandomSalt(16);

  rc := argon2id_hash_encoded(2, 19456, 1, @pwd[0], Length(pwd),
    @salt[0], Length(salt), 32, @enc[0], SizeOf(enc));
  if rc <> ARGON2_OK then
  begin
    Writeln('  hash_encoded falhou: ', argon2_error_message(rc));
    Exit;
  end;

  s := AnsiString(PAnsiChar(@enc[0]));
  Writeln('  senha      : ', SAMPLE_PWD);
  Writeln('  encoded    : ', string(s));

  rc := argon2id_verify(PAnsiChar(s), @pwd[0], Length(pwd));
  Writeln('  verify OK  : ', argon2_error_message(rc));

  rc := argon2id_verify(PAnsiChar(s), @pwdWrong[0], Length(pwdWrong));
  Writeln('  verify bad : ', argon2_error_message(rc));
end;

{ 3. Tag raw em hex. }
procedure DemoRaw;
var
  pwd: TBytes;
  salt: TBytes;
  hash: array [0 .. 31] of Byte;
  rc: Integer;
begin
  pwd := StrToBytes(SAMPLE_PWD);
  salt := RandomSalt(16);
  rc := argon2id_hash_raw(2, 19456, 1, @pwd[0], Length(pwd),
    @salt[0], Length(salt), @hash[0], 32);
  if rc = ARGON2_OK then
    Writeln('  tag (32 bytes): ', BytesToHex(hash))
  else
    Writeln('  falhou: ', argon2_error_message(rc));
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

function BenchOne(const threads: UInt32): Double;
var
  pwd: TBytes;
  salt: TBytes;
  hash: array [0 .. 31] of Byte;
  t0: Double;
  rc: Integer;
begin
  pwd := StrToBytes(SAMPLE_PWD);
  salt := RandomSalt(16);
  t0 := NowMs;
  rc := argon2id_hash_raw(3, 65536, threads, @pwd[0], Length(pwd),
    @salt[0], Length(salt), @hash[0], 32);
  if rc <> ARGON2_OK then
    Exit(-1);
  Result := NowMs - t0;
end;

{ 4. Benchmark de desempenho (util para avaliar a necessidade de SIMD). }
procedure Benchmark;
var
  st, mt: Double;
begin
  Writeln('  parametros: m=64 MiB, t=3, taglen=32');
  st := BenchOne(1);
  mt := BenchOne(4);
  Writeln(Format('  p=1 (single-thread): %.1f ms', [st]));
  Writeln(Format('  p=4 (multi-thread) : %.1f ms', [mt]));
  if (st > 0) and (mt > 0) then
    Writeln(Format('  speedup p=4: %.2fx', [st / mt]));
end;

var
  fails: Integer;
begin
  Randomize;
  {$IFDEF WIN32}
    Writeln('HD-Argon2Lib4D - exemplo de uso 32 Bits');
  {$ENDIF}
  {$IFDEF WIN64}
    Writeln('HD-Argon2Lib4D - exemplo de uso 64 Bits');
  {$ENDIF}

  Sep('0. Uso simples via fachada (THDArgon2)');
  DemoFacade;

  Sep('1. Vetores conhecidos');
  fails := KnownVectors;

  Sep('2. argon2id_hash_encoded + verify');
  DemoEncodeVerify;

  Sep('3. argon2id_hash_raw');
  DemoRaw;

  Sep('4. Benchmark');
  Benchmark;

  Sep('Resultado');
  if fails = 0 then
    Writeln('  Auto-teste: OK (0 falhas)')
  else
    Writeln('  Auto-teste: ', fails, ' falha(s)');
  Writeln('  Pressione ENTER para sair...');
  Readln;
end.
