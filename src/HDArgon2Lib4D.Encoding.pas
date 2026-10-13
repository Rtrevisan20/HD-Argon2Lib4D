{******************************************************************************}
{  HDArgon2Lib4D - Porte nativo do Argon2 (P-H-C/phc-winner-argon2) para Pascal  }
{                                                                              }
{  Unit   : HDArgon2Lib4D.Encoding                                            }
{  Fase   : 4                                                                    }
{  Papel  : codificacao/decodificacao PHC. Base64 sem padding (to_base64 /      }
{           from_base64 de Thomas Pornin) + encode_string / decode_string.       }
{                                                                              }
{  Baseado em: src/encoding.c + src/encoding.h                                   }
{  Licenca original: CC0 1.0 (T. Pornin) / Apache 2.0 (atribuicao mantida).     }
{******************************************************************************}

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)

unit HDArgon2Lib4D.Encoding;

interface

uses
  HDArgon2Lib4D.Types;

{ --- Base64 PHC (sem '=' de padding) --- }

{ Codifica src[0..src_len-1] como Base64 (sem padding) em dst, terminando com
  #0. dst_len e a capacidade de dst em chars (incluindo o #0). Retorna o numero
  de chars escritos (sem contar o #0), ou NativeUInt(-1) se dst for pequeno. }
function B64Encode(dst: PAnsiChar; const dst_len: NativeUInt; src: Pointer;
  const src_len: NativeUInt): NativeUInt;

{ Decodifica Base64 de src para dst. dst_len entra com a capacidade de dst e sai
  com o numero de bytes decodificados. Retorna o ponteiro para o primeiro char
  nao-Base64, ou nil em caso de erro. }
function B64Decode(dst: Pointer; var dst_len: NativeUInt;
  src: PAnsiChar): PAnsiChar;

{ Numero de chars Base64 necessarios para 'len' bytes (sem padding). }
function B64Len(const len: UInt32): NativeUInt;

{ Numero de digitos decimais de 'num'. }
function NumLen(const num: UInt32): NativeUInt;

{ --- Formatos PHC do Argon2 --- }
{ $argon2<T>[$v=<num>]$m=<num>,t=<num>,p=<num>$<salt-b64>$<out-b64> }

{ Escreve a string PHC em dst. Retorna ARGON2_OK ou ARGON2_ENCODING_FAIL. }
function EncodeString(dst: PAnsiChar; const dst_len: NativeUInt;
  ctx: PArgon2Context; const atype: TArgon2Type): Integer;

{ Preenche ctx a partir da string PHC 'str'. Antes da chamada, ctx.salt/saltlen
  e ctx.output/outlen devem conter buffers e capacidades maximas. }
function DecodeString(ctx: PArgon2Context; str: PAnsiChar;
  const atype: TArgon2Type): Integer;

implementation

uses
{$IFDEF FPC}
  SysUtils,
{$ELSE}
  System.SysUtils,
{$ENDIF}
  HDArgon2Lib4D.Core;

function B64ByteToChar(const x: Byte): AnsiChar;
begin
  if x < 26 then
    Result := AnsiChar(Ord('A') + x)
  else if x < 52 then
    Result := AnsiChar(Ord('a') + x - 26)
  else if x < 62 then
    Result := AnsiChar(Ord('0') + x - 52)
  else if x = 62 then
    Result := '+'
  else
    Result := '/';
end;

{ Retorna o valor 0..63, ou $FF se o char nao for Base64. }
function B64CharToByte(const c: Byte): Byte;
begin
  if (c >= Ord('A')) and (c <= Ord('Z')) then
    Result := c - Ord('A')
  else if (c >= Ord('a')) and (c <= Ord('z')) then
    Result := c - Ord('a') + 26
  else if (c >= Ord('0')) and (c <= Ord('9')) then
    Result := c - Ord('0') + 52
  else if c = Ord('+') then
    Result := 62
  else if c = Ord('/') then
    Result := 63
  else
    Result := $FF;
end;

function B64Encode(dst: PAnsiChar; const dst_len: NativeUInt; src: Pointer;
  const src_len: NativeUInt): NativeUInt;
var
  olen, n: NativeUInt;
  buf: PByte;
  acc, acc_len: Cardinal;
begin
  olen := (src_len div 3) shl 2;
  case src_len mod 3 of
    2: olen := olen + 1 + 2;
    1: olen := olen + 2;
  end;

  if dst_len <= olen then
    Exit(NativeUInt(-1));

  acc := 0;
  acc_len := 0;
  buf := PByte(src);
  n := src_len;
  while n > 0 do
  begin
    acc := (acc shl 8) + buf^;
    Inc(buf);
    Inc(acc_len, 8);
    while acc_len >= 6 do
    begin
      Dec(acc_len, 6);
      dst^ := B64ByteToChar((acc shr acc_len) and $3F);
      Inc(dst);
    end;
    Dec(n);
  end;
  if acc_len > 0 then
  begin
    dst^ := B64ByteToChar((acc shl (6 - acc_len)) and $3F);
    Inc(dst);
  end;
  dst^ := #0;
  Result := olen;
end;

function B64Decode(dst: Pointer; var dst_len: NativeUInt;
  src: PAnsiChar): PAnsiChar;
var
  len: NativeUInt;
  buf: PByte;
  acc, acc_len: Cardinal;
  d: Byte;
begin
  buf := PByte(dst);
  len := 0;
  acc := 0;
  acc_len := 0;
  while True do
  begin
    d := B64CharToByte(Byte(src^));
    if d = $FF then
      Break;
    Inc(src);
    acc := (acc shl 6) + d;
    Inc(acc_len, 6);
    if acc_len >= 8 then
    begin
      Dec(acc_len, 8);
      if len >= dst_len then
        Exit(nil);
      Inc(len);
      buf^ := Byte((acc shr acc_len) and $FF);
      Inc(buf);
    end;
  end;

  if (acc_len > 4) or ((acc and ((Cardinal(1) shl acc_len) - 1)) <> 0) then
    Exit(nil);

  dst_len := len;
  Result := src;
end;

function B64Len(const len: UInt32): NativeUInt;
var
  olen: NativeUInt;
begin
  olen := (NativeUInt(len) div 3) shl 2;
  case len mod 3 of
    2: olen := olen + 1 + 2;
    1: olen := olen + 2;
  end;
  Result := olen;
end;

function NumLen(const num: UInt32): NativeUInt;
var
  n: UInt32;
begin
  Result := 1;
  n := num;
  while n >= 10 do
  begin
    Inc(Result);
    n := n div 10;
  end;
end;

{ Converte a sequencia decimal em 'str' para inteiro (>=0). Retorna o ponteiro
  apos os digitos, ou nil se invalido/sem digitos/zeros a esquerda/overflow. }
function DecodeDecimal(str: PAnsiChar; out v: UInt64): PAnsiChar;
var
  orig: PAnsiChar;
  acc: UInt64;
  c: Integer;
begin
  acc := 0;
  orig := str;
  while True do
  begin
    c := Ord(str^);
    if (c < Ord('0')) or (c > Ord('9')) then
      Break;
    c := c - Ord('0');
    if acc > (High(UInt64) div 10) then
      Exit(nil);
    acc := acc * 10;
    if UInt64(Cardinal(c)) > (High(UInt64) - acc) then
      Exit(nil);
    acc := acc + UInt64(Cardinal(c));
    Inc(str);
  end;
  if (str = orig) or ((orig^ = '0') and (str <> orig + 1)) then
    Exit(nil);
  v := acc;
  Result := str;
end;

function B64EncodeStr(const p: Pointer; const n: NativeUInt): AnsiString;
var
  tmp: TBytes;
  l: NativeUInt;
begin
  if n = 0 then
    Exit('');
  SetLength(tmp, B64Len(n) + 1);
  l := B64Encode(PAnsiChar(@tmp[0]), NativeUInt(Length(tmp)), p, n);
  if l = NativeUInt(-1) then
    Exit('');
  SetLength(tmp, l);
  Result := AnsiString(PAnsiChar(@tmp[0]));
end;

function EncodeString(dst: PAnsiChar; const dst_len: NativeUInt;
  ctx: PArgon2Context; const atype: TArgon2Type): Integer;
var
  typeStr: string;
  buf: AnsiString;
  vr: Integer;
begin
  if ctx = nil then
    Exit(ARGON2_ENCODING_FAIL);

  typeStr := Argon2TypeToString(atype, False);
  if typeStr = '' then
    Exit(ARGON2_ENCODING_FAIL);

  vr := validate_inputs(ctx);
  if vr <> ARGON2_OK then
    Exit(vr);

  buf := '';
  buf := buf + '$';
  buf := buf + AnsiString(typeStr);
  buf := buf + '$v=';
  buf := buf + AnsiString(IntToStr(ctx^.version));
  buf := buf + '$m=';
  buf := buf + AnsiString(IntToStr(ctx^.m_cost));
  buf := buf + ',t=';
  buf := buf + AnsiString(IntToStr(ctx^.t_cost));
  buf := buf + ',p=';
  buf := buf + AnsiString(IntToStr(ctx^.lanes));
  buf := buf + '$';
  buf := buf + B64EncodeStr(ctx^.salt, ctx^.saltlen);
  buf := buf + '$';
  buf := buf + B64EncodeStr(ctx^.output, ctx^.outlen);

  if NativeUInt(Length(buf)) >= dst_len then
    Exit(ARGON2_ENCODING_FAIL);

  Move(buf[1], dst^, Length(buf));
  dst[Length(buf)] := #0;
  Result := ARGON2_OK;
end;

function DecodeString(ctx: PArgon2Context; str: PAnsiChar;
  const atype: TArgon2Type): Integer;
var
  p: PAnsiChar;
  typeStr: AnsiString;
  maxsaltlen, maxoutlen: UInt32;
  binLen: NativeUInt;
  dec: UInt64;
  vr: Integer;

  function MatchPrefix(const prefix: AnsiString): Boolean;
  var
    i: Integer;
  begin
    for i := 1 to Length(prefix) do
      if p[i - 1] <> prefix[i] then
        Exit(False);
    Result := True;
  end;

  procedure Skip(const n: Integer);
  begin
    Inc(p, n);
  end;

  function ReadU32(out value: UInt32): Boolean;
  begin
    p := DecodeDecimal(p, dec);
    if (p = nil) or (dec > High(UInt32)) then
      Exit(False);
    value := UInt32(dec);
    Result := True;
  end;

  function ReadBin(dstbuf: Pointer; var actual, maxcap: UInt32): Boolean;
  begin
    binLen := maxcap;
    p := B64Decode(dstbuf, binLen, p);
{$IFDEF FPC}{$WARN 4044 OFF}{$WARN 6018 OFF}{$ELSE}{$WARN COMPARISON_FALSE OFF}{$ENDIF}
    if (p = nil) or (binLen > High(UInt32)) then
      Exit(False);
{$IFDEF FPC}{$WARN 4044 ON}{$WARN 6018 ON}{$ELSE}{$WARN COMPARISON_FALSE ON}{$ENDIF}
    actual := UInt32(binLen);
    Result := True;
  end;

begin
  if (ctx = nil) or (str = nil) then
    Exit(ARGON2_DECODING_FAIL);

  p := str;
  typeStr := AnsiString(Argon2TypeToString(atype, False));
  if typeStr = '' then
    Exit(ARGON2_INCORRECT_TYPE);

  maxsaltlen := ctx^.saltlen;
  maxoutlen := ctx^.outlen;

  if not MatchPrefix('$') then
    Exit(ARGON2_DECODING_FAIL);
  Skip(1);
  if not MatchPrefix(typeStr) then
    Exit(ARGON2_DECODING_FAIL);
  Skip(Length(typeStr));

  ctx^.version := ARGON2_VERSION_10;
  if MatchPrefix('$v=') then
  begin
    Skip(3);
    if not ReadU32(ctx^.version) then
      Exit(ARGON2_DECODING_FAIL);
  end;

  if not MatchPrefix('$m=') then
    Exit(ARGON2_DECODING_FAIL);
  Skip(3);
  if not ReadU32(ctx^.m_cost) then
    Exit(ARGON2_DECODING_FAIL);

  if not MatchPrefix(',t=') then
    Exit(ARGON2_DECODING_FAIL);
  Skip(3);
  if not ReadU32(ctx^.t_cost) then
    Exit(ARGON2_DECODING_FAIL);

  if not MatchPrefix(',p=') then
    Exit(ARGON2_DECODING_FAIL);
  Skip(3);
  if not ReadU32(ctx^.lanes) then
    Exit(ARGON2_DECODING_FAIL);
  ctx^.threads := ctx^.lanes;

  if not MatchPrefix('$') then
    Exit(ARGON2_DECODING_FAIL);
  Skip(1);
  if not ReadBin(ctx^.salt, ctx^.saltlen, maxsaltlen) then
    Exit(ARGON2_DECODING_FAIL);

  if not MatchPrefix('$') then
    Exit(ARGON2_DECODING_FAIL);
  Skip(1);
  if not ReadBin(ctx^.output, ctx^.outlen, maxoutlen) then
    Exit(ARGON2_DECODING_FAIL);

  ctx^.secret := nil;
  ctx^.secretlen := 0;
  ctx^.ad := nil;
  ctx^.adlen := 0;
  ctx^.allocate_cbk := nil;
  ctx^.free_cbk := nil;
  ctx^.flags := ARGON2_DEFAULT_FLAGS;

  vr := validate_inputs(ctx);
  if vr <> ARGON2_OK then
    Exit(vr);

  if p^ = #0 then
    Result := ARGON2_OK
  else
    Result := ARGON2_DECODING_FAIL;
end;

end.
