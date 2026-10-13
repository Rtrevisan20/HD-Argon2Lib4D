{******************************************************************************}
{  HDArgon2Lib4D - Porte nativo do Argon2 (P-H-C/phc-winner-argon2) para Pascal  }
{                                                                              }
{  Unit   : HDArgon2Lib4D.Blake2b                                             }
{  Fase   : 1                                                                    }
{  Papel  : BLAKE2b (init/init_key/init_param/update/final) + blake2b_long.     }
{                                                                              }
{  Baseado em: src/blake2/blake2b.c, blake2.h, blake2-impl.h                    }
{  Licenca original: CC0 1.0 / Apache 2.0 (atribuicao mantida).                }
{******************************************************************************}

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)

unit HDArgon2Lib4D.Blake2b;

{$Q-}{$R-}

interface

uses
  HDArgon2Lib4D.Types;

type
  { blake2b_param - layout empacotado de 64 bytes (packed) }
  TBlake2bParam = packed record
    digest_length: Byte;                    { 1  }
    key_length: Byte;                       { 2  }
    fanout: Byte;                           { 3  }
    depth: Byte;                            { 4  }
    leaf_length: UInt32;                    { 8  }
    node_offset: UInt64;                    { 16 }
    node_depth: Byte;                       { 17 }
    inner_length: Byte;                     { 18 }
    reserved: array [0 .. 13] of Byte;      { 32 }
    salt: array [0 .. BLAKE2B_SALTBYTES - 1] of Byte;          { 48 }
    personal: array [0 .. BLAKE2B_PERSONALBYTES - 1] of Byte;  { 64 }
  end;

  TBlake2bState = record
    h: array [0 .. 7] of UInt64;
    t: array [0 .. 1] of UInt64;
    f: array [0 .. 1] of UInt64;
    buf: array [0 .. BLAKE2B_BLOCKBYTES - 1] of Byte;
    buflen: Cardinal;
    outlen: Cardinal;
    last_node: Byte;
  end;

function blake2b_init(var S: TBlake2bState; outlen: NativeUInt): Integer;
function blake2b_init_key(var S: TBlake2bState; outlen: NativeUInt;
  key: Pointer; keylen: NativeUInt): Integer;
function blake2b_init_param(var S: TBlake2bState;
  const P: TBlake2bParam): Integer;
function blake2b_update(var S: TBlake2bState; inData: Pointer;
  inlen: NativeUInt): Integer;
function blake2b_final(var S: TBlake2bState; outData: Pointer;
  outlen: NativeUInt): Integer;
function blake2b(outData: Pointer; outlen: NativeUInt; inData: Pointer;
  inlen: NativeUInt; key: Pointer; keylen: NativeUInt): Integer;
function blake2b_long(outData: Pointer; outlen: NativeUInt; inData: Pointer;
  inlen: NativeUInt): Integer;

implementation

const
  blake2b_IV: array [0 .. 7] of UInt64 = (
    UInt64($6a09e667f3bcc908), UInt64($bb67ae8584caa73b),
    UInt64($3c6ef372fe94f82b), UInt64($a54ff53a5f1d36f1),
    UInt64($510e527fade682d1), UInt64($9b05688c2b3e6c1f),
    UInt64($1f83d9abfb41bd6b), UInt64($5be0cd19137e2179));

  blake2b_sigma: array [0 .. 11, 0 .. 15] of Byte = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3));

procedure blake2b_set_lastnode(var S: TBlake2bState);
begin
  S.f[1] := UInt64(-1);
end;

procedure blake2b_set_lastblock(var S: TBlake2bState);
begin
  if S.last_node <> 0 then
    blake2b_set_lastnode(S);
  S.f[0] := UInt64(-1);
end;

procedure blake2b_increment_counter(var S: TBlake2bState; const inc: UInt64);
begin
  S.t[0] := S.t[0] + inc;
  if S.t[0] < inc then
    S.t[1] := S.t[1] + 1;
end;

procedure blake2b_invalidate_state(var S: TBlake2bState);
begin
  SecureZeroMemoryArgon(@S, SizeOf(S));  { wipe }
  blake2b_set_lastblock(S);              { invalida para uso futuro }
end;

procedure blake2b_init0(var S: TBlake2bState);
begin
  FillChar(S, SizeOf(S), 0);
  Move(blake2b_IV[0], S.h[0], SizeOf(S.h));
end;

function blake2b_init_param(var S: TBlake2bState;
  const P: TBlake2bParam): Integer;
var
  pb: PByte;
  i: Integer;
begin
  pb := PByte(@P);
  blake2b_init0(S);
  { IV XOR bloco de parametros }
  for i := 0 to 7 do
    S.h[i] := S.h[i] xor Load64(pb + i * SizeOf(UInt64));
  S.outlen := P.digest_length;
  Result := 0;
end;

function blake2b_init(var S: TBlake2bState; outlen: NativeUInt): Integer;
var
  P: TBlake2bParam;
begin
  if (outlen = 0) or (outlen > BLAKE2B_OUTBYTES) then
  begin
    blake2b_invalidate_state(S);
    Exit(-1);
  end;

  FillChar(P, SizeOf(P), 0);
  P.digest_length := Byte(outlen);
  P.key_length := 0;
  P.fanout := 1;
  P.depth := 1;

  Result := blake2b_init_param(S, P);
end;

function blake2b_init_key(var S: TBlake2bState; outlen: NativeUInt;
  key: Pointer; keylen: NativeUInt): Integer;
var
  P: TBlake2bParam;
  block: array [0 .. BLAKE2B_BLOCKBYTES - 1] of Byte;
begin
  if (outlen = 0) or (outlen > BLAKE2B_OUTBYTES) then
  begin
    blake2b_invalidate_state(S);
    Exit(-1);
  end;

  if (key = nil) or (keylen = 0) or (keylen > BLAKE2B_KEYBYTES) then
  begin
    blake2b_invalidate_state(S);
    Exit(-1);
  end;

  FillChar(P, SizeOf(P), 0);
  P.digest_length := Byte(outlen);
  P.key_length := Byte(keylen);
  P.fanout := 1;
  P.depth := 1;

  if blake2b_init_param(S, P) < 0 then
  begin
    blake2b_invalidate_state(S);
    Exit(-1);
  end;

  FillChar(block, SizeOf(block), 0);
  Move(PByte(key)^, block[0], keylen);
  blake2b_update(S, @block[0], BLAKE2B_BLOCKBYTES);
  SecureZeroMemoryArgon(@block[0], BLAKE2B_BLOCKBYTES);
  Result := 0;
end;

procedure blake2b_compress(var S: TBlake2bState; const block: PByte);
var
  m: array [0 .. 15] of UInt64;
  v: array [0 .. 15] of UInt64;
  i, r: Integer;

  procedure G(rr, ii: Integer; var a, b, c, d: UInt64);
  begin
    a := a + b + m[blake2b_sigma[rr][2 * ii]];
    d := Rotr64(d xor a, 32);
    c := c + d;
    b := Rotr64(b xor c, 24);
    a := a + b + m[blake2b_sigma[rr][2 * ii + 1]];
    d := Rotr64(d xor a, 16);
    c := c + d;
    b := Rotr64(b xor c, 63);
  end;

begin
  for i := 0 to 15 do
    m[i] := Load64(block + i * SizeOf(UInt64));

  for i := 0 to 7 do
    v[i] := S.h[i];

  v[8]  := blake2b_IV[0];
  v[9]  := blake2b_IV[1];
  v[10] := blake2b_IV[2];
  v[11] := blake2b_IV[3];
  v[12] := blake2b_IV[4] xor S.t[0];
  v[13] := blake2b_IV[5] xor S.t[1];
  v[14] := blake2b_IV[6] xor S.f[0];
  v[15] := blake2b_IV[7] xor S.f[1];

  for r := 0 to 11 do
  begin
    G(r, 0, v[0], v[4], v[8],  v[12]);
    G(r, 1, v[1], v[5], v[9],  v[13]);
    G(r, 2, v[2], v[6], v[10], v[14]);
    G(r, 3, v[3], v[7], v[11], v[15]);
    G(r, 4, v[0], v[5], v[10], v[15]);
    G(r, 5, v[1], v[6], v[11], v[12]);
    G(r, 6, v[2], v[7], v[8],  v[13]);
    G(r, 7, v[3], v[4], v[9],  v[14]);
  end;

  for i := 0 to 7 do
    S.h[i] := S.h[i] xor v[i] xor v[i + 8];
end;

function blake2b_update(var S: TBlake2bState; inData: Pointer;
  inlen: NativeUInt): Integer;
var
  pin: PByte;
  left, fill: NativeUInt;
begin
  pin := PByte(inData);

  if inlen = 0 then
    Exit(0);

  if (inData = nil) or (S.f[0] <> 0) then
    Exit(-1);

  if NativeUInt(S.buflen) + inlen > BLAKE2B_BLOCKBYTES then
  begin
    { Completa o bloco corrente }
    left := S.buflen;
    fill := BLAKE2B_BLOCKBYTES - left;
    Move(pin^, S.buf[left], fill);
    blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
    blake2b_compress(S, @S.buf[0]);
    S.buflen := 0;
    Dec(inlen, fill);
    Inc(pin, fill);
    { Evita copias quando possivel }
    while inlen > BLAKE2B_BLOCKBYTES do
    begin
      blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
      blake2b_compress(S, pin);
      Dec(inlen, BLAKE2B_BLOCKBYTES);
      Inc(pin, BLAKE2B_BLOCKBYTES);
    end;
  end;

  Move(pin^, S.buf[S.buflen], inlen);
  Inc(S.buflen, Cardinal(inlen));
  Result := 0;
end;

function blake2b_final(var S: TBlake2bState; outData: Pointer;
  outlen: NativeUInt): Integer;
var
  buffer: array [0 .. BLAKE2B_OUTBYTES - 1] of Byte;
  i: Integer;
begin
  FillChar(buffer, SizeOf(buffer), 0);

  if (outData = nil) or (outlen < S.outlen) then
    Exit(-1);

  if S.f[0] <> 0 then
    Exit(-1);

  blake2b_increment_counter(S, S.buflen);
  blake2b_set_lastblock(S);
  FillChar(S.buf[S.buflen], BLAKE2B_BLOCKBYTES - S.buflen, 0);  { padding }
  blake2b_compress(S, @S.buf[0]);

  for i := 0 to 7 do
    Store64(@buffer[i * SizeOf(UInt64)], S.h[i]);

  Move(buffer[0], PByte(outData)^, S.outlen);
  SecureZeroMemoryArgon(@buffer[0], SizeOf(buffer));
  SecureZeroMemoryArgon(@S.buf[0], SizeOf(S.buf));
  SecureZeroMemoryArgon(@S.h[0], SizeOf(S.h));
  Result := 0;
end;

function blake2b(outData: Pointer; outlen: NativeUInt; inData: Pointer;
  inlen: NativeUInt; key: Pointer; keylen: NativeUInt): Integer;
var
  S: TBlake2bState;
begin
  Result := -1;
  try
    if (inData = nil) and (inlen > 0) then
      Exit;

    if (outData = nil) or (outlen = 0) or (outlen > BLAKE2B_OUTBYTES) then
      Exit;

    if ((key = nil) and (keylen > 0)) or (keylen > BLAKE2B_KEYBYTES) then
      Exit;

    if keylen > 0 then
    begin
      if blake2b_init_key(S, outlen, key, keylen) < 0 then
        Exit;
    end
    else if blake2b_init(S, outlen) < 0 then
      Exit;

    if blake2b_update(S, inData, inlen) < 0 then
      Exit;

    Result := blake2b_final(S, outData, outlen);
  finally
    SecureZeroMemoryArgon(@S, SizeOf(S));
  end;
end;

function blake2b_long(outData: Pointer; outlen: NativeUInt; inData: Pointer;
  inlen: NativeUInt): Integer;
var
  outPtr: PByte;
  blake_state: TBlake2bState;
  outlen_bytes: array [0 .. 3] of Byte;
  toproduce: UInt32;
  out_buffer: array [0 .. BLAKE2B_OUTBYTES - 1] of Byte;
  in_buffer: array [0 .. BLAKE2B_OUTBYTES - 1] of Byte;
begin
  outPtr := PByte(outData);
  FillChar(outlen_bytes, SizeOf(outlen_bytes), 0);
  Result := -1;
  try
{$IFDEF FPC}{$WARN 4044 OFF}{$WARN 6018 OFF}{$ELSE}{$WARN COMPARISON_FALSE OFF}{$ENDIF}
    if outlen > NativeUInt(High(UInt32)) then
      Exit;
{$IFDEF FPC}{$WARN 4044 ON}{$WARN 6018 ON}{$ELSE}{$WARN COMPARISON_FALSE ON}{$ENDIF}

    { Ordem little-endian garantida }
    Store32(@outlen_bytes[0], UInt32(outlen));

    if outlen <= BLAKE2B_OUTBYTES then
    begin
      if blake2b_init(blake_state, outlen) < 0 then Exit;
      if blake2b_update(blake_state, @outlen_bytes[0], SizeOf(outlen_bytes)) < 0 then Exit;
      if blake2b_update(blake_state, inData, inlen) < 0 then Exit;
      if blake2b_final(blake_state, outPtr, outlen) < 0 then Exit;
    end
    else
    begin
      if blake2b_init(blake_state, BLAKE2B_OUTBYTES) < 0 then Exit;
      if blake2b_update(blake_state, @outlen_bytes[0], SizeOf(outlen_bytes)) < 0 then Exit;
      if blake2b_update(blake_state, inData, inlen) < 0 then Exit;
      if blake2b_final(blake_state, @out_buffer[0], BLAKE2B_OUTBYTES) < 0 then Exit;

      Move(out_buffer[0], outPtr^, BLAKE2B_OUTBYTES div 2);
      Inc(outPtr, BLAKE2B_OUTBYTES div 2);
      toproduce := UInt32(outlen) - BLAKE2B_OUTBYTES div 2;

      while toproduce > BLAKE2B_OUTBYTES do
      begin
        Move(out_buffer[0], in_buffer[0], BLAKE2B_OUTBYTES);
        if blake2b(@out_buffer[0], BLAKE2B_OUTBYTES, @in_buffer[0],
          BLAKE2B_OUTBYTES, nil, 0) < 0 then Exit;
        Move(out_buffer[0], outPtr^, BLAKE2B_OUTBYTES div 2);
        Inc(outPtr, BLAKE2B_OUTBYTES div 2);
        Dec(toproduce, BLAKE2B_OUTBYTES div 2);
      end;

      Move(out_buffer[0], in_buffer[0], BLAKE2B_OUTBYTES);
      if blake2b(@out_buffer[0], toproduce, @in_buffer[0], BLAKE2B_OUTBYTES,
        nil, 0) < 0 then Exit;
      Move(out_buffer[0], outPtr^, toproduce);
    end;

    Result := 0;
  finally
    SecureZeroMemoryArgon(@blake_state, SizeOf(blake_state));
  end;
end;

end.
