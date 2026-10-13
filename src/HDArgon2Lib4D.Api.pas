{******************************************************************************}
{  HDArgon2Lib4D - Porte nativo do Argon2 (P-H-C/phc-winner-argon2) para Pascal  }
{                                                                              }
{  Unit   : HDArgon2Lib4D.Api                                                 }
{  Fase   : 5                                                                    }
{  Papel  : API publica (drop-in do binding argon2.dll): argon2_ctx,           }
{           argon2_hash / argon2i_hash_encoded / argon2d_hash_raw etc.,         }
{           argon2_verify / argon2i_verify etc., argon2_type2string,            }
{           argon2_error_message, argon2_encodedlen.                            }
{                                                                              }
{  Baseado em: src/argon2.c + include/argon2.h                                   }
{  Licenca original: CC0 1.0 / Apache 2.0 (atribuicao mantida).                }
{******************************************************************************}

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)

unit HDArgon2Lib4D.Api;

{$Q-}{$R-}

interface

uses
  HDArgon2Lib4D.Types;

{ Representacao textual do tipo. Retorna nil se o tipo for invalido. }
function argon2_type2string(const atype: TArgon2Type;
  const uppercase: Boolean): PAnsiChar; cdecl;

{ Nucleo generico: valida, alinha memoria, inicializa, preenche e finaliza. }
function argon2_ctx(context: PArgon2Context;
  const atype: TArgon2Type): Integer; cdecl;

{ Funcao generica por tras das demais. }
function argon2_hash(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt;
  const salt: Pointer; const saltlen: NativeUInt;
  const hash: Pointer; const hashlen: NativeUInt;
  const encoded: PAnsiChar; const encodedlen: NativeUInt;
  const atype: TArgon2Type; const version: UInt32): Integer; cdecl;

function argon2i_hash_encoded(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt;
  const salt: Pointer; const saltlen: NativeUInt;
  const hashlen: NativeUInt; const encoded: PAnsiChar;
  const encodedlen: NativeUInt): Integer; cdecl;

function argon2i_hash_raw(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt;
  const salt: Pointer; const saltlen: NativeUInt;
  const hash: Pointer; const hashlen: NativeUInt): Integer; cdecl;

function argon2d_hash_encoded(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt;
  const salt: Pointer; const saltlen: NativeUInt;
  const hashlen: NativeUInt; const encoded: PAnsiChar;
  const encodedlen: NativeUInt): Integer; cdecl;

function argon2d_hash_raw(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt;
  const salt: Pointer; const saltlen: NativeUInt;
  const hash: Pointer; const hashlen: NativeUInt): Integer; cdecl;

function argon2id_hash_encoded(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt;
  const salt: Pointer; const saltlen: NativeUInt;
  const hashlen: NativeUInt; const encoded: PAnsiChar;
  const encodedlen: NativeUInt): Integer; cdecl;

function argon2id_hash_raw(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt;
  const salt: Pointer; const saltlen: NativeUInt;
  const hash: Pointer; const hashlen: NativeUInt): Integer; cdecl;

{ Verificacao contra a string PHC. }
function argon2_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt; const atype: TArgon2Type): Integer; cdecl;

function argon2i_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt): Integer; cdecl;

function argon2d_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt): Integer; cdecl;

function argon2id_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt): Integer; cdecl;

{ Variantes *_ctx. }
function argon2d_ctx(context: PArgon2Context): Integer; cdecl;
function argon2i_ctx(context: PArgon2Context): Integer; cdecl;
function argon2id_ctx(context: PArgon2Context): Integer; cdecl;

{ Verificacao contra um hash cru usando o contexto. }
function argon2_verify_ctx(context: PArgon2Context; const hash: PAnsiChar;
  const atype: TArgon2Type): Integer; cdecl;

function argon2d_verify_ctx(context: PArgon2Context;
  const hash: PAnsiChar): Integer; cdecl;
function argon2i_verify_ctx(context: PArgon2Context;
  const hash: PAnsiChar): Integer; cdecl;
function argon2id_verify_ctx(context: PArgon2Context;
  const hash: PAnsiChar): Integer; cdecl;

{ Mensagem textual para um codigo de erro. }
function argon2_error_message(const error_code: Integer): PAnsiChar; cdecl;

{ Comprimento (em bytes, incluindo o #0) da string PHC para os parametros. }
function argon2_encodedlen(const t_cost, m_cost, parallelism, saltlen, hashlen:
  UInt32; const atype: TArgon2Type): NativeUInt; cdecl;

implementation

uses
{$IFDEF FPC}
  SysUtils,  // StrLen (o FPC nao possui a unit System.AnsiStrings)
{$ELSE}
  System.AnsiStrings,
{$ENDIF}
  HDArgon2Lib4D.Core,
  HDArgon2Lib4D.Encoding;

function TypeToString(const atype: TArgon2Type;
  const uppercase: Boolean): PAnsiChar;
begin
  case atype of
    Argon2_d: if uppercase then Result := 'Argon2d' else Result := 'argon2d';
    Argon2_i: if uppercase then Result := 'Argon2i' else Result := 'argon2i';
    Argon2_id: if uppercase then Result := 'Argon2id' else Result := 'argon2id';
  else
    Result := nil;
  end;
end;

function argon2_type2string(const atype: TArgon2Type;
  const uppercase: Boolean): PAnsiChar;
begin
  Result := TypeToString(atype, uppercase);
end;

function argon2_ctx(context: PArgon2Context;
  const atype: TArgon2Type): Integer;
var
  memory_blocks, segment_length: UInt32;
  instance: TArgon2Instance;
begin
  Result := validate_inputs(context);
  if Result <> ARGON2_OK then
    Exit;

  if (atype <> Argon2_d) and (atype <> Argon2_i) and (atype <> Argon2_id) then
    Exit(ARGON2_INCORRECT_TYPE);

  { 2. Alinha o tamanho da memoria }
  memory_blocks := context^.m_cost;
  if memory_blocks < 2 * ARGON2_SYNC_POINTS * context^.lanes then
    memory_blocks := 2 * ARGON2_SYNC_POINTS * context^.lanes;

  segment_length := memory_blocks div (context^.lanes * ARGON2_SYNC_POINTS);
  memory_blocks := segment_length * (context^.lanes * ARGON2_SYNC_POINTS);

  FillChar(instance, SizeOf(instance), 0);
  instance.version := context^.version;
  instance.memory := nil;
  instance.passes := context^.t_cost;
  instance.memory_blocks := memory_blocks;
  instance.segment_length := segment_length;
  instance.lane_length := segment_length * ARGON2_SYNC_POINTS;
  instance.lanes := context^.lanes;
  instance.threads := context^.threads;
  instance.atype := atype;

  if instance.threads > instance.lanes then
    instance.threads := instance.lanes;

  Result := initialize(@instance, context);
  if Result <> ARGON2_OK then
    Exit;

  Result := fill_memory_blocks(@instance);
  if Result <> ARGON2_OK then
    Exit;

  finalize(context, @instance);
  Result := ARGON2_OK;
end;

function argon2_hash(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt; const salt: Pointer;
  const saltlen: NativeUInt; const hash: Pointer; const hashlen: NativeUInt;
  const encoded: PAnsiChar; const encodedlen: NativeUInt;
  const atype: TArgon2Type; const version: UInt32): Integer;
var
  context: TArgon2Context;
  outbuf: Pointer;
begin
{$IFDEF FPC}{$WARN 4044 OFF}{$WARN 6018 OFF}{$ELSE}{$WARN COMPARISON_FALSE OFF}{$ENDIF}
  if pwdlen > ARGON2_MAX_PWD_LENGTH then
    Exit(ARGON2_PWD_TOO_LONG);
  if saltlen > ARGON2_MAX_SALT_LENGTH then
    Exit(ARGON2_SALT_TOO_LONG);
  if hashlen > ARGON2_MAX_OUTLEN then
    Exit(ARGON2_OUTPUT_TOO_LONG);
{$IFDEF FPC}{$WARN 4044 ON}{$WARN 6018 ON}{$ELSE}{$WARN COMPARISON_FALSE ON}{$ENDIF}
  if hashlen < ARGON2_MIN_OUTLEN then
    Exit(ARGON2_OUTPUT_TOO_SHORT);

  outbuf := GetMemory(hashlen);
  if outbuf = nil then
    Exit(ARGON2_MEMORY_ALLOCATION_ERROR);

  FillChar(context, SizeOf(context), 0);
  context.output := PByte(outbuf);
  context.outlen := UInt32(hashlen);
  context.pwd := PByte(pwd);
  context.pwdlen := UInt32(pwdlen);
  context.salt := PByte(salt);
  context.saltlen := UInt32(saltlen);
  context.secret := nil;
  context.secretlen := 0;
  context.ad := nil;
  context.adlen := 0;
  context.t_cost := t_cost;
  context.m_cost := m_cost;
  context.lanes := parallelism;
  context.threads := parallelism;
  context.allocate_cbk := nil;
  context.free_cbk := nil;
  context.flags := ARGON2_DEFAULT_FLAGS;
  context.version := version;

  Result := argon2_ctx(@context, atype);
  if Result <> ARGON2_OK then
  begin
    SecureZeroMemoryArgon(outbuf, hashlen);
    FreeMemory(outbuf);
    Exit;
  end;

  if hash <> nil then
    Move(outbuf^, hash^, hashlen);

  if (encoded <> nil) and (encodedlen > 0) then
  begin
    if EncodeString(encoded, encodedlen, @context, atype) <> ARGON2_OK then
    begin
      SecureZeroMemoryArgon(outbuf, hashlen);
      SecureZeroMemoryArgon(encoded, encodedlen);
      FreeMemory(outbuf);
      Exit(ARGON2_ENCODING_FAIL);
    end;
  end;

  SecureZeroMemoryArgon(outbuf, hashlen);
  FreeMemory(outbuf);
  Result := ARGON2_OK;
end;

function argon2i_hash_encoded(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt; const salt: Pointer;
  const saltlen: NativeUInt; const hashlen: NativeUInt;
  const encoded: PAnsiChar; const encodedlen: NativeUInt): Integer;
begin
  Result := argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
    nil, hashlen, encoded, encodedlen, Argon2_i, ARGON2_VERSION_NUMBER);
end;

function argon2i_hash_raw(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt; const salt: Pointer;
  const saltlen: NativeUInt; const hash: Pointer;
  const hashlen: NativeUInt): Integer;
begin
  Result := argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
    hash, hashlen, nil, 0, Argon2_i, ARGON2_VERSION_NUMBER);
end;

function argon2d_hash_encoded(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt; const salt: Pointer;
  const saltlen: NativeUInt; const hashlen: NativeUInt;
  const encoded: PAnsiChar; const encodedlen: NativeUInt): Integer;
begin
  Result := argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
    nil, hashlen, encoded, encodedlen, Argon2_d, ARGON2_VERSION_NUMBER);
end;

function argon2d_hash_raw(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt; const salt: Pointer;
  const saltlen: NativeUInt; const hash: Pointer;
  const hashlen: NativeUInt): Integer;
begin
  Result := argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
    hash, hashlen, nil, 0, Argon2_d, ARGON2_VERSION_NUMBER);
end;

function argon2id_hash_encoded(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt; const salt: Pointer;
  const saltlen: NativeUInt; const hashlen: NativeUInt;
  const encoded: PAnsiChar; const encodedlen: NativeUInt): Integer;
begin
  Result := argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
    nil, hashlen, encoded, encodedlen, Argon2_id, ARGON2_VERSION_NUMBER);
end;

function argon2id_hash_raw(const t_cost, m_cost, parallelism: UInt32;
  const pwd: Pointer; const pwdlen: NativeUInt; const salt: Pointer;
  const saltlen: NativeUInt; const hash: Pointer;
  const hashlen: NativeUInt): Integer;
begin
  Result := argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
    hash, hashlen, nil, 0, Argon2_id, ARGON2_VERSION_NUMBER);
end;

{ Comparacao em tempo constante: 0 se iguais, -1 caso contrario. }
function argon2_compare(const b1, b2: PByte; const len: NativeUInt): Integer;
var
  i: NativeUInt;
  d: Byte;
begin
  d := 0;
  for i := 0 to len - 1 do
    d := d or (b1[i] xor b2[i]);
  Result := (1 and ((Integer(d) - 1) shr 8)) - 1;
end;

function argon2_verify_ctx(context: PArgon2Context; const hash: PAnsiChar;
  const atype: TArgon2Type): Integer;
begin
  Result := argon2_ctx(context, atype);
  if Result <> ARGON2_OK then
    Exit;

  if argon2_compare(PByte(hash), context^.output, context^.outlen) <> 0 then
    Exit(ARGON2_VERIFY_MISMATCH);

  Result := ARGON2_OK;
end;

function argon2d_verify_ctx(context: PArgon2Context;
  const hash: PAnsiChar): Integer;
begin
  Result := argon2_verify_ctx(context, hash, Argon2_d);
end;

function argon2i_verify_ctx(context: PArgon2Context;
  const hash: PAnsiChar): Integer;
begin
  Result := argon2_verify_ctx(context, hash, Argon2_i);
end;

function argon2id_verify_ctx(context: PArgon2Context;
  const hash: PAnsiChar): Integer;
begin
  Result := argon2_verify_ctx(context, hash, Argon2_id);
end;

function argon2_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt; const atype: TArgon2Type): Integer;
label
  cleanup;
var
  ctx: TArgon2Context;
  desired_result: PByte;
  encoded_len, max_field_len: NativeUInt;
begin
  desired_result := nil;

{$IFDEF FPC}{$WARN 4044 OFF}{$WARN 6018 OFF}{$ELSE}{$WARN COMPARISON_FALSE OFF}{$ENDIF}
  if pwdlen > ARGON2_MAX_PWD_LENGTH then
    Exit(ARGON2_PWD_TOO_LONG);
{$IFDEF FPC}{$WARN 4044 ON}{$WARN 6018 ON}{$ELSE}{$WARN COMPARISON_FALSE ON}{$ENDIF}
  if encoded = nil then
    Exit(ARGON2_DECODING_FAIL);

  encoded_len := StrLen(encoded);
{$IFDEF FPC}{$WARN 4044 OFF}{$WARN 6018 OFF}{$ELSE}{$WARN COMPARISON_FALSE OFF}{$ENDIF}
  if encoded_len > High(UInt32) then
    Exit(ARGON2_DECODING_FAIL);
{$IFDEF FPC}{$WARN 4044 ON}{$WARN 6018 ON}{$ELSE}{$WARN COMPARISON_FALSE ON}{$ENDIF}

  max_field_len := encoded_len;

  FillChar(ctx, SizeOf(ctx), 0);
  ctx.saltlen := UInt32(max_field_len);
  ctx.outlen := UInt32(max_field_len);

  ctx.salt := PByte(GetMemory(ctx.saltlen));
  ctx.output := PByte(GetMemory(ctx.outlen));
  if (ctx.salt = nil) or (ctx.output = nil) then
  begin
    Result := ARGON2_MEMORY_ALLOCATION_ERROR;
    goto cleanup;
  end;

  ctx.pwd := PByte(pwd);
  ctx.pwdlen := UInt32(pwdlen);

  Result := DecodeString(@ctx, encoded, atype);
  if Result <> ARGON2_OK then
    goto cleanup;

  desired_result := ctx.output;
  ctx.output := PByte(GetMemory(ctx.outlen));
  if ctx.output = nil then
  begin
    Result := ARGON2_MEMORY_ALLOCATION_ERROR;
    goto cleanup;
  end;

  Result := argon2_verify_ctx(@ctx, PAnsiChar(desired_result), atype);

cleanup:
  if ctx.salt <> nil then
    FreeMemory(ctx.salt);
  if ctx.output <> nil then
    FreeMemory(ctx.output);
  if desired_result <> nil then
    FreeMemory(desired_result);
end;

function argon2i_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt): Integer;
begin
  Result := argon2_verify(encoded, pwd, pwdlen, Argon2_i);
end;

function argon2d_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt): Integer;
begin
  Result := argon2_verify(encoded, pwd, pwdlen, Argon2_d);
end;

function argon2id_verify(const encoded: PAnsiChar; const pwd: Pointer;
  const pwdlen: NativeUInt): Integer;
begin
  Result := argon2_verify(encoded, pwd, pwdlen, Argon2_id);
end;

function argon2d_ctx(context: PArgon2Context): Integer;
begin
  Result := argon2_ctx(context, Argon2_d);
end;

function argon2i_ctx(context: PArgon2Context): Integer;
begin
  Result := argon2_ctx(context, Argon2_i);
end;

function argon2id_ctx(context: PArgon2Context): Integer;
begin
  Result := argon2_ctx(context, Argon2_id);
end;

const
  ErrMsgs: array [0 .. 36] of AnsiString = (
    'OK',                                                        { 0 }
    'Output pointer is NULL',                                    { -1 }
    'Output is too short',                                       { -2 }
    'Output is too long',                                        { -3 }
    'Password is too short',                                     { -4 }
    'Password is too long',                                      { -5 }
    'Salt is too short',                                         { -6 }
    'Salt is too long',                                          { -7 }
    'Associated data is too short',                              { -8 }
    'Associated data is too long',                               { -9 }
    'Secret is too short',                                       { -10 }
    'Secret is too long',                                        { -11 }
    'Time cost is too small',                                    { -12 }
    'Time cost is too large',                                    { -13 }
    'Memory cost is too small',                                  { -14 }
    'Memory cost is too large',                                  { -15 }
    'Too few lanes',                                             { -16 }
    'Too many lanes',                                            { -17 }
    'Password pointer is NULL, but password length is not 0',    { -18 }
    'Salt pointer is NULL, but salt length is not 0',            { -19 }
    'Secret pointer is NULL, but secret length is not 0',        { -20 }
    'Associated data pointer is NULL, but ad length is not 0',   { -21 }
    'Memory allocation error',                                   { -22 }
    'The free memory callback is NULL',                          { -23 }
    'The allocate memory callback is NULL',                      { -24 }
    'Argon2_Context context is NULL',                            { -25 }
    'There is no such version of Argon2',                        { -26 }
    'Output pointer mismatch',                                   { -27 }
    'Not enough threads',                                        { -28 }
    'Too many threads',                                          { -29 }
    'Missing arguments',                                         { -30 }
    'Encoding failed',                                           { -31 }
    'Decoding failed',                                           { -32 }
    'Threading failure',                                         { -33 }
    'Some of encoded parameters are too long or too short',      { -34 }
    'The password does not match the supplied hash',             { -35 }
    'Unknown error code'                                         { other }
  );

function argon2_error_message(const error_code: Integer): PAnsiChar;
var
  idx: Integer;
begin
  if error_code = ARGON2_OK then
    idx := 0
  else if (error_code < 0) and (error_code >= -35) then
    idx := -error_code
  else
    idx := 36;
  Result := PAnsiChar(ErrMsgs[idx]);
end;

function argon2_encodedlen(const t_cost, m_cost, parallelism, saltlen, hashlen:
  UInt32; const atype: TArgon2Type): NativeUInt;
var
  typeStr: PAnsiChar;
begin
  typeStr := argon2_type2string(atype, False);
  if typeStr = nil then
    Exit(0);
  Result := 15 { strlen("$$v=$m=,t=,p=$$") } + StrLen(typeStr) +
    NumLen(t_cost) + NumLen(m_cost) + NumLen(parallelism) +
    B64Len(saltlen) + B64Len(hashlen) + NumLen(ARGON2_VERSION_NUMBER) + 1;
end;

end.
