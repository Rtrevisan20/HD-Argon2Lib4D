{******************************************************************************}
{  HDArgon2Lib4D - Porte nativo do Argon2 (P-H-C/phc-winner-argon2) para Pascal  }
{                                                                              }
{  Unit   : HDArgon2Lib4D.Types                                               }
{  Fase   : 0 (preparacao)                                                      }
{  Papel  : tipos base, constantes, helpers little-endian e rotacao de bits.   }
{                                                                              }
{  Baseado em: src/blake2/blake2-impl.h, src/core.h, include/argon2.h          }
{  Licenca original: CC0 1.0 / Apache 2.0 (atribuicao mantida).                }
{******************************************************************************}

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)

unit HDArgon2Lib4D.Types;

{$Q-}{$R-}  // wraparound de 64 bits obrigatorio (ver AGENTS.md)

interface

const
  { --- BLAKE2b (src/blake2/blake2.h) --- }
  BLAKE2B_BLOCKBYTES    = 128;
  BLAKE2B_OUTBYTES      = 64;
  BLAKE2B_KEYBYTES      = 64;
  BLAKE2B_SALTBYTES     = 16;
  BLAKE2B_PERSONALBYTES = 16;

  { --- Argon2 core (src/core.h) --- }
  ARGON2_BLOCK_SIZE            = 1024;
  ARGON2_QWORDS_IN_BLOCK       = ARGON2_BLOCK_SIZE div 8;   // 128
  ARGON2_OWORDS_IN_BLOCK       = ARGON2_BLOCK_SIZE div 16;  // 64
  ARGON2_HWORDS_IN_BLOCK       = ARGON2_BLOCK_SIZE div 32;  // 32
  ARGON2_512BIT_WORDS_IN_BLOCK = ARGON2_BLOCK_SIZE div 64;  // 16
  ARGON2_ADDRESSES_IN_BLOCK    = 128;
  ARGON2_SYNC_POINTS           = 4;
  ARGON2_PREHASH_DIGEST_LENGTH = 64;
  ARGON2_PREHASH_SEED_LENGTH   = 72;
  ARGON2_VERSION_10            = $10;
  ARGON2_VERSION_13            = $13;
  ARGON2_VERSION_NUMBER        = ARGON2_VERSION_13;
  ARGON2_DEFAULT_FLAGS         = UInt32(0);
  ARGON2_FLAG_CLEAR_PASSWORD   = UInt32(1) shl 0;
  ARGON2_FLAG_CLEAR_SECRET     = UInt32(1) shl 1;

  { --- Limites (include/argon2.h) --- }
  ARGON2_MIN_LANES     = UInt32(1);
  ARGON2_MAX_LANES     = UInt32($FFFFFF);
  ARGON2_MIN_THREADS   = UInt32(1);
  ARGON2_MAX_THREADS   = UInt32($FFFFFF);
  ARGON2_MIN_OUTLEN    = UInt32(4);
  ARGON2_MAX_OUTLEN    = UInt32($FFFFFFFF);
  ARGON2_MIN_TIME      = UInt32(1);
  ARGON2_MAX_TIME      = UInt32($FFFFFFFF);
  ARGON2_MIN_PWD_LENGTH = UInt32(0);
  ARGON2_MAX_PWD_LENGTH = UInt32($FFFFFFFF);
  ARGON2_MIN_AD_LENGTH  = UInt32(0);
  ARGON2_MAX_AD_LENGTH  = UInt32($FFFFFFFF);
  ARGON2_MIN_SALT_LENGTH = UInt32(8);
  ARGON2_MAX_SALT_LENGTH = UInt32($FFFFFFFF);
  ARGON2_MIN_SECRET    = UInt32(0);
  ARGON2_MAX_SECRET    = UInt32($FFFFFFFF);
  ARGON2_MIN_MEMORY    = UInt32(2) * ARGON2_SYNC_POINTS; { 8 }

  { --- Codigos de erro (include/argon2.h) --- }
  ARGON2_OK = 0;
  ARGON2_OUTPUT_PTR_NULL = -1;
  ARGON2_OUTPUT_TOO_SHORT = -2;
  ARGON2_OUTPUT_TOO_LONG = -3;
  ARGON2_PWD_TOO_SHORT = -4;
  ARGON2_PWD_TOO_LONG = -5;
  ARGON2_SALT_TOO_SHORT = -6;
  ARGON2_SALT_TOO_LONG = -7;
  ARGON2_AD_TOO_SHORT = -8;
  ARGON2_AD_TOO_LONG = -9;
  ARGON2_SECRET_TOO_SHORT = -10;
  ARGON2_SECRET_TOO_LONG = -11;
  ARGON2_TIME_TOO_SMALL = -12;
  ARGON2_TIME_TOO_LARGE = -13;
  ARGON2_MEMORY_TOO_LITTLE = -14;
  ARGON2_MEMORY_TOO_MUCH = -15;
  ARGON2_LANES_TOO_FEW = -16;
  ARGON2_LANES_TOO_MANY = -17;
  ARGON2_PWD_PTR_MISMATCH = -18;
  ARGON2_SALT_PTR_MISMATCH = -19;
  ARGON2_SECRET_PTR_MISMATCH = -20;
  ARGON2_AD_PTR_MISMATCH = -21;
  ARGON2_MEMORY_ALLOCATION_ERROR = -22;
  ARGON2_FREE_MEMORY_CBK_NULL = -23;
  ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24;
  ARGON2_INCORRECT_PARAMETER = -25;
  ARGON2_INCORRECT_TYPE = -26;
  ARGON2_OUT_PTR_MISMATCH = -27;
  ARGON2_THREADS_TOO_FEW = -28;
  ARGON2_THREADS_TOO_MANY = -29;
  ARGON2_MISSING_ARGS = -30;
  ARGON2_ENCODING_FAIL = -31;
  ARGON2_DECODING_FAIL = -32;
  ARGON2_THREAD_FAIL = -33;
  ARGON2_DECODING_LENGTH_FAIL = -34;
  ARGON2_VERIFY_MISMATCH = -35;

type
  PUInt32 = ^UInt32;
  PUInt64 = ^UInt64;

  { Bloco de memoria do Argon2: 128 palavras de 64 bits = 1024 bytes (core.h) }
  TBlock = record
    v: array [0 .. ARGON2_QWORDS_IN_BLOCK - 1] of UInt64;
  end;
  PBlock = ^TBlock;

  PPByte = ^PByte;

  { Tipo de variante do Argon2 (argon2_type) }
  TArgon2Type = (Argon2_d = 0, Argon2_i = 1, Argon2_id = 2);

  TAllocateFunc = function(memory: PPByte; bytes: NativeUInt): Integer; cdecl;
  TDeallocateFunc = procedure(memory: PByte; bytes: NativeUInt); cdecl;

  { argon2_context - conjunto de entradas da API publica (include/argon2.h) }
  TArgon2Context = record
    output: PByte;   outlen: UInt32;
    pwd: PByte;      pwdlen: UInt32;
    salt: PByte;     saltlen: UInt32;
    secret: PByte;   secretlen: UInt32;
    ad: PByte;       adlen: UInt32;
    t_cost: UInt32;
    m_cost: UInt32;
    lanes: UInt32;
    threads: UInt32;
    version: UInt32;
    allocate_cbk: TAllocateFunc;
    free_cbk: TDeallocateFunc;
    flags: UInt32;
  end;
  PArgon2Context = ^TArgon2Context;

{ Maior m_cost (em blocos) suportado nesta plataforma (MACRO ARGON2_MAX_MEMORY) }
function Argon2MaxMemory: UInt32;

{ Nome textual do tipo ("argon2i"/"Argon2i" etc). Retorna '' se desconhecido. }
function Argon2TypeToString(const atype: TArgon2Type; const uppercase: Boolean): string;

{ Helpers de bloco (core.c) }
procedure BlockInitValue(b: PBlock; const inValue: Byte); inline;
procedure BlockCopy(dst, src: PBlock); inline;
procedure BlockXor(dst, src: PBlock); inline;

{ Little-endian explicito (nunca cast de ponteiro) - blake2-impl.h }
function Load32(const src: PByte): UInt32; inline;
function Load64(const src: PByte): UInt64; inline;
procedure Store32(const dst: PByte; w: UInt32); inline;
procedure Store64(const dst: PByte; w: UInt64); inline;

{ Rotacoes de bits }
function Rotr32(const w: UInt32; const c: Byte): UInt32; inline;
function Rotr64(const w: UInt64; const c: Byte): UInt64; inline;

{ Zera memoria resistindo a otimizacao do compilador }
procedure SecureZeroMemoryArgon(const dst: Pointer; const len: NativeUInt);

implementation

function Argon2MaxMemory: UInt32;
var
  bits: Integer;
  v: UInt64;
begin
  bits := (SizeOf(Pointer) * 8) - 10 - 1;
  if bits > 32 then
    bits := 32;
  v := UInt64(1) shl bits;
  if v > UInt64($FFFFFFFF) then
    v := UInt64($FFFFFFFF);
  Result := UInt32(v);
end;

function Argon2TypeToString(const atype: TArgon2Type; const uppercase: Boolean): string;
begin
  case atype of
    Argon2_d: if uppercase then Result := 'Argon2d' else Result := 'argon2d';
    Argon2_i: if uppercase then Result := 'Argon2i' else Result := 'argon2i';
    Argon2_id: if uppercase then Result := 'Argon2id' else Result := 'argon2id';
  else
    Result := '';
  end;
end;

procedure BlockInitValue(b: PBlock; const inValue: Byte);
begin
  FillChar(b^.v[0], SizeOf(TBlock), inValue);
end;

procedure BlockCopy(dst, src: PBlock);
begin
  Move(src^.v[0], dst^.v[0], SizeOf(TBlock));
end;

procedure BlockXor(dst, src: PBlock);
var
  i: Integer;
begin
  for i := 0 to ARGON2_QWORDS_IN_BLOCK - 1 do
    dst^.v[i] := dst^.v[i] xor src^.v[i];
end;

function Load32(const src: PByte): UInt32;
begin
  Result := UInt32(src[0])
    or (UInt32(src[1]) shl 8)
    or (UInt32(src[2]) shl 16)
    or (UInt32(src[3]) shl 24);
end;

function Load64(const src: PByte): UInt64;
begin
  Result := UInt64(Load32(src)) or (UInt64(Load32(src + 4)) shl 32);
end;

procedure Store32(const dst: PByte; w: UInt32);
begin
  dst[0] := Byte(w);
  dst[1] := Byte(w shr 8);
  dst[2] := Byte(w shr 16);
  dst[3] := Byte(w shr 24);
end;

procedure Store64(const dst: PByte; w: UInt64);
begin
  Store32(dst, UInt32(w));
  Store32(dst + 4, UInt32(w shr 32));
end;

function Rotr32(const w: UInt32; const c: Byte): UInt32;
begin
  Result := (w shr c) or (w shl (32 - c));
end;

function Rotr64(const w: UInt64; const c: Byte): UInt64;
begin
  if c = 0 then
    Result := w
  else
    Result := (w shr c) or (w shl (64 - c));
end;

procedure SecureZeroMemoryArgon(const dst: Pointer; const len: NativeUInt);
var
  p: PByte;
  n: NativeUInt;
begin
  p := PByte(dst);
  n := len;
  while n > 0 do
  begin
    p^ := 0;
    Inc(p);
    Dec(n);
  end;
end;

end.
