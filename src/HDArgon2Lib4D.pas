{******************************************************************************}
{  HDArgon2Lib4D - Porte nativo do Argon2 (P-H-C/phc-winner-argon2) para Pascal  }
{                                                                              }
{  Unit   : HDArgon2Lib4D                                                     }
{  Fase   : 10 (camada de conveniencia)                                        }
{  Papel  : Fachada de alto nivel sobre HDArgon2Lib4D (100% nativo, sem DLL).   }
{           Esconde contexto/buffers e expoe uso simples: gerar hash PHC com    }
{           salt aleatorio seguro, verificar senha e detectar rehash.          }
{                                                                              }
{  Licenca original: CC0 1.0 / Apache 2.0 (atribuicao mantida).                }
{******************************************************************************}

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)

unit HDArgon2Lib4D;

{$Q-}{$R-}

interface

uses
{$IFDEF FPC}
  SysUtils,
{$ELSE}
  System.SysUtils,
{$ENDIF}
  HDArgon2Lib4D.Types;

type
  { Erro levantado pela fachada (carrega o codigo de erro do Argon2). }
  EHDArgon2 = class(Exception)
  private
    FCode: Integer;
  public
    constructor Create(const aCode: Integer; const aMessage: string); overload;
    property Code: Integer read FCode;
  end;

  { Fachada de uso simples do Argon2 (padrao Argon2id). }
  THDArgon2 = class
  private
    class var FIterations: Integer;
    class var FMemory: Integer;
    class var FParallelism: Integer;
    class var FSaltLength: Integer;
    class var FHashLength: Integer;
    class var FMode: TArgon2Type;
    class function GenSalt(const aLen: Integer): TBytes;
    class function PasswordBytes(const aPass: string): TBytes;
    class function DetectedType(const aEncoded: string): TArgon2Type;
    class function EncodedLength: NativeUInt;
    class function DoHashEncoded(const pw, salt: TBytes; const enc: PAnsiChar;
      const encLen: NativeUInt): Integer;
    class function DoHashRaw(const pw, salt: TBytes; const tag: Pointer;
      const tagLen: NativeUInt): Integer;
  public
    { Gera a string PHC (ex.: $argon2id$v=19$m=65536,t=3,p=4$salt$hash) com salt
      aleatorio seguro. Levanta EHDArgon2 em caso de erro. }
    class function HashPassword(const aPass: string): string;
    { Gera o hash cru (tag binaria), sem codificacao PHC. }
    class function HashRaw(const aPass: string): TBytes;
    { Verifica a senha contra a string PHC; auto-detecta o tipo pelo prefixo. }
    class function VerifyPassword(const aHash, aPass: string): Boolean;
    { True se o hash foi gerado com tipo/versao/parametros diferentes dos atuais. }
    class function NeedsRehash(const aHash: string): Boolean;
    { Mensagem textual para um codigo de erro do Argon2. }
    class function ErrorMessage(const aCode: Integer): string;

    class property Iterations: Integer read FIterations write FIterations;
    class property Memory: Integer read FMemory write FMemory;
    class property Parallelism: Integer read FParallelism write FParallelism;
    class property SaltLength: Integer read FSaltLength write FSaltLength;
    class property HashLength: Integer read FHashLength write FHashLength;
    class property Mode: TArgon2Type read FMode write FMode;
  end;

  { Alias para paridade com o binding HDArgon2 (DLL). }
  TArgon2 = THDArgon2;

implementation

uses
  HDArgon2Lib4D.Api
{$IF Defined(MSWINDOWS)}
  {$IFDEF FPC}, Windows{$ELSE}, Winapi.Windows{$ENDIF}
{$ENDIF}
  ;

const
  { Defaults recomendados (OWASP / RFC 9106). }
  DEF_ITERATIONS  = 3;
  DEF_MEMORY      = 19456;   { KiB (19 MiB) }
  DEF_PARALLELISM = 4;
  DEF_SALT_LEN    = 16;
  DEF_HASH_LEN    = 32;

{ Retorna @b[0] ou nil quando vazio (evita indices invalidos). }
function BytesPtr(const b: TBytes): Pointer;
begin
  if Length(b) = 0 then
    Result := nil
  else
    Result := @b[0];
end;

{ Le um parametro numerico do formato PHC (ex.: 'm=' -> 65536). -1 se ausente. }
function ParamValue(const s, key: string): Integer;
var
  i, j: Integer;
begin
  Result := -1;
  i := Pos(key, s);
  if i = 0 then
    Exit;
  Inc(i, Length(key));
  j := i;
  while (j <= Length(s)) and (s[j] >= '0') and (s[j] <= '9') do
    Inc(j);
  if j > i then
    Result := StrToIntDef(Copy(s, i, j - i), -1);
end;

{ Bytes aleatorios criptograficamente seguros (BCryptGenRandom / /dev/urandom). }
function SecureRandomBytes(Buff: Pointer; Count: Integer): Boolean;
{$IF Defined(MSWINDOWS)}
type
  TBCryptGenRandomProc = function(hAlgorithm: NativeUInt; pbBuffer: PByte;
    cbBuffer: DWORD; dwFlags: DWORD): Integer; stdcall;
const
  BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;
var
  Lib: HMODULE;
  Fn: TBCryptGenRandomProc;
begin
  Result := False;
  if Count <= 0 then
    Exit;
  Lib := SafeLoadLibrary('bcrypt.dll');
  if Lib = 0 then
    Exit;
  try
    @Fn := GetProcAddress(Lib, 'BCryptGenRandom');
    if Assigned(Fn) then
      Result := Fn(0, PByte(Buff), DWORD(Count),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) = 0;
  finally
    FreeLibrary(Lib);
  end;
end;
{$ELSE}
var
  F: THandle;
  N, R: Integer;
begin
  Result := False;
  if Count <= 0 then
    Exit;
  F := FileOpen('/dev/urandom', fmOpenRead or fmShareDenyNone);
  if F = THandle(-1) then
    Exit;
  try
    N := 0;
    while N < Count do
    begin
      R := FileRead(F, PByte(Buff)[N], Count - N);
      if R <= 0 then
        Exit;
      Inc(N, R);
    end;
    Result := True;
  finally
    FileClose(F);
  end;
end;
{$ENDIF}

constructor EHDArgon2.Create(const aCode: Integer; const aMessage: string);
begin
  FCode := aCode;
  inherited Create(aMessage);
end;

class function THDArgon2.GenSalt(const aLen: Integer): TBytes;
var
  salt: TBytes;
begin
  SetLength(salt, aLen);
  if (aLen > 0) and (not SecureRandomBytes(@salt[0], aLen)) then
    raise EHDArgon2.Create(-1,
      'Falha ao obter bytes aleatorios seguros para o salt.');
  Result := salt;
end;

class function THDArgon2.PasswordBytes(const aPass: string): TBytes;
{$IFDEF FPC}
var
  b: TBytes;
{$ENDIF}
begin
{$IFDEF FPC}
  { No Lazarus 'string' e UTF-8 (AnsiString): usa os bytes como estao. }
  SetLength(b, Length(aPass));
  if Length(aPass) > 0 then
    Move(aPass[1], b[0], Length(aPass));
  Result := b;
{$ELSE}
  Result := TEncoding.UTF8.GetBytes(aPass);
{$ENDIF}
end;

class function THDArgon2.DetectedType(const aEncoded: string): TArgon2Type;
begin
  if Copy(aEncoded, 1, 10) = '$argon2id$' then
    Result := Argon2_id
  else if Copy(aEncoded, 1, 9) = '$argon2i$' then
    Result := Argon2_i
  else if Copy(aEncoded, 1, 9) = '$argon2d$' then
    Result := Argon2_d
  else
    Result := Argon2_id;
end;

class function THDArgon2.EncodedLength: NativeUInt;
begin
  Result := argon2_encodedlen(UInt32(FIterations), UInt32(FMemory),
    UInt32(FParallelism), UInt32(FSaltLength), UInt32(FHashLength), FMode);
end;

class function THDArgon2.DoHashEncoded(const pw, salt: TBytes;
  const enc: PAnsiChar; const encLen: NativeUInt): Integer;
var
  pp, sp: Pointer;
begin
  pp := BytesPtr(pw);
  sp := BytesPtr(salt);
  case FMode of
    Argon2_i:
      Result := argon2i_hash_encoded(UInt32(FIterations), UInt32(FMemory),
        UInt32(FParallelism), pp, NativeUInt(Length(pw)), sp,
        NativeUInt(Length(salt)), NativeUInt(FHashLength), enc, encLen);
    Argon2_d:
      Result := argon2d_hash_encoded(UInt32(FIterations), UInt32(FMemory),
        UInt32(FParallelism), pp, NativeUInt(Length(pw)), sp,
        NativeUInt(Length(salt)), NativeUInt(FHashLength), enc, encLen);
  else
    Result := argon2id_hash_encoded(UInt32(FIterations), UInt32(FMemory),
      UInt32(FParallelism), pp, NativeUInt(Length(pw)), sp,
      NativeUInt(Length(salt)), NativeUInt(FHashLength), enc, encLen);
  end;
end;

class function THDArgon2.DoHashRaw(const pw, salt: TBytes; const tag: Pointer;
  const tagLen: NativeUInt): Integer;
var
  pp, sp: Pointer;
begin
  pp := BytesPtr(pw);
  sp := BytesPtr(salt);
  case FMode of
    Argon2_i:
      Result := argon2i_hash_raw(UInt32(FIterations), UInt32(FMemory),
        UInt32(FParallelism), pp, NativeUInt(Length(pw)), sp,
        NativeUInt(Length(salt)), tag, tagLen);
    Argon2_d:
      Result := argon2d_hash_raw(UInt32(FIterations), UInt32(FMemory),
        UInt32(FParallelism), pp, NativeUInt(Length(pw)), sp,
        NativeUInt(Length(salt)), tag, tagLen);
  else
    Result := argon2id_hash_raw(UInt32(FIterations), UInt32(FMemory),
      UInt32(FParallelism), pp, NativeUInt(Length(pw)), sp,
      NativeUInt(Length(salt)), tag, tagLen);
  end;
end;

class function THDArgon2.HashPassword(const aPass: string): string;
var
  salt, pw, buf: TBytes;
  rc: Integer;
begin
  salt := GenSalt(FSaltLength);
  pw := PasswordBytes(aPass);
  SetLength(buf, Integer(EncodedLength) + 1);
  rc := DoHashEncoded(pw, salt, PAnsiChar(@buf[0]), NativeUInt(Length(buf)));
  if rc <> ARGON2_OK then
    raise EHDArgon2.Create(rc, ErrorMessage(rc));
  Result := string(AnsiString(PAnsiChar(@buf[0])));
end;

class function THDArgon2.HashRaw(const aPass: string): TBytes;
var
  salt, pw, tag: TBytes;
  rc: Integer;
begin
  SetLength(tag, FHashLength);
  salt := GenSalt(FSaltLength);
  pw := PasswordBytes(aPass);
  rc := DoHashRaw(pw, salt, @tag[0], NativeUInt(FHashLength));
  if rc <> ARGON2_OK then
    raise EHDArgon2.Create(rc, ErrorMessage(rc));
  Result := tag;
end;

class function THDArgon2.VerifyPassword(const aHash, aPass: string): Boolean;
var
  enc: AnsiString;
  pw: TBytes;
begin
  enc := AnsiString(aHash);
  pw := PasswordBytes(aPass);
  Result := argon2_verify(PAnsiChar(enc), BytesPtr(pw), NativeUInt(Length(pw)),
    DetectedType(aHash)) = ARGON2_OK;
end;

class function THDArgon2.NeedsRehash(const aHash: string): Boolean;
begin
  Result := (DetectedType(aHash) <> FMode) or
    (ParamValue(aHash, 'v=') <> Integer(ARGON2_VERSION_13)) or
    (ParamValue(aHash, 'm=') <> FMemory) or
    (ParamValue(aHash, 't=') <> FIterations) or
    (ParamValue(aHash, 'p=') <> FParallelism);
end;

class function THDArgon2.ErrorMessage(const aCode: Integer): string;
begin
  Result := string(AnsiString(argon2_error_message(aCode)));
end;

initialization
  THDArgon2.FIterations := DEF_ITERATIONS;
  THDArgon2.FMemory := DEF_MEMORY;
  THDArgon2.FParallelism := DEF_PARALLELISM;
  THDArgon2.FSaltLength := DEF_SALT_LEN;
  THDArgon2.FHashLength := DEF_HASH_LEN;
  THDArgon2.FMode := Argon2_id;

end.
