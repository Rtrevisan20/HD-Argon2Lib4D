{******************************************************************************}
{  HDArgon2Lib4D - Porte nativo do Argon2 (P-H-C/phc-winner-argon2) para Pascal  }
{                                                                              }
{  Unit   : HDArgon2Lib4D.Blamka                                              }
{  Fase   : 2                                                                    }
{  Papel  : funcao fBlaMka, round G sem mensagem (BLAKE2_ROUND_NOMSG) e a       }
{           compressao fill_block, alem de next_addresses (Argon2i).            }
{                                                                              }
{  Baseado em: src/blake2/blamka-round-ref.h e src/ref.c                         }
{  Licenca original: CC0 1.0 / Apache 2.0 (atribuicao mantida).                }
{******************************************************************************}

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)

unit HDArgon2Lib4D.Blamka;

{$Q-}{$R-}

interface

uses
  HDArgon2Lib4D.Types;

{ Bloco de saida = C(prev_block, ref_block), com XOR opcional sobre next_block.
  next_block deve estar inicializado. Aliasing entre ref_block e next_block e
  permitido (o ref e copiado no inicio). (ref.c: fill_block) }
procedure fill_block(const prev_block, ref_block, next_block: PBlock;
  const with_xor: Integer);

{ Gera o bloco de enderecos usado pelo Argon2i (ref.c: next_addresses). }
procedure next_addresses(address_block, input_block, zero_block: PBlock);

implementation

function fBlaMka(const x, y: UInt64): UInt64; inline;
const
  m: UInt64 = $FFFFFFFF;
var
  xy: UInt64;
begin
  xy := (x and m) * (y and m);
  Result := x + y + 2 * xy;
end;

procedure fill_block(const prev_block, ref_block, next_block: PBlock;
  const with_xor: Integer);
var
  blockR, block_tmp: TBlock;
  i: Integer;

  procedure G(var a, b, c, d: UInt64);
  begin
    a := fBlaMka(a, b);
    d := Rotr64(d xor a, 32);
    c := fBlaMka(c, d);
    b := Rotr64(b xor c, 24);
    a := fBlaMka(a, b);
    d := Rotr64(d xor a, 16);
    c := fBlaMka(c, d);
    b := Rotr64(b xor c, 63);
  end;

  procedure RoundNosg(var B: TBlock;
    i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14,
    i15: Integer);
  begin
    G(B.v[i0], B.v[i4], B.v[i8], B.v[i12]);
    G(B.v[i1], B.v[i5], B.v[i9], B.v[i13]);
    G(B.v[i2], B.v[i6], B.v[i10], B.v[i14]);
    G(B.v[i3], B.v[i7], B.v[i11], B.v[i15]);
    G(B.v[i0], B.v[i5], B.v[i10], B.v[i15]);
    G(B.v[i1], B.v[i6], B.v[i11], B.v[i12]);
    G(B.v[i2], B.v[i7], B.v[i8], B.v[i13]);
    G(B.v[i3], B.v[i4], B.v[i9], B.v[i14]);
  end;

begin
  BlockCopy(@blockR, ref_block);
  BlockXor(@blockR, prev_block);
  BlockCopy(@block_tmp, @blockR);
  { blockR = ref + prev; block_tmp = ref + prev (+ next se with_xor) }
  if with_xor <> 0 then
    BlockXor(@block_tmp, next_block);

  { Blake2 sobre as colunas: (0..15), (16..31), ... (112..127) }
  for i := 0 to 7 do
    RoundNosg(blockR,
      16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3,
      16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
      16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11,
      16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);

  { Blake2 sobre as linhas: (0,1,16,17,...,112,113), ... }
  for i := 0 to 7 do
    RoundNosg(blockR,
      2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17,
      2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49,
      2 * i + 64, 2 * i + 65, 2 * i + 80, 2 * i + 81,
      2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);

  BlockCopy(next_block, @block_tmp);
  BlockXor(next_block, @blockR);
end;

procedure next_addresses(address_block, input_block, zero_block: PBlock);
begin
  input_block^.v[6] := input_block^.v[6] + 1;
  fill_block(zero_block, input_block, address_block, 0);
  fill_block(zero_block, address_block, address_block, 0);
end;

end.
