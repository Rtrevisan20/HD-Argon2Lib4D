{******************************************************************************}
{  HDArgon2Lib4D - Porte nativo do Argon2 (P-H-C/phc-winner-argon2) para Pascal  }
{                                                                              }
{  Unit   : HDArgon2Lib4D.Core                                                }
{  Fase   : 3                                                                    }
{  Papel  : nucleo do Argon2. H0 (initial_hash), initialize, fill_first_blocks,  }
{           index_alpha, fill_segment, fill_memory_blocks (multi-thread via      }
{           TThread), finalize e validate_inputs.                                }
{                                                                              }
{  Baseado em: src/core.c + src/core.h e src/ref.c (fill_segment)               }
{  Licenca original: CC0 1.0 / Apache 2.0 (atribuicao mantida).                }
{******************************************************************************}

{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}  // FPC/Lazarus: sintaxe Delphi (ignorado no Delphi)

unit HDArgon2Lib4D.Core;

{$Q-}{$R-}

interface

uses
  HDArgon2Lib4D.Types,
  HDArgon2Lib4D.Blake2b,
  HDArgon2Lib4D.Blamka;

type
  { argon2_position_t - onde estamos construindo o bloco (core.h) }
  TArgon2Position = record
    pass: UInt32;
    lane: UInt32;
    slice: Byte;
    index: UInt32;
  end;

  { argon2_instance_t - memoria + derivados (core.h) }
  TArgon2Instance = record
    memory: PBlock;
    version: UInt32;
    passes: UInt32;
    memory_blocks: UInt32;
    segment_length: UInt32;
    lane_length: UInt32;
    lanes: UInt32;
    threads: UInt32;
    atype: TArgon2Type;
    print_internals: Integer;
    context_ptr: PArgon2Context;
  end;
  PArgon2Instance = ^TArgon2Instance;

function validate_inputs(const context: PArgon2Context): Integer;

procedure initial_hash(blockhash: PByte; context: PArgon2Context;
  const atype: TArgon2Type);

procedure fill_first_blocks(blockhash: PByte; const instance: PArgon2Instance);

function initialize(instance: PArgon2Instance; context: PArgon2Context): Integer;

procedure finalize(const context: PArgon2Context; instance: PArgon2Instance);

function index_alpha(const instance: PArgon2Instance;
  const position: TArgon2Position; const pseudo_rand: UInt32;
  const same_lane: Integer): UInt32;

procedure fill_segment(const instance: PArgon2Instance;
  const position: TArgon2Position);

function fill_memory_blocks(instance: PArgon2Instance): Integer;

implementation

uses
{$IFDEF FPC}
  SysUtils, Classes;
{$ELSE}
  System.SysUtils, System.Classes;
{$ENDIF}

var
  { Equivalente ao FLAG_clear_internal_memory global (default = 1). }
  FLAG_clear_internal_memory: Integer = 1;

procedure secure_wipe_memory(v: Pointer; const n: NativeUInt);
begin
  if (v <> nil) and (n > 0) then
    SecureZeroMemoryArgon(v, n);
end;

procedure clear_internal_memory(v: Pointer; const n: NativeUInt);
begin
  if (FLAG_clear_internal_memory <> 0) and (v <> nil) then
    secure_wipe_memory(v, n);
end;

{ Ponteiro para o bloco de indice idx dentro de instance^.memory }
function block_at(const instance: PArgon2Instance; const idx: UInt64): PBlock;
begin
  Result := PBlock(PByte(instance^.memory) + idx * SizeOf(TBlock));
end;

procedure load_block(dst: PBlock; const input: Pointer);
var
  i: Integer;
  p: PByte;
begin
  p := PByte(input);
  for i := 0 to ARGON2_QWORDS_IN_BLOCK - 1 do
    dst^.v[i] := Load64(p + i * SizeOf(UInt64));
end;

procedure store_block(output: Pointer; const src: PBlock);
var
  i: Integer;
  p: PByte;
begin
  p := PByte(output);
  for i := 0 to ARGON2_QWORDS_IN_BLOCK - 1 do
    Store64(p + i * SizeOf(UInt64), src^.v[i]);
end;

function allocate_memory(const context: PArgon2Context; var memory: Pointer;
  const num, size: NativeUInt): Integer;
var
  memory_size: NativeUInt;
begin
  memory_size := num * size;

  { 1. Checa overflow da multiplicacao }
  if (size <> 0) and (memory_size div size <> num) then
    Exit(ARGON2_MEMORY_ALLOCATION_ERROR);

  { 2. Aloca com o callback do contexto ou o alocador padrao }
  if Assigned(context^.allocate_cbk) then
  begin
    memory := nil;
    context^.allocate_cbk(PPByte(@memory), memory_size);
  end
  else
    memory := GetMemory(memory_size);

  if memory = nil then
    Exit(ARGON2_MEMORY_ALLOCATION_ERROR);

  Result := ARGON2_OK;
end;

procedure free_memory(const context: PArgon2Context; memory: Pointer;
  const num, size: NativeUInt);
var
  memory_size: NativeUInt;
begin
  memory_size := num * size;
  clear_internal_memory(memory, memory_size);
  if Assigned(context^.free_cbk) then
    context^.free_cbk(PByte(memory), memory_size)
  else
    FreeMemory(memory);
end;

function index_alpha(const instance: PArgon2Instance;
  const position: TArgon2Position; const pseudo_rand: UInt32;
  const same_lane: Integer): UInt32;
var
  reference_area_size: UInt32;
  relative_position: UInt64;
  start_position, absolute_position: UInt32;
  adjust: UInt32;
begin
  if position.pass = 0 then
  begin
    if position.slice = 0 then
      reference_area_size := position.index - 1
    else if same_lane <> 0 then
      reference_area_size := UInt32(position.slice) * instance^.segment_length +
        position.index - 1
    else
    begin
      if position.index = 0 then adjust := UInt32($FFFFFFFF) else adjust := 0;
      reference_area_size := UInt32(position.slice) * instance^.segment_length +
        adjust;
    end;
  end
  else
  begin
    if same_lane <> 0 then
      reference_area_size := instance^.lane_length - instance^.segment_length +
        position.index - 1
    else
    begin
      if position.index = 0 then adjust := UInt32($FFFFFFFF) else adjust := 0;
      reference_area_size := instance^.lane_length - instance^.segment_length +
        adjust;
    end;
  end;

  { Mapeia pseudo_rand para 0..<reference_area_size-1> }
  relative_position := pseudo_rand;
  relative_position := (relative_position * relative_position) shr 32;
  relative_position := UInt64(reference_area_size) - 1 -
    ((UInt64(reference_area_size) * relative_position) shr 32);

  start_position := 0;
  if position.pass <> 0 then
  begin
    if position.slice = ARGON2_SYNC_POINTS - 1 then
      start_position := 0
    else
      start_position := (UInt32(position.slice) + 1) * instance^.segment_length;
  end;

  absolute_position := UInt32((UInt64(start_position) + relative_position) mod
    instance^.lane_length);
  Result := absolute_position;
end;

procedure fill_segment(const instance: PArgon2Instance;
  const position: TArgon2Position);
var
  ref_block, curr_block: PBlock;
  address_block, input_block, zero_block: TBlock;
  pseudo_rand, ref_index, ref_lane: UInt64;
  prev_offset, curr_offset, starting_index, i: UInt32;
  data_independent_addressing: Boolean;
  pos: TArgon2Position;
begin
  if instance = nil then
    Exit;

  pos := position;

  data_independent_addressing :=
    (instance^.atype = Argon2_i) or
    ((instance^.atype = Argon2_id) and (pos.pass = 0) and
     (pos.slice < ARGON2_SYNC_POINTS div 2));

  if data_independent_addressing then
  begin
    BlockInitValue(@zero_block, 0);
    BlockInitValue(@input_block, 0);

    input_block.v[0] := pos.pass;
    input_block.v[1] := pos.lane;
    input_block.v[2] := pos.slice;
    input_block.v[3] := instance^.memory_blocks;
    input_block.v[4] := instance^.passes;
    input_block.v[5] := UInt64(Ord(instance^.atype));
  end;

  starting_index := 0;

  if (pos.pass = 0) and (pos.slice = 0) then
  begin
    starting_index := 2; { os dois primeiros blocos ja foram gerados }

    if data_independent_addressing then
      next_addresses(@address_block, @input_block, @zero_block);
  end;

  curr_offset := pos.lane * instance^.lane_length +
    UInt32(pos.slice) * instance^.segment_length + starting_index;

  if (curr_offset mod instance^.lane_length) = 0 then
    prev_offset := curr_offset + instance^.lane_length - 1
  else
    prev_offset := curr_offset - 1;

  i := starting_index;
  while i < instance^.segment_length do
  begin
    { 1.1 Rotaciona prev_offset se necessario }
    if (curr_offset mod instance^.lane_length) = 1 then
      prev_offset := curr_offset - 1;

    { 1.2 Indice do bloco de referencia }
    if data_independent_addressing then
    begin
      if (i mod ARGON2_ADDRESSES_IN_BLOCK) = 0 then
        next_addresses(@address_block, @input_block, @zero_block);
      pseudo_rand := address_block.v[i mod ARGON2_ADDRESSES_IN_BLOCK];
    end
    else
      pseudo_rand := block_at(instance, prev_offset)^.v[0];

    { 1.2.2 Lane de referencia }
    ref_lane := (pseudo_rand shr 32) mod instance^.lanes;

    if (pos.pass = 0) and (pos.slice = 0) then
      ref_lane := pos.lane;

    pos.index := i;

    { 1.2.3 - 1.2.6 }
    ref_index := index_alpha(instance, pos, UInt32(pseudo_rand),
      Ord(ref_lane = pos.lane));

    { 2. Cria novo bloco }
    ref_block := block_at(instance,
      UInt64(instance^.lane_length) * ref_lane + ref_index);
    curr_block := block_at(instance, curr_offset);

    if instance^.version = ARGON2_VERSION_10 then
      fill_block(block_at(instance, prev_offset), ref_block, curr_block, 0)
    else
    begin
      if pos.pass = 0 then
        fill_block(block_at(instance, prev_offset), ref_block, curr_block, 0)
      else
        fill_block(block_at(instance, prev_offset), ref_block, curr_block, 1);
    end;

    Inc(i);
    Inc(curr_offset);
    Inc(prev_offset);
  end;
end;

{$IFDEF FPC}{$WARN 4044 OFF}{$WARN 6018 OFF}{$ELSE}{$WARN COMPARISON_FALSE OFF}{$ENDIF}
function validate_inputs(const context: PArgon2Context): Integer;
begin
  if context = nil then
    Exit(ARGON2_INCORRECT_PARAMETER);

  if context^.output = nil then
    Exit(ARGON2_OUTPUT_PTR_NULL);

  if context^.outlen < ARGON2_MIN_OUTLEN then
    Exit(ARGON2_OUTPUT_TOO_SHORT);
  if context^.outlen > ARGON2_MAX_OUTLEN then
    Exit(ARGON2_OUTPUT_TOO_LONG);

  if context^.pwd = nil then
  begin
    if context^.pwdlen <> 0 then
      Exit(ARGON2_PWD_PTR_MISMATCH);
  end;
  if context^.pwdlen < ARGON2_MIN_PWD_LENGTH then
    Exit(ARGON2_PWD_TOO_SHORT);
  if context^.pwdlen > ARGON2_MAX_PWD_LENGTH then
    Exit(ARGON2_PWD_TOO_LONG);

  if context^.salt = nil then
  begin
    if context^.saltlen <> 0 then
      Exit(ARGON2_SALT_PTR_MISMATCH);
  end;
  if context^.saltlen < ARGON2_MIN_SALT_LENGTH then
    Exit(ARGON2_SALT_TOO_SHORT);
  if context^.saltlen > ARGON2_MAX_SALT_LENGTH then
    Exit(ARGON2_SALT_TOO_LONG);

  if context^.secret = nil then
  begin
    if context^.secretlen <> 0 then
      Exit(ARGON2_SECRET_PTR_MISMATCH);
  end
  else
  begin
    if context^.secretlen < ARGON2_MIN_SECRET then
      Exit(ARGON2_SECRET_TOO_SHORT);
    if context^.secretlen > ARGON2_MAX_SECRET then
      Exit(ARGON2_SECRET_TOO_LONG);
  end;

  if context^.ad = nil then
  begin
    if context^.adlen <> 0 then
      Exit(ARGON2_AD_PTR_MISMATCH);
  end
  else
  begin
    if context^.adlen < ARGON2_MIN_AD_LENGTH then
      Exit(ARGON2_AD_TOO_SHORT);
    if context^.adlen > ARGON2_MAX_AD_LENGTH then
      Exit(ARGON2_AD_TOO_LONG);
  end;

  if context^.m_cost < ARGON2_MIN_MEMORY then
    Exit(ARGON2_MEMORY_TOO_LITTLE);
  if UInt64(context^.m_cost) > UInt64(Argon2MaxMemory) then
    Exit(ARGON2_MEMORY_TOO_MUCH);
  if context^.m_cost < 8 * context^.lanes then
    Exit(ARGON2_MEMORY_TOO_LITTLE);

  if context^.t_cost < ARGON2_MIN_TIME then
    Exit(ARGON2_TIME_TOO_SMALL);
  if context^.t_cost > ARGON2_MAX_TIME then
    Exit(ARGON2_TIME_TOO_LARGE);

  if context^.lanes < ARGON2_MIN_LANES then
    Exit(ARGON2_LANES_TOO_FEW);
  if context^.lanes > ARGON2_MAX_LANES then
    Exit(ARGON2_LANES_TOO_MANY);

  if context^.threads < ARGON2_MIN_THREADS then
    Exit(ARGON2_THREADS_TOO_FEW);
  if context^.threads > ARGON2_MAX_THREADS then
    Exit(ARGON2_THREADS_TOO_MANY);

  if Assigned(context^.allocate_cbk) and (not Assigned(context^.free_cbk)) then
    Exit(ARGON2_FREE_MEMORY_CBK_NULL);
  if (not Assigned(context^.allocate_cbk)) and Assigned(context^.free_cbk) then
    Exit(ARGON2_ALLOCATE_MEMORY_CBK_NULL);

  Result := ARGON2_OK;
end;
{$IFDEF FPC}{$WARN 4044 ON}{$WARN 6018 ON}{$ELSE}{$WARN COMPARISON_FALSE ON}{$ENDIF}

procedure initial_hash(blockhash: PByte; context: PArgon2Context;
  const atype: TArgon2Type);
var
  BlakeHash: TBlake2bState;
  value: array [0 .. 3] of Byte;
begin
  if (context = nil) or (blockhash = nil) then
    Exit;

  blake2b_init(BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);

  Store32(@value[0], context^.lanes);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  Store32(@value[0], context^.outlen);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  Store32(@value[0], context^.m_cost);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  Store32(@value[0], context^.t_cost);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  Store32(@value[0], context^.version);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  Store32(@value[0], UInt32(Ord(atype)));
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  Store32(@value[0], context^.pwdlen);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  if context^.pwd <> nil then
  begin
    blake2b_update(BlakeHash, context^.pwd, context^.pwdlen);
    if (context^.flags and ARGON2_FLAG_CLEAR_PASSWORD) <> 0 then
    begin
      secure_wipe_memory(context^.pwd, context^.pwdlen);
      context^.pwdlen := 0;
    end;
  end;

  Store32(@value[0], context^.saltlen);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  if context^.salt <> nil then
    blake2b_update(BlakeHash, context^.salt, context^.saltlen);

  Store32(@value[0], context^.secretlen);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  if context^.secret <> nil then
  begin
    blake2b_update(BlakeHash, context^.secret, context^.secretlen);
    if (context^.flags and ARGON2_FLAG_CLEAR_SECRET) <> 0 then
    begin
      secure_wipe_memory(context^.secret, context^.secretlen);
      context^.secretlen := 0;
    end;
  end;

  Store32(@value[0], context^.adlen);
  blake2b_update(BlakeHash, @value[0], SizeOf(value));

  if context^.ad <> nil then
    blake2b_update(BlakeHash, context^.ad, context^.adlen);

  blake2b_final(BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
end;

procedure fill_first_blocks(blockhash: PByte; const instance: PArgon2Instance);
var
  l: UInt32;
  blockhash_bytes: array [0 .. ARGON2_BLOCK_SIZE - 1] of Byte;
begin
  for l := 0 to instance^.lanes - 1 do
  begin
    Store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
    Store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
    blake2b_long(@blockhash_bytes[0], ARGON2_BLOCK_SIZE, blockhash,
      ARGON2_PREHASH_SEED_LENGTH);
    load_block(block_at(instance, UInt64(l) * instance^.lane_length + 0),
      @blockhash_bytes[0]);

    Store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
    blake2b_long(@blockhash_bytes[0], ARGON2_BLOCK_SIZE, blockhash,
      ARGON2_PREHASH_SEED_LENGTH);
    load_block(block_at(instance, UInt64(l) * instance^.lane_length + 1),
      @blockhash_bytes[0]);
  end;
  clear_internal_memory(@blockhash_bytes[0], ARGON2_BLOCK_SIZE);
end;

function initialize(instance: PArgon2Instance; context: PArgon2Context): Integer;
var
  blockhash: array [0 .. ARGON2_PREHASH_SEED_LENGTH - 1] of Byte;
  result_code: Integer;
  mem: Pointer;
begin
  if (instance = nil) or (context = nil) then
    Exit(ARGON2_INCORRECT_PARAMETER);
  instance^.context_ptr := context;

  { 1. Alocacao de memoria }
  result_code := allocate_memory(context, mem, instance^.memory_blocks,
    SizeOf(TBlock));
  if result_code <> ARGON2_OK then
    Exit(result_code);
  instance^.memory := PBlock(mem);

  { 2. Hashing inicial (H0 + 8 bytes extras) }
  initial_hash(@blockhash[0], context, instance^.atype);
  clear_internal_memory(@blockhash[ARGON2_PREHASH_DIGEST_LENGTH],
    ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH);

  { 3. Primeiros blocos }
  fill_first_blocks(@blockhash[0], instance);
  clear_internal_memory(@blockhash[0], ARGON2_PREHASH_SEED_LENGTH);

  Result := ARGON2_OK;
end;

procedure finalize(const context: PArgon2Context; instance: PArgon2Instance);
var
  blockhash: TBlock;
  l, last_block_in_lane: UInt32;
  blockhash_bytes: array [0 .. ARGON2_BLOCK_SIZE - 1] of Byte;
begin
  if (context = nil) or (instance = nil) then
    Exit;

  BlockCopy(@blockhash, block_at(instance, instance^.lane_length - 1));

  { XOR dos ultimos blocos de todas as lanes }
  for l := 1 to instance^.lanes - 1 do
  begin
    last_block_in_lane := l * instance^.lane_length +
      (instance^.lane_length - 1);
    BlockXor(@blockhash, block_at(instance, last_block_in_lane));
  end;

  store_block(@blockhash_bytes[0], @blockhash);
  blake2b_long(context^.output, context^.outlen, @blockhash_bytes[0],
    ARGON2_BLOCK_SIZE);

  clear_internal_memory(@blockhash.v[0], ARGON2_BLOCK_SIZE);
  clear_internal_memory(@blockhash_bytes[0], ARGON2_BLOCK_SIZE);

  free_memory(context, instance^.memory, instance^.memory_blocks,
    SizeOf(TBlock));
end;

function fill_memory_blocks_st(instance: PArgon2Instance): Integer;
var
  r, s, l: UInt32;
  position: TArgon2Position;
begin
  for r := 0 to instance^.passes - 1 do
  begin
    for s := 0 to ARGON2_SYNC_POINTS - 1 do
    begin
      for l := 0 to instance^.lanes - 1 do
      begin
        position.pass := r;
        position.lane := l;
        position.slice := Byte(s);
        position.index := 0;
        fill_segment(instance, position);
      end;
    end;
  end;
  Result := ARGON2_OK;
end;

type
  { Thread que executa fill_segment para uma lane/slice. }
  TArgon2FillSegmentThread = class(TThread)
  private
    FInstance: PArgon2Instance;
    FPosition: TArgon2Position;
  protected
    procedure Execute; override;
  public
    constructor Create(const AInstance: PArgon2Instance;
      const APosition: TArgon2Position);
  end;

constructor TArgon2FillSegmentThread.Create(const AInstance: PArgon2Instance;
  const APosition: TArgon2Position);
begin
  FInstance := AInstance;
  FPosition := APosition;
  inherited Create(True);
  FreeOnTerminate := False;
end;

procedure TArgon2FillSegmentThread.Execute;
begin
  fill_segment(FInstance, FPosition);
end;

{ Multi-threaded: cria ate 'threads' workers por slice e sincroniza entre
  slices (barreira). Espelha fill_memory_blocks_mt de core.c. }
function fill_memory_blocks_mt(instance: PArgon2Instance): Integer;
var
  r, s, l: UInt32;
  nt: UInt32;
  threads: array of TArgon2FillSegmentThread;
  position: TArgon2Position;
begin
  nt := instance^.threads;
  if nt > instance^.lanes then
    nt := instance^.lanes;
  if nt = 0 then
    nt := 1;

  SetLength(threads, instance^.lanes);

  for r := 0 to instance^.passes - 1 do
  begin
    for s := 0 to ARGON2_SYNC_POINTS - 1 do
    begin
      { Cria uma thread por lane, limitando a concorrencia a 'nt' }
      for l := 0 to instance^.lanes - 1 do
      begin
        if l >= nt then
        begin
          threads[l - nt].WaitFor;
          threads[l - nt].Free;
          threads[l - nt] := nil;
        end;

        position.pass := r;
        position.lane := l;
        position.slice := Byte(s);
        position.index := 0;

        threads[l] := TArgon2FillSegmentThread.Create(instance, position);
        threads[l].Start;
      end;

      { Junta as threads restantes antes da proxima slice }
      for l := instance^.lanes - nt to instance^.lanes - 1 do
      begin
        threads[l].WaitFor;
        threads[l].Free;
        threads[l] := nil;
      end;
    end;
  end;

  Result := ARGON2_OK;
end;

function fill_memory_blocks(instance: PArgon2Instance): Integer;
begin
  if (instance = nil) or (instance^.lanes = 0) then
    Exit(ARGON2_INCORRECT_PARAMETER);

  if instance^.threads = 1 then
    Result := fill_memory_blocks_st(instance)
  else
    Result := fill_memory_blocks_mt(instance);
end;

end.
