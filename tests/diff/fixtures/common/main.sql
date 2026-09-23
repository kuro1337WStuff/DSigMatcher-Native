BEGIN TRANSACTION;
CREATE TABLE basic_blocks (
                  id integer primary key,
                  num integer,
                  address text,
                  asm_type text);
CREATE TABLE bb_instructions (
                  id integer primary key,
                  basic_block_id integer references basic_blocks(id) on delete cascade,
                  instruction_id integer references instructions(id) on delete cascade);
CREATE TABLE bb_relations (
                  id integer primary key,
                  parent_id integer not null references basic_blocks(id) ON DELETE CASCADE,
                  child_id integer not null references basic_blocks(id) ON DELETE CASCADE);
CREATE TABLE callgraph (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  address text not null,
                  type text not null);
CREATE TABLE compilation_unit_functions (
                  id integer primary key,
                  cu_id integer not null references compilation_units(id) on delete cascade,
                  func_id integer not null references functions(id) on delete cascade);
CREATE TABLE compilation_units (
                  id integer primary key,
                  name text,
                  functions int,
                  primes_value text,
                  pseudocode_primes text,
                  start_ea text unique,
                  end_ea text);
CREATE TABLE constants (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  constant text not null);
CREATE TABLE function_bblocks (
                  id integer primary key,
                  function_id integer not null references functions(id) on delete cascade,
                  basic_block_id integer not null references basic_blocks(id) on delete cascade,
                  asm_type text);
CREATE TABLE functions (
                          id integer primary key,
                          name varchar(255),
                          address text unique,
                          nodes integer,
                          edges integer,
                          indegree integer,
                          outdegree integer,
                          size integer,
                          instructions integer,
                          mnemonics text,
                          names text,
                          prototype text,
                          cyclomatic_complexity integer,
                          primes_value text,
                          comment text,
                          mangled_function text,
                          bytes_hash text,
                          pseudocode text,
                          pseudocode_lines integer,
                          pseudocode_hash1 text,
                          pseudocode_primes text,
                          function_flags integer,
                          assembly text,
                          prototype2 text,
                          pseudocode_hash2 text,
                          pseudocode_hash3 text,
                          strongly_connected integer,
                          loops integer,
                          rva text unique,
                          tarjan_topological_sort text,
                          strongly_connected_spp text,
                          clean_assembly text,
                          clean_pseudo text,
                          mnemonics_spp text,
                          switches text,
                          function_hash text,
                          bytes_sum integer,
                          md_index text,
                          constants text,
                          constants_count integer,
                          segment_rva text,
                          assembly_addrs text,
                          kgh_hash text,
                          source_file text,
                          userdata text,
                          microcode text,
                          clean_microcode text,
                          microcode_spp text,
                          export_time real);
INSERT INTO "functions" VALUES(1,'Foo::Bar(int)','6442455040',5,4,1,1,40,10,'["push", "sub", "mov", "call", "test", "jz", "mov", "add", "pop", "retn"]','[]',NULL,1,'11',NULL,'?Bar@Foo@@QEAAXH@Z','c899a1fb81aa8d471253957d473699d9','void __fastcall Foo::Bar(Foo *this, int a2)
{
  if ( sub_180001400() )
    return;
}',5,'0f9e32ceb486f45f',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
call sub_180001400
test eax, eax
jz short loc_180001030
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'4096','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
call sub_180001400
test eax, eax
jz short loc_180001030
mov eax, ebx
add rsp, 20h
pop rbx
retn','void __fastcall Foo::Bar(Foo *this, int a2)
{
  if ( sub_180001400() )
    return;
}','35','[]','10208637f6dadff8abcb79fe87a78bb2',40,'1.5','[]',0,'4096','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'named_fn','6442455296',3,2,1,1,32,8,'["mov", "cmp", "jbe", "mov", "loc_1:", "lea", "mov", "retn"]','[]',NULL,1,'7',NULL,'named_fn','9dc5777fa0367d4e32b4b9102bbe1782','int named_fn(int *a1)
{
  return a1[2];
}',4,'3c457856ad901e08',NULL,0,'mov eax, [rcx+8]
cmp eax, 10h
jbe short loc_1
mov eax, 10h
loc_1:
lea rdx, [rcx+10h]
mov [rdx], eax
retn',NULL,NULL,NULL,1,0,'4352','[[0]]','2','mov eax, [rcx+8]
cmp eax, 10h
jbe short loc_1
mov eax, 10h
loc_1:
lea rdx, [rcx+10h]
mov [rdx], eax
retn','int named_fn(int *a1)
{
  return a1[2];
}','33','[]','6c9cef41289894410b04af5803b83318',296,'2.25','[]',0,'4352','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'sub_180001200','6442455552',4,3,1,1,32,8,'["push", "mov", "mov", "call", "imul", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180001200','6cd7da4e022f5ade1189a5f6154e86c4','int sub_180001200()
{
  return 7 * x + 11;
}',4,'6f32bcb373664d6f',NULL,0,'push rbp
mov rbp, rsp
mov ecx, 3
call sub_180001500
imul eax, 7
add eax, 11
pop rbp
retn',NULL,NULL,NULL,1,0,'4608','[[0]]','2','push rbp
mov rbp, rsp
mov ecx, 3
call sub_180001500
imul eax, 7
add eax, 11
pop rbp
retn','int sub_180001200()
{
  return 7 * x + 11;
}','34','[]','73f57b84fd36ac1bf2b3ea74adbbde88',552,'3.125','[]',0,'4608','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'sub_180001300','6442455808',2,1,1,1,24,6,'["xor", "cmp", "setz", "shl", "or", "retn"]','[]',NULL,1,'5',NULL,'sub_180001300','3bd627e4da106baaa568fe36da7696ec',NULL,0,NULL,NULL,0,'xor eax, eax
cmp ecx, 1
setz al
shl eax, 2
or eax, 1
retn',NULL,NULL,NULL,1,0,'4864','[[0]]','2','xor eax, eax
cmp ecx, 1
setz al
shl eax, 2
or eax, 1
retn',NULL,'32','[]','dd092b47db690983aee9592c95ec9481',808,'4.0625','[]',0,'4864','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'sub_180001400','6442456064',3,2,1,1,24,6,'["xor", "loc_a:", "add", "dec", "jnz", "retn"]','[]',NULL,1,'7',NULL,'sub_180001400','801a7f7ab889905caf17e15aeba596c5','int sub_180001400(int a1)
{
  return a1;
}',4,'39e0fd70cf302fcb',NULL,0,'xor eax, eax
loc_a:
add eax, ecx
dec ecx
jnz short loc_a
retn',NULL,NULL,NULL,1,0,'5120','[[0]]','2','xor eax, eax
loc_a:
add eax, ecx
dec ecx
jnz short loc_a
retn','int sub_180001400(int a1)
{
  return a1;
}','33','[]','61b877f5bfd89d93fd17ee703ace2c31',64,'5.5','[]',0,'5120','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'only_in_main_ü','6442456320',2,1,1,1,8,2,'["mov", "retn"]','[]',NULL,1,'5',NULL,'only_in_main_ü','c5d791e476d9083959a0542d31b01186',NULL,0,NULL,NULL,0,'mov eax, 0DEADh
retn',NULL,NULL,NULL,1,0,'5376','[[0]]','2','mov eax, 0DEADh
retn',NULL,'32','[]','592ed14506269a75485b26e96c448cc6',320,'0','[]',0,'5376','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
CREATE TABLE instructions (
                  id integer primary key,
                  func_id integer not null,
                  address text,
                  disasm text,
                  mnemonic text,
                  comment1 text,
                  comment2 text,
                  operand_names text,
                  name text,
                  type text,
                  pseudocomment text,
                  pseudoitp integer,
                  asm_type text);
CREATE TABLE program (
                  id integer primary key,
                  callgraph_primes text,
                  callgraph_all_primes text,
                  processor text,
                  md5sum text
                );
INSERT INTO "program" VALUES(1,'6','{"6": 1}','metapc','00000000000000000000000000000006');
CREATE TABLE program_data (
                  id integer primary key,
                  name varchar(255),
                  type varchar(255),
                  value text
                );
ANALYZE "sqlite_master";
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','6 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','6 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','6 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','6 2 2 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','6 6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','6 2 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','6 2 2 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','6 2 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','6 2 2 1 1 1 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','6 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','6 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','6 1');
INSERT INTO "sqlite_stat1" VALUES('version',NULL,'1');
INSERT INTO "sqlite_stat1" VALUES('program',NULL,'1');
CREATE TABLE version (value text);
INSERT INTO "version" VALUES('3.4');
CREATE INDEX idx_0 on functions(bytes_hash);
CREATE INDEX idx_1 on functions(pseudocode);
CREATE INDEX idx_2 on functions(name);
CREATE INDEX idx_3 on functions(mangled_function);
CREATE INDEX idx_4 on functions(assembly, pseudocode);
CREATE INDEX idx_5 on functions(nodes, edges, mnemonics, names, cyclomatic_complexity, prototype2, indegree, outdegree);
CREATE INDEX idx_6 on functions(instructions, mnemonics, names);
CREATE INDEX idx_7 on functions(nodes, edges, cyclomatic_complexity);
CREATE INDEX idx_8 on functions(cyclomatic_complexity);
CREATE INDEX idx_9 on functions(pseudocode_lines, pseudocode_primes);
CREATE INDEX idx_10 on functions(names, mnemonics);
CREATE INDEX idx_11 on functions(pseudocode_hash2);
CREATE INDEX idx_12 on functions(pseudocode_hash3);
CREATE INDEX idx_13 on functions(pseudocode_hash1, pseudocode_hash2, pseudocode_hash3);
CREATE INDEX idx_14 on functions(strongly_connected);
CREATE INDEX idx_15 on functions(strongly_connected_spp);
CREATE INDEX idx_16 on functions(loops);
CREATE INDEX idx_17 on functions(rva);
CREATE INDEX idx_18 on functions(tarjan_topological_sort);
CREATE INDEX idx_19 on functions(mnemonics_spp);
CREATE INDEX idx_20 on functions(clean_assembly);
CREATE INDEX idx_21 on functions(clean_pseudo);
CREATE INDEX idx_22 on functions(switches);
CREATE INDEX idx_23 on functions(function_hash);
CREATE INDEX idx_24 on functions(md_index);
CREATE INDEX idx_25 on functions(kgh_hash);
CREATE INDEX idx_26 on functions(constants_count, constants);
CREATE INDEX idx_27 on functions(md_index, constants_count, constants);
CREATE INDEX idx_28 on functions(address);
CREATE INDEX idx_29 on functions(microcode_spp);
CREATE INDEX idx_30 on functions(microcode);
CREATE INDEX idx_31 on instructions(address);
CREATE INDEX idx_32 on bb_relations(parent_id, child_id);
CREATE INDEX idx_33 on bb_instructions(basic_block_id, instruction_id);
CREATE INDEX idx_34 on function_bblocks(function_id, basic_block_id);
CREATE INDEX idx_35 on constants(constant, func_id);
CREATE INDEX idx_36 on callgraph(func_id);
CREATE INDEX idx_37 on compilation_units(pseudocode_primes);
CREATE INDEX idx_38 on compilation_units(name);
CREATE INDEX idx_39 on compilation_unit_functions(func_id);
CREATE INDEX idx_40 on compilation_unit_functions(cu_id);
COMMIT;
