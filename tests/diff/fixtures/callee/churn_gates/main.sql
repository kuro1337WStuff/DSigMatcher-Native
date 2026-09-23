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
INSERT INTO "functions" VALUES(1,'hub_fn','4096',12,13,1,1,41,7,'["mov", "mov", "mov"]','[]','int f()',3,'1011',NULL,'hub_fn','hub','  int v1 = 0;
  int v2 = 1;
  same_exact(v1);
  c00 = 0;
  c01 = 0;
  same_changed(v1);
  c02 = 1;
  c03 = 1;
  gate_small_a(v1);
  c04 = 2;
  c05 = 2;
  gate_pct_a(v1);
  c06 = 3;
  c07 = 3;
  gate_edge_a(v1);
  c08 = 4;
  c09 = 4;
  nullsub_1a(v1);
  c10 = 5;
  c11 = 5;
  nullsubx_a(v1);
  c12 = 6;
  c13 = 6;
  return v1;',24,'h11','3001',0,'mov eax, 1
add eax, 2
xor ebx, 1
push ebp
mov ebp, esp
pop ebp
retn','int()','h21','h31',1,0,'4096','[]','12','mov eax, 1
add eax, 2
xor ebx, 1
push ebp
mov ebp, esp
pop ebp
retn','  int v1 = 0;
  int v2 = 1;
  same_exact(v1);
  c00 = 0;
  c01 = 0;
  same_changed(v1);
  c02 = 1;
  c03 = 1;
  gate_small_a(v1);
  c04 = 2;
  c05 = 2;
  gate_pct_a(v1);
  c06 = 3;
  c07 = 3;
  gate_edge_a(v1);
  c08 = 4;
  c09 = 4;
  nullsub_1a(v1);
  c10 = 5;
  c11 = 5;
  nullsubx_a(v1);
  c12 = 6;
  c13 = 6;
  return v1;','5001','[]','bd19836ddb62c11c55ab251ccaca5645',1,'1.6','[]',0,'4096','[]','7001',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(2,'same_exact','8192',5,5,1,1,70,7,'["mov", "mov", "mov"]','[]','int f()',32,'1069',NULL,'same_exact','exact','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_exact(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h130','3030',0,'mov eax, 30
add eax, 31
xor ebx, 30
push ebp
mov ebp, esp
pop ebp
retn','int()','h230','h330',1,0,'8192','[]','41','mov eax, 30
add eax, 31
xor ebx, 30
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_exact(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5030','[]','5ed40cc0659d685215b4897e21fa3cab',30,'4.5','[]',0,'8192','[]','7030',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(3,'same_changed','12288',5,5,1,1,43,7,'["mov", "mov", "mov"]','[]','int f()',5,'1015',NULL,'same_changed','7a6f150b83091ce20c89368641f9a137','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_changed_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h13','3003',0,'mov eax, 3
add eax, 4
xor ebx, 3
push ebp
mov ebp, esp
pop ebp
retn','int()','h23','h33',1,0,'12288','[]','14','mov eax, 3
add eax, 4
xor ebx, 3
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_changed_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5003','[]','1779cf3aa50c413afc7e05adb7e1b0de',3,'1.8','[]',0,'12288','[]','7003',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(4,'gate_small_a','16384',2,3,1,1,44,7,'["mov", "mov", "mov"]','[]','int f()',6,'1017',NULL,'gate_small_a','3dfe563103ab11bec75bb5081e7a1dbe','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_small_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h14','3004',0,'mov eax, 4
add eax, 5
xor ebx, 4
push ebp
mov ebp, esp
pop ebp
retn','int()','h24','h34',1,0,'16384','[]','15','mov eax, 4
add eax, 5
xor ebx, 4
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_small_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5004','[]','6e1fcd704528ad8bf6d6bbedb9210096',4,'1.9','[]',0,'16384','[]','7004',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(5,'gate_pct_a','20480',3,5,1,1,45,7,'["mov", "mov", "mov"]','[]','int f()',7,'1019',NULL,'gate_pct_a','2283335d8d12b21001439091e74f5028','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_pct_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h15','3005',0,'mov eax, 5
add eax, 6
xor ebx, 5
push ebp
mov ebp, esp
pop ebp
retn','int()','h25','h35',1,0,'20480','[]','16','mov eax, 5
add eax, 6
xor ebx, 5
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_pct_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5005','[]','74ce2e1a498f2fa27b5542040be774dc',5,'2.0','[]',0,'20480','[]','7005',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(6,'gate_edge_a','24576',4,4,1,1,46,7,'["mov", "mov", "mov"]','[]','int f()',8,'1021',NULL,'gate_edge_a','528953727ef3a4e1c441c6078534c39b','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_edge_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h16','3006',0,'mov eax, 6
add eax, 7
xor ebx, 6
push ebp
mov ebp, esp
pop ebp
retn','int()','h26','h36',1,0,'24576','[]','17','mov eax, 6
add eax, 7
xor ebx, 6
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_edge_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5006','[]','64e4cda19b3f3ea4a7a56b5ba8cc33ca',6,'2.1','[]',0,'24576','[]','7006',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(7,'nullsub_1a','28672',5,6,1,1,47,7,'["mov", "mov", "mov"]','[]','int f()',9,'1023',NULL,'nullsub_1a','d8708ecb9a1e7ba172c83d8360c57e7d','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_null_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h17','3007',0,'mov eax, 7
add eax, 8
xor ebx, 7
push ebp
mov ebp, esp
pop ebp
retn','int()','h27','h37',1,0,'28672','[]','18','mov eax, 7
add eax, 8
xor ebx, 7
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_null_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5007','[]','6c664eeed34d9c29a711bdb374831b49',7,'2.2','[]',0,'28672','[]','7007',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(8,'nullsubx_a','32768',5,7,1,1,48,7,'["mov", "mov", "mov"]','[]','int f()',10,'1025',NULL,'nullsubx_a','75d99404a02e2bc993a6bac34c60d679','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_nullx_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h18','3008',0,'mov eax, 8
add eax, 9
xor ebx, 8
push ebp
mov ebp, esp
pop ebp
retn','int()','h28','h38',1,0,'32768','[]','19','mov eax, 8
add eax, 9
xor ebx, 8
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_nullx_a(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5008','[]','581c3010417303e1ee4c0657d76318d0',8,'2.3','[]',0,'32768','[]','7008',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(9,'nopseudo_fn','36864',5,5,1,1,49,7,'["mov", "mov", "mov"]','[]','int f()',11,'1027',NULL,'nopseudo_fn','37cc8552b35560a7b91cd1f47df89cae','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_nopseudo(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h19','3009',0,'mov eax, 9
add eax, 10
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h29','h39',1,0,'36864','[]','20','mov eax, 9
add eax, 10
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_nopseudo(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5009','[]','6506f0388343a1f09fd708fb15c5ade9',9,'2.4','[]',0,'36864','[]','7009',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(10,'emptypseudo_fn','40960',5,6,1,1,50,7,'["mov", "mov", "mov"]','[]','int f()',12,'1029',NULL,'emptypseudo_fn','e324ad8ed03e3a7b3b98cf21cfdaadbb','',1,'h110','3010',0,'mov eax, 10
add eax, 11
xor ebx, 10
push ebp
mov ebp, esp
pop ebp
retn','int()','h210','h310',1,0,'40960','[]','21','mov eax, 10
add eax, 11
xor ebx, 10
push ebp
mov ebp, esp
pop ebp
retn','','5010','[]','82b5f6802b727b0d948d38cbccd48904',10,'2.5','[]',0,'40960','[]','7010',NULL,NULL,NULL,NULL,NULL,0.0);
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
INSERT INTO "program" VALUES(1,'6','{"2": 1, "3": 1}','metapc','g1');
CREATE TABLE program_data (
                  id integer primary key,
                  name varchar(255),
                  type varchar(255),
                  value text
                );
ANALYZE "sqlite_master";
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','10 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','10 10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','10 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','10 10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','10 4 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','10 2 2 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','10 10 10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','10 2 2 2 2 1 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','10 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','10 1');
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
