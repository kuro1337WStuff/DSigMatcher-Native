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
INSERT INTO "functions" VALUES(1,'caller_fn','4096',5,6,1,1,41,7,'["mov", "mov", "mov"]','[]','int f()',3,'1011',NULL,'caller_fn','same','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  alpha_old_callee(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h11','3001',0,'mov eax, 1
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
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  alpha_old_callee(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5001','[]','bd19836ddb62c11c55ab251ccaca5645',1,'1.6','[]',0,'4096','[]','7001',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(2,'alpha_old_callee','8192',0,2,1,1,42,7,'["mov", "mov", "mov"]','[]','int f()',4,'1013',NULL,'alpha_old_callee','fbfba2e45c2045dc5cab22a5afe83d9d','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  gamma_old_leaf(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h12','3002',0,'mov eax, 2
add eax, 3
xor ebx, 2
push ebp
mov ebp, esp
pop ebp
retn','int()','h22','h32',1,0,'8192','[]','13','mov eax, 2
add eax, 3
xor ebx, 2
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  gamma_old_leaf(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5002','[]','3667f6a0c97490758d7dc9659d01ea34',2,'1.7','[]',0,'8192','[]','7002',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(3,'gamma_old_leaf','12288',5,5,1,1,43,7,'["mov", "mov", "mov"]','[]','int f()',5,'1015',NULL,'gamma_old_leaf','7a6f150b83091ce20c89368641f9a137','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  v9 = 7;
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
  v9 = 7;
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5003','[]','1779cf3aa50c413afc7e05adb7e1b0de',3,'1.8','[]',0,'12288','[]','7003',NULL,NULL,NULL,NULL,NULL,0.0);
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
INSERT INTO "program" VALUES(1,'6','{"2": 1, "3": 1}','metapc','x1');
CREATE TABLE program_data (
                  id integer primary key,
                  name varchar(255),
                  type varchar(255),
                  value text
                );
ANALYZE "sqlite_master";
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','3 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','3 3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','3 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','3 3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','3 3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','3 2 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','3 3 3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','3 2 1 1 1 1 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','3 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','3 1');
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
