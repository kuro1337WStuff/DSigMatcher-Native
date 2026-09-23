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
INSERT INTO "functions" VALUES(1,'func_1','4198656',4,3,1,1,32,8,'["push", "mov", "add", "add", "add", "add", "pop", "ret"]','[]',NULL,1,'9',NULL,'func_1','4f27a1d58de2b7b44ebe79488e6bb499',NULL,0,NULL,NULL,0,'push rbp
mov rbp, rsp
add eax, 7
add eax, 8
add eax, 9
add eax, 10
pop rbp
ret',NULL,NULL,NULL,1,0,'4198656','[[0]]','2','push rbp
mov rbp, rsp
add eax, 7
add eax, 8
add eax, 9
add eax, 10
pop rbp
ret',NULL,'34','[]','d78f0ed9114983ed1affb76300609ba7',656,'0','[]',0,'4198656','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'func_2','4198912',4,3,1,1,32,8,'["push", "mov", "add", "add", "add", "add", "pop", "ret"]','[]',NULL,1,'9',NULL,'func_2','e26d758e6fe160839518809b92f8fdfc',NULL,0,NULL,NULL,0,'push rbp
mov rbp, rsp
add eax, 14
add eax, 15
add eax, 16
add eax, 17
pop rbp
ret',NULL,NULL,NULL,1,0,'4198912','[[0]]','2','push rbp
mov rbp, rsp
add eax, 14
add eax, 15
add eax, 16
add eax, 17
pop rbp
ret',NULL,'34','[]','f08c981f2b71b202d04ca3c7035454e5',912,'0','[]',0,'4198912','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'func_3','4199168',4,3,1,1,32,8,'["push", "mov", "add", "add", "add", "add", "pop", "ret"]','[]',NULL,1,'9',NULL,'func_3','8794cb26fcd80778c6c7f8c8d5be5f48',NULL,0,NULL,NULL,0,'push rbp
mov rbp, rsp
add eax, 21
add eax, 22
add eax, 23
add eax, 24
pop rbp
ret',NULL,NULL,NULL,1,0,'4199168','[[0]]','2','push rbp
mov rbp, rsp
add eax, 21
add eax, 22
add eax, 23
add eax, 24
pop rbp
ret',NULL,'34','[]','a59ac60199e4456b8f506b9e842bfb05',168,'0','[]',0,'4199168','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'func_4','4199424',4,3,1,1,32,8,'["push", "mov", "add", "add", "add", "add", "pop", "ret"]','[]',NULL,1,'9',NULL,'func_4','d7940bc759b32217c5c520d085b44c03',NULL,0,NULL,NULL,0,'push rbp
mov rbp, rsp
add eax, 28
add eax, 29
add eax, 30
add eax, 31
pop rbp
ret',NULL,NULL,NULL,1,0,'4199424','[[0]]','2','push rbp
mov rbp, rsp
add eax, 28
add eax, 29
add eax, 30
add eax, 31
pop rbp
ret',NULL,'34','[]','f6a5d6386f273bd40b0f4955fcc87be6',424,'0','[]',0,'4199424','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'func_5','4199680',4,3,1,1,32,8,'["push", "mov", "add", "add", "add", "add", "pop", "ret"]','[]',NULL,1,'9',NULL,'func_5','2f320932dc6ecf7dd1300c8a82c7193e',NULL,0,NULL,NULL,0,'push rbp
mov rbp, rsp
add eax, 35
add eax, 36
add eax, 37
add eax, 38
pop rbp
ret',NULL,NULL,NULL,1,0,'4199680','[[0]]','2','push rbp
mov rbp, rsp
add eax, 35
add eax, 36
add eax, 37
add eax, 38
pop rbp
ret',NULL,'34','[]','12734b4be21161ff811babed9edc7dd2',680,'0','[]',0,'4199680','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'func_6','4199936',4,3,1,1,32,8,'["push", "mov", "add", "add", "add", "add", "pop", "ret"]','[]',NULL,1,'9',NULL,'func_6','e2bcb9d45d50f43f2bf86870f2238f6c',NULL,0,NULL,NULL,0,'push rbp
mov rbp, rsp
add eax, 42
add eax, 43
add eax, 44
add eax, 45
pop rbp
ret',NULL,NULL,NULL,1,0,'4199936','[[0]]','2','push rbp
mov rbp, rsp
add eax, 42
add eax, 43
add eax, 44
add eax, 45
pop rbp
ret',NULL,'34','[]','8540bf716b7c998a561b9c573a5a590f',936,'0','[]',0,'4199936','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
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
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','6 6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','6 6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','6 6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','6 6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','6 6 6 6 6 6 6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','6 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','6 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','6 6');
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
