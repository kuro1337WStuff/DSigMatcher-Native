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
INSERT INTO "compilation_unit_functions" VALUES(1,1,5);
INSERT INTO "compilation_unit_functions" VALUES(2,1,6);
CREATE TABLE compilation_units (
                  id integer primary key,
                  name text,
                  functions int,
                  primes_value text,
                  pseudocode_primes text,
                  start_ea text unique,
                  end_ea text);
INSERT INTO "compilation_units" VALUES(1,'cu_d',2,NULL,NULL,'80500','80600');
CREATE TABLE constants (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  constant text not null);
INSERT INTO "constants" VALUES(1,1,'abcdefgh');
INSERT INTO "constants" VALUES(2,2,'abcdefgh');
INSERT INTO "constants" VALUES(3,3,'abcdefgh');
INSERT INTO "constants" VALUES(4,4,'plain text');
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
INSERT INTO "functions" VALUES(1,'e_count_null','80100',8,7,1,1,36,9,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'e_count_null','d1a17959d76f74193582d1871434a324',NULL,0,NULL,NULL,0,'mov eax, 115
add ebx, 129
xor ecx, 143
cmp edx, 157
mov eax, 167
add ebx, 181
xor ecx, 195
cmp edx, 209
retn',NULL,NULL,NULL,1,0,'80100','[[0]]','2','mov eax, 115
add ebx, 129
xor ecx, 143
cmp edx, 157
mov eax, 167
add ebx, 181
xor ecx, 195
cmp edx, 209
retn',NULL,'38','[]','e2fee6668252f6fbb632a2e48bbb16e3',100,'0','["abcdefgh"]',1,'80100','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'e_consts_null','80200',8,7,1,1,36,9,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'e_consts_null','b7e1933cf187617b1555938f64318584',NULL,0,NULL,NULL,0,'mov eax, 212
add ebx, 226
xor ecx, 240
cmp edx, 3
mov eax, 13
add ebx, 27
xor ecx, 41
cmp edx, 55
retn',NULL,NULL,NULL,1,0,'80200','[[0]]','2','mov eax, 212
add ebx, 226
xor ecx, 240
cmp edx, 3
mov eax, 13
add ebx, 27
xor ecx, 41
cmp edx, 55
retn',NULL,'38','[]','501308aad8ff31e3b1617b2885780ce4',200,'0','["abcdefgh"]',1,'80200','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'e_json_bad','80300',8,7,1,1,36,9,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'e_json_bad','dbf0777d8ee5ed609d79de31bbc4d194',NULL,0,NULL,NULL,0,'mov eax, 58
add ebx, 72
xor ecx, 86
cmp edx, 100
mov eax, 110
add ebx, 124
xor ecx, 138
cmp edx, 152
retn',NULL,NULL,NULL,1,0,'80300','[[0]]','2','mov eax, 58
add ebx, 72
xor ecx, 86
cmp edx, 100
mov eax, 110
add ebx, 124
xor ecx, 138
cmp edx, 152
retn',NULL,'38','[]','e46ee8236197cfc912efd57075908cb6',300,'0','["abcdefgh"]',1,'80300','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'e_surrogate','80400',8,7,1,1,36,9,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'e_surrogate','2c7e4bd170d5bbf2e5dc8e9908682f56',NULL,0,NULL,NULL,0,'mov eax, 155
add ebx, 169
xor ecx, 183
cmp edx, 197
mov eax, 207
add ebx, 221
xor ecx, 235
cmp edx, 249
retn',NULL,NULL,NULL,1,0,'80400','[[0]]','2','mov eax, 155
add ebx, 169
xor ecx, 183
cmp edx, 197
mov eax, 207
add ebx, 221
xor ecx, 235
cmp edx, 249
retn',NULL,'38','[]','b4273c926c27ee4f9ab008be22e347bc',400,'0','["plain text", "\ud800abcdef"]',2,'80400','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'e_cu_null','80500',8,7,1,1,36,9,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'e_cu_null','028903e3758d736899edb784aa6e7e5e',NULL,0,NULL,NULL,0,'mov eax, 1
add ebx, 15
xor ecx, 29
cmp edx, 43
mov eax, 53
add ebx, 67
xor ecx, 81
cmp edx, 95
retn',NULL,NULL,NULL,1,0,'80500','[[0]]','2','mov eax, 1
add ebx, 15
xor ecx, 29
cmp edx, 43
mov eax, 53
add ebx, 67
xor ecx, 81
cmp edx, 95
retn',NULL,'38','[]','978bca8e21811f52c5fbd4f0ee0f697b',500,'0','[]',0,'80500','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'e_cu_bad','80600',8,7,1,1,36,9,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'e_cu_bad','38dab4e5e030788d159d221db098a322',NULL,0,NULL,NULL,0,'mov eax, 98
add ebx, 112
xor ecx, 126
cmp edx, 140
mov eax, 150
add ebx, 164
xor ecx, 178
cmp edx, 192
retn',NULL,NULL,NULL,1,0,'80600','[[0]]','2','mov eax, 98
add ebx, 112
xor ecx, 126
cmp edx, 140
mov eax, 150
add ebx, 164
xor ecx, 178
cmp edx, 192
retn',NULL,'38','[]','30b64081d586776345160202c74a9d1d',600,'0','[]',0,'80600','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
INSERT INTO "functions" VALUES(7,'e_la_a','11000',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'e_la_a','b4f4dda16fddc088ff4a991c2e7365d5',NULL,0,NULL,NULL,0,'mov eax, 195
add ebx, 209
xor ecx, 223
cmp edx, 237
mov eax, 247
add ebx, 10
retn',NULL,NULL,NULL,1,0,'11000','[[0]]','2','mov eax, 195
add ebx, 209
xor ecx, 223
cmp edx, 237
mov eax, 247
add ebx, 10
retn',NULL,'36','[]','b12588e97ec61aaa690af8522a5763bf',0,'0','[]',0,'11000','[]','0',NULL,NULL,NULL,NULL,'1',0.007);
INSERT INTO "functions" VALUES(8,'sub_12000','12000',8,7,1,1,36,9,'["mov", "add", "sub", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'sub_12000','0c34dd59419a1780e0c74cd5f7db1d35',NULL,0,NULL,NULL,0,'mov eax, 41
add ebx, 55
sub esi, 74
cmp edx, 83
mov eax, 93
add ebx, 107
xor ecx, 121
cmp edx, 135
retn',NULL,NULL,NULL,1,0,'12000','[[0]]','2','mov eax, 41
add ebx, 55
sub esi, 74
cmp edx, 83
mov eax, 93
add ebx, 107
xor ecx, 121
cmp edx, 135
retn',NULL,'38','[]','658af73e38449746ca84cf53f415eb97',0,'0','[]',0,'12000','[]','0',NULL,NULL,NULL,NULL,'1',0.008);
INSERT INTO "functions" VALUES(9,'e_la_b','13000',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'e_la_b','cb8a4cdc4dc505d1197869a5c8cd51a3',NULL,0,NULL,NULL,0,'mov eax, 138
add ebx, 152
xor ecx, 166
cmp edx, 180
mov eax, 190
add ebx, 204
retn',NULL,NULL,NULL,1,0,'13000','[[0]]','2','mov eax, 138
add ebx, 152
xor ecx, 166
cmp edx, 180
mov eax, 190
add ebx, 204
retn',NULL,'36','[]','c1ba7414efe0aacc007315068622dc9d',0,'0','[]',0,'13000','[]','0',NULL,NULL,NULL,NULL,'1',9.000000000000001054e-03);
INSERT INTO "functions" VALUES(10,'e_la_c','14000',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'e_la_c','05d8e3a7facec5386d82a9829c86509a',NULL,0,NULL,NULL,0,'mov eax, 235
add ebx, 249
xor ecx, 12
cmp edx, 26
mov eax, 36
add ebx, 50
retn',NULL,NULL,NULL,1,0,'14000','[[0]]','2','mov eax, 235
add ebx, 249
xor ecx, 12
cmp edx, 26
mov eax, 36
add ebx, 50
retn',NULL,'36','[]','582184cdc25da268a7ecc8e7263c9b90',0,'0','[]',0,'14000','[]','0',NULL,NULL,NULL,NULL,'1',0.01);
INSERT INTO "functions" VALUES(11,'sub_15000','15000',8,7,1,1,36,9,'["mov", "add", "xor", "sub", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'sub_15000','afb5de4b9d743170c56d7500ddec706f',NULL,0,NULL,NULL,0,'mov eax, 81
add ebx, 95
xor ecx, 109
sub esi, 127
mov eax, 133
add ebx, 147
xor ecx, 161
cmp edx, 175
retn',NULL,NULL,NULL,1,0,'15000','[[0]]','2','mov eax, 81
add ebx, 95
xor ecx, 109
sub esi, 127
mov eax, 133
add ebx, 147
xor ecx, 161
cmp edx, 175
retn',NULL,'38','[]','699020515a1b26cbb923d760c867f7cc',0,'0','[]',0,'15000','[]','0',NULL,NULL,NULL,NULL,'1',0.011);
INSERT INTO "functions" VALUES(12,'e_la_d','16000',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'e_la_d','6a134c1b11ffa384d4e84957b03465d0',NULL,0,NULL,NULL,0,'mov eax, 178
add ebx, 192
xor ecx, 206
cmp edx, 220
mov eax, 230
add ebx, 244
retn',NULL,NULL,NULL,1,0,'16000','[[0]]','2','mov eax, 178
add ebx, 192
xor ecx, 206
cmp edx, 220
mov eax, 230
add ebx, 244
retn',NULL,'36','[]','90ddf4b80905467bc2a2077f96a0bd14',0,'0','[]',0,'16000','[]','0',NULL,NULL,NULL,NULL,'1',0.012);
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
INSERT INTO "program" VALUES(1,'10','{"10": 1}','metapc','0000000000000000000000000000000a');
CREATE TABLE program_data (
                  id integer primary key,
                  name varchar(255),
                  type varchar(255),
                  value text
                );
ANALYZE "sqlite_master";
INSERT INTO "sqlite_stat1" VALUES('constants','idx_35','4 2 1');
INSERT INTO "sqlite_stat1" VALUES('compilation_units','idx_38','1 1');
INSERT INTO "sqlite_stat1" VALUES('compilation_units','idx_37','1 1');
INSERT INTO "sqlite_stat1" VALUES('compilation_units','sqlite_autoindex_compilation_units_1','1 1');
INSERT INTO "sqlite_stat1" VALUES('compilation_unit_functions','idx_40','2 2');
INSERT INTO "sqlite_stat1" VALUES('compilation_unit_functions','idx_39','2 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','12 12 4 4');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','12 4 4');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','12 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','12 12 12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','12 12 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','12 12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','12 6 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','12 6 3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','12 6 6 3 3 3 3 3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','12 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','12 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','12 1');
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
