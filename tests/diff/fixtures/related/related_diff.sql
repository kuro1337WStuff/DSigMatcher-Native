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
INSERT INTO "compilation_unit_functions" VALUES(1,1,1);
INSERT INTO "compilation_unit_functions" VALUES(2,1,2);
INSERT INTO "compilation_unit_functions" VALUES(3,1,3);
INSERT INTO "compilation_unit_functions" VALUES(4,1,4);
INSERT INTO "compilation_unit_functions" VALUES(5,2,5);
INSERT INTO "compilation_unit_functions" VALUES(6,2,6);
INSERT INTO "compilation_unit_functions" VALUES(7,2,8);
INSERT INTO "compilation_unit_functions" VALUES(8,2,9);
INSERT INTO "compilation_unit_functions" VALUES(9,2,10);
CREATE TABLE compilation_units (
                  id integer primary key,
                  name text,
                  functions int,
                  primes_value text,
                  pseudocode_primes text,
                  start_ea text unique,
                  end_ea text);
INSERT INTO "compilation_units" VALUES(1,'cu_a2',4,NULL,NULL,'30100','30400');
INSERT INTO "compilation_units" VALUES(2,'cu_b2',5,NULL,NULL,'30500','31000');
CREATE TABLE constants (
                  id integer primary key,
                  func_id integer not null references functions(id) on delete cascade,
                  constant text not null);
INSERT INTO "constants" VALUES(1,1,'second shared B');
INSERT INTO "constants" VALUES(2,1,'Hello related world');
INSERT INTO "constants" VALUES(3,1,'0x1234 zero prefix');
INSERT INTO "constants" VALUES(4,1,'8192');
INSERT INTO "constants" VALUES(5,1,'shared text A');
INSERT INTO "constants" VALUES(6,2,'shared text A');
INSERT INTO "constants" VALUES(7,3,'Hello related world');
INSERT INTO "constants" VALUES(8,3,'second shared B');
INSERT INTO "constants" VALUES(9,4,'shared text A');
INSERT INTO "constants" VALUES(10,4,'tail constant C');
INSERT INTO "constants" VALUES(11,5,'delta only text');
INSERT INTO "constants" VALUES(12,6,'shared text A');
INSERT INTO "constants" VALUES(13,7,'Hello related world');
INSERT INTO "constants" VALUES(14,9,'tail constant C');
INSERT INTO "constants" VALUES(15,9,'shared text A');
INSERT INTO "constants" VALUES(16,10,'shared text A');
INSERT INTO "constants" VALUES(17,11,'hello');
INSERT INTO "constants" VALUES(18,11,'123abc');
INSERT INTO "constants" VALUES(19,11,'  42 apples');
INSERT INTO "constants" VALUES(20,11,'0 files');
INSERT INTO "constants" VALUES(21,11,'1e5 x');
INSERT INTO "constants" VALUES(22,11,'Infinity');
INSERT INTO "constants" VALUES(23,11,'1e999');
INSERT INTO "constants" VALUES(24,11,'1e-400');
INSERT INTO "constants" VALUES(25,11,'1e-320');
INSERT INTO "constants" VALUES(26,11,'4096');
INSERT INTO "constants" VALUES(27,11,'0x10');
INSERT INTO "constants" VALUES(28,11,'.5x');
INSERT INTO "constants" VALUES(29,11,'inf');
INSERT INTO "constants" VALUES(30,11,'NaN');
INSERT INTO "constants" VALUES(31,11,'-12');
INSERT INTO "constants" VALUES(32,11,'-0');
INSERT INTO "constants" VALUES(33,11,'	7');
INSERT INTO "constants" VALUES(34,11,'
5');
INSERT INTO "constants" VALUES(35,11,'5');
INSERT INTO "constants" VALUES(36,11,'+3a');
INSERT INTO "constants" VALUES(37,11,'0000');
INSERT INTO "constants" VALUES(38,11,'e5');
INSERT INTO "constants" VALUES(39,11,'1e');
INSERT INTO "constants" VALUES(40,11,'.e1');
INSERT INTO "constants" VALUES(41,11,'-.5');
INSERT INTO "constants" VALUES(42,11,'..5');
INSERT INTO "constants" VALUES(43,11,'٣');
INSERT INTO "constants" VALUES(44,11,' 5');
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
INSERT INTO "functions" VALUES(1,'alpha','30100',12,11,1,1,52,13,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'25',NULL,'alpha','b9707fc9359eb2d93224891c4114f251',NULL,0,NULL,NULL,0,'mov eax, 97
add ebx, 111
xor ecx, 125
cmp edx, 139
mov eax, 149
add ebx, 163
xor ecx, 177
cmp edx, 191
mov eax, 201
add ebx, 215
xor ecx, 229
cmp edx, 243
retn',NULL,NULL,NULL,1,0,'30100','[[0]]','2','mov eax, 97
add ebx, 111
xor ecx, 125
cmp edx, 139
mov eax, 149
add ebx, 163
xor ecx, 177
cmp edx, 191
mov eax, 201
add ebx, 215
xor ecx, 229
cmp edx, 243
retn',NULL,'42','[]','887343d80395f2f1ce2f7b45bed70779',100,'0','["second shared B", "Hello related world", "0x1234 zero prefix", 8192, "shared text A"]',5,'30100','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'sub_30200','30200',10,9,1,1,44,11,'["mov", "add", "xor", "sub", "mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_30200','091db10f15f1b44826139b7fd6357336',NULL,0,NULL,NULL,0,'mov eax, 194
add ebx, 208
xor ecx, 222
sub esi, 240
mov eax, 246
add ebx, 9
xor ecx, 23
cmp edx, 37
mov eax, 47
add ebx, 61
retn',NULL,NULL,NULL,1,0,'30200','[[0]]','2','mov eax, 194
add ebx, 208
xor ecx, 222
sub esi, 240
mov eax, 246
add ebx, 9
xor ecx, 23
cmp edx, 37
mov eax, 47
add ebx, 61
retn',NULL,'40','[]','13d8dc30643197187aa91e4ca17b5c5d',200,'0','["shared text A"]',1,'30200','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'sub_30300','30300',10,9,1,1,44,11,'["mov", "add", "sub", "cmp", "mov", "add", "xor", "sub", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_30300','a341fa46f7fd752e738362741a4fefe4',NULL,0,NULL,NULL,0,'mov eax, 40
add ebx, 54
sub esi, 73
cmp edx, 82
mov eax, 92
add ebx, 106
xor ecx, 120
sub esi, 138
mov eax, 144
add ebx, 158
retn',NULL,NULL,NULL,1,0,'30300','[[0]]','2','mov eax, 40
add ebx, 54
sub esi, 73
cmp edx, 82
mov eax, 92
add ebx, 106
xor ecx, 120
sub esi, 138
mov eax, 144
add ebx, 158
retn',NULL,'40','[]','f3487c73e3a23aa45a5e7274d4f784d0',300,'0','["Hello related world", "second shared B"]',2,'30300','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'gamma2','30400',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "sub", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'gamma2','4ea809d7cd8ff6401b50b964c3acbca2',NULL,0,NULL,NULL,0,'mov eax, 137
add ebx, 151
xor ecx, 165
cmp edx, 179
mov eax, 189
sub esi, 209
xor ecx, 217
cmp edx, 231
mov eax, 241
add ebx, 4
retn',NULL,NULL,NULL,1,0,'30400','[[0]]','2','mov eax, 137
add ebx, 151
xor ecx, 165
cmp edx, 179
mov eax, 189
sub esi, 209
xor ecx, 217
cmp edx, 231
mov eax, 241
add ebx, 4
retn',NULL,'40','[]','968e56ee23d39e2aee8a780edd3aab37',400,'0','["shared text A", "tail constant C"]',2,'30400','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'delta','30500',10,9,1,1,44,11,'["mov", "sub", "xor", "cmp", "sub", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'delta','0fb9486a328fdd41a2bfbba1e776d3b0',NULL,0,NULL,NULL,0,'mov eax, 234
sub esi, 254
xor ecx, 11
cmp edx, 25
sub esi, 42
add ebx, 49
xor ecx, 63
cmp edx, 77
mov eax, 87
add ebx, 101
retn',NULL,NULL,NULL,1,0,'30500','[[0]]','2','mov eax, 234
sub esi, 254
xor ecx, 11
cmp edx, 25
sub esi, 42
add ebx, 49
xor ecx, 63
cmp edx, 77
mov eax, 87
add ebx, 101
retn',NULL,'40','[]','cb0dd95b056fba4e9db0295374c54aac',500,'0','["delta only text"]',1,'30500','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'nullsub_30600','30600',4,3,1,1,20,5,'["mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'9',NULL,'nullsub_30600','d15effbd9276c4644251deded67a7424',NULL,0,NULL,NULL,0,'mov eax, 80
add ebx, 94
xor ecx, 108
cmp edx, 122
retn',NULL,NULL,NULL,1,0,'30600','[[0]]','2','mov eax, 80
add ebx, 94
xor ecx, 108
cmp edx, 122
retn',NULL,'34','[]','f6e65a0132294efa4404d9c3b1c08802',600,'0','["shared text A"]',1,'30600','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
INSERT INTO "functions" VALUES(7,'epsilon','30700',10,9,1,1,44,11,'["sub", "add", "xor", "sub", "mov", "add", "sub", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'epsilon','79399ad8eddd58ebae747bfcbcb9a435',NULL,0,NULL,NULL,0,'sub esi, 184
add ebx, 191
xor ecx, 205
sub esi, 223
mov eax, 229
add ebx, 243
sub esi, 11
cmp edx, 20
mov eax, 30
add ebx, 44
retn',NULL,NULL,NULL,1,0,'30700','[[0]]','2','sub esi, 184
add ebx, 191
xor ecx, 205
sub esi, 223
mov eax, 229
add ebx, 243
sub esi, 11
cmp edx, 20
mov eax, 30
add ebx, 44
retn',NULL,'40','[]','8120a0a154db04b39f8bc691f656d7c2',700,'0','["Hello related world"]',1,'30700','[]','0',NULL,NULL,NULL,NULL,'1',0.007);
INSERT INTO "functions" VALUES(8,'zeta','30800',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'zeta','2ceabcc2b8a315744019f7443fbd7e3b',NULL,0,NULL,NULL,0,'mov eax, 23
add ebx, 37
xor ecx, 51
cmp edx, 65
mov eax, 75
add ebx, 89
xor ecx, 103
cmp edx, 117
mov eax, 127
add ebx, 141
retn',NULL,NULL,NULL,1,0,'30800','[[0]]','2','mov eax, 23
add ebx, 37
xor ecx, 51
cmp edx, 65
mov eax, 75
add ebx, 89
xor ecx, 103
cmp edx, 117
mov eax, 127
add ebx, 141
retn',NULL,'40','[]','8be13ae9102f6ef25449deac9c4f9a53',800,'0','[]',NULL,'30800','[]','0',NULL,NULL,NULL,NULL,'1',0.008);
INSERT INTO "functions" VALUES(9,'sub_30900','30900',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "sub", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_30900','a9beb6c476365e15a01d8c4dfd91996b',NULL,0,NULL,NULL,0,'mov eax, 120
add ebx, 134
xor ecx, 148
cmp edx, 162
mov eax, 172
add ebx, 186
xor ecx, 200
cmp edx, 214
sub esi, 231
add ebx, 238
retn',NULL,NULL,NULL,1,0,'30900','[[0]]','2','mov eax, 120
add ebx, 134
xor ecx, 148
cmp edx, 162
mov eax, 172
add ebx, 186
xor ecx, 200
cmp edx, 214
sub esi, 231
add ebx, 238
retn',NULL,'40','[]','2d1ab0210013c132306d48dbc3c50899',900,'0','["tail constant C", "shared text A"]',2,'30900','[]','0',NULL,NULL,NULL,NULL,'1',9.000000000000001054e-03);
INSERT INTO "functions" VALUES(10,'sub_31000','31000',10,9,1,1,44,11,'["mov", "sub", "xor", "sub", "mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_31000','62602823128741476c21441b3365ce23',NULL,0,NULL,NULL,0,'mov eax, 194
sub esi, 214
xor ecx, 222
sub esi, 240
mov eax, 246
add ebx, 9
xor ecx, 23
cmp edx, 37
mov eax, 47
add ebx, 61
retn',NULL,NULL,NULL,1,0,'31000','[[0]]','2','mov eax, 194
sub esi, 214
xor ecx, 222
sub esi, 240
mov eax, 246
add ebx, 9
xor ecx, 23
cmp edx, 37
mov eax, 47
add ebx, 61
retn',NULL,'40','[]','beaa01226a1e7a86e5b95e51d7122295',0,'0','["shared text A"]',1,'31000','[]','0',NULL,NULL,NULL,NULL,'1',0.01);
INSERT INTO "functions" VALUES(11,'abs_probe','31100',8,7,1,1,36,9,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "retn"]','[]',NULL,1,'17',NULL,'abs_probe','73320ef25ed6f6f34d7118a581122812',NULL,0,NULL,NULL,0,'mov eax, 217
add ebx, 231
xor ecx, 245
cmp edx, 8
mov eax, 18
add ebx, 32
xor ecx, 46
cmp edx, 60
retn',NULL,NULL,NULL,1,0,'31100','[[0]]','2','mov eax, 217
add ebx, 231
xor ecx, 245
cmp edx, 8
mov eax, 18
add ebx, 32
xor ecx, 46
cmp edx, 60
retn',NULL,'38','[]','c2f67c71556cdab768a84f71d2b10f72',100,'0','["hello", "4096", "123abc", "  42 apples", "0x10", "0 files", "1e5 x", ".5x", "inf", "Infinity", "NaN", "-12", "-0", "1e999", "\t7", "\n5", "\u000b5", "+3a", "0000", "e5", "1e", ".e1", "-.5", "..5", "٣", " 5", "1e-400", "1e-320"]',28,'31100','[]','0',NULL,NULL,NULL,NULL,'1',0.011);
INSERT INTO "functions" VALUES(20,'la_anchor1','14096',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'la_anchor1','d5ec9bf54a29aa40bc55f4add4efbffe',NULL,0,NULL,NULL,0,'mov eax, 183
add ebx, 197
xor ecx, 211
cmp edx, 225
mov eax, 235
add ebx, 249
retn',NULL,NULL,NULL,1,0,'14096','[[0]]','2','mov eax, 183
add ebx, 197
xor ecx, 211
cmp edx, 225
mov eax, 235
add ebx, 249
retn',NULL,'36','[]','05b364ba8821b5bd0767b1caac974587',96,'0','[]',0,'14096','[]','0',NULL,NULL,NULL,NULL,'1',0.02);
INSERT INTO "functions" VALUES(21,'sub_15000','15000',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "sub", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_15000','3d2f860b9980eeb42f166fa1db7d14bf',NULL,0,NULL,NULL,0,'mov eax, 29
add ebx, 43
xor ecx, 57
cmp edx, 71
sub esi, 88
add ebx, 95
xor ecx, 109
cmp edx, 123
mov eax, 133
add ebx, 147
retn',NULL,NULL,NULL,1,0,'15000','[[0]]','2','mov eax, 29
add ebx, 43
xor ecx, 57
cmp edx, 71
sub esi, 88
add ebx, 95
xor ecx, 109
cmp edx, 123
mov eax, 133
add ebx, 147
retn',NULL,'40','[]','0357ef35edb420fa3f17175d54b90a1e',0,'0','[]',0,'15000','[]','0',NULL,NULL,NULL,NULL,'1',0.021);
INSERT INTO "functions" VALUES(22,'sub_16000','16000',10,9,1,1,44,11,'["mov", "add", "sub", "cmp", "mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_16000','360c305011480f2a899a82872d3f2412',NULL,0,NULL,NULL,0,'mov eax, 12
add ebx, 26
sub esi, 45
cmp edx, 54
mov eax, 64
add ebx, 78
xor ecx, 92
cmp edx, 106
mov eax, 116
add ebx, 130
retn',NULL,NULL,NULL,1,0,'16000','[[0]]','2','mov eax, 12
add ebx, 26
sub esi, 45
cmp edx, 54
mov eax, 64
add ebx, 78
xor ecx, 92
cmp edx, 106
mov eax, 116
add ebx, 130
retn',NULL,'40','[]','11f5e47c538a0113d82b032f5ab2d44e',0,'0','[]',0,'16000','[]','0',NULL,NULL,NULL,NULL,'1',0.022);
INSERT INTO "functions" VALUES(23,'la_named2','17000',10,9,1,1,44,11,'["mov", "sub", "xor", "cmp", "mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'la_named2','9e7b17730e45eca2e75ae97f060bf42c',NULL,0,NULL,NULL,0,'mov eax, 223
sub esi, 243
xor ecx, 251
cmp edx, 14
mov eax, 24
add ebx, 38
xor ecx, 52
cmp edx, 66
mov eax, 76
add ebx, 90
retn',NULL,NULL,NULL,1,0,'17000','[[0]]','2','mov eax, 223
sub esi, 243
xor ecx, 251
cmp edx, 14
mov eax, 24
add ebx, 38
xor ecx, 52
cmp edx, 66
mov eax, 76
add ebx, 90
retn',NULL,'40','[]','34f7e0f135f5322c0d617a4b11a48300',0,'0','[]',0,'17000','[]','0',NULL,NULL,NULL,NULL,'1',0.023);
INSERT INTO "functions" VALUES(24,'sub_18000','18000',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "add", "sub", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_18000','c0f3c8e0c45603e043613a26e959942d',NULL,0,NULL,NULL,0,'mov eax, 69
add ebx, 83
xor ecx, 97
cmp edx, 111
mov eax, 121
add ebx, 135
sub esi, 154
cmp edx, 163
mov eax, 173
add ebx, 187
retn',NULL,NULL,NULL,1,0,'18000','[[0]]','2','mov eax, 69
add ebx, 83
xor ecx, 97
cmp edx, 111
mov eax, 121
add ebx, 135
sub esi, 154
cmp edx, 163
mov eax, 173
add ebx, 187
retn',NULL,'40','[]','b7c93c10d9272fbc970f68d67c866c36',0,'0','[]',0,'18000','[]','0',NULL,NULL,NULL,NULL,'1',0.024);
INSERT INTO "functions" VALUES(25,'la_anchor2','18192',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'la_anchor2','390cf5414ea716cadee762ea2beca444',NULL,0,NULL,NULL,0,'mov eax, 166
add ebx, 180
xor ecx, 194
cmp edx, 208
mov eax, 218
add ebx, 232
retn',NULL,NULL,NULL,1,0,'18192','[[0]]','2','mov eax, 166
add ebx, 180
xor ecx, 194
cmp edx, 208
mov eax, 218
add ebx, 232
retn',NULL,'36','[]','f806348d69c8997448fe7d51c4b61db6',192,'0','[]',0,'18192','[]','0',NULL,NULL,NULL,NULL,'1',0.025);
INSERT INTO "functions" VALUES(26,'sub_15500','15500',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "mov", "sub", "retn"]','[]',NULL,1,'21',NULL,'sub_15500','1ad0ede7c8cbe2d8f017483c7096493d',NULL,0,NULL,NULL,0,'mov eax, 246
add ebx, 9
xor ecx, 23
cmp edx, 37
mov eax, 47
add ebx, 61
xor ecx, 75
cmp edx, 89
mov eax, 99
sub esi, 119
retn',NULL,NULL,NULL,1,0,'15500','[[0]]','2','mov eax, 246
add ebx, 9
xor ecx, 23
cmp edx, 37
mov eax, 47
add ebx, 61
xor ecx, 75
cmp edx, 89
mov eax, 99
sub esi, 119
retn',NULL,'40','[]','281bb05a7d6191a4f24731dc5d776e33',500,'0','[]',0,'15500','[]','0',NULL,NULL,NULL,NULL,'1',2.600000000000000227e-02);
INSERT INTO "functions" VALUES(27,'la_anchor4','19990',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'la_anchor4','8b9e9fcd4dc95944f963d8f29a158ad5',NULL,0,NULL,NULL,0,'mov eax, 149
add ebx, 163
xor ecx, 177
cmp edx, 191
mov eax, 201
add ebx, 215
retn',NULL,NULL,NULL,1,0,'19990','[[0]]','2','mov eax, 149
add ebx, 163
xor ecx, 177
cmp edx, 191
mov eax, 201
add ebx, 215
retn',NULL,'36','[]','d693b75e6c4b69ff23acd743802315d6',990,'0','[]',0,'19990','[]','0',NULL,NULL,NULL,NULL,'1',0.027);
INSERT INTO "functions" VALUES(28,'sub_19992','19992',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_19992','a7b7b07fb722a6fc5e2357c098a99110',NULL,0,NULL,NULL,0,'mov eax, 206
add ebx, 220
xor ecx, 234
cmp edx, 248
mov eax, 7
add ebx, 21
xor ecx, 35
cmp edx, 49
mov eax, 59
add ebx, 73
retn',NULL,NULL,NULL,1,0,'19992','[[0]]','2','mov eax, 206
add ebx, 220
xor ecx, 234
cmp edx, 248
mov eax, 7
add ebx, 21
xor ecx, 35
cmp edx, 49
mov eax, 59
add ebx, 73
retn',NULL,'40','[]','3d98c88c32f3c93fbdbc834acc4ed4a9',992,'0','[]',0,'19992','[]','0',NULL,NULL,NULL,NULL,'1',0.028);
INSERT INTO "functions" VALUES(29,'la_anchor3','19995',6,5,1,1,28,7,'["mov", "add", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'13',NULL,'la_anchor3','27c91810ef2b75a54b4b64c9360883bf',NULL,0,NULL,NULL,0,'mov eax, 109
add ebx, 123
xor ecx, 137
cmp edx, 151
mov eax, 161
add ebx, 175
retn',NULL,NULL,NULL,1,0,'19995','[[0]]','2','mov eax, 109
add ebx, 123
xor ecx, 137
cmp edx, 151
mov eax, 161
add ebx, 175
retn',NULL,'36','[]','b6200534f230a2d45016c08dfafa0e8d',995,'0','[]',0,'19995','[]','0',NULL,NULL,NULL,NULL,'1',0.029);
INSERT INTO "functions" VALUES(30,'sub_15100','15100',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "add", "sub", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_15100','78936382e4d2924714e82ee565fa8e77',NULL,0,NULL,NULL,0,'mov eax, 29
add ebx, 43
xor ecx, 57
cmp edx, 71
mov eax, 81
add ebx, 95
sub esi, 114
cmp edx, 123
mov eax, 133
add ebx, 147
retn',NULL,NULL,NULL,1,0,'15100','[[0]]','2','mov eax, 29
add ebx, 43
xor ecx, 57
cmp edx, 71
mov eax, 81
add ebx, 95
sub esi, 114
cmp edx, 123
mov eax, 133
add ebx, 147
retn',NULL,'40','[]','2ed44fd978e77e0cddee4d073a575f94',100,'0','[]',0,'15100','[]','0',NULL,NULL,NULL,NULL,'1',0.03);
INSERT INTO "functions" VALUES(31,'sub_15600','15600',10,9,1,1,44,11,'["mov", "add", "xor", "cmp", "mov", "sub", "xor", "cmp", "mov", "add", "retn"]','[]',NULL,1,'21',NULL,'sub_15600','93ed8e16ff38889665debfc8a6df04c4',NULL,-3,NULL,NULL,0,'mov eax, 92
add ebx, 106
xor ecx, 120
cmp edx, 134
mov eax, 144
sub esi, 164
xor ecx, 172
cmp edx, 186
mov eax, 196
add ebx, 210
retn',NULL,NULL,NULL,1,0,'15600','[[0]]','2','mov eax, 92
add ebx, 106
xor ecx, 120
cmp edx, 134
mov eax, 144
sub esi, 164
xor ecx, 172
cmp edx, 186
mov eax, 196
add ebx, 210
retn',NULL,'40','[]','33c4cbbfc969b1d6111f330f28215942',600,'0','[]',0,'15600','[]','0',NULL,NULL,NULL,NULL,'1',0.031);
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
INSERT INTO "sqlite_stat1" VALUES('constants','idx_35','44 2 1');
INSERT INTO "sqlite_stat1" VALUES('compilation_units','idx_38','2 1');
INSERT INTO "sqlite_stat1" VALUES('compilation_units','idx_37','2 2');
INSERT INTO "sqlite_stat1" VALUES('compilation_units','sqlite_autoindex_compilation_units_1','2 1');
INSERT INTO "sqlite_stat1" VALUES('compilation_unit_functions','idx_40','9 5');
INSERT INTO "sqlite_stat1" VALUES('compilation_unit_functions','idx_39','9 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','23 23 4 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','23 4 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','23 5');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','23 23 23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','23 23 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','23 12 12');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','23 5 5 5');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','23 5 2 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','23 5 5 2 2 2 2 2 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','23 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','23 23');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','23 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','23 1');
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
