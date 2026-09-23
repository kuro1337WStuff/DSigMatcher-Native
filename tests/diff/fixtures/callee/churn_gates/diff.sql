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
INSERT INTO "functions" VALUES(1,'hub_fn','4352',12,13,1,1,41,7,'["mov", "mov", "mov"]','[]','int f()',3,'1011',NULL,'hub_fn','hub','  int v1 = 0;
  int v2 = 1;
  same_exact(v2);
  c00 = 0;
  c01 = 0;
  same_changed(v2);
  c02 = 1;
  c03 = 1;
  gate_small_b(v2);
  c04 = 2;
  c05 = 2;
  gate_pct_b(v2);
  c06 = 3;
  c07 = 3;
  gate_edge_b(v2);
  c08 = 4;
  c09 = 4;
  nullsub_2b(v2);
  c10 = 5;
  c11 = 5;
  nullsubx_b(v2);
  c12 = 6;
  c13 = 6;
  return v1;',24,'h11','3001',0,'mov eax, 1
add eax, 2
xor ebx, 1
push ebp
mov ebp, esp
pop ebp
retn','int()','h21','h31',1,0,'4352','[]','12','mov eax, 1
add eax, 2
xor ebx, 1
push ebp
mov ebp, esp
pop ebp
retn','  int v1 = 0;
  int v2 = 1;
  same_exact(v2);
  c00 = 0;
  c01 = 0;
  same_changed(v2);
  c02 = 1;
  c03 = 1;
  gate_small_b(v2);
  c04 = 2;
  c05 = 2;
  gate_pct_b(v2);
  c06 = 3;
  c07 = 3;
  gate_edge_b(v2);
  c08 = 4;
  c09 = 4;
  nullsub_2b(v2);
  c10 = 5;
  c11 = 5;
  nullsubx_b(v2);
  c12 = 6;
  c13 = 6;
  return v1;','5001','[]','bd19836ddb62c11c55ab251ccaca5645',1,'1.6','[]',0,'4352','[]','7001',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(2,'same_exact','8448',5,5,1,1,70,7,'["mov", "mov", "mov"]','[]','int f()',32,'1069',NULL,'same_exact','exact','  int v1;
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
retn','int()','h230','h330',1,0,'8448','[]','41','mov eax, 30
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
  return v1;','5030','[]','5ed40cc0659d685215b4897e21fa3cab',30,'4.5','[]',0,'8448','[]','7030',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(3,'same_changed','12544',6,7,1,1,53,7,'["mov", "mov", "mov"]','[]','int f()',15,'1035',NULL,'same_changed','9882d05cb24f7fd0d1cd0dcd1b86a8a1','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_changed_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h113','3013',0,'mov eax, 3
add eax, 4
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h213','h313',1,0,'12544','[]','24','mov eax, 3
add eax, 4
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_changed_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5013','[]','89b45ff321063b749efc5b5b3aa79930',13,'2.8','[]',0,'12544','[]','7013',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(4,'gate_small_b','16640',2,4,1,1,54,7,'["mov", "mov", "mov"]','[]','int f()',16,'1037',NULL,'gate_small_b','b304337a7930c3a7050319dd77317dbd','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_small_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h114','3014',0,'mov eax, 4
add eax, 5
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h214','h314',1,0,'16640','[]','25','mov eax, 4
add eax, 5
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_small_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5014','[]','1323fd7c68edb36766c982e6343cfdb4',14,'2.9','[]',0,'16640','[]','7014',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(5,'gate_pct_b','20736',13,13,1,1,55,7,'["mov", "mov", "mov"]','[]','int f()',17,'1039',NULL,'gate_pct_b','c172a8ce69eede4a9d5041fbe039bfd8','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_pct_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h115','3015',0,'mov eax, 5
add eax, 6
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h215','h315',1,0,'20736','[]','26','mov eax, 5
add eax, 6
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_pct_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5015','[]','d3c8a0832878a5e1d4e873e57b7f4238',15,'3.0','[]',0,'20736','[]','7015',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(6,'gate_edge_b','24832',16,17,1,1,56,7,'["mov", "mov", "mov"]','[]','int f()',18,'1041',NULL,'gate_edge_b','20e9e854760d152615078596780b9a61','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_edge_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h116','3016',0,'mov eax, 6
add eax, 7
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h216','h316',1,0,'24832','[]','27','mov eax, 6
add eax, 7
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_edge_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5016','[]','a2449b6477c1fef79be4202906486876',16,'3.1','[]',0,'24832','[]','7016',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(7,'nullsub_2b','28928',6,8,1,1,57,7,'["mov", "mov", "mov"]','[]','int f()',19,'1043',NULL,'nullsub_2b','a846eba5b36345d496bf7693a549ef10','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_null_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h117','3017',0,'mov eax, 7
add eax, 8
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h217','h317',1,0,'28928','[]','28','mov eax, 7
add eax, 8
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_null_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5017','[]','fe397f3f6f24b8500bc9c5f356384020',17,'3.2','[]',0,'28928','[]','7017',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(8,'nullsubx_b','33024',6,6,1,1,58,7,'["mov", "mov", "mov"]','[]','int f()',20,'1045',NULL,'nullsubx_b','d3bda6ff7eabd4e861e899b20c308564','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_nullx_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;',9,'h118','3018',0,'mov eax, 8
add eax, 9
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h218','h318',1,0,'33024','[]','29','mov eax, 8
add eax, 9
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','  int v1;
  int v2;
  v1 = 1;
  v2 = 2;
  leaf_nullx_b(v1);
  v1 += v2;
  v2 -= 3;
  v1 ^= v2;
  return v1;','5018','[]','d60ea3899962ccffb8e5c7893e7eddd7',18,'3.3','[]',0,'33024','[]','7018',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(9,'nopseudo_fn','37120',5,6,1,1,59,7,'["mov", "mov", "mov"]','[]','int f()',21,'1047',NULL,'nopseudo_fn','999fe455196bf8d34e2d743fc4b22b85',NULL,0,'h119','3019',0,'mov eax, 9
add eax, 10
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn','int()','h219','h319',1,0,'37120','[]','30','mov eax, 9
add eax, 10
xor ebx, 9
push ebp
mov ebp, esp
pop ebp
retn',NULL,'5019','[]','599f127bd63e32d6fd5457f9f1fa1e14',19,'3.4','[]',0,'37120','[]','7019',NULL,NULL,NULL,NULL,NULL,0.0);
INSERT INTO "functions" VALUES(10,'emptypseudo_fn','41216',5,7,1,1,60,7,'["mov", "mov", "mov"]','[]','int f()',22,'1049',NULL,'emptypseudo_fn','3e7c1c394a8557a57012a9be9bf7b5ef','',1,'h120','3020',0,'mov eax, 10
add eax, 11
xor ebx, 10
push ebp
mov ebp, esp
pop ebp
retn','int()','h220','h320',1,0,'41216','[]','31','mov eax, 10
add eax, 11
xor ebx, 10
push ebp
mov ebp, esp
pop ebp
retn','','5020','[]','3ad32b999fe4b4b2f6229acc5630e97b',20,'3.5','[]',0,'41216','[]','7020',NULL,NULL,NULL,NULL,NULL,0.0);
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
INSERT INTO "program" VALUES(1,'10','{"2": 1, "3": 1}','metapc','g2');
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
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','10 3 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','10 2 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','10 10 10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','10 2 1 1 1 1 1 1 1');
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
