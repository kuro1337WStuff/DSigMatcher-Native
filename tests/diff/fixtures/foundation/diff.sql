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
INSERT INTO "constants" VALUES(1,1,'kernel32.dll');
INSERT INTO "constants" VALUES(2,2,'4096');
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
INSERT INTO "functions" VALUES(1,'alpha','12288',5,4,1,2,50,15,'["push", "mov", "ret"]','["callee_1"]',NULL,1,'11',NULL,'alpha','00000000000000000000000005ccd000','int alpha()
{
  return 1;
}',4,'h1_1',NULL,0,'push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret',NULL,NULL,NULL,1,0,'8192','[[0]]','2','push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret','int alpha()
{
  return 1;
}','35','[]','000000000000000000000000000000004cb4b000',288,'3.050963036440351716676733804','["kernel32.dll", 4096]',2,'8192','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'sub_3400','13312',3,2,1,2,30,9,'["push", "mov", "ret"]','["callee_2"]',NULL,1,'7',NULL,'sub_3400','00000000000000000000000006488c00',NULL,0,NULL,NULL,0,'push rbx
xor eax, eax
ret',NULL,NULL,NULL,1,0,'9216','[[0]]','2','',NULL,'33','[]','0000000000000000000000000000000053191400',312,'0','[]',0,'9216','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'sub_3800','14336',7,6,1,2,70,21,'["push", "mov", "ret"]','["callee_0"]',NULL,1,'15',NULL,'sub_3800','00000000000000000000000006c44800','void sub_3800()
{
}',3,'h1_3',NULL,0,'push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret
nop',NULL,NULL,NULL,1,0,'10240','[[0]]','2','push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret
nop','void sub_3800()
{
}','37','[]','00000000000000000000000000000000597d7800',336,'1.25','[]',0,'10240','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'sub_3C00','15360',4,3,1,2,40,12,'["push", "mov", "ret"]','["callee_1"]',NULL,1,'9',NULL,'sub_3C00','00000000000000000000000007400400','void sub_3C00(void)
{
}',3,'h1_4',NULL,0,'push rbx
xor eax, eax
ret
nop',NULL,NULL,NULL,1,0,'11264','[[0]]','2','push rbx
xor eax, eax
ret
nop','void sub_3C00(void)
{
}','34','[]','000000000000000000000000000000005fe1dc00',360,'2.5','[]',0,'11264','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'sub_4000','16384',6,5,1,2,60,18,'["push", "mov", "ret"]','["callee_2"]',NULL,1,'13',NULL,'sub_4000','00000000000000000000000007bbc000','int sub_4000()
{
  return 0;
}',4,'h1_5',NULL,0,'push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret
int3',NULL,NULL,NULL,1,0,'12288','[[0]]','2','push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret
int3','int sub_4000()
{
  return 0;
}','36','[]','0000000000000000000000000000000066464000',384,'2.5','[]',0,'12288','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'sub_4400','17408',2,1,1,2,20,6,'["push", "mov", "ret"]','["callee_0"]',NULL,1,'5',NULL,'sub_4400','00000000000000000000000008377c00',NULL,0,NULL,NULL,0,'xor eax, eax
retn',NULL,NULL,NULL,1,0,'13312','[[0]]','2','xor eax, eax
retn',NULL,'32','[]','000000000000000000000000000000006caaa400',408,'0','[]',0,'13312','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
INSERT INTO "functions" VALUES(7,'sub_4800','18432',9,8,1,2,90,27,'["push", "mov", "ret"]','["callee_1"]',NULL,1,'19',NULL,'sub_4800','00000000000000000000000008b33800','int sub_4800()
{
}',3,'h1_7',NULL,0,'push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret
hlt',NULL,NULL,NULL,1,0,'14336','[[0]]','2','push rbp
mov rbp, rsp
call sub_1000
pop rbp
ret
hlt','int sub_4800()
{
}','39','[]','00000000000000000000000000000000730f0800',432,'7.75','[]',0,'14336','[]','0',NULL,NULL,NULL,NULL,'1',0.007);
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
INSERT INTO "program" VALUES(1,'6','{"2": 1, "3": 1}','metapc','00000000000000000000000000000000');
CREATE TABLE program_data (
                  id integer primary key,
                  name varchar(255),
                  type varchar(255),
                  value text
                );
ANALYZE "sqlite_master";
INSERT INTO "sqlite_stat1" VALUES('constants','idx_35','2 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','7 2 2 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','7 4 4');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','7 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','7 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','7 2 2 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','7 3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','7 3 3');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','7 7');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','7 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','7 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','7 1 1 1 1 1 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','7 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','7 2');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','7 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','7 1');
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
