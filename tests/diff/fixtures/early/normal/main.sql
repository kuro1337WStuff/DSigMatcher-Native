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
INSERT INTO "functions" VALUES(1,'alpha','6442455296',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010100:", "lea", "imul", "cmp", "jle", "loc_180010110:", "lea", "imul", "cmp", "jle", "loc_180010120:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'alpha','e343f2ad814671057cb7fd6845cd49ec','int __fastcall alpha(int a1)
{
  int v1 = a1 * 3;
  return v1 + 1;
}',5,'5a77a500179761c7',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010100:
lea eax, [rbx+3]
imul eax, 3
cmp eax, 41h
jle short loc_180010100
loc_180010110:
lea eax, [rbx+4]
imul eax, 4
cmp eax, 41h
jle short loc_180010100
loc_180010120:
lea eax, [rbx+5]
imul eax, 5
cmp eax, 41h
jle short loc_180010100
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'4352','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010100:
lea eax, [rbx+3]
imul eax, 3
cmp eax, 41h
jle short loc_180010100
loc_180010110:
lea eax, [rbx+4]
imul eax, 4
cmp eax, 41h
jle short loc_180010100
loc_180010120:
lea eax, [rbx+5]
imul eax, 5
cmp eax, 41h
jle short loc_180010100
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall alpha(int a1)
{
  int v1 = a1 * 3;
  return v1 + 1;
}','34','[]','20649b0f706f80f5722e2fbd1a0a45ef',296,'1.4','[]',0,'4352','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'beta','6442455552',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010200:", "lea", "imul", "cmp", "jle", "loc_180010210:", "lea", "imul", "cmp", "jle", "loc_180010220:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'beta','a2b975255cc3f6a4957668e048df540c','int __fastcall beta(int a1)
{
  int v1 = a1 * 4;
  return v1 + 2;
}',5,'c0e39edc28ff9586',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010200:
lea eax, [rbx+6]
imul eax, 4
cmp eax, 42h
jle short loc_180010200
loc_180010210:
lea eax, [rbx+7]
imul eax, 5
cmp eax, 42h
jle short loc_180010200
loc_180010220:
lea eax, [rbx+8]
imul eax, 6
cmp eax, 42h
jle short loc_180010200
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'4608','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010200:
lea eax, [rbx+6]
imul eax, 4
cmp eax, 42h
jle short loc_180010200
loc_180010210:
lea eax, [rbx+7]
imul eax, 5
cmp eax, 42h
jle short loc_180010200
loc_180010220:
lea eax, [rbx+8]
imul eax, 6
cmp eax, 42h
jle short loc_180010200
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall beta(int a1)
{
  int v1 = a1 * 4;
  return v1 + 2;
}','34','[]','4ff6aee39d8504fcfe6d5f4ffb464e05',552,'2.4','[]',0,'4608','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'gamma','6442455808',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010300:", "lea", "imul", "cmp", "jle", "loc_180010310:", "lea", "imul", "cmp", "jle", "loc_180010320:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'gamma','0be19232fe218d1e8ca04a7b54643731','int __fastcall gamma(int a1)
{
  int v1 = a1 * 5;
  return v1 + 3;
}',5,'a18f7f19f38b8a51',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010300:
lea eax, [rbx+9]
imul eax, 5
cmp eax, 43h
jle short loc_180010300
loc_180010310:
lea eax, [rbx+10]
imul eax, 6
cmp eax, 43h
jle short loc_180010300
loc_180010320:
lea eax, [rbx+11]
imul eax, 7
cmp eax, 43h
jle short loc_180010300
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'4864','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010300:
lea eax, [rbx+9]
imul eax, 5
cmp eax, 43h
jle short loc_180010300
loc_180010310:
lea eax, [rbx+10]
imul eax, 6
cmp eax, 43h
jle short loc_180010300
loc_180010320:
lea eax, [rbx+11]
imul eax, 7
cmp eax, 43h
jle short loc_180010300
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall gamma(int a1)
{
  int v1 = a1 * 5;
  return v1 + 3;
}','34','[]','2da1538a7fcab279ccbf4c08b4f2d720',808,'3.4','[]',0,'4864','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'delta','6442456064',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010400:", "lea", "imul", "cmp", "jle", "loc_180010410:", "lea", "imul", "cmp", "jle", "loc_180010420:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'delta','5d93c5b8108a06fcdb2ef45ae7e9fac4','int __fastcall delta(int a1)
{
  int v1 = a1 * 6;
  return v1 + 4;
}',5,'70d5bea46503a210',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010400:
lea eax, [rbx+12]
imul eax, 6
cmp eax, 44h
jle short loc_180010400
loc_180010410:
lea eax, [rbx+13]
imul eax, 7
cmp eax, 44h
jle short loc_180010400
loc_180010420:
lea eax, [rbx+14]
imul eax, 8
cmp eax, 44h
jle short loc_180010400
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'5120','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010400:
lea eax, [rbx+12]
imul eax, 6
cmp eax, 44h
jle short loc_180010400
loc_180010410:
lea eax, [rbx+13]
imul eax, 7
cmp eax, 44h
jle short loc_180010400
loc_180010420:
lea eax, [rbx+14]
imul eax, 8
cmp eax, 44h
jle short loc_180010400
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall delta(int a1)
{
  int v1 = a1 * 6;
  return v1 + 4;
}','34','[]','ff57b1b66448a9e0a7a6f13b7b44d9b2',64,'4.4','[]',0,'5120','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'epsilon','6442456320',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010500:", "lea", "imul", "cmp", "jle", "loc_180010510:", "lea", "imul", "cmp", "jle", "loc_180010520:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'epsilon','92791822d20f2ff210fe4d632f5d8755','int __fastcall epsilon(int a1)
{
  int v1 = a1 * 7;
  return v1 + 5;
}',5,'d8c2e76612849615',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010500:
lea eax, [rbx+15]
imul eax, 7
cmp eax, 45h
jle short loc_180010500
loc_180010510:
lea eax, [rbx+16]
imul eax, 8
cmp eax, 45h
jle short loc_180010500
loc_180010520:
lea eax, [rbx+17]
imul eax, 9
cmp eax, 45h
jle short loc_180010500
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'5376','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010500:
lea eax, [rbx+15]
imul eax, 7
cmp eax, 45h
jle short loc_180010500
loc_180010510:
lea eax, [rbx+16]
imul eax, 8
cmp eax, 45h
jle short loc_180010500
loc_180010520:
lea eax, [rbx+17]
imul eax, 9
cmp eax, 45h
jle short loc_180010500
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall epsilon(int a1)
{
  int v1 = a1 * 7;
  return v1 + 5;
}','34','[]','e3cdf7a57ce47ee89951433c9c654108',320,'5.4','[]',0,'5376','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'zeta','6442456576',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010600:", "lea", "imul", "cmp", "jle", "loc_180010610:", "lea", "imul", "cmp", "jle", "loc_180010620:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'zeta','62d52c9a8967f91e502067b7e8571317','int __fastcall zeta(int a1)
{
  int v1 = a1 * 8;
  return v1 + 6;
}',5,'da25b06b7a1f6956',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010600:
lea eax, [rbx+18]
imul eax, 8
cmp eax, 46h
jle short loc_180010600
loc_180010610:
lea eax, [rbx+19]
imul eax, 9
cmp eax, 46h
jle short loc_180010600
loc_180010620:
lea eax, [rbx+20]
imul eax, 10
cmp eax, 46h
jle short loc_180010600
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'5632','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010600:
lea eax, [rbx+18]
imul eax, 8
cmp eax, 46h
jle short loc_180010600
loc_180010610:
lea eax, [rbx+19]
imul eax, 9
cmp eax, 46h
jle short loc_180010600
loc_180010620:
lea eax, [rbx+20]
imul eax, 10
cmp eax, 46h
jle short loc_180010600
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall zeta(int a1)
{
  int v1 = a1 * 8;
  return v1 + 6;
}','34','[]','e83a5609deb45b2086c2bf9396733a90',576,'6.4','[]',0,'5632','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
INSERT INTO "functions" VALUES(7,'eta','6442456832',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010700:", "lea", "imul", "cmp", "jle", "loc_180010710:", "lea", "imul", "cmp", "jle", "loc_180010720:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'eta','6833b206ec9c4d1dde3785b395012f48','int __fastcall eta(int a1)
{
  int v1 = a1 * 9;
  return v1 + 7;
}',5,'6716b962a2d23867',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010700:
lea eax, [rbx+21]
imul eax, 9
cmp eax, 47h
jle short loc_180010700
loc_180010710:
lea eax, [rbx+22]
imul eax, 10
cmp eax, 47h
jle short loc_180010700
loc_180010720:
lea eax, [rbx+23]
imul eax, 11
cmp eax, 47h
jle short loc_180010700
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'5888','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010700:
lea eax, [rbx+21]
imul eax, 9
cmp eax, 47h
jle short loc_180010700
loc_180010710:
lea eax, [rbx+22]
imul eax, 10
cmp eax, 47h
jle short loc_180010700
loc_180010720:
lea eax, [rbx+23]
imul eax, 11
cmp eax, 47h
jle short loc_180010700
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall eta(int a1)
{
  int v1 = a1 * 9;
  return v1 + 7;
}','34','[]','d29b875449f9e2d92237a93f55a7b7f0',832,'7.4','[]',0,'5888','[]','0',NULL,NULL,NULL,NULL,'1',0.007);
INSERT INTO "functions" VALUES(8,'theta','6442457088',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010800:", "lea", "imul", "cmp", "jle", "loc_180010810:", "lea", "imul", "cmp", "jle", "loc_180010820:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'theta','22a17235db340b5f84048e691265f7ed','int __fastcall theta(int a1)
{
  int v1 = a1 * 10;
  return v1 + 8;
}',5,'640e12709e5b32ce',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010800:
lea eax, [rbx+24]
imul eax, 10
cmp eax, 48h
jle short loc_180010800
loc_180010810:
lea eax, [rbx+25]
imul eax, 11
cmp eax, 48h
jle short loc_180010800
loc_180010820:
lea eax, [rbx+26]
imul eax, 12
cmp eax, 48h
jle short loc_180010800
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'6144','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010800:
lea eax, [rbx+24]
imul eax, 10
cmp eax, 48h
jle short loc_180010800
loc_180010810:
lea eax, [rbx+25]
imul eax, 11
cmp eax, 48h
jle short loc_180010800
loc_180010820:
lea eax, [rbx+26]
imul eax, 12
cmp eax, 48h
jle short loc_180010800
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall theta(int a1)
{
  int v1 = a1 * 10;
  return v1 + 8;
}','34','[]','49cb299862a2a93784a28323691b164d',88,'8.4','[]',0,'6144','[]','0',NULL,NULL,NULL,NULL,'1',0.008);
INSERT INTO "functions" VALUES(9,'iota','6442457344',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010900:", "lea", "imul", "cmp", "jle", "loc_180010910:", "lea", "imul", "cmp", "jle", "loc_180010920:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'iota','ea611e157d2f0f9483f7c2e5468e1443','int __fastcall iota(int a1)
{
  int v1 = a1 * 11;
  return v1 + 9;
}',5,'cd5d84a6b9023a49',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010900:
lea eax, [rbx+27]
imul eax, 11
cmp eax, 49h
jle short loc_180010900
loc_180010910:
lea eax, [rbx+28]
imul eax, 12
cmp eax, 49h
jle short loc_180010900
loc_180010920:
lea eax, [rbx+29]
imul eax, 13
cmp eax, 49h
jle short loc_180010900
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'6400','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010900:
lea eax, [rbx+27]
imul eax, 11
cmp eax, 49h
jle short loc_180010900
loc_180010910:
lea eax, [rbx+28]
imul eax, 12
cmp eax, 49h
jle short loc_180010900
loc_180010920:
lea eax, [rbx+29]
imul eax, 13
cmp eax, 49h
jle short loc_180010900
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall iota(int a1)
{
  int v1 = a1 * 11;
  return v1 + 9;
}','34','[]','746c7ecc189b5c3d4fd97929fb2253a7',344,'9.4','[]',0,'6400','[]','0',NULL,NULL,NULL,NULL,'1',9.000000000000001054e-03);
INSERT INTO "functions" VALUES(10,'kappa','6442457600',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010A00:", "lea", "imul", "cmp", "jle", "loc_180010A10:", "lea", "imul", "cmp", "jle", "loc_180010A20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'kappa','129e3da942e967b612ac1428481ae709','int __fastcall kappa(int a1)
{
  int v1 = a1 * 12;
  return v1 + 10;
}',5,'cc552305bc92c126',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010A00:
lea eax, [rbx+30]
imul eax, 12
cmp eax, 4Ah
jle short loc_180010A00
loc_180010A10:
lea eax, [rbx+31]
imul eax, 13
cmp eax, 4Ah
jle short loc_180010A00
loc_180010A20:
lea eax, [rbx+32]
imul eax, 14
cmp eax, 4Ah
jle short loc_180010A00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'6656','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010A00:
lea eax, [rbx+30]
imul eax, 12
cmp eax, 4Ah
jle short loc_180010A00
loc_180010A10:
lea eax, [rbx+31]
imul eax, 13
cmp eax, 4Ah
jle short loc_180010A00
loc_180010A20:
lea eax, [rbx+32]
imul eax, 14
cmp eax, 4Ah
jle short loc_180010A00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall kappa(int a1)
{
  int v1 = a1 * 12;
  return v1 + 10;
}','34','[]','7270bf3317c82720e99566819660d7c6',600,'10.4','[]',0,'6656','[]','0',NULL,NULL,NULL,NULL,'1',0.01);
INSERT INTO "functions" VALUES(11,'sub_180001B00','6442457856',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011400:", "lea", "imul", "cmp", "jle", "loc_180011410:", "lea", "imul", "cmp", "jle", "loc_180011420:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180001B00','213130e9a518c95be51374686a00ca1a','int __fastcall sub_180001B00(int a1)
{
  int v1 = a1 * 22;
  return v1 + 20;
}',5,'776cdbd5a2eb9ef6',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011400:
lea eax, [rbx+60]
imul eax, 22
cmp eax, 54h
jle short loc_180011400
loc_180011410:
lea eax, [rbx+61]
imul eax, 23
cmp eax, 54h
jle short loc_180011400
loc_180011420:
lea eax, [rbx+62]
imul eax, 24
cmp eax, 54h
jle short loc_180011400
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'6912','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011400:
lea eax, [rbx+60]
imul eax, 22
cmp eax, 54h
jle short loc_180011400
loc_180011410:
lea eax, [rbx+61]
imul eax, 23
cmp eax, 54h
jle short loc_180011400
loc_180011420:
lea eax, [rbx+62]
imul eax, 24
cmp eax, 54h
jle short loc_180011400
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180001B00(int a1)
{
  int v1 = a1 * 22;
  return v1 + 20;
}','34','[]','678f47115b7affc177b733f8f10c6202',856,'20.4','[]',0,'6912','[]','0',NULL,NULL,NULL,NULL,'1',0.011);
INSERT INTO "functions" VALUES(12,'sub_180001C00','6442458112',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011500:", "lea", "imul", "cmp", "jle", "loc_180011510:", "lea", "imul", "cmp", "jle", "loc_180011520:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180001C00','7271f3e5f9857e02663be369477afa2c','int __fastcall sub_180001C00(int a1)
{
  int v1 = a1 * 23;
  return v1 + 21;
}',5,'55d22b9269824c4f',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011500:
lea eax, [rbx+63]
imul eax, 23
cmp eax, 55h
jle short loc_180011500
loc_180011510:
lea eax, [rbx+64]
imul eax, 24
cmp eax, 55h
jle short loc_180011500
loc_180011520:
lea eax, [rbx+65]
imul eax, 25
cmp eax, 55h
jle short loc_180011500
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'7168','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011500:
lea eax, [rbx+63]
imul eax, 23
cmp eax, 55h
jle short loc_180011500
loc_180011510:
lea eax, [rbx+64]
imul eax, 24
cmp eax, 55h
jle short loc_180011500
loc_180011520:
lea eax, [rbx+65]
imul eax, 25
cmp eax, 55h
jle short loc_180011500
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180001C00(int a1)
{
  int v1 = a1 * 23;
  return v1 + 21;
}','34','[]','0cc60622936e1bfbbe4b5a2325abba53',112,'21.4','[]',0,'7168','[]','0',NULL,NULL,NULL,NULL,'1',0.012);
INSERT INTO "functions" VALUES(13,'sub_180001D00','6442458368',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011600:", "lea", "imul", "cmp", "jle", "loc_180011610:", "lea", "imul", "cmp", "jle", "loc_180011620:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180001D00','af76ea8ab094852351f5d8fd3b759f3b','int __fastcall sub_180001D00(int a1)
{
  int v1 = a1 * 24;
  return v1 + 22;
}',5,'f358f7d5d9fbb43a',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011600:
lea eax, [rbx+66]
imul eax, 24
cmp eax, 56h
jle short loc_180011600
loc_180011610:
lea eax, [rbx+67]
imul eax, 25
cmp eax, 56h
jle short loc_180011600
loc_180011620:
lea eax, [rbx+68]
imul eax, 26
cmp eax, 56h
jle short loc_180011600
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'7424','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011600:
lea eax, [rbx+66]
imul eax, 24
cmp eax, 56h
jle short loc_180011600
loc_180011610:
lea eax, [rbx+67]
imul eax, 25
cmp eax, 56h
jle short loc_180011600
loc_180011620:
lea eax, [rbx+68]
imul eax, 26
cmp eax, 56h
jle short loc_180011600
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180001D00(int a1)
{
  int v1 = a1 * 24;
  return v1 + 22;
}','34','[]','ce09a70830821f0562e889f0fff64fd7',368,'22.4','[]',0,'7424','[]','0',NULL,NULL,NULL,NULL,'1',1.300000000000000113e-02);
INSERT INTO "functions" VALUES(14,'sub_180001E00','6442458624',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011700:", "lea", "imul", "cmp", "jle", "loc_180011710:", "lea", "imul", "cmp", "jle", "loc_180011720:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180001E00','7e7e3840a433015e19febf9a7b344747','int __fastcall sub_180001E00(int a1)
{
  int v1 = a1 * 25;
  return v1 + 23;
}',5,'c0204b67227f517d',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011700:
lea eax, [rbx+69]
imul eax, 25
cmp eax, 57h
jle short loc_180011700
loc_180011710:
lea eax, [rbx+70]
imul eax, 26
cmp eax, 57h
jle short loc_180011700
loc_180011720:
lea eax, [rbx+71]
imul eax, 27
cmp eax, 57h
jle short loc_180011700
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'7680','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011700:
lea eax, [rbx+69]
imul eax, 25
cmp eax, 57h
jle short loc_180011700
loc_180011710:
lea eax, [rbx+70]
imul eax, 26
cmp eax, 57h
jle short loc_180011700
loc_180011720:
lea eax, [rbx+71]
imul eax, 27
cmp eax, 57h
jle short loc_180011700
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180001E00(int a1)
{
  int v1 = a1 * 25;
  return v1 + 23;
}','34','[]','1044e09cb5fa1c74b1a2ba73753d7a3b',624,'23.4','[]',0,'7680','[]','0',NULL,NULL,NULL,NULL,'1',0.014);
INSERT INTO "functions" VALUES(15,'sub_180001F00','6442458880',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011800:", "lea", "imul", "cmp", "jle", "loc_180011810:", "lea", "imul", "cmp", "jle", "loc_180011820:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180001F00','4a7a9749ef26a51f03d9eb5066af74f5','int __fastcall sub_180001F00(int a1)
{
  int v1 = a1 * 26;
  return v1 + 24;
}',5,'24cdc76ff71efc50',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011800:
lea eax, [rbx+72]
imul eax, 26
cmp eax, 58h
jle short loc_180011800
loc_180011810:
lea eax, [rbx+73]
imul eax, 27
cmp eax, 58h
jle short loc_180011800
loc_180011820:
lea eax, [rbx+74]
imul eax, 28
cmp eax, 58h
jle short loc_180011800
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'7936','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011800:
lea eax, [rbx+72]
imul eax, 26
cmp eax, 58h
jle short loc_180011800
loc_180011810:
lea eax, [rbx+73]
imul eax, 27
cmp eax, 58h
jle short loc_180011800
loc_180011820:
lea eax, [rbx+74]
imul eax, 28
cmp eax, 58h
jle short loc_180011800
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180001F00(int a1)
{
  int v1 = a1 * 26;
  return v1 + 24;
}','34','[]','efc15117e0a684059b51e6bd2149f885',880,'24.4','[]',0,'7936','[]','0',NULL,NULL,NULL,NULL,'1',0.015);
INSERT INTO "functions" VALUES(16,'sub_180002000','6442459136',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011900:", "lea", "imul", "cmp", "jle", "loc_180011910:", "lea", "imul", "cmp", "jle", "loc_180011920:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180002000','46319da8d3dd96c5f310bf021e2b4dcf','int __fastcall sub_180002000(int a1)
{
  int v1 = a1 * 27;
  return v1 + 25;
}',5,'0e0f8bec5fd4205b',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011900:
lea eax, [rbx+75]
imul eax, 27
cmp eax, 59h
jle short loc_180011900
loc_180011910:
lea eax, [rbx+76]
imul eax, 28
cmp eax, 59h
jle short loc_180011900
loc_180011920:
lea eax, [rbx+77]
imul eax, 29
cmp eax, 59h
jle short loc_180011900
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'8192','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011900:
lea eax, [rbx+75]
imul eax, 27
cmp eax, 59h
jle short loc_180011900
loc_180011910:
lea eax, [rbx+76]
imul eax, 28
cmp eax, 59h
jle short loc_180011900
loc_180011920:
lea eax, [rbx+77]
imul eax, 29
cmp eax, 59h
jle short loc_180011900
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180002000(int a1)
{
  int v1 = a1 * 27;
  return v1 + 25;
}','34','[]','ee596ef983fad27baf2cedf8694e7c0b',136,'25.4','[]',0,'8192','[]','0',NULL,NULL,NULL,NULL,'1',0.016);
INSERT INTO "functions" VALUES(17,'sub_180002100','6442459392',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011A00:", "lea", "imul", "cmp", "jle", "loc_180011A10:", "lea", "imul", "cmp", "jle", "loc_180011A20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180002100','3232a84334675c38f0e97cbba7aff381','int __fastcall sub_180002100(int a1)
{
  int v1 = a1 * 28;
  return v1 + 26;
}',5,'541c6e334182058c',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011A00:
lea eax, [rbx+78]
imul eax, 28
cmp eax, 5Ah
jle short loc_180011A00
loc_180011A10:
lea eax, [rbx+79]
imul eax, 29
cmp eax, 5Ah
jle short loc_180011A00
loc_180011A20:
lea eax, [rbx+80]
imul eax, 30
cmp eax, 5Ah
jle short loc_180011A00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'8448','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011A00:
lea eax, [rbx+78]
imul eax, 28
cmp eax, 5Ah
jle short loc_180011A00
loc_180011A10:
lea eax, [rbx+79]
imul eax, 29
cmp eax, 5Ah
jle short loc_180011A00
loc_180011A20:
lea eax, [rbx+80]
imul eax, 30
cmp eax, 5Ah
jle short loc_180011A00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180002100(int a1)
{
  int v1 = a1 * 28;
  return v1 + 26;
}','34','[]','ddf563d2a1c8d23cb268262f7c2c7f19',392,'26.4','[]',0,'8448','[]','0',NULL,NULL,NULL,NULL,'1',0.017);
INSERT INTO "functions" VALUES(18,'sub_180002200','6442459648',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011B00:", "lea", "imul", "cmp", "jle", "loc_180011B10:", "lea", "imul", "cmp", "jle", "loc_180011B20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180002200','8f124078a3f4d255f78e5e61fb288a96','int __fastcall sub_180002200(int a1)
{
  int v1 = a1 * 29;
  return v1 + 27;
}',5,'ebbe9e55f45615e7',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011B00:
lea eax, [rbx+81]
imul eax, 29
cmp eax, 5Bh
jle short loc_180011B00
loc_180011B10:
lea eax, [rbx+82]
imul eax, 30
cmp eax, 5Bh
jle short loc_180011B00
loc_180011B20:
lea eax, [rbx+83]
imul eax, 31
cmp eax, 5Bh
jle short loc_180011B00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'8704','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011B00:
lea eax, [rbx+81]
imul eax, 29
cmp eax, 5Bh
jle short loc_180011B00
loc_180011B10:
lea eax, [rbx+82]
imul eax, 30
cmp eax, 5Bh
jle short loc_180011B00
loc_180011B20:
lea eax, [rbx+83]
imul eax, 31
cmp eax, 5Bh
jle short loc_180011B00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180002200(int a1)
{
  int v1 = a1 * 29;
  return v1 + 27;
}','34','[]','2f19da0d905d3d6c7c91f8c4977a5e18',648,'27.4','[]',0,'8704','[]','0',NULL,NULL,NULL,NULL,'1',1.800000000000000211e-02);
INSERT INTO "functions" VALUES(19,'sub_180002300','6442459904',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011C00:", "lea", "imul", "cmp", "jle", "loc_180011C10:", "lea", "imul", "cmp", "jle", "loc_180011C20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180002300','7ae85ffd9c91c0d93b658a2c187689f6','int __fastcall sub_180002300(int a1)
{
  int v1 = a1 * 30;
  return v1 + 28;
}',5,'c3a803b4f404f428',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011C00:
lea eax, [rbx+84]
imul eax, 30
cmp eax, 5Ch
jle short loc_180011C00
loc_180011C10:
lea eax, [rbx+85]
imul eax, 31
cmp eax, 5Ch
jle short loc_180011C00
loc_180011C20:
lea eax, [rbx+86]
imul eax, 32
cmp eax, 5Ch
jle short loc_180011C00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'8960','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011C00:
lea eax, [rbx+84]
imul eax, 30
cmp eax, 5Ch
jle short loc_180011C00
loc_180011C10:
lea eax, [rbx+85]
imul eax, 31
cmp eax, 5Ch
jle short loc_180011C00
loc_180011C20:
lea eax, [rbx+86]
imul eax, 32
cmp eax, 5Ch
jle short loc_180011C00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180002300(int a1)
{
  int v1 = a1 * 30;
  return v1 + 28;
}','34','[]','fe003b0518cc53641e78fb43db440e8d',904,'28.4','[]',0,'8960','[]','0',NULL,NULL,NULL,NULL,'1',0.019);
INSERT INTO "functions" VALUES(20,'sub_180002400','6442460160',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011D00:", "lea", "imul", "cmp", "jle", "loc_180011D10:", "lea", "imul", "cmp", "jle", "loc_180011D20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_180002400','1e9dfdeae2fca93efe64e92ab555949c','int __fastcall sub_180002400(int a1)
{
  int v1 = a1 * 31;
  return v1 + 29;
}',5,'cd6e2b50bd7578ee',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011D00:
lea eax, [rbx+87]
imul eax, 31
cmp eax, 5Dh
jle short loc_180011D00
loc_180011D10:
lea eax, [rbx+88]
imul eax, 32
cmp eax, 5Dh
jle short loc_180011D00
loc_180011D20:
lea eax, [rbx+89]
imul eax, 33
cmp eax, 5Dh
jle short loc_180011D00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'9216','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011D00:
lea eax, [rbx+87]
imul eax, 31
cmp eax, 5Dh
jle short loc_180011D00
loc_180011D10:
lea eax, [rbx+88]
imul eax, 32
cmp eax, 5Dh
jle short loc_180011D00
loc_180011D20:
lea eax, [rbx+89]
imul eax, 33
cmp eax, 5Dh
jle short loc_180011D00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall sub_180002400(int a1)
{
  int v1 = a1 * 31;
  return v1 + 29;
}','34','[]','8c3a02f0d70d1cccfcc44df0d94fce1b',160,'29.4','[]',0,'9216','[]','0',NULL,NULL,NULL,NULL,'1',0.02);
INSERT INTO "functions" VALUES(21,'tiny','6442460416',3,2,1,1,24,6,'["xor", "loc_1:", "add", "dec", "jnz", "retn"]','[]',NULL,1,'7',NULL,'tiny','7c7dead53788d5575e4cd17067aba655','int tiny(int a1)
{
  return a1 * (a1 + 1) / 2;
}',4,'83fbb21ebe0908d3',NULL,0,'xor eax, eax
loc_1:
add eax, ecx
dec ecx
jnz short loc_1
retn',NULL,NULL,NULL,1,0,'9472','[[0]]','2','xor eax, eax
loc_1:
add eax, ecx
dec ecx
jnz short loc_1
retn','int tiny(int a1)
{
  return a1 * (a1 + 1) / 2;
}','33','[]','822c0652de7639a881aeb912cdddf34a',416,'7.25','[]',0,'9472','[]','0',NULL,NULL,NULL,NULL,'1',0.021);
INSERT INTO "functions" VALUES(22,'alpha_x','6442460672',1,0,1,1,28,7,'["push", "mov", "call", "call", "call", "pop", "retn"]','["alpha", "beta", "sub_180001500", "g_count"]',NULL,1,'3',NULL,'alpha_x','26d3938966a98ad763adc764e75dba6f',NULL,0,NULL,NULL,0,'push rbp
mov rbp, rsp
call sub_180001500
call alpha
call beta
pop rbp
retn',NULL,NULL,NULL,1,0,'9728','[[0]]','2','push rbp
mov rbp, rsp
call sub_180001500
call alpha
call beta
pop rbp
retn',NULL,'31','[]','1db4bc3534ee8702d25c2f2315314b19',672,'0','[]',0,'9728','[]','0',NULL,NULL,NULL,NULL,'1',0.022);
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
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','22 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','22 22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','22 8');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','22 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','22 11 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','22 8 8');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','22 8 8 8');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','22 8 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','22 8 8 1 1 1 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','22 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','22 1');
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
