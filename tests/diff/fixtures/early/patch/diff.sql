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
INSERT INTO "functions" VALUES(1,'func_1','6442459392',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010100:", "lea", "imul", "cmp", "jle", "loc_180010110:", "lea", "imul", "cmp", "jle", "loc_180010120:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_1','e343f2ad814671057cb7fd6845cd49ec','int __fastcall func_1(int a1)
{
  int v1 = a1 * 3;
  if ( v1 > 65 )
    return v1 - a1;
  return v1;
}',7,'c34272ecc7bee33e',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'8448','[[0]]','2','push rbx
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
retn','int __fastcall func_1(int a1)
{
  int v1 = a1 * 3;
  if ( v1 > 65 )
    return v1 - a1;
  return v1;
}','34','[]','20649b0f706f80f5722e2fbd1a0a45ef',392,'1.4','[]',0,'8448','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'func_2','6442459648',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010200:", "lea", "imul", "cmp", "jbe", "loc_180010210:", "lea", "imul", "cmp", "jbe", "loc_180010220:", "lea", "imul", "cmp", "jbe", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_2','f612af739c78593c4c98c39134651b29','int __fastcall func_2(int a1)
{
  int v1 = a1 * 4;
  v1 = (unsigned int)v1;
  if ( v1 > 66 )
    return v1 - a1;
  return v1;
}',8,'791a97e801a70612',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010200:
lea eax, [rbx+6]
imul eax, 4
cmp eax, 42h
jbe short loc_180010200
loc_180010210:
lea eax, [rbx+7]
imul eax, 5
cmp eax, 42h
jbe short loc_180010200
loc_180010220:
lea eax, [rbx+8]
imul eax, 6
cmp eax, 42h
jbe short loc_180010200
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'8704','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010200:
lea eax, [rbx+6]
imul eax, 4
cmp eax, 42h
jbe short loc_180010200
loc_180010210:
lea eax, [rbx+7]
imul eax, 5
cmp eax, 42h
jbe short loc_180010200
loc_180010220:
lea eax, [rbx+8]
imul eax, 6
cmp eax, 42h
jbe short loc_180010200
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_2(int a1)
{
  int v1 = a1 * 4;
  v1 = (unsigned int)v1;
  if ( v1 > 66 )
    return v1 - a1;
  return v1;
}','34','[]','44e8eaa2bcadff46281f3b8d9a688f71',648,'2.4','[]',0,'8704','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'func_3','6442459904',4,3,1,1,92,23,'["push", "sub", "mov", "loc_180010300:", "lea", "imul", "cmp", "jle", "loc_180010310:", "lea", "imul", "cmp", "jle", "loc_180010320:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn", "nop"]','[]',NULL,1,'9',NULL,'func_3','ccbe1b6d9b15da6d78964c26885ccf3a','int __fastcall func_3(int a1)
{
  int v1 = a1 * 5;
  if ( a1 > 256 )
    return 0;
  if ( v1 > 67 )
    return v1 - a1;
  return v1;
}',9,'918a467104a56f1c',NULL,0,'push rbx
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
retn
nop',NULL,NULL,NULL,1,0,'8960','[[0]]','2','push rbx
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
retn
nop','int __fastcall func_3(int a1)
{
  int v1 = a1 * 5;
  if ( a1 > 256 )
    return 0;
  if ( v1 > 67 )
    return v1 - a1;
  return v1;
}','34','[]','ed433d83df10cef3422480e40936f391',904,'3.4','[]',0,'8960','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'func_4','6442460160',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010400:", "lea", "imul", "cmp", "jle", "loc_180010410:", "lea", "imul", "cmp", "jle", "loc_180010420:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_4','5d93c5b8108a06fcdb2ef45ae7e9fac4','int __fastcall func_4(int a1)
{
  int v1 = a1 * 6;
  if ( v1 > 68 )
    return v1 - a1;
  return v1;
}',7,'9acbc1c388cec976',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'9216','[[0]]','2','push rbx
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
retn','int __fastcall func_4(int a1)
{
  int v1 = a1 * 6;
  if ( v1 > 68 )
    return v1 - a1;
  return v1;
}','34','[]','ff57b1b66448a9e0a7a6f13b7b44d9b2',160,'4.4','[]',0,'9216','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'func_5','6442460416',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010500:", "lea", "imul", "cmp", "jle", "loc_180010510:", "lea", "imul", "cmp", "jle", "loc_180010520:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_5','92791822d20f2ff210fe4d632f5d8755','int __fastcall func_5(int a1)
{
  int v1 = a1 * 7;
  if ( v1 > 69 )
    return v1 - a1;
  return v1;
}',7,'413ec737542f934f',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'9472','[[0]]','2','push rbx
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
retn','int __fastcall func_5(int a1)
{
  int v1 = a1 * 7;
  if ( v1 > 69 )
    return v1 - a1;
  return v1;
}','34','[]','e3cdf7a57ce47ee89951433c9c654108',416,'5.4','[]',0,'9472','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'func_6','6442460672',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010600:", "lea", "imul", "cmp", "jle", "loc_180010610:", "lea", "imul", "cmp", "jle", "loc_180010620:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_6','62d52c9a8967f91e502067b7e8571317','int __fastcall func_6(int a1)
{
  int v1 = a1 * 8;
  if ( v1 > 70 )
    return v1 - a1;
  return v1;
}',7,'8eea6ab46767337b',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'9728','[[0]]','2','push rbx
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
retn','int __fastcall func_6(int a1)
{
  int v1 = a1 * 8;
  if ( v1 > 70 )
    return v1 - a1;
  return v1;
}','34','[]','e83a5609deb45b2086c2bf9396733a90',672,'6.4','[]',0,'9728','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
INSERT INTO "functions" VALUES(7,'func_7','6442460928',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010700:", "lea", "imul", "cmp", "jle", "loc_180010710:", "lea", "imul", "cmp", "jle", "loc_180010720:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_7','6833b206ec9c4d1dde3785b395012f48','int __fastcall func_7(int a1)
{
  int v1 = a1 * 9;
  if ( v1 > 71 )
    return v1 - a1;
  return v1;
}',7,'33216235c0481071',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'9984','[[0]]','2','push rbx
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
retn','int __fastcall func_7(int a1)
{
  int v1 = a1 * 9;
  if ( v1 > 71 )
    return v1 - a1;
  return v1;
}','34','[]','d29b875449f9e2d92237a93f55a7b7f0',928,'7.4','[]',0,'9984','[]','0',NULL,NULL,NULL,NULL,'1',0.007);
INSERT INTO "functions" VALUES(8,'func_8','6442461184',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010800:", "lea", "imul", "cmp", "jle", "loc_180010810:", "lea", "imul", "cmp", "jle", "loc_180010820:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_8','22a17235db340b5f84048e691265f7ed','int __fastcall func_8(int a1)
{
  int v1 = a1 * 10;
  if ( v1 > 72 )
    return v1 - a1;
  return v1;
}',7,'8ae0e491e96c3830',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'10240','[[0]]','2','push rbx
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
retn','int __fastcall func_8(int a1)
{
  int v1 = a1 * 10;
  if ( v1 > 72 )
    return v1 - a1;
  return v1;
}','34','[]','49cb299862a2a93784a28323691b164d',184,'8.4','[]',0,'10240','[]','0',NULL,NULL,NULL,NULL,'1',0.008);
INSERT INTO "functions" VALUES(9,'func_9','6442461440',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010900:", "lea", "imul", "cmp", "jle", "loc_180010910:", "lea", "imul", "cmp", "jle", "loc_180010920:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_9','ea611e157d2f0f9483f7c2e5468e1443','int __fastcall func_9(int a1)
{
  int v1 = a1 * 11;
  if ( v1 > 73 )
    return v1 - a1;
  return v1;
}',7,'2e4df425dfcc1ccf',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'10496','[[0]]','2','push rbx
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
retn','int __fastcall func_9(int a1)
{
  int v1 = a1 * 11;
  if ( v1 > 73 )
    return v1 - a1;
  return v1;
}','34','[]','746c7ecc189b5c3d4fd97929fb2253a7',440,'9.4','[]',0,'10496','[]','0',NULL,NULL,NULL,NULL,'1',9.000000000000001054e-03);
INSERT INTO "functions" VALUES(10,'func_10','6442461696',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010A00:", "lea", "imul", "cmp", "jle", "loc_180010A10:", "lea", "imul", "cmp", "jle", "loc_180010A20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_10','129e3da942e967b612ac1428481ae709','int __fastcall func_10(int a1)
{
  int v1 = a1 * 12;
  if ( v1 > 74 )
    return v1 - a1;
  return v1;
}',7,'db249e5c90d381fa',NULL,0,'push rbx
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
retn',NULL,NULL,NULL,1,0,'10752','[[0]]','2','push rbx
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
retn','int __fastcall func_10(int a1)
{
  int v1 = a1 * 12;
  if ( v1 > 74 )
    return v1 - a1;
  return v1;
}','34','[]','7270bf3317c82720e99566819660d7c6',696,'10.4','[]',0,'10752','[]','0',NULL,NULL,NULL,NULL,'1',0.01);
INSERT INTO "functions" VALUES(11,'func_11','6442461952',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010B00:", "lea", "imul", "cmp", "jle", "loc_180010B10:", "lea", "imul", "cmp", "jle", "loc_180010B20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_11','b70795ebf2a38713b642e0996bc258f1','int __fastcall func_11(int a1)
{
  int v1 = a1 * 13;
  if ( v1 > 75 )
    return v1 - a1;
  return v1;
}',7,'ebca1d744923da99',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010B00:
lea eax, [rbx+33]
imul eax, 13
cmp eax, 4Bh
jle short loc_180010B00
loc_180010B10:
lea eax, [rbx+34]
imul eax, 14
cmp eax, 4Bh
jle short loc_180010B00
loc_180010B20:
lea eax, [rbx+35]
imul eax, 15
cmp eax, 4Bh
jle short loc_180010B00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'11008','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010B00:
lea eax, [rbx+33]
imul eax, 13
cmp eax, 4Bh
jle short loc_180010B00
loc_180010B10:
lea eax, [rbx+34]
imul eax, 14
cmp eax, 4Bh
jle short loc_180010B00
loc_180010B20:
lea eax, [rbx+35]
imul eax, 15
cmp eax, 4Bh
jle short loc_180010B00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_11(int a1)
{
  int v1 = a1 * 13;
  if ( v1 > 75 )
    return v1 - a1;
  return v1;
}','34','[]','3c4c29fc534aae9ca2134c9bf65d1ac7',952,'11.4','[]',0,'11008','[]','0',NULL,NULL,NULL,NULL,'1',0.011);
INSERT INTO "functions" VALUES(12,'func_12','6442462208',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010C00:", "lea", "imul", "cmp", "jle", "loc_180010C10:", "lea", "imul", "cmp", "jle", "loc_180010C20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_12','edc776ff78dcd525a87acb03e4fede7f','int __fastcall func_12(int a1)
{
  int v1 = a1 * 14;
  if ( v1 > 76 )
    return v1 - a1;
  return v1;
}',7,'1ac1a1d035ce1334',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010C00:
lea eax, [rbx+36]
imul eax, 14
cmp eax, 4Ch
jle short loc_180010C00
loc_180010C10:
lea eax, [rbx+37]
imul eax, 15
cmp eax, 4Ch
jle short loc_180010C00
loc_180010C20:
lea eax, [rbx+38]
imul eax, 16
cmp eax, 4Ch
jle short loc_180010C00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'11264','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010C00:
lea eax, [rbx+36]
imul eax, 14
cmp eax, 4Ch
jle short loc_180010C00
loc_180010C10:
lea eax, [rbx+37]
imul eax, 15
cmp eax, 4Ch
jle short loc_180010C00
loc_180010C20:
lea eax, [rbx+38]
imul eax, 16
cmp eax, 4Ch
jle short loc_180010C00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_12(int a1)
{
  int v1 = a1 * 14;
  if ( v1 > 76 )
    return v1 - a1;
  return v1;
}','34','[]','e2c830ad3e9d538d1156f5a3463f8e97',208,'12.4','[]',0,'11264','[]','0',NULL,NULL,NULL,NULL,'1',0.012);
INSERT INTO "functions" VALUES(13,'func_13','6442462464',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010D00:", "lea", "imul", "cmp", "jle", "loc_180010D10:", "lea", "imul", "cmp", "jle", "loc_180010D20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_13','c3c445ceeead429ed27fb2282ca26740','int __fastcall func_13(int a1)
{
  int v1 = a1 * 15;
  if ( v1 > 77 )
    return v1 - a1;
  return v1;
}',7,'ab6c353efe5e27a6',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010D00:
lea eax, [rbx+39]
imul eax, 15
cmp eax, 4Dh
jle short loc_180010D00
loc_180010D10:
lea eax, [rbx+40]
imul eax, 16
cmp eax, 4Dh
jle short loc_180010D00
loc_180010D20:
lea eax, [rbx+41]
imul eax, 17
cmp eax, 4Dh
jle short loc_180010D00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'11520','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010D00:
lea eax, [rbx+39]
imul eax, 15
cmp eax, 4Dh
jle short loc_180010D00
loc_180010D10:
lea eax, [rbx+40]
imul eax, 16
cmp eax, 4Dh
jle short loc_180010D00
loc_180010D20:
lea eax, [rbx+41]
imul eax, 17
cmp eax, 4Dh
jle short loc_180010D00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_13(int a1)
{
  int v1 = a1 * 15;
  if ( v1 > 77 )
    return v1 - a1;
  return v1;
}','34','[]','f5f42c86414a4c36b4d3861cd6008b34',464,'13.4','[]',0,'11520','[]','0',NULL,NULL,NULL,NULL,'1',1.300000000000000113e-02);
INSERT INTO "functions" VALUES(14,'func_14','6442462720',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010E00:", "lea", "imul", "cmp", "jle", "loc_180010E10:", "lea", "imul", "cmp", "jle", "loc_180010E20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_14','3c415bed40700fd38b8e6f0b5deb3bd0','int __fastcall func_14(int a1)
{
  int v1 = a1 * 16;
  if ( v1 > 78 )
    return v1 - a1;
  return v1;
}',7,'7ba75bb2d5c3255b',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010E00:
lea eax, [rbx+42]
imul eax, 16
cmp eax, 4Eh
jle short loc_180010E00
loc_180010E10:
lea eax, [rbx+43]
imul eax, 17
cmp eax, 4Eh
jle short loc_180010E00
loc_180010E20:
lea eax, [rbx+44]
imul eax, 18
cmp eax, 4Eh
jle short loc_180010E00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'11776','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010E00:
lea eax, [rbx+42]
imul eax, 16
cmp eax, 4Eh
jle short loc_180010E00
loc_180010E10:
lea eax, [rbx+43]
imul eax, 17
cmp eax, 4Eh
jle short loc_180010E00
loc_180010E20:
lea eax, [rbx+44]
imul eax, 18
cmp eax, 4Eh
jle short loc_180010E00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_14(int a1)
{
  int v1 = a1 * 16;
  if ( v1 > 78 )
    return v1 - a1;
  return v1;
}','34','[]','95e4ea97fc65b7945889d01b8a0501be',720,'14.4','[]',0,'11776','[]','0',NULL,NULL,NULL,NULL,'1',0.014);
INSERT INTO "functions" VALUES(15,'func_15','6442462976',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180010F00:", "lea", "imul", "cmp", "jle", "loc_180010F10:", "lea", "imul", "cmp", "jle", "loc_180010F20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_15','cb47550ad77af15b054f4619eee3753b','int __fastcall func_15(int a1)
{
  int v1 = a1 * 17;
  if ( v1 > 79 )
    return v1 - a1;
  return v1;
}',7,'8ab89b2f969c0d8a',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010F00:
lea eax, [rbx+45]
imul eax, 17
cmp eax, 4Fh
jle short loc_180010F00
loc_180010F10:
lea eax, [rbx+46]
imul eax, 18
cmp eax, 4Fh
jle short loc_180010F00
loc_180010F20:
lea eax, [rbx+47]
imul eax, 19
cmp eax, 4Fh
jle short loc_180010F00
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'12032','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180010F00:
lea eax, [rbx+45]
imul eax, 17
cmp eax, 4Fh
jle short loc_180010F00
loc_180010F10:
lea eax, [rbx+46]
imul eax, 18
cmp eax, 4Fh
jle short loc_180010F00
loc_180010F20:
lea eax, [rbx+47]
imul eax, 19
cmp eax, 4Fh
jle short loc_180010F00
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_15(int a1)
{
  int v1 = a1 * 17;
  if ( v1 > 79 )
    return v1 - a1;
  return v1;
}','34','[]','c7e67fa949623eb0c22c2aeb6f96b388',976,'15.4','[]',0,'12032','[]','0',NULL,NULL,NULL,NULL,'1',0.015);
INSERT INTO "functions" VALUES(16,'func_16','6442463232',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011000:", "lea", "imul", "cmp", "jle", "loc_180011010:", "lea", "imul", "cmp", "jle", "loc_180011020:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_16','90dd9643fbdeadcfa305bfbd1006da64','int __fastcall func_16(int a1)
{
  int v1 = a1 * 18;
  if ( v1 > 80 )
    return v1 - a1;
  return v1;
}',7,'998710bf154ccb34',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011000:
lea eax, [rbx+48]
imul eax, 18
cmp eax, 50h
jle short loc_180011000
loc_180011010:
lea eax, [rbx+49]
imul eax, 19
cmp eax, 50h
jle short loc_180011000
loc_180011020:
lea eax, [rbx+50]
imul eax, 20
cmp eax, 50h
jle short loc_180011000
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'12288','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011000:
lea eax, [rbx+48]
imul eax, 18
cmp eax, 50h
jle short loc_180011000
loc_180011010:
lea eax, [rbx+49]
imul eax, 19
cmp eax, 50h
jle short loc_180011000
loc_180011020:
lea eax, [rbx+50]
imul eax, 20
cmp eax, 50h
jle short loc_180011000
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_16(int a1)
{
  int v1 = a1 * 18;
  if ( v1 > 80 )
    return v1 - a1;
  return v1;
}','34','[]','b676a6c92307e0b743e55ea67d56ce23',232,'16.4','[]',0,'12288','[]','0',NULL,NULL,NULL,NULL,'1',0.016);
INSERT INTO "functions" VALUES(17,'func_17','6442463488',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011100:", "lea", "imul", "cmp", "jle", "loc_180011110:", "lea", "imul", "cmp", "jle", "loc_180011120:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_17','b9a5a773a47ad04635fbd24b55c9eba8','int __fastcall func_17(int a1)
{
  int v1 = a1 * 19;
  if ( v1 > 81 )
    return v1 - a1;
  return v1;
}',7,'c34c4b15752ae355',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011100:
lea eax, [rbx+51]
imul eax, 19
cmp eax, 51h
jle short loc_180011100
loc_180011110:
lea eax, [rbx+52]
imul eax, 20
cmp eax, 51h
jle short loc_180011100
loc_180011120:
lea eax, [rbx+53]
imul eax, 21
cmp eax, 51h
jle short loc_180011100
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'12544','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011100:
lea eax, [rbx+51]
imul eax, 19
cmp eax, 51h
jle short loc_180011100
loc_180011110:
lea eax, [rbx+52]
imul eax, 20
cmp eax, 51h
jle short loc_180011100
loc_180011120:
lea eax, [rbx+53]
imul eax, 21
cmp eax, 51h
jle short loc_180011100
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_17(int a1)
{
  int v1 = a1 * 19;
  if ( v1 > 81 )
    return v1 - a1;
  return v1;
}','34','[]','19f1b74dad4e84c09f01f8a482733760',488,'17.4','[]',0,'12544','[]','0',NULL,NULL,NULL,NULL,'1',0.017);
INSERT INTO "functions" VALUES(18,'func_18','6442463744',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011200:", "lea", "imul", "cmp", "jle", "loc_180011210:", "lea", "imul", "cmp", "jle", "loc_180011220:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_18','8eb70b62d3dfcb1aa236e2541f60a580','int __fastcall func_18(int a1)
{
  int v1 = a1 * 20;
  if ( v1 > 82 )
    return v1 - a1;
  return v1;
}',7,'0e06448bf165e3fc',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011200:
lea eax, [rbx+54]
imul eax, 20
cmp eax, 52h
jle short loc_180011200
loc_180011210:
lea eax, [rbx+55]
imul eax, 21
cmp eax, 52h
jle short loc_180011200
loc_180011220:
lea eax, [rbx+56]
imul eax, 22
cmp eax, 52h
jle short loc_180011200
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'12800','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011200:
lea eax, [rbx+54]
imul eax, 20
cmp eax, 52h
jle short loc_180011200
loc_180011210:
lea eax, [rbx+55]
imul eax, 21
cmp eax, 52h
jle short loc_180011200
loc_180011220:
lea eax, [rbx+56]
imul eax, 22
cmp eax, 52h
jle short loc_180011200
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_18(int a1)
{
  int v1 = a1 * 20;
  if ( v1 > 82 )
    return v1 - a1;
  return v1;
}','34','[]','3f047a7769a9b4b70b5cb05c8205e8ad',744,'18.4','[]',0,'12800','[]','0',NULL,NULL,NULL,NULL,'1',1.800000000000000211e-02);
INSERT INTO "functions" VALUES(19,'func_19','6442464000',4,3,1,1,88,22,'["push", "sub", "mov", "loc_180011300:", "lea", "imul", "cmp", "jle", "loc_180011310:", "lea", "imul", "cmp", "jle", "loc_180011320:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'func_19','fd1571a89c1974c0bc01a32a3aaa451c','int __fastcall func_19(int a1)
{
  int v1 = a1 * 21;
  if ( v1 > 83 )
    return v1 - a1;
  return v1;
}',7,'e54a1d82512e8fe9',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011300:
lea eax, [rbx+57]
imul eax, 21
cmp eax, 53h
jle short loc_180011300
loc_180011310:
lea eax, [rbx+58]
imul eax, 22
cmp eax, 53h
jle short loc_180011300
loc_180011320:
lea eax, [rbx+59]
imul eax, 23
cmp eax, 53h
jle short loc_180011300
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'13056','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180011300:
lea eax, [rbx+57]
imul eax, 21
cmp eax, 53h
jle short loc_180011300
loc_180011310:
lea eax, [rbx+58]
imul eax, 22
cmp eax, 53h
jle short loc_180011300
loc_180011320:
lea eax, [rbx+59]
imul eax, 23
cmp eax, 53h
jle short loc_180011300
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall func_19(int a1)
{
  int v1 = a1 * 21;
  if ( v1 > 83 )
    return v1 - a1;
  return v1;
}','34','[]','903b1d7ed5d233ba25e8467ca3b1bba5',0,'19.4','[]',0,'13056','[]','0',NULL,NULL,NULL,NULL,'1',0.019);
INSERT INTO "functions" VALUES(20,'renamed_fn','6442475520',5,4,1,1,112,28,'["push", "sub", "mov", "loc_180012800:", "lea", "imul", "cmp", "jle", "loc_180012810:", "lea", "imul", "cmp", "jle", "loc_180012820:", "lea", "imul", "cmp", "jle", "loc_180012830:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn", "nop"]','[]',NULL,1,'11',NULL,'renamed_fn','aa0610fef4563b713f189d3c5c5c1194','int __fastcall renamed_fn(int a1)
{
  int v1 = a1 * 42;
  if ( v1 > 104 )
    return v1 - a1;
  return v1;
}',7,'1e9e6c71a9831778',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180012800:
lea eax, [rbx+120]
imul eax, 42
cmp eax, 68h
jle short loc_180012800
loc_180012810:
lea eax, [rbx+121]
imul eax, 43
cmp eax, 68h
jle short loc_180012800
loc_180012820:
lea eax, [rbx+122]
imul eax, 44
cmp eax, 68h
jle short loc_180012800
loc_180012830:
lea eax, [rbx+123]
imul eax, 45
cmp eax, 68h
jle short loc_180012800
mov eax, ebx
add rsp, 20h
pop rbx
retn
nop',NULL,NULL,NULL,1,0,'24576','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180012800:
lea eax, [rbx+120]
imul eax, 42
cmp eax, 68h
jle short loc_180012800
loc_180012810:
lea eax, [rbx+121]
imul eax, 43
cmp eax, 68h
jle short loc_180012800
loc_180012820:
lea eax, [rbx+122]
imul eax, 44
cmp eax, 68h
jle short loc_180012800
loc_180012830:
lea eax, [rbx+123]
imul eax, 45
cmp eax, 68h
jle short loc_180012800
mov eax, ebx
add rsp, 20h
pop rbx
retn
nop','int __fastcall renamed_fn(int a1)
{
  int v1 = a1 * 42;
  if ( v1 > 104 )
    return v1 - a1;
  return v1;
}','35','[]','a4a8c61c42ba006a86c8bc068ac65435',520,'40.5','[]',0,'24576','[]','0',NULL,NULL,NULL,NULL,'1',0.02);
INSERT INTO "functions" VALUES(21,'renamed_small','6442479616',2,1,1,1,12,3,'["mov", "add", "retn"]','[]',NULL,1,'5',NULL,'renamed_small','00a4568491ba78ab758f860b8fb13892',NULL,0,NULL,NULL,0,'mov eax, [rcx]
add eax, 2
retn',NULL,NULL,NULL,1,0,'28672','[[0]]','2','mov eax, [rcx]
add eax, 2
retn',NULL,'32','[]','9c4cd01c706de833072dad627d96c23c',616,'0','[]',0,'28672','[]','0',NULL,NULL,NULL,NULL,'1',0.021);
INSERT INTO "functions" VALUES(22,'unnamed_extra','6442483712',5,4,1,1,108,27,'["push", "sub", "mov", "loc_180012900:", "lea", "imul", "cmp", "jle", "loc_180012910:", "lea", "imul", "cmp", "jle", "loc_180012920:", "lea", "imul", "cmp", "jle", "loc_180012930:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'11',NULL,'unnamed_extra','64ab56a0a80d9dd3dfc3f30cab3ca501','int __fastcall unnamed_extra(int a1)
{
  int v1 = a1 * 43;
  if ( v1 > 105 )
    return v1 - a1;
  return v1;
}',7,'e9f7eb9748c13078',NULL,0,'push rbx
sub rsp, 20h
mov ebx, ecx
loc_180012900:
lea eax, [rbx+123]
imul eax, 43
cmp eax, 69h
jle short loc_180012900
loc_180012910:
lea eax, [rbx+124]
imul eax, 44
cmp eax, 69h
jle short loc_180012900
loc_180012920:
lea eax, [rbx+125]
imul eax, 45
cmp eax, 69h
jle short loc_180012900
loc_180012930:
lea eax, [rbx+126]
imul eax, 46
cmp eax, 69h
jle short loc_180012900
mov eax, ebx
add rsp, 20h
pop rbx
retn',NULL,NULL,NULL,1,0,'32768','[[0]]','2','push rbx
sub rsp, 20h
mov ebx, ecx
loc_180012900:
lea eax, [rbx+123]
imul eax, 43
cmp eax, 69h
jle short loc_180012900
loc_180012910:
lea eax, [rbx+124]
imul eax, 44
cmp eax, 69h
jle short loc_180012900
loc_180012920:
lea eax, [rbx+125]
imul eax, 45
cmp eax, 69h
jle short loc_180012900
loc_180012930:
lea eax, [rbx+126]
imul eax, 46
cmp eax, 69h
jle short loc_180012900
mov eax, ebx
add rsp, 20h
pop rbx
retn','int __fastcall unnamed_extra(int a1)
{
  int v1 = a1 * 43;
  if ( v1 > 105 )
    return v1 - a1;
  return v1;
}','35','[]','9dfca4f8651cd4bc4677509aa04e5f95',712,'41.5','[]',0,'32768','[]','0',NULL,NULL,NULL,NULL,'1',0.022);
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
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','22 22 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','22 6 6');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','22 22');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','22 8 8 8');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','22 5 1 1');
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
