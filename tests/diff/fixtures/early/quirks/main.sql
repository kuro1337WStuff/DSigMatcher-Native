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
INSERT INTO "functions" VALUES(1,'nullsubX','4235520',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480100:", "lea", "imul", "cmp", "jle", "loc_480110:", "lea", "imul", "cmp", "jle", "loc_480120:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'nullsubX','6dfaada1123e463bc14df624f21ca462','int __fastcall nullsubX(int a1)
{
  int v1 = a1 * 3;
  return v1 + 1;
}',5,'4ead8fad3c061888',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480100:
lea eax, [ebx+3]
imul eax, 3
cmp eax, 41h
jle short loc_480100
loc_480110:
lea eax, [ebx+4]
imul eax, 4
cmp eax, 41h
jle short loc_480100
loc_480120:
lea eax, [ebx+5]
imul eax, 5
cmp eax, 41h
jle short loc_480100
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4235520','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480100:
lea eax, [ebx+3]
imul eax, 3
cmp eax, 41h
jle short loc_480100
loc_480110:
lea eax, [ebx+4]
imul eax, 4
cmp eax, 41h
jle short loc_480100
loc_480120:
lea eax, [ebx+5]
imul eax, 5
cmp eax, 41h
jle short loc_480100
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall nullsubX(int a1)
{
  int v1 = a1 * 3;
  return v1 + 1;
}','34','[]','04124dcd5fef099ad32742ed63f51a51',520,'1.4','[]',0,'4235520','[]','0',NULL,NULL,NULL,NULL,'1',0.001);
INSERT INTO "functions" VALUES(2,'NULLSUB_2','4235776',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480200:", "lea", "imul", "cmp", "jle", "loc_480210:", "lea", "imul", "cmp", "jle", "loc_480220:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'NULLSUB_2','101932818e9d2bbf4b79b994e73fbb5b','int __fastcall NULLSUB_2(int a1)
{
  int v1 = a1 * 4;
  return v1 + 2;
}',5,'3c3f38f30f2a6589',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480200:
lea eax, [ebx+6]
imul eax, 4
cmp eax, 42h
jle short loc_480200
loc_480210:
lea eax, [ebx+7]
imul eax, 5
cmp eax, 42h
jle short loc_480200
loc_480220:
lea eax, [ebx+8]
imul eax, 6
cmp eax, 42h
jle short loc_480200
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4235776','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480200:
lea eax, [ebx+6]
imul eax, 4
cmp eax, 42h
jle short loc_480200
loc_480210:
lea eax, [ebx+7]
imul eax, 5
cmp eax, 42h
jle short loc_480200
loc_480220:
lea eax, [ebx+8]
imul eax, 6
cmp eax, 42h
jle short loc_480200
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall NULLSUB_2(int a1)
{
  int v1 = a1 * 4;
  return v1 + 2;
}','34','[]','7073524e2caa00eac19ea688e92665a5',776,'2.4','[]',0,'4235776','[]','0',NULL,NULL,NULL,NULL,'1',0.002);
INSERT INTO "functions" VALUES(3,'nullsub_1','4236032',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480300:", "lea", "imul", "cmp", "jle", "loc_480310:", "lea", "imul", "cmp", "jle", "loc_480320:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'nullsub_1','bd7147b3542a361d745e4a819eb8184e','int __fastcall nullsub_1(int a1)
{
  int v1 = a1 * 5;
  return v1 + 3;
}',5,'65c295ab154b200f',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480300:
lea eax, [ebx+9]
imul eax, 5
cmp eax, 43h
jle short loc_480300
loc_480310:
lea eax, [ebx+10]
imul eax, 6
cmp eax, 43h
jle short loc_480300
loc_480320:
lea eax, [ebx+11]
imul eax, 7
cmp eax, 43h
jle short loc_480300
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4236032','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480300:
lea eax, [ebx+9]
imul eax, 5
cmp eax, 43h
jle short loc_480300
loc_480310:
lea eax, [ebx+10]
imul eax, 6
cmp eax, 43h
jle short loc_480300
loc_480320:
lea eax, [ebx+11]
imul eax, 7
cmp eax, 43h
jle short loc_480300
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall nullsub_1(int a1)
{
  int v1 = a1 * 5;
  return v1 + 3;
}','34','[]','92f81ef12ec5911f137b17dd3c6cc524',32,'3.4','[]',0,'4236032','[]','0',NULL,NULL,NULL,NULL,'1',0.003);
INSERT INTO "functions" VALUES(4,'nullsub','4236288',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480400:", "lea", "imul", "cmp", "jle", "loc_480410:", "lea", "imul", "cmp", "jle", "loc_480420:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'nullsub','dc987e7b01e31ebfa6fabcf6138ef9fb','int __fastcall nullsub(int a1)
{
  int v1 = a1 * 6;
  return v1 + 4;
}',5,'a0f6f5715545c2d3',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480400:
lea eax, [ebx+12]
imul eax, 6
cmp eax, 44h
jle short loc_480400
loc_480410:
lea eax, [ebx+13]
imul eax, 7
cmp eax, 44h
jle short loc_480400
loc_480420:
lea eax, [ebx+14]
imul eax, 8
cmp eax, 44h
jle short loc_480400
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4236288','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480400:
lea eax, [ebx+12]
imul eax, 6
cmp eax, 44h
jle short loc_480400
loc_480410:
lea eax, [ebx+13]
imul eax, 7
cmp eax, 44h
jle short loc_480400
loc_480420:
lea eax, [ebx+14]
imul eax, 8
cmp eax, 44h
jle short loc_480400
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall nullsub(int a1)
{
  int v1 = a1 * 6;
  return v1 + 4;
}','34','[]','9cd1776fd3098287d74a5eeb4a4ef8cd',288,'4.4','[]',0,'4236288','[]','0',NULL,NULL,NULL,NULL,'1',0.004);
INSERT INTO "functions" VALUES(5,'j_nullsub_1','4236544',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480500:", "lea", "imul", "cmp", "jle", "loc_480510:", "lea", "imul", "cmp", "jle", "loc_480520:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'j_nullsub_1','896940a7d36bd9997b6ac3153ff4992d','int __fastcall j_nullsub_1(int a1)
{
  int v1 = a1 * 7;
  return v1 + 5;
}',5,'a5818555a14a7c5d',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480500:
lea eax, [ebx+15]
imul eax, 7
cmp eax, 45h
jle short loc_480500
loc_480510:
lea eax, [ebx+16]
imul eax, 8
cmp eax, 45h
jle short loc_480500
loc_480520:
lea eax, [ebx+17]
imul eax, 9
cmp eax, 45h
jle short loc_480500
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4236544','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480500:
lea eax, [ebx+15]
imul eax, 7
cmp eax, 45h
jle short loc_480500
loc_480510:
lea eax, [ebx+16]
imul eax, 8
cmp eax, 45h
jle short loc_480500
loc_480520:
lea eax, [ebx+17]
imul eax, 9
cmp eax, 45h
jle short loc_480500
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall j_nullsub_1(int a1)
{
  int v1 = a1 * 7;
  return v1 + 5;
}','34','[]','531451d9971c67fc6f152fb75fbcfb19',544,'5.4','[]',0,'4236544','[]','0',NULL,NULL,NULL,NULL,'1',0.005);
INSERT INTO "functions" VALUES(6,'wrapper_a','4236800',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480600:", "lea", "imul", "cmp", "jle", "loc_480610:", "lea", "imul", "cmp", "jle", "loc_480620:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'?a@@YAXXZ','7ce34507de68ad65a0931bf31395b23f','int __fastcall wrapper_a(int a1)
{
  int v1 = a1 * 8;
  return v1 + 6;
}',5,'dc35a7742098679f',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480600:
lea eax, [ebx+18]
imul eax, 8
cmp eax, 46h
jle short loc_480600
loc_480610:
lea eax, [ebx+19]
imul eax, 9
cmp eax, 46h
jle short loc_480600
loc_480620:
lea eax, [ebx+20]
imul eax, 10
cmp eax, 46h
jle short loc_480600
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4236800','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480600:
lea eax, [ebx+18]
imul eax, 8
cmp eax, 46h
jle short loc_480600
loc_480610:
lea eax, [ebx+19]
imul eax, 9
cmp eax, 46h
jle short loc_480600
loc_480620:
lea eax, [ebx+20]
imul eax, 10
cmp eax, 46h
jle short loc_480600
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall wrapper_a(int a1)
{
  int v1 = a1 * 8;
  return v1 + 6;
}','34','[]','d4ecb565cc8a89d21670564b4042926e',800,'6.4','[]',0,'4236800','[]','0',NULL,NULL,NULL,NULL,'1',0.006);
INSERT INTO "functions" VALUES(7,'prettyname','4237056',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480700:", "lea", "imul", "cmp", "jle", "loc_480710:", "lea", "imul", "cmp", "jle", "loc_480720:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40C000','ec7ae1f3faddf8f6a0edca9d92432949','int __fastcall prettyname(int a1)
{
  int v1 = a1 * 9;
  return v1 + 7;
}',5,'2916c932717bce6c',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480700:
lea eax, [ebx+21]
imul eax, 9
cmp eax, 47h
jle short loc_480700
loc_480710:
lea eax, [ebx+22]
imul eax, 10
cmp eax, 47h
jle short loc_480700
loc_480720:
lea eax, [ebx+23]
imul eax, 11
cmp eax, 47h
jle short loc_480700
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4237056','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480700:
lea eax, [ebx+21]
imul eax, 9
cmp eax, 47h
jle short loc_480700
loc_480710:
lea eax, [ebx+22]
imul eax, 10
cmp eax, 47h
jle short loc_480700
loc_480720:
lea eax, [ebx+23]
imul eax, 11
cmp eax, 47h
jle short loc_480700
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall prettyname(int a1)
{
  int v1 = a1 * 9;
  return v1 + 7;
}','34','[]','7aff2fd8c0477d9c5edcc1644cf6c734',56,'7.4','[]',0,'4237056','[]','0',NULL,NULL,NULL,NULL,'1',0.007);
INSERT INTO "functions" VALUES(8,'tiny','4237312',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480800:", "lea", "imul", "cmp", "jle", "loc_480810:", "lea", "imul", "cmp", "jle", "loc_480820:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'tiny','30af324be63a8aff062142b7d7c6d009','int __fastcall tiny(int a1)
{
  int v1 = a1 * 10;
  return v1 + 8;
}',5,'39e8d7511832e13a',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480800:
lea eax, [ebx+24]
imul eax, 10
cmp eax, 48h
jle short loc_480800
loc_480810:
lea eax, [ebx+25]
imul eax, 11
cmp eax, 48h
jle short loc_480800
loc_480820:
lea eax, [ebx+26]
imul eax, 12
cmp eax, 48h
jle short loc_480800
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4237312','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480800:
lea eax, [ebx+24]
imul eax, 10
cmp eax, 48h
jle short loc_480800
loc_480810:
lea eax, [ebx+25]
imul eax, 11
cmp eax, 48h
jle short loc_480800
loc_480820:
lea eax, [ebx+26]
imul eax, 12
cmp eax, 48h
jle short loc_480800
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall tiny(int a1)
{
  int v1 = a1 * 10;
  return v1 + 8;
}','34','[]','3c9215e17f3243f75054beafc60da492',312,'8.4','[]',0,'4237312','[]','0',NULL,NULL,NULL,NULL,'1',0.008);
INSERT INTO "functions" VALUES(9,'dupname','4237568',4,3,1,1,88,22,'["push", "sub", "mov", "loc_480900:", "lea", "imul", "cmp", "jle", "loc_480910:", "lea", "imul", "cmp", "jle", "loc_480920:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'dupname','e0c2f48bd1425280eb829fd758ac7924','int __fastcall dupname(int a1)
{
  int v1 = a1 * 11;
  return v1 + 9;
}',5,'abd481c03d9246e9',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_480900:
lea eax, [ebx+27]
imul eax, 11
cmp eax, 49h
jle short loc_480900
loc_480910:
lea eax, [ebx+28]
imul eax, 12
cmp eax, 49h
jle short loc_480900
loc_480920:
lea eax, [ebx+29]
imul eax, 13
cmp eax, 49h
jle short loc_480900
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4237568','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_480900:
lea eax, [ebx+27]
imul eax, 11
cmp eax, 49h
jle short loc_480900
loc_480910:
lea eax, [ebx+28]
imul eax, 12
cmp eax, 49h
jle short loc_480900
loc_480920:
lea eax, [ebx+29]
imul eax, 13
cmp eax, 49h
jle short loc_480900
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall dupname(int a1)
{
  int v1 = a1 * 11;
  return v1 + 9;
}','34','[]','2db1dbd7c742ea9520bfdb2b2a9a448d',568,'9.4','[]',0,'4237568','[]','0',NULL,NULL,NULL,NULL,'1',9.000000000000001054e-03);
INSERT INTO "functions" VALUES(11,'lowA','4238080',1,0,1,1,24,6,'["push", "mov", "call", "call", "pop", "retn"]','["alpha", "beta"]',NULL,1,'3',NULL,'lowA','6f9864e1034923089c7d07cfa1366f4b','int lowA()
{
  alpha();
  return beta();
}',5,'8a4d64525258d778',NULL,0,'push ebp
mov ebp, esp
call alpha
call beta
pop ebp
retn',NULL,NULL,NULL,1,0,'4238080','[[0]]','2','push ebp
mov ebp, esp
call alpha
call beta
pop ebp
retn','int lowA()
{
  alpha();
  return beta();
}','31','[]','511b53b099d8521371918dbfa348b936',80,'0','[]',0,'4238080','[]','0',NULL,NULL,NULL,NULL,'1',0.011);
INSERT INTO "functions" VALUES(12,'sub_40AC00','4238336',4,3,1,1,88,22,'["push", "sub", "mov", "loc_481E00:", "lea", "imul", "cmp", "jle", "loc_481E10:", "lea", "imul", "cmp", "jle", "loc_481E20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40AC00','3321303b32864e030afd277e95fa0db5','int __fastcall sub_40AC00(int a1)
{
  int v1 = a1 * 32;
  return v1 + 30;
}',5,'55134b5ce3fc4cd6',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_481E00:
lea eax, [ebx+90]
imul eax, 32
cmp eax, 5Eh
jle short loc_481E00
loc_481E10:
lea eax, [ebx+91]
imul eax, 33
cmp eax, 5Eh
jle short loc_481E00
loc_481E20:
lea eax, [ebx+92]
imul eax, 34
cmp eax, 5Eh
jle short loc_481E00
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4238336','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_481E00:
lea eax, [ebx+90]
imul eax, 32
cmp eax, 5Eh
jle short loc_481E00
loc_481E10:
lea eax, [ebx+91]
imul eax, 33
cmp eax, 5Eh
jle short loc_481E00
loc_481E20:
lea eax, [ebx+92]
imul eax, 34
cmp eax, 5Eh
jle short loc_481E00
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40AC00(int a1)
{
  int v1 = a1 * 32;
  return v1 + 30;
}','34','[]','86430354b1dbbb1a2679378c00a2c479',336,'30.4','[]',0,'4238336','[]','0',NULL,NULL,NULL,NULL,'1',0.012);
INSERT INTO "functions" VALUES(13,'sub_40AD00','4238592',4,3,1,1,88,22,'["push", "sub", "mov", "loc_481F00:", "lea", "imul", "cmp", "jle", "loc_481F10:", "lea", "imul", "cmp", "jle", "loc_481F20:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40AD00','c6feb95ac5f3b74e41d15f3cddde45a3','int __fastcall sub_40AD00(int a1)
{
  int v1 = a1 * 33;
  return v1 + 31;
}',5,'3258f77031dbf18f',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_481F00:
lea eax, [ebx+93]
imul eax, 33
cmp eax, 5Fh
jle short loc_481F00
loc_481F10:
lea eax, [ebx+94]
imul eax, 34
cmp eax, 5Fh
jle short loc_481F00
loc_481F20:
lea eax, [ebx+95]
imul eax, 35
cmp eax, 5Fh
jle short loc_481F00
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4238592','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_481F00:
lea eax, [ebx+93]
imul eax, 33
cmp eax, 5Fh
jle short loc_481F00
loc_481F10:
lea eax, [ebx+94]
imul eax, 34
cmp eax, 5Fh
jle short loc_481F00
loc_481F20:
lea eax, [ebx+95]
imul eax, 35
cmp eax, 5Fh
jle short loc_481F00
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40AD00(int a1)
{
  int v1 = a1 * 33;
  return v1 + 31;
}','34','[]','bd080bb71a541b1b9d006bcc2acaf442',592,'31.4','[]',0,'4238592','[]','0',NULL,NULL,NULL,NULL,'1',1.300000000000000113e-02);
INSERT INTO "functions" VALUES(14,'sub_40AE00','4238848',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482000:", "lea", "imul", "cmp", "jle", "loc_482010:", "lea", "imul", "cmp", "jle", "loc_482020:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40AE00','aab50abd2c2f4f479b3ef08b1bdff06c','int __fastcall sub_40AE00(int a1)
{
  int v1 = a1 * 34;
  return v1 + 32;
}',5,'b0b60310d8932fb6',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482000:
lea eax, [ebx+96]
imul eax, 34
cmp eax, 60h
jle short loc_482000
loc_482010:
lea eax, [ebx+97]
imul eax, 35
cmp eax, 60h
jle short loc_482000
loc_482020:
lea eax, [ebx+98]
imul eax, 36
cmp eax, 60h
jle short loc_482000
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4238848','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482000:
lea eax, [ebx+96]
imul eax, 34
cmp eax, 60h
jle short loc_482000
loc_482010:
lea eax, [ebx+97]
imul eax, 35
cmp eax, 60h
jle short loc_482000
loc_482020:
lea eax, [ebx+98]
imul eax, 36
cmp eax, 60h
jle short loc_482000
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40AE00(int a1)
{
  int v1 = a1 * 34;
  return v1 + 32;
}','34','[]','82610b051fa6609e6483b16b256b598a',848,'32.4','[]',0,'4238848','[]','0',NULL,NULL,NULL,NULL,'1',0.014);
INSERT INTO "functions" VALUES(15,'sub_40AF00','4239104',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482100:", "lea", "imul", "cmp", "jle", "loc_482110:", "lea", "imul", "cmp", "jle", "loc_482120:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40AF00','b30ca73ee5ae856ad062793aa2636d00','int __fastcall sub_40AF00(int a1)
{
  int v1 = a1 * 35;
  return v1 + 33;
}',5,'1b66e9bde5509381',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482100:
lea eax, [ebx+99]
imul eax, 35
cmp eax, 61h
jle short loc_482100
loc_482110:
lea eax, [ebx+100]
imul eax, 36
cmp eax, 61h
jle short loc_482100
loc_482120:
lea eax, [ebx+101]
imul eax, 37
cmp eax, 61h
jle short loc_482100
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4239104','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482100:
lea eax, [ebx+99]
imul eax, 35
cmp eax, 61h
jle short loc_482100
loc_482110:
lea eax, [ebx+100]
imul eax, 36
cmp eax, 61h
jle short loc_482100
loc_482120:
lea eax, [ebx+101]
imul eax, 37
cmp eax, 61h
jle short loc_482100
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40AF00(int a1)
{
  int v1 = a1 * 35;
  return v1 + 33;
}','34','[]','ce0e9f786813f9cfd1634e35d34e6537',104,'33.4','[]',0,'4239104','[]','0',NULL,NULL,NULL,NULL,'1',0.015);
INSERT INTO "functions" VALUES(16,'sub_40B000','4239360',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482200:", "lea", "imul", "cmp", "jle", "loc_482210:", "lea", "imul", "cmp", "jle", "loc_482220:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40B000','b2af4b547cab32fc0542fd463235ae5d','int __fastcall sub_40B000(int a1)
{
  int v1 = a1 * 36;
  return v1 + 34;
}',5,'26fe2e3b2dc54300',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482200:
lea eax, [ebx+102]
imul eax, 36
cmp eax, 62h
jle short loc_482200
loc_482210:
lea eax, [ebx+103]
imul eax, 37
cmp eax, 62h
jle short loc_482200
loc_482220:
lea eax, [ebx+104]
imul eax, 38
cmp eax, 62h
jle short loc_482200
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4239360','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482200:
lea eax, [ebx+102]
imul eax, 36
cmp eax, 62h
jle short loc_482200
loc_482210:
lea eax, [ebx+103]
imul eax, 37
cmp eax, 62h
jle short loc_482200
loc_482220:
lea eax, [ebx+104]
imul eax, 38
cmp eax, 62h
jle short loc_482200
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40B000(int a1)
{
  int v1 = a1 * 36;
  return v1 + 34;
}','34','[]','d36d5287922527077e0c00bac96fbeec',360,'34.4','[]',0,'4239360','[]','0',NULL,NULL,NULL,NULL,'1',0.016);
INSERT INTO "functions" VALUES(17,'sub_40B100','4239616',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482300:", "lea", "imul", "cmp", "jle", "loc_482310:", "lea", "imul", "cmp", "jle", "loc_482320:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40B100','4a91edc6974f637e91a4927b478b5387','int __fastcall sub_40B100(int a1)
{
  int v1 = a1 * 37;
  return v1 + 35;
}',5,'a7e161641bf8313b',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482300:
lea eax, [ebx+105]
imul eax, 37
cmp eax, 63h
jle short loc_482300
loc_482310:
lea eax, [ebx+106]
imul eax, 38
cmp eax, 63h
jle short loc_482300
loc_482320:
lea eax, [ebx+107]
imul eax, 39
cmp eax, 63h
jle short loc_482300
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4239616','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482300:
lea eax, [ebx+105]
imul eax, 37
cmp eax, 63h
jle short loc_482300
loc_482310:
lea eax, [ebx+106]
imul eax, 38
cmp eax, 63h
jle short loc_482300
loc_482320:
lea eax, [ebx+107]
imul eax, 39
cmp eax, 63h
jle short loc_482300
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40B100(int a1)
{
  int v1 = a1 * 37;
  return v1 + 35;
}','34','[]','5749d98b9cf1f7adc8ea9ca092a701f1',616,'35.4','[]',0,'4239616','[]','0',NULL,NULL,NULL,NULL,'1',0.017);
INSERT INTO "functions" VALUES(18,'sub_40B200','4239872',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482400:", "lea", "imul", "cmp", "jle", "loc_482410:", "lea", "imul", "cmp", "jle", "loc_482420:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40B200','1af245e57ffcf49ad6525d164f345406','int __fastcall sub_40B200(int a1)
{
  int v1 = a1 * 38;
  return v1 + 36;
}',5,'c1c3c2f4744b31af',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482400:
lea eax, [ebx+108]
imul eax, 38
cmp eax, 64h
jle short loc_482400
loc_482410:
lea eax, [ebx+109]
imul eax, 39
cmp eax, 64h
jle short loc_482400
loc_482420:
lea eax, [ebx+110]
imul eax, 40
cmp eax, 64h
jle short loc_482400
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4239872','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482400:
lea eax, [ebx+108]
imul eax, 38
cmp eax, 64h
jle short loc_482400
loc_482410:
lea eax, [ebx+109]
imul eax, 39
cmp eax, 64h
jle short loc_482400
loc_482420:
lea eax, [ebx+110]
imul eax, 40
cmp eax, 64h
jle short loc_482400
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40B200(int a1)
{
  int v1 = a1 * 38;
  return v1 + 36;
}','34','[]','e0ef46c4ac6e687591f9f252cd7600f2',872,'36.4','[]',0,'4239872','[]','0',NULL,NULL,NULL,NULL,'1',1.800000000000000211e-02);
INSERT INTO "functions" VALUES(19,'sub_40B300','4240128',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482500:", "lea", "imul", "cmp", "jle", "loc_482510:", "lea", "imul", "cmp", "jle", "loc_482520:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40B300','efb9c49a682c654acebf31db66594ab1','int __fastcall sub_40B300(int a1)
{
  int v1 = a1 * 39;
  return v1 + 37;
}',5,'45da22833a10592e',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482500:
lea eax, [ebx+111]
imul eax, 39
cmp eax, 65h
jle short loc_482500
loc_482510:
lea eax, [ebx+112]
imul eax, 40
cmp eax, 65h
jle short loc_482500
loc_482520:
lea eax, [ebx+113]
imul eax, 41
cmp eax, 65h
jle short loc_482500
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4240128','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482500:
lea eax, [ebx+111]
imul eax, 39
cmp eax, 65h
jle short loc_482500
loc_482510:
lea eax, [ebx+112]
imul eax, 40
cmp eax, 65h
jle short loc_482500
loc_482520:
lea eax, [ebx+113]
imul eax, 41
cmp eax, 65h
jle short loc_482500
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40B300(int a1)
{
  int v1 = a1 * 39;
  return v1 + 37;
}','34','[]','51aaa72b8602163f2b2541a006cd136d',128,'37.4','[]',0,'4240128','[]','0',NULL,NULL,NULL,NULL,'1',0.019);
INSERT INTO "functions" VALUES(20,'sub_40B400','4240384',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482600:", "lea", "imul", "cmp", "jle", "loc_482610:", "lea", "imul", "cmp", "jle", "loc_482620:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40B400','dbf92a83f0369442e7029b6fd4e06231','int __fastcall sub_40B400(int a1)
{
  int v1 = a1 * 40;
  return v1 + 38;
}',5,'fb7b5735aa03dc72',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482600:
lea eax, [ebx+114]
imul eax, 40
cmp eax, 66h
jle short loc_482600
loc_482610:
lea eax, [ebx+115]
imul eax, 41
cmp eax, 66h
jle short loc_482600
loc_482620:
lea eax, [ebx+116]
imul eax, 42
cmp eax, 66h
jle short loc_482600
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4240384','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482600:
lea eax, [ebx+114]
imul eax, 40
cmp eax, 66h
jle short loc_482600
loc_482610:
lea eax, [ebx+115]
imul eax, 41
cmp eax, 66h
jle short loc_482600
loc_482620:
lea eax, [ebx+116]
imul eax, 42
cmp eax, 66h
jle short loc_482600
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40B400(int a1)
{
  int v1 = a1 * 40;
  return v1 + 38;
}','34','[]','5dd2c9a71b15814f4af587de17de0d17',384,'38.4','[]',0,'4240384','[]','0',NULL,NULL,NULL,NULL,'1',0.02);
INSERT INTO "functions" VALUES(21,'sub_40B500','4240640',4,3,1,1,88,22,'["push", "sub", "mov", "loc_482700:", "lea", "imul", "cmp", "jle", "loc_482710:", "lea", "imul", "cmp", "jle", "loc_482720:", "lea", "imul", "cmp", "jle", "mov", "add", "pop", "retn"]','[]',NULL,1,'9',NULL,'sub_40B500','b7ac33f5b22185e2328e47b520889a53','int __fastcall sub_40B500(int a1)
{
  int v1 = a1 * 41;
  return v1 + 39;
}',5,'e945a5dadd714199',NULL,0,'push ebx
sub esp, 20h
mov ebx, ecx
loc_482700:
lea eax, [ebx+117]
imul eax, 41
cmp eax, 67h
jle short loc_482700
loc_482710:
lea eax, [ebx+118]
imul eax, 42
cmp eax, 67h
jle short loc_482700
loc_482720:
lea eax, [ebx+119]
imul eax, 43
cmp eax, 67h
jle short loc_482700
mov eax, ebx
add esp, 20h
pop ebx
retn',NULL,NULL,NULL,1,0,'4240640','[[0]]','2','push ebx
sub esp, 20h
mov ebx, ecx
loc_482700:
lea eax, [ebx+117]
imul eax, 41
cmp eax, 67h
jle short loc_482700
loc_482710:
lea eax, [ebx+118]
imul eax, 42
cmp eax, 67h
jle short loc_482700
loc_482720:
lea eax, [ebx+119]
imul eax, 43
cmp eax, 67h
jle short loc_482700
mov eax, ebx
add esp, 20h
pop ebx
retn','int __fastcall sub_40B500(int a1)
{
  int v1 = a1 * 41;
  return v1 + 39;
}','34','[]','985c156c3d5a5bc77917d2a1de38ab8f',640,'39.4','[]',0,'4240640','[]','0',NULL,NULL,NULL,NULL,'1',0.021);
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
INSERT INTO "sqlite_stat1" VALUES('functions','idx_30','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_29','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_28','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_27','20 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_26','20 20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_25','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_24','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_23','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_22','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_21','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_20','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_19','20 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_18','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_17','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_16','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_15','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_14','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_13','20 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_12','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_11','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_10','20 10 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_9','20 20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_8','20 20');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_7','20 10 10 10');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_6','20 10 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_5','20 10 10 1 1 1 1 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_4','20 1 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_3','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_2','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_1','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','idx_0','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_2','20 1');
INSERT INTO "sqlite_stat1" VALUES('functions','sqlite_autoindex_functions_1','20 1');
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
