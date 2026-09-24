// Lane P1: crash resilience of `diff` (checkpoints and --resume) and break-the-app tests.
//
// Included by foundation_tests.cpp (inside its unnamed namespace, after its helpers): the suites here
// reuse FixturePair, BuildFoundationFixture, Join, ReadFile, WriteText, Exists, Sha256Of and, on
// Windows, QuoteArgument / Utf8ToWide. Every scenario checks the documented exit code, that no input
// changed, and that no partial results file is left at -o.
//
//   * checkpoint files: the state and manifest formats round-trip; step names; the store's file names;
//   * kill and resume: the test binary re-runs itself as a child ("--p1-checkpoint-child") that ends
//     its own process (TerminateProcess / _exit, no unwinding, no flushing) at a chosen checkpoint step,
//     then --resume must write a results file identical to an uninterrupted run's (config.date
//     masked), at every checkpoint of the fixture run, mid-write of a state file or of the manifest,
//     and after a second kill of the resumed run; with the corpus, also on ls-old vs ls, compared with
//     the oracle's run1 at L2;
//   * checkpoint directory problems, a full disk while checkpointing (the checkpoint fault hook),
//     corrupt and truncated inputs, a locked input (SQLITE_BUSY), damaged checkpoints on resume, an
//     unexpected exception (DiffStatus::Internal, exit 70);
//   * the audit gaps of the last verification: F01 --snapshot-out equal to --replay and inside an oracle
//     capture; F58 the UTF-8 fetch-error messages name the row;
//   * JsonValue::AsDouble without floating-point from_chars: equal to Python float() (PyFloat) on
//     shortest round-trip texts, long and extreme literals.

// ---------------------------------------------------------------------------------------------
// Helpers

std::string g_P1SelfPath;  // this test executable (set by main from argv[0] / the module path)

void P1SetSelfPath(const char* Argv0) {
#ifdef _WIN32
  (void)Argv0;
  std::wstring Buffer(32768, L'\0');
  const DWORD Length = GetModuleFileNameW(nullptr, Buffer.data(), static_cast<DWORD>(Buffer.size()));
  Buffer.resize(Length);
  g_P1SelfPath = PathToUtf8(fs::path(Buffer));
#else
  std::error_code Error;
  const fs::path Absolute = fs::absolute(fs::path(Argv0 != nullptr ? Argv0 : ""), Error);
  g_P1SelfPath = Error ? std::string(Argv0 != nullptr ? Argv0 : "") : Absolute.string();
#endif
}

// Ends this process at once with `Code`: no destructors, no atexit handlers, no stream flushing (a kill).
[[noreturn]] void P1HardExit(int Code) {
#ifdef _WIN32
  TerminateProcess(GetCurrentProcess(), static_cast<UINT>(Code));
#endif
  std::_Exit(Code);
}

constexpr int kP1KilledCode = 86;
constexpr unsigned kP1ChildTimeoutMs = 300000;  // a child that runs longer than this is reported as hung

// Runs `Exe` with UTF-8 arguments (stdout/stderr to LogPath) and returns its exit code; -1 when it could
// not start, -2 when it had to be terminated after TimeoutMs (a hang).
int P1RunProgram(const std::string& Exe, const std::vector<std::string>& Arguments, const std::string& LogPath,
                 unsigned TimeoutMs = kP1ChildTimeoutMs) {
#ifdef _WIN32
  std::wstring WideExe = Utf8ToWide(Exe);
  std::replace(WideExe.begin(), WideExe.end(), L'/', L'\\');
  std::wstring Line = QuoteArgument(WideExe);
  for (const std::string& Argument : Arguments) {
    Line += L' ';
    Line += QuoteArgument(Utf8ToWide(Argument));
  }
  SECURITY_ATTRIBUTES Inherit{};
  Inherit.nLength = sizeof(Inherit);
  Inherit.bInheritHandle = TRUE;
  const HANDLE Log = CreateFileW(Utf8ToWide(LogPath).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &Inherit, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (Log == INVALID_HANDLE_VALUE) {
    return -1;
  }
  STARTUPINFOW Startup{};
  Startup.cb = sizeof(Startup);
  Startup.dwFlags = STARTF_USESTDHANDLES;
  Startup.hStdInput = nullptr;
  Startup.hStdOutput = Log;
  Startup.hStdError = Log;
  PROCESS_INFORMATION Process{};
  std::vector<wchar_t> Mutable(Line.begin(), Line.end());
  Mutable.push_back(L'\0');
  if (!CreateProcessW(WideExe.c_str(), Mutable.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
                      &Startup, &Process)) {
    CloseHandle(Log);
    return -1;
  }
  int Result = 0;
  if (WaitForSingleObject(Process.hProcess, TimeoutMs) == WAIT_TIMEOUT) {
    TerminateProcess(Process.hProcess, 99);
    WaitForSingleObject(Process.hProcess, INFINITE);
    Result = -2;
  } else {
    DWORD Code = 0;
    GetExitCodeProcess(Process.hProcess, &Code);
    Result = static_cast<int>(Code);
  }
  CloseHandle(Process.hThread);
  CloseHandle(Process.hProcess);
  CloseHandle(Log);
  return Result;
#else
  (void)TimeoutMs;
  std::string Command = "'" + Exe + "'";
  for (const std::string& Argument : Arguments) {
    std::string Quoted = "'";
    for (const char Ch : Argument) {
      Quoted += Ch == '\'' ? std::string("'\\''") : std::string(1, Ch);
    }
    Command += " " + Quoted + "'";
  }
  Command += " >'" + LogPath + "' 2>&1";
  const int Status = std::system(Command.c_str());
  if (Status == -1) {
    return -1;
  }
  return (Status >> 8) & 0xff;  // WEXITSTATUS without <sys/wait.h>
#endif
}

// The results file's bytes with the config.date text replaced by 'X's (the only field that differs
// between two runs on the same inputs). "" when the file cannot be read.
std::string P1MaskedResults(const std::string& Path) {
  std::string Bytes = ReadFile(Path);
  if (Bytes.empty()) {
    return std::string();
  }
  try {
    DiffDatabase Db;
    Db.OpenSingle(Path);
    Statement Query = Db.Prepare("select date from config");
    while (Query.Step()) {
      const std::string Date(Query.Text(0));
      const size_t At = Bytes.find(Date);
      if (Date.empty() || At == std::string::npos || Bytes.find(Date, At + 1) != std::string::npos) {
        return "<config.date not found exactly once>";
      }
      Bytes.replace(At, Date.size(), std::string(Date.size(), 'X'));
    }
  } catch (const std::exception& Error) {
    return std::string("<unreadable results: ") + Error.what() + ">";
  }
  return Bytes;
}

DiffArgs P1Args(const std::string& Db1, const std::string& Db2, const std::string& Out) {
  DiffArgs Args;
  Args.Db1 = Db1;
  Args.Db2 = Db2;
  Args.Out = Out;
  Args.Quiet = true;
  Args.AllowSqliteMismatch = true;
  return Args;
}

// Every file of a directory (name -> bytes), for "nothing was changed" checks.
std::map<std::string, std::string> P1DirContents(const std::string& Dir) {
  std::map<std::string, std::string> Files;
  std::error_code Error;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Utf8ToPath(Dir), Error)) {
    if (Entry.is_regular_file(Error)) {
      Files[PathToUtf8(Entry.path().filename())] = ReadFile(PathToUtf8(Entry.path()));
    }
  }
  return Files;
}

void P1CopyDir(const std::string& From, const std::string& To) {
  std::error_code Error;
  fs::remove_all(Utf8ToPath(To), Error);
  fs::create_directories(Utf8ToPath(To), Error);
  for (const fs::directory_entry& Entry : fs::directory_iterator(Utf8ToPath(From), Error)) {
    fs::copy_file(Entry.path(), Utf8ToPath(To) / Entry.path().filename(), fs::copy_options::overwrite_existing, Error);
  }
}

// ---------------------------------------------------------------------------------------------
// The child process: runs one diff with a fault hook that kills the process at a checkpoint step.
//   <exe> --p1-checkpoint-child <db1> <db2> <out> <dir> <fresh|resume> <hook step> <n>
// The hook ends the process with kP1KilledCode at the n-th call with that step ("committed",
// "state:write", "state:rename", "manifest:write", "manifest:rename"). Without a kill the child exits
// with the diff's status.

std::string g_P1KillStep;
int g_P1KillAt = 0;
int g_P1KillSeen = 0;

void P1KillHook(std::string_view Step) {
  if (Step == g_P1KillStep && ++g_P1KillSeen == g_P1KillAt) {
    P1HardExit(kP1KilledCode);
  }
}

int P1CheckpointChildMain(int Argc, char** Argv) {
  if (Argc != 9) {
    std::fprintf(stderr, "p1 child: expected 7 arguments\n");
    return 64;
  }
  DiffArgs Args = P1Args(Argv[2], Argv[3], Argv[4]);
  if (std::string(Argv[6]) == "resume") {
    Args.ResumeDir = Argv[5];
  } else {
    Args.CheckpointDir = Argv[5];
  }
  g_P1KillStep = Argv[7];
  g_P1KillAt = std::atoi(Argv[8]);
  Detail::SetCheckpointFaultHook(&P1KillHook);
  const DiffOutcome Outcome = RunDiff(Args);
  if (Outcome.Status != DiffStatus::Ok) {
    std::fprintf(stderr, "p1 child: %s\n", Outcome.Message.c_str());
  }
  return static_cast<int>(Outcome.Status);
}

int P1RunChild(const FixturePair& Pair, const std::string& Out, const std::string& Dir, bool Resume,
               const std::string& Step, int At, const std::string& Log) {
  return P1RunProgram(g_P1SelfPath, {"--p1-checkpoint-child", Pair.Main, Pair.Diff, Out, Dir,
                                     Resume ? "resume" : "fresh", Step, std::to_string(At)},
                      Log);
}

// ---------------------------------------------------------------------------------------------
// 1. Checkpoint file formats

void TestP1CheckpointFormats() {
  DSig::Test::Suite("P1 checkpoint formats");
  for (int Value = 0; Value <= static_cast<int>(PipelineStep::FindUnmatched); ++Value) {
    const auto Step = static_cast<PipelineStep>(Value);
    const auto Back = PipelineStepFromName(PipelineStepName(Step));
    CHECK(Back.has_value() && *Back == Step);
  }
  CHECK(!PipelineStepFromName("no_such_stage").has_value());
  CHECK(IsLoopStep(PipelineStep::RelatedCompilationUnit) && !IsLoopStep(PipelineStep::FinalPass) &&
        !IsLoopStep(PipelineStep::SmallDifferences));
  for (const char* Name : {"manifest.json", "manifest.json.tmp", "state-000001.json", "state-1234567.json",
                           "state-000002.json.tmp", ".dsig-checkpoint-probe"}) {
    CHECK(CheckpointStore::IsStoreFileName(Name));
  }
  for (const char* Name : {"manifest.jsonx", "state-1.json", "state-00000a.json", "results.diaphora", "index.json",
                           "state-000001.json.bak"}) {
    CHECK(!CheckpointStore::IsStoreFileName(Name));
  }

  EngineCheckpoint C;
  C.Binding.ToolVersion = "9.9.9";
  C.Binding.SqliteVersion = "3.51.1";
  C.Binding.Db1Sha256 = std::string(64, 'a');
  C.Binding.Db1Size = 4096;
  C.Binding.Db2Sha256 = std::string(64, 'b');
  C.Binding.Db2Size = 8192;
  C.Binding.Db2WalSha256 = std::string(64, 'c');
  C.Binding.IgnoreSmallFunctions = true;
  C.Binding.RelatedCuSource = "sql";
  C.Cursor = PipelineCursor{PipelineStep::RelatedCompilationUnit, 3, false, 1234};
  C.State.Pair = "p";
  C.State.Point = "checkpoint:x";
  C.State.Iteration = 3;
  C.State.Best.push_back(SnapItem{"4096", "f\xc3\xa9", "8192", std::nullopt, "desc \"q\"", RatioBits(0.1), 3, 4});
  C.State.MatchedPrimary.push_back(SnapMatched{std::nullopt, "n", RatioBits(1.0)});
  C.RatiosCache.push_back(CheckpointCacheEntry{"4096", "8192", RatioBits(0.30000000000000004)});
  C.RatiosCache.push_back(CheckpointCacheEntry{std::nullopt, "1-2", 0x7ff8000000000001ull});  // NaN payload kept
  C.HookDones.emplace_back(std::nullopt, "b");
  C.PointSeq = 77;
  C.CleanupCounters = {{1551, 2}, {3655, 4}};
  const std::string Text = SerializeCheckpointState(C);
  CHECK(!Text.empty() && Text.back() == '\n');
  const EngineCheckpoint Back = ParseCheckpointState(Text);
  CHECK(Back.Binding == C.Binding);
  CHECK(Back.Cursor == C.Cursor);
  CHECK(Back.State.Best == C.State.Best && Back.State.MatchedPrimary == C.State.MatchedPrimary);
  CHECK(Back.State.Iteration == C.State.Iteration && !Back.State.RatiosCache);
  CHECK(Back.RatiosCache == C.RatiosCache);
  CHECK(Back.HookDones == C.HookDones && Back.PointSeq == 77 && Back.CleanupCounters == C.CleanupCounters);
  CHECK_TEXT_EQ(SerializeCheckpointState(Back), Text);  // stable

  CheckpointManifest M;
  M.Binding = C.Binding;
  M.Cursor = C.Cursor;
  M.Generation = 12;
  M.StateFile = "state-000012.json";
  M.StateSha256 = std::string(64, 'd');
  M.StateBytes = 99;
  M.Db1 = "C:\\a b\\x.sqlite";
  M.Db2 = "y.sqlite";
  M.CreatedDirectory = true;
  const CheckpointManifest MB = ParseCheckpointManifest(SerializeCheckpointManifest(M));
  CHECK(MB.Binding == M.Binding && MB.Cursor == M.Cursor && MB.Generation == 12 && MB.StateFile == M.StateFile &&
        MB.StateSha256 == M.StateSha256 && MB.StateBytes == 99 && MB.Db1 == M.Db1 && MB.Db2 == M.Db2 &&
        MB.CreatedDirectory);

  // malformed state texts are JsonError, never a crash
  for (const std::string& Bad : {std::string(), std::string("[]"), Text.substr(0, Text.size() / 2),
                                 std::string("{\"schema\":\"dsigmatcher-checkpoint-state/0\"}")}) {
    bool Threw = false;
    try {
      (void)ParseCheckpointState(Bad);
    } catch (const JsonError&) {
      Threw = true;
    }
    CHECK(Threw);
  }
  CheckpointBinding Other = C.Binding;
  Other.Db1Sha256 = std::string(64, 'e');
  CHECK(DescribeBindingMismatch(C.Binding, Other).find("db1 sha256") == 0);
  CHECK(DescribeBindingMismatch(C.Binding, C.Binding).empty());
}

// ---------------------------------------------------------------------------------------------
// 2. Kill and resume

struct P1Baseline {
  std::string Masked;         // the uninterrupted run's results, config.date masked
  size_t Checkpoints = 0;     // checkpoints a checkpointed run writes
  bool Ok = false;
};

P1Baseline P1RunBaseline(const FixturePair& Pair, const std::string& Tag) {
  P1Baseline Base;
  const std::string Out = Join(Pair.Dir, Tag + "-straight.diaphora");
  const DiffOutcome Straight = RunDiff(P1Args(Pair.Main, Pair.Diff, Out));
  CHECK(Straight.Status == DiffStatus::Ok);
  CHECK_NUM_EQ(Straight.CheckpointsWritten, 0);
  Base.Masked = P1MaskedResults(Out);
  const std::string Dir = Join(Pair.Dir, Tag + "-ck-straight");
  DiffArgs Args = P1Args(Pair.Main, Pair.Diff, Join(Pair.Dir, Tag + "-with-ck.diaphora"));
  Args.CheckpointDir = Dir;
  const DiffOutcome With = RunDiff(Args);
  CHECK(With.Status == DiffStatus::Ok && With.Warnings.empty());
  CHECK(P1MaskedResults(Args.Out) == Base.Masked);  // checkpointing never changes the results
  CHECK(!Exists(Dir));                              // created by the run, removed after the results
  Base.Checkpoints = With.CheckpointsWritten;
  Base.Ok = Straight.Status == DiffStatus::Ok && !Base.Masked.empty() && Base.Checkpoints > 0;
  return Base;
}

// Kills a checkpointed child at (Step, At), then resumes in this process; returns true when the resumed
// results equal the baseline and nothing was left behind.
bool P1KillThenResume(const FixturePair& Pair, const P1Baseline& Base, const std::string& Tag, const std::string& Step,
                      int At, std::string* ResumedAfter = nullptr) {
  const std::string Dir = Join(Pair.Dir, Tag + "-ck");
  const std::string Out = Join(Pair.Dir, Tag + ".diaphora");
  std::error_code Error;
  fs::remove_all(Utf8ToPath(Dir), Error);
  fs::remove(Utf8ToPath(Out), Error);
  const std::string MainSha = Sha256Of(ReadFile(Pair.Main));
  const std::string DiffSha = Sha256Of(ReadFile(Pair.Diff));
  const int Killed = P1RunChild(Pair, Out, Dir, false, Step, At, Join(Pair.Dir, Tag + "-child.log"));
  bool Ok = Killed == kP1KilledCode;
  if (!Ok) {
    DSig::Test::Note(Tag + ": the child exited " + std::to_string(Killed) + " instead of being killed");
  }
  Ok = Ok && !Exists(Out);  // no partial results file
  Ok = Ok && Exists(Join(Dir, "manifest.json"));
  DiffArgs Resume = P1Args(Pair.Main, Pair.Diff, Out);
  Resume.ResumeDir = Dir;
  const DiffOutcome Outcome = RunDiff(Resume);
  if (Outcome.Status != DiffStatus::Ok) {
    DSig::Test::Note(Tag + ": resume failed: " + Outcome.Message);
  }
  Ok = Ok && Outcome.Status == DiffStatus::Ok && !Outcome.ResumedAfter.empty() && Outcome.Warnings.empty();
  Ok = Ok && P1MaskedResults(Out) == Base.Masked;
  Ok = Ok && !Exists(Dir);  // the first run created it; removed once the results are written
  Ok = Ok && Sha256Of(ReadFile(Pair.Main)) == MainSha && Sha256Of(ReadFile(Pair.Diff)) == DiffSha;
  if (ResumedAfter != nullptr) {
    *ResumedAfter = Outcome.ResumedAfter;
  }
  DSig::Test::Report(Ok, (Tag + " (" + Step + " #" + std::to_string(At) + ", resumed after " +
                          Outcome.ResumedAfter + ")").c_str(),
                     __FILE__, __LINE__);
  return Ok;
}

void TestP1KillAndResume(const FixturePair& Pair) {
  DSig::Test::Suite("P1 kill and resume (fixture, every checkpoint)");
  if (g_P1SelfPath.empty()) {
    DSig::Test::Skip("P1 kill and resume", "the test executable's path is unknown");
    return;
  }
  const P1Baseline Base = P1RunBaseline(Pair, "p1");
  CHECK(Base.Ok);
  if (!Base.Ok) {
    return;
  }
  DSig::Test::Note(std::to_string(Base.Checkpoints) + " checkpoints per run");
  std::set<std::string> Resumed;
  for (int At = 1; At <= static_cast<int>(Base.Checkpoints); ++At) {
    std::string After;
    P1KillThenResume(Pair, Base, "p1-commit-" + std::to_string(At), "committed", At, &After);
    Resumed.insert(After);
  }
  // every checkpoint is a distinct resume point, loop steps included
  CHECK_NUM_EQ(Resumed.size(), Base.Checkpoints);
  CHECK(Resumed.count("find_related_compilation_unit:0") == 1);
  CHECK(Resumed.count("find_unmatched") == 1);
  // killed while a state file or the manifest is half written: the previous checkpoint is resumed
  const int Mid = static_cast<int>((Base.Checkpoints + 1) / 2);
  for (const auto& [Step, At] : std::vector<std::pair<std::string, int>>{{"state:write", 1},
                                                                         {"state:rename", 2},
                                                                         {"state:rename", Mid},
                                                                         {"manifest:write", Mid},
                                                                         {"manifest:rename", Mid},
                                                                         {"manifest:rename", static_cast<int>(Base.Checkpoints)}}) {
    const std::string Tag = "p1-mid-" + std::string(Step == "state:write" ? "sw" : Step == "state:rename" ? "sr"
                                                   : Step == "manifest:write" ? "mw" : "mr") +
                            "-" + std::to_string(At);
    if (Step == "state:write" && At == 1) {
      // killed before the first checkpoint exists: there is nothing to resume (exit 4), and a fresh run
      // into the same directory works (the directory holds no manifest)
      const std::string Dir = Join(Pair.Dir, Tag + "-ck");
      const std::string Out = Join(Pair.Dir, Tag + ".diaphora");
      CHECK_NUM_EQ(P1RunChild(Pair, Out, Dir, false, Step, At, Join(Pair.Dir, Tag + ".log")), kP1KilledCode);
      CHECK(!Exists(Out) && !Exists(Join(Dir, "manifest.json")));
      DiffArgs Resume = P1Args(Pair.Main, Pair.Diff, Out);
      Resume.ResumeDir = Dir;
      const DiffOutcome Outcome = RunDiff(Resume);
      CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Unsupported));
      CHECK(Outcome.Message.find("holds no checkpoint") != std::string::npos);
      CHECK(!Exists(Out));
      DiffArgs Fresh = P1Args(Pair.Main, Pair.Diff, Out);
      Fresh.CheckpointDir = Dir;
      CHECK(RunDiff(Fresh).Status == DiffStatus::Ok);
      CHECK(P1MaskedResults(Out) == Base.Masked);
      continue;
    }
    P1KillThenResume(Pair, Base, Tag, Step, At);
  }
  // killed twice: the resumed run is killed again and resumed again
  {
    const std::string Dir = Join(Pair.Dir, "p1-twice-ck");
    const std::string Out = Join(Pair.Dir, "p1-twice.diaphora");
    CHECK_NUM_EQ(P1RunChild(Pair, Out, Dir, false, "committed", 2, Join(Pair.Dir, "p1-twice-1.log")), kP1KilledCode);
    CHECK_NUM_EQ(P1RunChild(Pair, Out, Dir, true, "committed", 3, Join(Pair.Dir, "p1-twice-2.log")), kP1KilledCode);
    CHECK(!Exists(Out));
    DiffArgs Resume = P1Args(Pair.Main, Pair.Diff, Out);
    Resume.ResumeDir = Dir;
    const DiffOutcome Outcome = RunDiff(Resume);
    CHECK(Outcome.Status == DiffStatus::Ok);
    CHECK_NUM_EQ(Outcome.CheckpointsWritten, Base.Checkpoints - 5);
    CHECK(P1MaskedResults(Out) == Base.Masked);
    CHECK(!Exists(Dir));
  }
  // a checkpoint directory the user made is kept (emptied) after success
  {
    const std::string Dir = Join(Pair.Dir, "p1-user-dir");
    std::error_code Error;
    fs::create_directories(Utf8ToPath(Dir), Error);
    WriteText(Join(Dir, "notes.txt"), "mine\n");
    const std::string Out = Join(Pair.Dir, "p1-user-dir.diaphora");
    CHECK_NUM_EQ(P1RunChild(Pair, Out, Dir, false, "committed", 4, Join(Pair.Dir, "p1-user-dir.log")), kP1KilledCode);
    DiffArgs Resume = P1Args(Pair.Main, Pair.Diff, Out);
    Resume.ResumeDir = Dir;
    CHECK(RunDiff(Resume).Status == DiffStatus::Ok);
    CHECK(P1MaskedResults(Out) == Base.Masked);
    const auto Left = P1DirContents(Dir);
    CHECK(Left.size() == 1 && Left.count("notes.txt") == 1 && Left.at("notes.txt") == "mine\n");
  }
}

// The same on a real pair: ls-old vs ls, compared with an uninterrupted run byte for byte and with the
// oracle's run1 at L2 (the stored db paths differ from the oracle's command line, so not byte for byte).
void TestP1CorpusKillAndResume() {
  DSig::Test::Suite("P1 kill and resume (corpus: ls-old vs ls)");
  if (!DSig::Test::ExportAvailable("ls-old") || !DSig::Test::ExportAvailable("ls") || g_P1SelfPath.empty()) {
    DSig::Test::Skip("P1 kill and resume (corpus)", "the ls-old / ls exports are not available");
    return;
  }
  const std::string Oracle = DSig::Test::OracleResultsPath("ls-old_vs_ls");
  FixturePair Pair;
  Pair.Dir = DSig::Test::ScratchDir("p1-corpus");
  Pair.Main = DSig::Test::ExportPath("ls-old");
  Pair.Diff = DSig::Test::ExportPath("ls");
  Pair.Ok = true;
  const P1Baseline Base = P1RunBaseline(Pair, "ls");
  CHECK(Base.Ok);
  if (!Base.Ok) {
    DSig::Test::RemoveScratchDir(Pair.Dir);
    return;
  }
  const bool HaveOracle = Exists(Oracle) && DiffDatabase::IsOracleSqlite();
  const DSig::Test::ResultsFile OracleFile = HaveOracle ? DSig::Test::ReadResultsFile(Oracle) : DSig::Test::ResultsFile{};
  const int N = static_cast<int>(Base.Checkpoints);
  for (const auto& [Step, At] : std::vector<std::pair<std::string, int>>{
           {"committed", 1}, {"committed", 4}, {"committed", 9}, {"state:rename", 11}, {"committed", N - 1}}) {
    const std::string Tag = "ls-" + std::string(Step == "committed" ? "c" : "sr") + std::to_string(At);
    P1KillThenResume(Pair, Base, Tag, Step, At);
    if (HaveOracle) {
      // P1KillThenResume leaves the resumed results at <Tag>.diaphora
      const DSig::Test::CompareReport Report =
          DSig::Test::CompareResults(OracleFile, DSig::Test::ReadResultsFile(Join(Pair.Dir, Tag + ".diaphora")));
      DSig::Test::Report(Report.DdlEqual && Report.L2Equal, (Tag + " resumed = oracle run1 at L2").c_str(), __FILE__,
                         __LINE__);
    }
  }
  if (!HaveOracle) {
    DSig::Test::Note("oracle run1 of ls-old_vs_ls not compared (missing, or not the oracle's SQLite)");
  }
  DSig::Test::RemoveScratchDir(Pair.Dir);
}

// ---------------------------------------------------------------------------------------------
// 3. Checkpoint directory problems and command-line combinations

void TestP1CheckpointDirProblems(const FixturePair& Pair) {
  DSig::Test::Suite("P1 checkpoint directory problems");
  const std::string MainSha = Sha256Of(ReadFile(Pair.Main));
  const std::string DiffSha = Sha256Of(ReadFile(Pair.Diff));
  const auto InputsIntact = [&] {
    return Sha256Of(ReadFile(Pair.Main)) == MainSha && Sha256Of(ReadFile(Pair.Diff)) == DiffSha;
  };
  const std::string Out = Join(Pair.Dir, "p1-dir.diaphora");
  const auto Expect = [&](DiffArgs Args, DiffStatus Status, const std::string& Mentions, const char* Label) {
    std::error_code Error;
    fs::remove(Utf8ToPath(Args.Out), Error);
    const DiffOutcome Outcome = RunDiff(Args);
    const bool Ok = Outcome.Status == Status && Outcome.Message.find(Mentions) != std::string::npos;
    DSig::Test::Report(Ok, Label, __FILE__, __LINE__);
    if (!Ok) {
      DSig::Test::Note(std::string(Label) + ": status " + std::to_string(static_cast<int>(Outcome.Status)) + ", " +
                       Outcome.Message);
    }
    CHECK(InputsIntact());
    if (Status != DiffStatus::Ok) {
      CHECK(!Exists(Args.Out));
    }
    return Outcome;
  };
  // a missing directory (and missing parents) is created, and removed again after the results
  {
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.CheckpointDir = Join(Join(Join(Pair.Dir, "p1-new"), "a"), "b");
    Expect(A, DiffStatus::Ok, "", "missing checkpoint directory is created");
    CHECK(Exists(Out) && !Exists(A.CheckpointDir));
  }
  // a path that cannot be a directory: under a regular file, or a regular file itself -> exit 6
  const std::string File = Join(Pair.Dir, "p1-a-file.txt");
  WriteText(File, "x");
  for (const std::string& Dir : {Join(File, "ck"), File}) {
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.CheckpointDir = Dir;
    Expect(A, DiffStatus::Io, "checkpoint directory", "unusable checkpoint directory is exit 6");
    CHECK(ReadFile(File) == "x");
  }
#ifndef _WIN32
  // a directory without write permission (POSIX; root ignores the mode)
  if (::geteuid() != 0) {
    const std::string Locked = Join(Pair.Dir, "p1-readonly");
    fs::create_directories(Utf8ToPath(Locked));
    fs::permissions(Utf8ToPath(Locked), fs::perms::owner_read | fs::perms::owner_exec);
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.CheckpointDir = Locked;
    Expect(A, DiffStatus::Io, "not writable", "read-only checkpoint directory is exit 6");
    fs::permissions(Utf8ToPath(Locked), fs::perms::owner_all);
  }
#endif
  // --resume of a missing directory, an empty one, one with a foreign manifest -> exit 4
  {
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.ResumeDir = Join(Pair.Dir, "p1-no-such-ck");
    Expect(A, DiffStatus::Unsupported, "is not a directory", "--resume of a missing directory is exit 4");
    CHECK(!Exists(A.ResumeDir));
    const std::string Empty = Join(Pair.Dir, "p1-empty-ck");
    fs::create_directories(Utf8ToPath(Empty));
    A.ResumeDir = Empty;
    Expect(A, DiffStatus::Unsupported, "holds no checkpoint", "--resume of an empty directory is exit 4");
    CHECK(P1DirContents(Empty).empty());
    const std::string Foreign = Join(Pair.Dir, "p1-foreign-ck");
    fs::create_directories(Utf8ToPath(Foreign));
    WriteText(Join(Foreign, "manifest.json"), "{\"name\": \"my web app\"}\n");
    A.ResumeDir = Foreign;
    Expect(A, DiffStatus::Unsupported, "is damaged", "--resume of a foreign manifest is exit 4");
    // ... and a fresh run refuses to replace that foreign manifest.json (exit 2, untouched)
    DiffArgs F = P1Args(Pair.Main, Pair.Diff, Out);
    F.CheckpointDir = Foreign;
    Expect(F, DiffStatus::Usage, "not a dsigmatcher checkpoint", "a foreign manifest.json is refused");
    CHECK(ReadFile(Join(Foreign, "manifest.json")) == "{\"name\": \"my web app\"}\n");
    CHECK(P1DirContents(Foreign).size() == 1);
  }
  // a fresh run into a directory that holds a checkpoint is refused (exit 2), the checkpoint untouched
  if (!g_P1SelfPath.empty()) {
    const std::string Dir = Join(Pair.Dir, "p1-held-ck");
    CHECK_NUM_EQ(P1RunChild(Pair, Out, Dir, false, "committed", 3, Join(Pair.Dir, "p1-held.log")), kP1KilledCode);
    const auto Before = P1DirContents(Dir);
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.CheckpointDir = Dir;
    Expect(A, DiffStatus::Usage, "already holds a checkpoint", "a fresh run over a checkpoint is refused");
    CHECK(P1DirContents(Dir) == Before);
    // --checkpoint-dir naming the same directory as --resume is accepted, another one is refused
    DiffArgs R = P1Args(Pair.Main, Pair.Diff, Out);
    R.ResumeDir = Dir;
    R.CheckpointDir = Join(Pair.Dir, "p1-other-ck");
    Expect(R, DiffStatus::Usage, "different directories", "--checkpoint-dir and --resume must agree");
    CHECK(P1DirContents(Dir) == Before && !Exists(R.CheckpointDir));
    // --resume with --trace / --snapshot-dir / --replay is refused
    DiffArgs T = P1Args(Pair.Main, Pair.Diff, Out);
    T.ResumeDir = Dir;
    T.TracePath = Join(Pair.Dir, "p1-trace.jsonl");
    Expect(T, DiffStatus::Usage, "--trace", "--resume with --trace is refused");
    CHECK(!Exists(T.TracePath));
    DiffArgs P = P1Args(Pair.Main, Pair.Diff, Out);
    P.ResumeDir = Dir;
    P.ReplayPath = Join(Pair.Dir, "p1-none.json");
    P.ReplayStage = "final_pass";
    P.SnapshotOut = Join(Pair.Dir, "p1-after.json");
    Expect(P, DiffStatus::Usage, "--replay", "--resume with --replay is refused");
    CHECK(P1DirContents(Dir) == Before);
    R.CheckpointDir = Dir;
    Expect(R, DiffStatus::Ok, "", "--checkpoint-dir equal to --resume resumes");
  }
  // the checkpoint's own files may not be an input or an output (exit 2, nothing changed)
  {
    const std::string Dir = Join(Pair.Dir, "p1-alias-ck");
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Join(Dir, "manifest.json"));
    A.CheckpointDir = Dir;
    Expect(A, DiffStatus::Usage, "is a file of the checkpoint directory", "-o <dir>/manifest.json is refused");
    CHECK(!Exists(Dir));
    const std::string Inside = Join(Pair.Dir, "p1-alias2-ck");
    fs::create_directories(Utf8ToPath(Inside));
    const std::string Db1Copy = Join(Inside, "state-000001.json");
    CopyFileTo(Pair.Main, Db1Copy);
    DiffArgs B = P1Args(Db1Copy, Pair.Diff, Out);
    B.CheckpointDir = Inside;
    Expect(B, DiffStatus::Usage, "db1", "an input named like a state file in the directory is refused");
    CHECK(Sha256Of(ReadFile(Db1Copy)) == MainSha);
    // an -o beside the checkpoint files is fine
    DiffArgs C = P1Args(Pair.Main, Pair.Diff, Join(Inside, "beside.diaphora"));
    C.CheckpointDir = Inside;
    Expect(C, DiffStatus::Ok, "", "-o inside the checkpoint directory is fine");
    CHECK(Exists(C.Out));
  }
#ifdef DSIG_CLI_PATH
  // through the CLI: the flags, their combinations and the JSON outcome
  {
    const std::string Log = Join(Pair.Dir, "p1-cli.log");
    const std::string Dir = Join(Pair.Dir, "p1-cli-ck");
    CHECK_NUM_EQ(RunCli({"diff", Pair.Main, Pair.Diff, "-o", Out, "--checkpoint-dir", Dir, "--json", "--quiet",
                         "--allow-sqlite-mismatch"},
                        Log),
                 0);
    const std::string Json = ReadFile(Log);
    CHECK(Json.find("\"checkpoints_written\":") != std::string::npos && Json.find("\"warnings\":[]") != std::string::npos);
    CHECK(!Exists(Dir));
    CHECK_NUM_EQ(RunCli({"diff", Pair.Main, Pair.Diff, "-o", Out, "--resume", Dir, "--quiet", "--allow-sqlite-mismatch"}, Log),
                 4);
    CHECK(ReadFile(Log).find("error: --resume") != std::string::npos);
    CHECK_NUM_EQ(RunCli({"diff", Pair.Main, Pair.Diff, "--replay", "x.json", "--stage", "final_pass", "--snapshot-out",
                         "y.json", "--resume", Dir},
                        Log),
                 2);
    CHECK_NUM_EQ(RunCli({"diff", Pair.Main, Pair.Diff, "-o", Out, "--checkpoint-dir", ""}, Log), 2);
    CHECK_NUM_EQ(RunCli({"diff", "--help"}, Log), 0);
    CHECK(ReadFile(Log).find("--resume <dir>") != std::string::npos);
  }
#endif
}

// ---------------------------------------------------------------------------------------------
// 4. A full disk while checkpointing

int g_P1DiskFullAfter = 0;  // the first `g_P1DiskFullAfter` state writes succeed, later ones fail
int g_P1DiskFullSeen = 0;
std::string g_P1DiskFullStep = "state:write";
int g_P1CrashAt = 0;  // with the disk full, "crash" (throw a non-std exception) at this state write

struct P1SimulatedCrash {};

void P1DiskFullHook(std::string_view Step) {
  if (Step != g_P1DiskFullStep) {
    return;
  }
  ++g_P1DiskFullSeen;
  if (g_P1CrashAt != 0 && g_P1DiskFullSeen == g_P1CrashAt) {
    throw P1SimulatedCrash{};
  }
  if (g_P1DiskFullSeen > g_P1DiskFullAfter) {
    throw IoFailure("No space left on device (simulated)");
  }
}

void TestP1DiskFull(const FixturePair& Pair) {
  DSig::Test::Suite("P1 full disk while checkpointing");
  const P1Baseline Base = P1RunBaseline(Pair, "p1-full");
  CHECK(Base.Ok);
  if (!Base.Ok) {
    return;
  }
  const std::string Out = Join(Pair.Dir, "p1-full.diaphora");
  for (const std::string& Step : {std::string("state:write"), std::string("state:rename"), std::string("manifest:write"),
                                  std::string("manifest:rename")}) {
    // every checkpoint after the third fails: the run finishes (exit 0) with one warning per failure
    const std::string Dir = Join(Pair.Dir, "p1-full-ck");
    g_P1DiskFullStep = Step;
    g_P1DiskFullAfter = 3;
    g_P1DiskFullSeen = 0;
    g_P1CrashAt = 0;
    Detail::SetCheckpointFaultHook(&P1DiskFullHook);
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.CheckpointDir = Dir;
    DiffOutcome Outcome;
    const std::string Err = CaptureStderr(Join(Pair.Dir, "p1-full-stderr.txt"), [&] { Outcome = RunDiff(A); });
    Detail::SetCheckpointFaultHook(nullptr);
    CHECK(Outcome.Status == DiffStatus::Ok);
    CHECK_NUM_EQ(Outcome.CheckpointsWritten, 3);
    CHECK_NUM_EQ(Outcome.Warnings.size(), Base.Checkpoints - 3);
    CHECK(!Outcome.Warnings.empty() && Outcome.Warnings[0].find("No space left on device (simulated)") != std::string::npos);
    CHECK(Err.find("WARNING: no checkpoint after") != std::string::npos);  // printed although --quiet
    CHECK(P1MaskedResults(Out) == Base.Masked);
    CHECK(!Exists(Dir));
  }
  // disk full after the third checkpoint, then a crash: --resume continues after the third checkpoint
  {
    const std::string Dir = Join(Pair.Dir, "p1-full-crash-ck");
    std::error_code Error;
    fs::remove(Utf8ToPath(Out), Error);
    g_P1DiskFullStep = "state:write";
    g_P1DiskFullAfter = 3;
    g_P1DiskFullSeen = 0;
    g_P1CrashAt = 7;
    Detail::SetCheckpointFaultHook(&P1DiskFullHook);
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.CheckpointDir = Dir;
    bool Crashed = false;
    try {
      (void)CaptureStderr(Join(Pair.Dir, "p1-full-crash.txt"), [&] { (void)RunDiff(A); });
    } catch (const P1SimulatedCrash&) {
      Crashed = true;
    }
    Detail::SetCheckpointFaultHook(nullptr);
    CHECK(Crashed);
    CHECK(!Exists(Out));
    const auto Files = P1DirContents(Dir);
    CHECK(Files.size() == 2 && Files.count("manifest.json") == 1 && Files.count("state-000003.json") == 1);
    DiffArgs Resume = P1Args(Pair.Main, Pair.Diff, Out);
    Resume.ResumeDir = Dir;
    const DiffOutcome Outcome = RunDiff(Resume);
    CHECK(Outcome.Status == DiffStatus::Ok && Outcome.CheckpointsWritten == Base.Checkpoints - 3);
    CHECK(P1MaskedResults(Out) == Base.Masked);
  }
}

// ---------------------------------------------------------------------------------------------
// 5. Corrupt and truncated inputs, a locked input

void TestP1BrokenInputs(const FixturePair& Pair) {
  DSig::Test::Suite("P1 corrupt, truncated and locked inputs");
  const std::string Good = ReadFile(Pair.Main);
  CHECK(Good.size() > 8192);
  struct Case {
    const char* Label;
    std::string Bytes;
  };
  std::string Header = Good;
  std::fill(Header.begin(), Header.begin() + 100, '\0');
  std::string Pages = Good;
  for (size_t At = 4096; At < Pages.size() && At < 4096 * 6; ++At) {
    Pages[At] = static_cast<char>(0xA5 ^ (At & 0xFF));  // b-tree pages 2..6 overwritten
  }
  std::string Garbage(Good.size(), '\0');
  for (size_t At = 0; At < Garbage.size(); ++At) {
    Garbage[At] = static_cast<char>((At * 131u + 7u) & 0xFF);
  }
  const std::vector<Case> Cases = {{"truncated to half", Good.substr(0, Good.size() / 2)},
                                   {"truncated inside the first page", Good.substr(0, 1000)},
                                   {"header zeroed", Header},
                                   {"b-tree pages overwritten", Pages},
                                   {"not a database at all", Garbage}};
  const std::string Out = Join(Pair.Dir, "p1-broken.diaphora");
  for (const bool Checkpointed : {false, true}) {
    for (const Case& C : Cases) {
      const std::string Db1 = Join(Pair.Dir, "p1-broken.sqlite");
      std::error_code Error;
      for (const char* Suffix : {"", "-wal", "-shm", "-journal"}) {
        fs::remove(Utf8ToPath(Db1 + Suffix), Error);
      }
      fs::remove(Utf8ToPath(Out), Error);
      WriteText(Db1, C.Bytes);
      DiffArgs A = P1Args(Db1, Pair.Diff, Out);
      const std::string Dir = Join(Pair.Dir, "p1-broken-ck");
      if (Checkpointed) {
        A.CheckpointDir = Dir;
      }
      const auto Start = std::chrono::steady_clock::now();
      const DiffOutcome Outcome = RunDiff(A);
      const double Seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - Start).count();
      // a damaged database file is an environment failure (exit 6), found before or during the diff
      const bool Ok = Outcome.Status == DiffStatus::Io && !Outcome.OutputWritten && !Exists(Out) && Seconds < 60.0;
      DSig::Test::Report(Ok, (std::string("broken db1: ") + C.Label + (Checkpointed ? " (checkpointed)" : "")).c_str(),
                         __FILE__, __LINE__);
      if (!Ok) {
        DSig::Test::Note(std::string(C.Label) + ": status " + std::to_string(static_cast<int>(Outcome.Status)) + ", " +
                         Outcome.Message);
      }
      CHECK(ReadFile(Db1) == C.Bytes);                  // never modified
      CHECK(!Exists(Db1 + "-wal") && !Exists(Db1 + "-shm") && !Exists(Db1 + "-journal"));
      CHECK(!Exists(Join(Dir, "manifest.json")));  // no checkpoint of a failed run's first stage
      fs::remove_all(Utf8ToPath(Dir), Error);
    }
  }
  // an input changed after its checkpoint: --resume refuses it (exit 4) and names the difference
  if (!g_P1SelfPath.empty()) {
    const std::string Db1 = Join(Pair.Dir, "p1-changing.sqlite");
    WriteText(Db1, Good);
    FixturePair Copy = Pair;
    Copy.Main = Db1;
    const std::string Dir = Join(Pair.Dir, "p1-changing-ck");
    CHECK_NUM_EQ(P1RunChild(Copy, Out, Dir, false, "committed", 2, Join(Pair.Dir, "p1-changing.log")), kP1KilledCode);
    std::string Changed = Good;
    Changed[Changed.size() - 1] = static_cast<char>(Changed[Changed.size() - 1] ^ 1);
    WriteText(Db1, Changed);
    DiffArgs A = P1Args(Db1, Pair.Diff, Out);
    A.ResumeDir = Dir;
    const auto Before = P1DirContents(Dir);
    const DiffOutcome Outcome = RunDiff(A);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Unsupported));
    CHECK(Outcome.Message.find("db1 sha256") != std::string::npos);
    CHECK(!Exists(Out) && P1DirContents(Dir) == Before && ReadFile(Db1) == Changed);
    // another option is refused the same way
    WriteText(Db1, Good);
    A.Config.IgnoreSmallFunctions = true;
    const DiffOutcome Option = RunDiff(A);
    CHECK(Option.Status == DiffStatus::Unsupported && Option.Message.find("--ignore-small-functions") != std::string::npos);
    A.Config.IgnoreSmallFunctions = false;
    CHECK(RunDiff(A).Status == DiffStatus::Ok);  // the original inputs resume
  }

  // SQLITE_BUSY: another connection holds db1 locked while it writes (a WAL database in EXCLUSIVE
  // locking mode with committed frames, or a rollback-journal database in the middle of a write
  // transaction, so the input has a non-empty -wal / -journal and is opened normally, not immutable).
  // The diff fails at once with exit 6 and never waits for the lock; once the lock is released the same
  // input diffs normally.
  for (const bool WalMode : {true, false}) {
    const std::string Db1 = Join(Pair.Dir, WalMode ? "p1-locked-wal.sqlite" : "p1-locked-journal.sqlite");
    std::error_code Error;
    for (const char* Suffix : {"", "-wal", "-shm", "-journal"}) {
      fs::remove(Utf8ToPath(Db1 + Suffix), Error);
    }
    CopyFileTo(Pair.Main, Db1);
    sqlite3* Holder = nullptr;
    CHECK(sqlite3_open_v2(Db1.c_str(), &Holder, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    const char* Change = "update functions set comment = coalesce(comment, '') || 'x' "
                         "where id = (select min(id) from functions);";
    const std::string Sql =
        WalMode ? std::string("pragma journal_mode=wal; pragma wal_autocheckpoint=0; pragma locking_mode=exclusive; "
                              "begin immediate; ") + Change + " commit;"
                : std::string("pragma journal_mode=delete; begin exclusive; ") + Change;
    char* Message = nullptr;
    const int Locked = sqlite3_exec(Holder, Sql.c_str(), nullptr, nullptr, &Message);
    sqlite3_free(Message);
    CHECK(Locked == SQLITE_OK);
    CHECK(Exists(Db1 + (WalMode ? "-wal" : "-journal")));
    const std::string LockedSha = Sha256Of(ReadFile(Db1));
    for (const bool Checkpointed : {false, true}) {
      DiffArgs A = P1Args(Db1, Pair.Diff, Out);
      if (Checkpointed) {
        A.CheckpointDir = Join(Pair.Dir, "p1-locked-ck");
      }
      fs::remove(Utf8ToPath(Out), Error);
      const auto Start = std::chrono::steady_clock::now();
      const DiffOutcome Outcome = RunDiff(A);
      const double Seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - Start).count();
      const bool Ok = Outcome.Status == DiffStatus::Io && Seconds < 30.0 &&
                      Outcome.Message.find("database is locked") != std::string::npos;
      const std::string Label = std::string("locked db1 (") + (WalMode ? "WAL, exclusive" : "journal, writing") +
                                (Checkpointed ? ", checkpointed" : "") + ") is exit 6 at once";
      DSig::Test::Report(Ok, Label.c_str(), __FILE__, __LINE__);
      if (!Ok) {
        DSig::Test::Note(Label + ": status " + std::to_string(static_cast<int>(Outcome.Status)) + " after " +
                         std::to_string(Seconds) + " s: " + Outcome.Message);
      }
      CHECK(!Exists(Out));
      CHECK(Sha256Of(ReadFile(Db1)) == LockedSha);
      CHECK(!Exists(Join(Pair.Dir, "p1-locked-ck")) || !Exists(Join(Join(Pair.Dir, "p1-locked-ck"), "manifest.json")));
    }
    sqlite3_close(Holder);  // commits nothing more (WAL) / rolls the open transaction back (journal)
    DiffArgs A = P1Args(Db1, Pair.Diff, Out);
    CHECK(RunDiff(A).Status == DiffStatus::Ok);  // released: the same input diffs normally
  }
}

// ---------------------------------------------------------------------------------------------
// 6. A damaged checkpoint on resume

void TestP1DamagedCheckpoint(const FixturePair& Pair) {
  DSig::Test::Suite("P1 damaged checkpoint on resume");
  if (g_P1SelfPath.empty()) {
    DSig::Test::Skip("P1 damaged checkpoint", "the test executable's path is unknown");
    return;
  }
  const std::string Out = Join(Pair.Dir, "p1-damaged.diaphora");
  const std::string Pristine = Join(Pair.Dir, "p1-damaged-pristine");
  CHECK_NUM_EQ(P1RunChild(Pair, Out, Pristine, false, "committed", 6, Join(Pair.Dir, "p1-damaged.log")), kP1KilledCode);
  const std::string ManifestText = ReadFile(Join(Pristine, "manifest.json"));
  const CheckpointManifest Manifest = ParseCheckpointManifest(ManifestText);
  const std::string StateText = ReadFile(Join(Pristine, Manifest.StateFile));
  CHECK(!StateText.empty());
  CHECK(Manifest.StateSha256.size() == 64 && Manifest.StateSha256 == Sha256Of(StateText));
  CHECK_NUM_EQ(Manifest.StateBytes, StateText.size());
  CHECK(ManifestText.size() < 4096);  // the manifest stays small
  // Rewrites the manifest so that it vouches for `State` (size and sha256), so the damage is found by the
  // parser or the binding checks rather than by the checksum.
  const auto Vouch = [&](const std::string& Dir, const std::string& State) {
    CheckpointManifest M = Manifest;
    M.StateBytes = static_cast<int64_t>(State.size());
    M.StateSha256 = Sha256Of(State);
    WriteText(Join(Dir, Manifest.StateFile), State);
    WriteText(Join(Dir, "manifest.json"), SerializeCheckpointManifest(M));
  };
  EngineCheckpoint Parsed = ParseCheckpointState(StateText);
  struct Damage {
    const char* Label;
    std::function<void(const std::string&)> Apply;
    const char* Mentions;
  };
  const std::vector<Damage> Damages = {
      {"state truncated", [&](const std::string& Dir) { WriteText(Join(Dir, Manifest.StateFile), StateText.substr(0, StateText.size() / 3)); }, "bytes"},
      {"state byte flipped", [&](const std::string& Dir) {
         std::string S = StateText;
         S[S.size() / 2] = static_cast<char>(S[S.size() / 2] ^ 0x20);
         WriteText(Join(Dir, Manifest.StateFile), S);
       }, "sha256"},
      {"state missing", [&](const std::string& Dir) { fs::remove(Utf8ToPath(Join(Dir, Manifest.StateFile))); }, "missing"},
      {"state empty", [&](const std::string& Dir) { Vouch(Dir, ""); }, "is damaged"},
      {"state truncated, manifest agreeing", [&](const std::string& Dir) { Vouch(Dir, StateText.substr(0, StateText.size() - 40)); }, "is damaged"},
      {"state of another schema", [&](const std::string& Dir) {
         std::string S = StateText;
         const size_t At = S.find("checkpoint-state/1");
         S.replace(At, 18, "checkpoint-state/7");
         Vouch(Dir, S);
       }, "schema"},
      {"state with a foreign address", [&](const std::string& Dir) {
         EngineCheckpoint E = Parsed;
         SnapItem Stranger;
         Stranger.Ea1 = "987654321987";
         Stranger.Ea2 = "987654321988";
         Stranger.Desc = "x";
         E.State.Partial.push_back(Stranger);
         Vouch(Dir, SerializeCheckpointState(E));
       }, "987654321987"},
      {"state with a cursor diff() never reaches", [&](const std::string& Dir) {
         EngineCheckpoint E = Parsed;
         E.Cursor.Done = PipelineStep::RemainingFunctions;  // without skip_others
         E.Cursor.SkipOthers = false;
         CheckpointManifest M = Manifest;
         M.Cursor = E.Cursor;
         const std::string S = SerializeCheckpointState(E);
         M.StateBytes = static_cast<int64_t>(S.size());
         M.StateSha256 = Sha256Of(S);
         WriteText(Join(Dir, Manifest.StateFile), S);
         WriteText(Join(Dir, "manifest.json"), SerializeCheckpointManifest(M));
       }, "never reaches"},
      {"state of another step than the manifest", [&](const std::string& Dir) {
         EngineCheckpoint E = Parsed;
         E.Cursor.Done = E.Cursor.Done == PipelineStep::FinalPass ? PipelineStep::SameName : PipelineStep::FinalPass;
         Vouch(Dir, SerializeCheckpointState(E));
       }, "does not belong to its manifest"},
      {"manifest truncated", [&](const std::string& Dir) { WriteText(Join(Dir, "manifest.json"), ManifestText.substr(0, 30)); }, "manifest.json"},
      {"manifest missing", [&](const std::string& Dir) { fs::remove(Utf8ToPath(Join(Dir, "manifest.json"))); }, "holds no checkpoint"},
      {"manifest names a path", [&](const std::string& Dir) {
         CheckpointManifest M = Manifest;
         M.StateFile = "../elsewhere.json";
         WriteText(Join(Dir, "manifest.json"), SerializeCheckpointManifest(M));
       }, "names the state file"},
      {"another tool version", [&](const std::string& Dir) {
         EngineCheckpoint E = Parsed;
         E.Binding.ToolVersion = "0.0.1";
         CheckpointManifest M = Manifest;
         M.Binding.ToolVersion = "0.0.1";
         const std::string S = SerializeCheckpointState(E);
         M.StateBytes = static_cast<int64_t>(S.size());
         M.StateSha256 = Sha256Of(S);
         WriteText(Join(Dir, Manifest.StateFile), S);
         WriteText(Join(Dir, "manifest.json"), SerializeCheckpointManifest(M));
       }, "tool version"},
  };
  const std::string MainSha = Sha256Of(ReadFile(Pair.Main));
  for (const Damage& D : Damages) {
    const std::string Dir = Join(Pair.Dir, "p1-damaged-copy");
    P1CopyDir(Pristine, Dir);
    D.Apply(Dir);
    const auto Before = P1DirContents(Dir);
    std::error_code Error;
    fs::remove(Utf8ToPath(Out), Error);
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.ResumeDir = Dir;
    const DiffOutcome Outcome = RunDiff(A);
    const bool Ok = Outcome.Status == DiffStatus::Unsupported && Outcome.Message.find(D.Mentions) != std::string::npos;
    DSig::Test::Report(Ok, (std::string("damaged checkpoint: ") + D.Label).c_str(), __FILE__, __LINE__);
    if (!Ok) {
      DSig::Test::Note(std::string(D.Label) + ": status " + std::to_string(static_cast<int>(Outcome.Status)) + ", " +
                       Outcome.Message);
    }
    CHECK(!Exists(Out));
    CHECK(P1DirContents(Dir) == Before);  // a refused checkpoint is left as it was
    CHECK(Sha256Of(ReadFile(Pair.Main)) == MainSha);
  }
  // the pristine copy still resumes
  DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
  A.ResumeDir = Pristine;
  CHECK(RunDiff(A).Status == DiffStatus::Ok);
}

// ---------------------------------------------------------------------------------------------
// 7. Unexpected exceptions: DiffStatus::Internal (exit 70)

void P1LogicErrorHook(std::string_view Step) {
  if (Step == "state:write") {
    throw std::logic_error("simulated bug");
  }
}

void P1WriterLogicErrorHook(std::string_view Step) {
  if (Step == "results") {
    throw std::logic_error("simulated writer bug");
  }
}

void TestP1InternalErrors(const FixturePair& Pair) {
  DSig::Test::Suite("P1 unexpected exceptions are DiffStatus::Internal (exit 70)");
  CHECK_NUM_EQ(static_cast<int>(DiffStatus::Internal), 70);
  const std::string Out = Join(Pair.Dir, "p1-internal.diaphora");
  WriteText(Out, "previous results\n");  // an earlier file at -o is never replaced by a failed run
  {
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    A.CheckpointDir = Join(Pair.Dir, "p1-internal-ck");
    Detail::SetCheckpointFaultHook(&P1LogicErrorHook);
    const DiffOutcome Outcome = RunDiff(A);
    Detail::SetCheckpointFaultHook(nullptr);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), 70);
    CHECK(Outcome.Message.find("internal error: simulated bug") == 0);
    CHECK(ReadFile(Out) == "previous results\n");
  }
  {
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, Out);
    Detail::SetWriterFaultHook(&P1WriterLogicErrorHook);
    const DiffOutcome Outcome = RunDiff(A);
    Detail::SetWriterFaultHook(nullptr);
    CHECK_NUM_EQ(static_cast<int>(Outcome.Status), 70);
    CHECK(ReadFile(Out) == "previous results\n");
    std::error_code Error;
    size_t Stray = 0;
    for (const fs::directory_entry& Entry : fs::directory_iterator(Utf8ToPath(Pair.Dir), Error)) {
      Stray += PathToUtf8(Entry.path().filename()).find("p1-internal.diaphora.tmp") == 0 ? 1 : 0;
    }
    CHECK_NUM_EQ(Stray, 0);  // the writer's temporary file is removed
  }
}

// ---------------------------------------------------------------------------------------------
// 8. Audit gaps of the last verification: F01 and F58

void TestP1AuditGaps(const FixturePair& Pair) {
  DSig::Test::Suite("P1 audit gaps: F01 --snapshot-out, F58 UTF-8 fetch errors");
  // F01: --snapshot-out equal to --replay, and --snapshot-out inside an oracle capture (run.json)
  {
    const std::string Capture = Join(Pair.Dir, "p1-f01-capture");
    DiffArgs Snap = P1Args(Pair.Main, Pair.Diff, Join(Pair.Dir, "p1-f01.diaphora"));
    Snap.SnapshotDir = Capture;
    Snap.SnapshotPoints = "before:final_pass";
    CHECK(RunDiff(Snap).Status == DiffStatus::Ok);
    const std::string Before = CaptureSnapshotFile(Capture, "before:final_pass");
    CHECK(!Before.empty());
    const std::string Replay = Join(Pair.Dir, "p1-f01-before.json");
    CopyFileTo(Before, Replay);
    const std::string ReplayBytes = ReadFile(Replay);
    DiffArgs A = P1Args(Pair.Main, Pair.Diff, "");
    A.ReplayPath = Replay;
    A.ReplayStage = "final_pass";
    A.SnapshotOut = Replay;
    const DiffOutcome Same = RunDiff(A);
    CHECK_NUM_EQ(static_cast<int>(Same.Status), static_cast<int>(DiffStatus::Usage));
    CHECK(Same.Message.find("--replay snapshot") != std::string::npos);
    CHECK(ReadFile(Replay) == ReplayBytes && !Exists(Replay + ".tmp"));
    // the same file under another spelling (a relative/../ path) is still the same file
    A.SnapshotOut = Join(Join(Pair.Dir, "p1-f01-capture"), Join("..", "p1-f01-before.json"));
    CHECK_NUM_EQ(static_cast<int>(RunDiff(A).Status), static_cast<int>(DiffStatus::Usage));
    CHECK(ReadFile(Replay) == ReplayBytes);
    // an oracle capture: a directory holding run.json, or a directory inside one
    const std::string Oracle = Join(Pair.Dir, "p1-f01-oracle");
    fs::create_directories(Utf8ToPath(Join(Oracle, "snapshots")));
    WriteText(Join(Oracle, "run.json"), "{\"pair\": \"x\"}\n");
    for (const std::string& Target : {Join(Oracle, "after.json"), Join(Join(Oracle, "snapshots"), "after.json")}) {
      A.SnapshotOut = Target;
      const DiffOutcome Outcome = RunDiff(A);
      CHECK_NUM_EQ(static_cast<int>(Outcome.Status), static_cast<int>(DiffStatus::Usage));
      CHECK(Outcome.Message.find("oracle capture") != std::string::npos);
      CHECK(!Exists(Target) && !Exists(Target + ".tmp"));
    }
    CHECK(ReadFile(Join(Oracle, "run.json")) == "{\"pair\": \"x\"}\n");
    // ... and the checkpoint directory may not be one either
    DiffArgs K = P1Args(Pair.Main, Pair.Diff, Join(Pair.Dir, "p1-f01-k.diaphora"));
    K.CheckpointDir = Join(Oracle, "ck");
    CHECK_NUM_EQ(static_cast<int>(RunDiff(K).Status), static_cast<int>(DiffStatus::Usage));
    CHECK(!Exists(K.CheckpointDir) && !Exists(K.Out));
  }
  // F58: the UTF-8 decode errors at fetch name the row (ea / ea2, or the function's address)
  {
    FixturePair Bad = BuildFoundationFixture("p1-f58", "update functions set clean_pseudo = cast(X'C328' as text) "
                                                       "where id = 3;\nupdate functions set comment = cast(X'FF' as text) "
                                                       "where id = 2;\n");
    CHECK(Bad.Ok);
    if (Bad.Ok) {
      DiffSession S;
      S.Open(Bad.Main, Bad.Diff);
      std::string Message;
      try {
        std::vector<BindValue> Binds = {BindValue::Str("x"), BindValue::Str("6144"), BindValue::Str("14336")};
        const std::string Sql(kSqlRemainingPair);
        SqlRowSource Rows(S, Sql, Binds);
        HeuristicRow Row;
        (void)Rows.Next(Row);
      } catch (const DiaphoraWouldRaise& Error) {
        Message = Error.Detail;
      }
      CHECK(Message.find("Could not decode to UTF-8") == 0);
      CHECK(Message.find("of the row ea ") != std::string::npos && Message.find(", ea2 ") != std::string::npos);
      const std::string Gamma(S.Ids().AddrText(S.Main().Functions.AddrIdOf[2]));
      CHECK(!Gamma.empty() && Message.find("ea " + Gamma) != std::string::npos);
      Message.clear();
      try {
        const BindValue Beta = BindValue::Str("beta");
        (void)FetchFunctionRows(S, kSqlFunctionRowMain, std::span<const BindValue>(&Beta, 1), Side::Main, 1);
      } catch (const DiaphoraWouldRaise& Error) {
        Message = Error.Detail;
      }
      const std::string BetaAddr(S.Ids().AddrText(S.Main().Functions.AddrIdOf[1]));
      CHECK(Message.find("Could not decode to UTF-8") == 0);
      CHECK(!BetaAddr.empty() && Message.find("of the function at address " + BetaAddr) != std::string::npos);
      DSig::Test::RemoveScratchDir(Bad.Dir);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// 9. JsonValue::AsDouble == Python float() (no floating-point from_chars)

void TestP1JsonDoubles() {
  DSig::Test::Suite("P1 JsonValue::AsDouble without floating-point from_chars");
  const auto Same = [](double A, double B) { return RatioBits(A) == RatioBits(B); };
  const auto Parse = [](const std::string& Text) { return JsonParse(Text).AsDouble(); };
  // shortest round-trip texts (repr) of random doubles come back bit for bit
  std::mt19937_64 Rng(0x50310u);
  size_t Mismatch = 0;
  for (int I = 0; I < 200000; ++I) {
    uint64_t Bits = Rng();
    double Value = RatioFromBits(Bits);
    if (!std::isfinite(Value)) {
      Value = RatioFromBits(Bits & ~(uint64_t{1} << 62));
    }
    const std::string Text = PyReprFloat(Value);
    if (!Same(Parse(Text), Value)) {
      ++Mismatch;
    }
  }
  std::uniform_real_distribution<double> Unit(0.0, 1.0);
  for (int I = 0; I < 100000; ++I) {
    const double Value = Unit(Rng);
    if (!Same(Parse(PyReprFloat(Value)), Value)) {
      ++Mismatch;
    }
  }
  CHECK_NUM_EQ(Mismatch, 0);
  // Python float() on literals no shortest repr produces
  const std::vector<std::pair<std::string, double>> Cases = {
      {"0.1", 0.1},
      {"-0", -0.0},
      {"1e400", std::numeric_limits<double>::infinity()},
      {"-1e400", -std::numeric_limits<double>::infinity()},
      {"1e-400", 0.0},
      {"-1e-400", -0.0},
      {"4.9406564584124654e-324", std::numeric_limits<double>::denorm_min()},
      {"2.4703282292062328e-324", std::numeric_limits<double>::denorm_min()},  // just above the halfway point
      {"2.4703282292062327e-324", 0.0},                                        // just below it
      {"1.7976931348623157e308", std::numeric_limits<double>::max()},
      {"1.7976931348623159e308", std::numeric_limits<double>::infinity()},
      {"2.2250738585072011e-308", RatioFromBits(0x000fffffffffffffull)},
      {"9007199254740993", 9007199254740992.0},  // a tie, to even
      {"0.30000000000000004", 0.30000000000000004},
      {"123456789012345678901234567890e-10", 12345678901234567890.1234567890},
      {"1" + std::string(400, '0') + "e-400", 1.0},
  };
  for (const auto& [Text, Want] : Cases) {
    const double Got = Parse(Text);
    DSig::Test::Report(Same(Got, Want), ("AsDouble(" + Text.substr(0, 40) + ")").c_str(), __FILE__, __LINE__);
    const std::optional<double> Py = PyFloat(Text);
    CHECK(Py && Same(*Py, Got));
  }
  // NaN / Infinity literals (Python-compatible parsing), and texts that are not JSON numbers
  JsonParseOptions Compat;
  Compat.PythonCompat = true;
  CHECK(std::isnan(JsonParse("NaN", Compat).AsDouble()));
  CHECK(JsonParse("-Infinity", Compat).AsDouble() == -std::numeric_limits<double>::infinity());
  for (const char* Text : {"1_0", " 1", "inf", "1.", ".5", "+1", "0x10", "1e", "--1", "01"}) {
    CHECK(!IsJsonNumberText(Text));
    bool Threw = false;
    try {
      (void)JsonValue::Number(Text).AsDouble();
    } catch (const JsonError&) {
      Threw = true;
    }
    CHECK(Threw);
  }
  for (const char* Text : {"0", "-0.0", "1e5", "1E+5", "12.5e-3", "-7"}) {
    CHECK(IsJsonNumberText(Text));
  }
}

// ---------------------------------------------------------------------------------------------
// Entry

void TestP1Resilience() {
  FixturePair Pair = BuildFoundationFixture("p1-resilience");
  CHECK(Pair.Ok);
  if (!Pair.Ok) {
    return;
  }
  TestP1CheckpointFormats();
  TestP1KillAndResume(Pair);
  TestP1CheckpointDirProblems(Pair);
  TestP1DiskFull(Pair);
  TestP1BrokenInputs(Pair);
  TestP1DamagedCheckpoint(Pair);
  TestP1InternalErrors(Pair);
  TestP1AuditGaps(Pair);
  TestP1JsonDoubles();
  TestP1CorpusKillAndResume();
  DSig::Test::RemoveScratchDir(Pair.Dir);
}
