#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "dsigmatcher/Heuristics.h"
#include "dsigmatcher/MatchStore.h"
#include "dsigmatcher/Synth.h"
#include "dsigmatcher/Types.h"

namespace {

using namespace DSig;
using Clock = std::chrono::steady_clock;

double MillisecondsSince(const Clock::time_point& Start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - Start).count();
}

std::vector<unsigned> ParseThreadList(const std::string& Text) {
  std::vector<unsigned> Values;
  size_t Position = 0;

  while (Position <= Text.size()) {
    const size_t Comma = Text.find(',', Position);
    const std::string Token = Text.substr(Position, Comma == std::string::npos
                                                         ? std::string::npos
                                                         : Comma - Position);
    const long Parsed = std::strtol(Token.c_str(), nullptr, 10);
    if (Parsed > 0) {
      Values.push_back(static_cast<unsigned>(Parsed));
    }
    if (Comma == std::string::npos) {
      break;
    }
    Position = Comma + 1;
  }

  if (Values.empty()) {
    Values.push_back(1);
  }
  std::sort(Values.begin(), Values.end());
  Values.erase(std::unique(Values.begin(), Values.end()), Values.end());
  return Values;
}

struct AccuracyReport {
  size_t Resolved = 0;
  size_t TruePositives = 0;
  size_t FalsePositives = 0;
  double Precision = 0.0;
  double Recall = 0.0;
};

AccuracyReport Score(const SynthPair& Pair, const std::vector<Match>& Matches) {
  AccuracyReport Report;
  Report.Resolved = Matches.size();

  for (const Match& Item : Matches) {
    if (Pair.ReferenceToTarget[Item.Index1] == Item.Index2) {
      ++Report.TruePositives;
    } else {
      ++Report.FalsePositives;
    }
  }

  if (!Matches.empty()) {
    Report.Precision = static_cast<double>(Report.TruePositives) / static_cast<double>(Matches.size());
  }
  if (Pair.PairedCount() > 0) {
    Report.Recall =
        static_cast<double>(Report.TruePositives) / static_cast<double>(Pair.PairedCount());
  }
  return Report;
}

}

int main(int Argc, char** Argv) {
  size_t FunctionCount = 20000;
  uint64_t Seed = 0x9E3779B97F4A7C15ull;
  int Repetitions = 3;
  std::string ThreadListText = "1,2,4,8,16";

  for (int Index = 1; Index < Argc; ++Index) {
    const std::string Argument = Argv[Index];
    const bool HasValue = Index + 1 < Argc;

    if ((Argument == "-n" || Argument == "--functions") && HasValue) {
      FunctionCount = static_cast<size_t>(std::strtoul(Argv[++Index], nullptr, 10));
    } else if ((Argument == "-s" || Argument == "--seed") && HasValue) {
      Seed = std::strtoull(Argv[++Index], nullptr, 10);
    } else if ((Argument == "-r" || Argument == "--repeats") && HasValue) {
      Repetitions = std::atoi(Argv[++Index]);
    } else if ((Argument == "-t" || Argument == "--threads") && HasValue) {
      ThreadListText = Argv[++Index];
    } else {
      std::printf("usage: dsigmatcher_bench [-n functions] [-s seed] [-r repeats] [-t threadlist]\n");
      return 1;
    }
  }

  if (FunctionCount == 0 || Repetitions < 1) {
    std::printf("error: function count and repeat count must be positive\n");
    return 1;
  }

  const unsigned HardwareThreads = std::thread::hardware_concurrency();

  SynthOptions Options;
  Options.FunctionCount = FunctionCount;
  Options.Seed = Seed;

  const auto GenerationStart = Clock::now();
  const SynthPair Pair = MakeSyntheticPair(Options);
  const double GenerationMs = MillisecondsSince(GenerationStart);

  std::printf("dsigmatcher benchmark\n");
  std::printf("  hardware threads : %u\n", HardwareThreads);
  std::printf("  functions        : %zu per side (seed %llu)\n", Pair.Reference.Count(),
              static_cast<unsigned long long>(Seed));
  std::printf("  ground truth     : %zu paired, %zu + %zu orphans\n", Pair.PairedCount(),
              Pair.OrphanReferenceCount, Pair.OrphanTargetCount);
  std::printf("  generation       : %.1f ms\n", GenerationMs);
  std::printf("  reference pool   : %.2f MiB of interned text\n",
              static_cast<double>(Pair.Reference.Pool.Bytes()) / (1024.0 * 1024.0));
  std::printf("  target pool      : %.2f MiB of interned text\n",
              static_cast<double>(Pair.Target.Pool.Bytes()) / (1024.0 * 1024.0));
  std::printf("  repeats          : %d (best of)\n\n", Repetitions);

  DiffOptions Base;
  Base.SameProcessor = true;

  std::printf("%-30s %12s %12s\n", "heuristic (serial)", "ms", "raw matches");
  std::printf("%-30s %12s %12s\n", "------------------------------", "------------", "------------");

  double SerialSum = 0.0;
  std::vector<double> PerHeuristic(HeuristicCount(), 0.0);
  std::vector<std::vector<Match>> PerHeuristicMatches(HeuristicCount());

  for (size_t Slot = 0; Slot < HeuristicCount(); ++Slot) {
    Base.ThreadCount = 1;
    double Best = 1e18;

    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      PerHeuristicMatches[Slot].clear();
      const auto Start = Clock::now();
      RunHeuristic(Slot, Pair.Reference, Pair.Target, Base, PerHeuristicMatches[Slot]);
      const double Elapsed = MillisecondsSince(Start);
      Best = std::min(Best, Elapsed);
    }

    PerHeuristic[Slot] = Best;
    SerialSum += Best;
    std::printf("%-30s %12.2f %12zu\n", HeuristicName(Slot), Best,
                PerHeuristicMatches[Slot].size());
  }

  std::printf("%-30s %12.2f\n", "sum of heuristics", SerialSum);

  MatchStore Store;
  for (const std::vector<Match>& Matches : PerHeuristicMatches) {
    Store.AddAll(Matches);
  }
  double ResolveBest = 1e18;
  std::vector<Match> ResolvedSerial;
  for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
    const auto Start = Clock::now();
    ResolvedSerial = Store.Resolve();
    ResolveBest = std::min(ResolveBest, MillisecondsSince(Start));
  }
  std::printf("%-30s %12.2f %12zu\n", "resolve (serial, unavoidable)", ResolveBest,
              ResolvedSerial.size());
  std::printf("\n");

  const AccuracyReport SerialAccuracy = Score(Pair, ResolvedSerial);
  std::printf("serial accuracy: %zu resolved, %zu correct, %zu wrong, precision %.4f, recall %.4f\n\n",
              SerialAccuracy.Resolved, SerialAccuracy.TruePositives, SerialAccuracy.FalsePositives,
              SerialAccuracy.Precision, SerialAccuracy.Recall);

  std::printf("%-10s %12s %12s %12s %12s\n", "threads", "wall ms", "speedup", "efficiency",
              "resolved");
  std::printf("%-10s %12s %12s %12s %12s\n", "----------", "------------", "------------",
              "------------", "------------");

  const std::vector<unsigned> ThreadCounts = ParseThreadList(ThreadListText);
  double SerialWall = 0.0;

  for (const unsigned Threads : ThreadCounts) {
    Base.ThreadCount = Threads;
    double Best = 1e18;
    DiffResult BestResult;

    for (int Attempt = 0; Attempt < Repetitions; ++Attempt) {
      const auto Start = Clock::now();
      DiffResult Result = RunExactHeuristics(Pair.Reference, Pair.Target, Base);
      const double Elapsed = MillisecondsSince(Start);
      if (Elapsed < Best) {
        Best = Elapsed;
        BestResult = std::move(Result);
      }
    }

    if (Threads == 1) {
      SerialWall = Best;
    }

    const double Baseline = SerialWall > 0.0 ? SerialWall : Best;
    const double Speedup = Baseline / Best;
    const double Efficiency = Speedup / static_cast<double>(Threads);

    std::printf("%-10u %12.2f %12.2fx %11.1f%% %12zu\n", Threads, Best, Speedup,
                Efficiency * 100.0, BestResult.Resolved.size());

    const bool SameCount = BestResult.Resolved.size() == SerialAccuracy.Resolved;
    if (!SameCount) {
      std::printf("  WARNING: resolved count differs from the serial run (%zu vs %zu)\n",
                  BestResult.Resolved.size(), SerialAccuracy.Resolved);
    }
  }

  std::printf("\n");
  std::printf("notes:\n");
  std::printf("  resolve is single threaded by construction; it sets the floor on total wall time.\n");
  std::printf("  sum of heuristics %.2f ms vs serial wall %.2f ms shows scheduler overhead.\n",
              SerialSum, SerialWall);

  return 0;
}
