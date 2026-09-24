// diff_state: MatchState, the row consumers, final_pass and find_unmatched (01 §8-§10.3; 02 §6-§16;
// 06 §12-§15).
//
//   * unit tests: every documented probe (02 Appendix A probes 1, 6 and 10; 01 E2; the 01 §9.4 KeyError
//     analysis), Python int() of address texts, the trace events, snapshot round trips;
//   * vector tests: tests/diff/vectors/state/*.json, produced by tools/parity/gen_state_vectors.py from
//     the REAL Diaphora on synthetic data (every op's outcome, state, chooser and trace event);
//   * corpus replays (skip without DSIG_CORPUS_ROOT): for every oracle capture under
//     <corpus>/oracle/traces/<pair>/, every before:cleanup:<site>:<n> -> Cleanup -> after:cleanup:<site>:<n>,
//     before:final_pass -> final pass -> after:final_pass (chooser dumps included) and after:final_pass ->
//     find_unmatched -> after:find_unmatched, compared at S-L2. Oracle files are only read:
//     snapshots through the shared-delete reader, exports through immutable=1 connections.

#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../../src/diff/FileIo.h"
#include "../../src/diff/StateDetail.h"
#include "diff/CorpusPaths.h"
#include "diff/ResultsCompare.h"
#include "diff/TestHarness.h"
#include "dsigmatcher/diff/Config.h"
#include "dsigmatcher/diff/Consumer.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Json.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Snapshot.h"
#include "dsigmatcher/diff/StageSql.h"
#include "dsigmatcher/diff/Stages.h"
#include "dsigmatcher/diff/Trace.h"

namespace fs = std::filesystem;
using namespace DSig::Diff;

namespace {

// ---------------------------------------------------------------------------------------------
// Helpers

using OptText = std::optional<std::string>;

NameId Nm(DiffSession& S, const OptText& Text) { return Text ? S.Ids().Name(*Text) : kNoneName; }

Item MakeItem(DiffSession& S, std::string_view Ea1, const OptText& N1, std::string_view Ea2, const OptText& N2,
              std::string_view Desc, double Ratio, int64_t Nodes1 = 3, int64_t Nodes2 = 3) {
  return Item{S.Ids().Addr(Ea1), Nm(S, N1), S.Ids().Addr(Ea2), Nm(S, N2), S.Ids().Desc(Desc), Ratio, Nodes1, Nodes2};
}

HeuristicRow MakeRow(DiffSession& S, std::string_view Ea1, const OptText& N1, std::string_view Ea2, const OptText& N2,
                     std::string_view Desc, std::optional<int64_t> Nodes1 = 3, std::optional<int64_t> Nodes2 = 3) {
  HeuristicRow Row;
  Row.Ea1 = S.Ids().Addr(Ea1);
  Row.Ea2 = S.Ids().Addr(Ea2);
  Row.Name1 = Nm(S, N1);
  Row.Name2 = Nm(S, N2);
  Row.Desc = S.Ids().Desc(Desc);
  Row.Nodes1 = Nodes1;
  Row.Nodes2 = Nodes2;
  return Row;
}

// A scripted check_ratio: a ratio per (ea, ea2) address text, or a raise (nullopt).
class FakeRatio final : public IRatioProvider {
public:
  explicit FakeRatio(DiffSession& Session) : S(Session) {}
  std::map<std::pair<std::string, std::string>, std::optional<double>> Table;
  int Calls = 0;
  std::optional<MdSource> LastSource;

  double CheckRatio(const HeuristicRow& Row, MdSource Src) override {
    ++Calls;
    LastSource = Src;
    const auto Key = std::make_pair(std::string(S.Ids().AddrKeyText(Row.Ea1)), std::string(S.Ids().AddrKeyText(Row.Ea2)));
    const auto Found = Table.find(Key);
    if (Found == Table.end()) {
      throw std::logic_error("no scripted ratio for " + Key.first + "-" + Key.second);
    }
    if (!Found->second) {
      throw DiaphoraWouldRaise("scripted", "ValueError: scripted check_ratio failure");
    }
    return *Found->second;
  }
  double CompareFunctionRows(uint32_t, uint32_t) override { throw std::logic_error("CompareFunctionRows is unused"); }

private:
  DiffSession& S;
};

std::string Hex(double Value) { return RatioBitsHex(Value); }

std::string NameText(const DiffSession& S, NameId Name) {
  const auto Text = S.Ids().NameOrNone(Name);
  return Text ? "'" + std::string(*Text) + "'" : std::string("None");
}

std::string ItemText(const SnapItem& I) {
  return "[" + I.Ea1 + "," + I.Name1.value_or("<None>") + "," + I.Ea2 + "," + I.Name2.value_or("<None>") + "," + I.Desc +
         "," + Hex(RatioFromBits(I.RatioBits)) + "," + std::to_string(I.Nodes1) + "," + std::to_string(I.Nodes2) + "]";
}

std::string ItemsText(const std::vector<SnapItem>& Items) {
  std::string Out;
  for (const SnapItem& I : Items) {
    Out += ItemText(I);
  }
  return Out;
}

std::string DictText(const std::vector<SnapMatched>& Rows) {
  std::string Out;
  for (const SnapMatched& R : Rows) {
    Out += "{" + R.Key.value_or("<None>") + ":" + R.Other.value_or("<None>") + "," + Hex(RatioFromBits(R.RatioBits)) + "}";
  }
  return Out;
}

// The state in a canonical text: lists in order, dicts in insertion order.
std::string StateText(const StateSnapshot& Snap) {
  return "best=" + ItemsText(Snap.Best) + "\npartial=" + ItemsText(Snap.Partial) + "\nunreliable=" +
         ItemsText(Snap.Unreliable) + "\nmp=" + DictText(Snap.MatchedPrimary) + "\nms=" + DictText(Snap.MatchedSecondary);
}

std::vector<SnapItem> SnapItems(const DiffSession& S, const std::vector<Item>& Items) {
  std::vector<SnapItem> Out;
  for (const Item& It : Items) {
    SnapItem I;
    I.Ea1 = std::string(S.Ids().AddrKeyText(It.Ea1));
    if (auto N = S.Ids().NameOrNone(It.Name1)) {
      I.Name1 = std::string(*N);
    }
    I.Ea2 = std::string(S.Ids().AddrKeyText(It.Ea2));
    if (auto N = S.Ids().NameOrNone(It.Name2)) {
      I.Name2 = std::string(*N);
    }
    I.Desc = std::string(S.Ids().DescText(It.Desc));
    I.RatioBits = RatioBits(It.Ratio);
    I.Nodes1 = It.Nodes1;
    I.Nodes2 = It.Nodes2;
    Out.push_back(std::move(I));
  }
  return Out;
}

// (name1, name2, ratio) triples of a list, like the probes print them.
std::string Triples(const DiffSession& S, const std::vector<Item>& Items) {
  std::string Out;
  for (const Item& It : Items) {
    Out += "(" + NameText(S, It.Name1) + "," + NameText(S, It.Name2) + "," + Hex(It.Ratio) + ")";
  }
  return Out;
}

std::string Entry(const DiffSession& S, const std::optional<MatchedEntry>& E) {
  return E ? NameText(S, E->Other) + "/" + Hex(E->Ratio) : std::string("missing");
}

// Reads a trace file (JSONL) into parsed events.
std::vector<JsonValue> ReadTrace(const std::string& Path) {
  std::vector<JsonValue> Events;
  std::ifstream In(DSig::Test::Utf8ToPath(Path), std::ios::binary);
  std::string Line;
  while (std::getline(In, Line)) {
    if (!Line.empty()) {
      Events.push_back(JsonParse(Line));
    }
  }
  return Events;
}

// Captures the trace events of one operation.
class TraceCapture {
public:
  TraceCapture(DiffSession& Session, std::string Path) : S_(Session), Path_(std::move(Path)) { S_.EnableTrace(Path_, true); }
  std::vector<JsonValue> Finish() {
    S_.Tracer().Close();
    return ReadTrace(Path_);
  }

private:
  DiffSession& S_;
  std::string Path_;
};

StateSnapshot SnapshotFromJsonRoundTrip(const StateSnapshot& Snap) { return ParseSnapshot(SerializeSnapshot(Snap)); }

bool ThrowsWouldRaise(const std::function<void()>& F, std::string* Site = nullptr) {
  try {
    F();
  } catch (const DiaphoraWouldRaise& Error) {
    if (Site != nullptr) {
      *Site = Error.Site;
    }
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// Unit tests: 02 Appendix A probe 1 (the spec authors' probe_bookkeeping.py, sections 2-8)

void TestProbe1() {
  DSig::Test::Suite("probe 1: has_better_match, same-name fake, cleanup downgrade, ties, cross-category");
  {
    DiffSession S;
    MatchState& M = S.State();
    M.SetTotals(100, 100);
    M.AddMatch(Nm(S, "foo"), Nm(S, "bar"), 0.9, MakeItem(S, "1", "foo", "2", "bar", "h", 0.9), Chooser::Partial);
    // "hbm(foo,baz,0.5) named short-circuit -> False"
    CHECK(!M.HasBetterMatch(Nm(S, "foo"), Nm(S, "baz"), 0.5));
    M.AddMatch(Nm(S, "foo"), Nm(S, "baz"), 0.5, MakeItem(S, "1", "foo", "3", "baz", "h", 0.5), Chooser::Partial);
    // "after lower-ratio named add: mp[foo]= {'name': 'baz', 'ratio': 0.5} partial list len 2"
    CHECK_TEXT_EQ(Entry(S, M.Primary(Nm(S, "foo"))), "'baz'/" + Hex(0.5));
    CHECK_NUM_EQ(M.Items(Chooser::Partial).size(), 2);
    // "hbm(sub_1,bar,0.5) -> True (bar has 0.9 in secondary)", "hbm(sub_1,bar,0.9) equal ratio -> False"
    CHECK(M.HasBetterMatch(Nm(S, "sub_1"), Nm(S, "bar"), 0.5));
    CHECK(!M.HasBetterMatch(Nm(S, "sub_1"), Nm(S, "bar"), 0.9));
  }
  {
    DiffSession S;
    MatchState& M = S.State();
    M.SetTotals(100, 100);
    M.AddMatch(Nm(S, "foo"), Nm(S, "foo"), 0.7, MakeItem(S, "1", "foo", "2", "foo", "h", 0.7), Chooser::Partial);
    // "same-name add: mp[foo]= {'name': 'foo', 'ratio': 1.0} hbm(foo,zzz,0.95)-> True has_best_match -> True"
    CHECK_TEXT_EQ(Entry(S, M.Primary(Nm(S, "foo"))), "'foo'/" + Hex(1.0));
    CHECK_TEXT_EQ(Hex(M.Items(Chooser::Partial).at(0).Ratio), Hex(0.7));  // the item keeps its own ratio
    CHECK(M.HasBetterMatch(Nm(S, "foo"), Nm(S, "zzz"), 0.95));
    CHECK(M.HasBestMatch(Nm(S, "foo"), Nm(S, "zzz")));
    M.Cleanup(CleanupSite::L3655);
    // "after cleanup same-name: mp[foo]= {'name': 'foo', 'ratio': 0.7} has_best_match -> False"
    CHECK_TEXT_EQ(Entry(S, M.Primary(Nm(S, "foo"))), "'foo'/" + Hex(0.7));
    CHECK(!M.HasBestMatch(Nm(S, "foo"), Nm(S, "zzz")));
  }
  {
    DiffSession S;
    MatchState& M = S.State();
    M.SetTotals(100, 100);
    M.AddMatch(Nm(S, "sub_B"), Nm(S, "sub_C"), 0.7, MakeItem(S, "20", "sub_B", "30", "sub_C", "h", 0.7), Chooser::Partial);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_C"), 0.9, MakeItem(S, "10", "sub_A", "30", "sub_C", "h", 0.9), Chooser::Partial);
    // "before cleanup ms[sub_C]= {'name': 'sub_A', 'ratio': 0.9}"
    CHECK_TEXT_EQ(Entry(S, M.Secondary(Nm(S, "sub_C"))), "'sub_A'/" + Hex(0.9));
    M.Cleanup(CleanupSite::L3655);
    // "after cleanup ms[sub_C]= {'name': 'sub_B', 'ratio': 0.7} partial= [('sub_A','sub_C',0.9), ('sub_B','sub_C',0.7)]"
    CHECK_TEXT_EQ(Entry(S, M.Secondary(Nm(S, "sub_C"))), "'sub_B'/" + Hex(0.7));
    CHECK_TEXT_EQ(Triples(S, M.Items(Chooser::Partial)),
                  "('sub_A','sub_C'," + Hex(0.9) + ")('sub_B','sub_C'," + Hex(0.7) + ")");
  }
  {
    DiffSession S;
    MatchState& M = S.State();
    M.SetTotals(100, 100);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_X"), 0.8, MakeItem(S, "10", "sub_A", "40", "sub_X", "h1", 0.8), Chooser::Partial);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_Y"), 0.8, MakeItem(S, "10", "sub_A", "50", "sub_Y", "h2", 0.8), Chooser::Partial);
    // "tie: mp[sub_A]= {'name': 'sub_Y', 'ratio': 0.8}"
    CHECK_TEXT_EQ(Entry(S, M.Primary(Nm(S, "sub_A"))), "'sub_Y'/" + Hex(0.8));
    M.Cleanup(CleanupSite::L3655);
    // "tie after cleanup partial= [('sub_A','sub_X',0.8), ('sub_A','sub_Y',0.8)] mp[sub_A]= {'name': 'sub_Y', 'ratio': 0.8}"
    CHECK_TEXT_EQ(Triples(S, M.Items(Chooser::Partial)),
                  "('sub_A','sub_X'," + Hex(0.8) + ")('sub_A','sub_Y'," + Hex(0.8) + ")");
    CHECK_TEXT_EQ(Entry(S, M.Primary(Nm(S, "sub_A"))), "'sub_Y'/" + Hex(0.8));
  }
  {
    // Cross-category: the probe appends to all_matches directly, then cleans up.
    DiffSession S;
    StateSnapshot Snap;
    Snap.Flags.TotalFunctions1 = Snap.Flags.TotalFunctions2 = 100;
    const auto Si = [&](const char* Ea1, const char* N1, const char* Ea2, const char* N2, const char* Desc, double R) {
      return SnapItems(S, {MakeItem(S, Ea1, N1, Ea2, N2, Desc, R)}).at(0);
    };
    Snap.Best = {Si("10", "sub_A", "40", "sub_X", "h1", 1.0)};
    Snap.Partial = {Si("10", "sub_A", "40", "sub_X", "h2", 0.8), Si("10", "sub_A", "41", "sub_Z", "h3", 0.95),
                    Si("11", "sub_Q", "40", "sub_X", "h4", 0.95)};
    Snap.MatchedPrimary = {SnapMatched{"sub_A", "sub_X", RatioBits(1.0)}};
    Snap.MatchedSecondary = {SnapMatched{"sub_X", "sub_A", RatioBits(1.0)}};
    S.State().Import(Snap);
    S.State().Cleanup(CleanupSite::L3655);
    // "xcat best= [('sub_A','sub_X',1.0)] partial= [('sub_Q','sub_X',0.95)] ms[sub_X]= {'name': 'sub_Q', 'ratio': 0.95}"
    CHECK_TEXT_EQ(Triples(S, S.State().Items(Chooser::Best)), "('sub_A','sub_X'," + Hex(1.0) + ")");
    CHECK_TEXT_EQ(Triples(S, S.State().Items(Chooser::Partial)), "('sub_Q','sub_X'," + Hex(0.95) + ")");
    CHECK_TEXT_EQ(Entry(S, S.State().Secondary(Nm(S, "sub_X"))), "'sub_Q'/" + Hex(0.95));
  }
  {
    // Membership: the int 1 and the float 1.0 are equal (the '10' vs 10 case cannot occur: eas are
    // always the address TEXT, 02 §2).
    DiffSession S;
    MatchState& M = S.State();
    M.SetTotals(100, 100);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_X"), 1.0, MakeItem(S, "10", "sub_A", "40", "sub_X", "h", 1), Chooser::Best);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_X"), 1.0, MakeItem(S, "10", "sub_A", "40", "sub_X", "h", 1.0), Chooser::Best);
    CHECK_NUM_EQ(M.Items(Chooser::Best).size(), 1);
    // a -0.0 and a 0.0 item are equal too (Python 0.0 == -0.0), in the hashed membership test
    M.AddMatch(Nm(S, "sub_B"), Nm(S, "sub_Y"), 0.0, MakeItem(S, "11", "sub_B", "41", "sub_Y", "h", 0.0), Chooser::Partial);
    M.AddMatch(Nm(S, "sub_B"), Nm(S, "sub_Y"), -0.0, MakeItem(S, "11", "sub_B", "41", "sub_Y", "h", -0.0), Chooser::Partial);
    CHECK_NUM_EQ(M.Items(Chooser::Partial).size(), 1);
  }
  {
    // D:1369-1374: a duplicate item is not appended, but the dicts are rewritten (last writer wins).
    DiffSession S;
    MatchState& M = S.State();
    M.SetTotals(100, 100);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_X"), 0.9, MakeItem(S, "10", "sub_A", "40", "sub_X", "h", 0.9), Chooser::Partial);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_Y"), 0.9, MakeItem(S, "10", "sub_A", "50", "sub_Y", "h", 0.9), Chooser::Partial);
    M.AddMatch(Nm(S, "sub_A"), Nm(S, "sub_X"), 0.9, MakeItem(S, "10", "sub_A", "40", "sub_X", "h", 0.9), Chooser::Partial);
    CHECK_NUM_EQ(M.Items(Chooser::Partial).size(), 2);
    CHECK_TEXT_EQ(Entry(S, M.Primary(Nm(S, "sub_A"))), "'sub_X'/" + Hex(0.9));
  }
  {
    // "dones key collision survivors: [('a-b', 'c')]"
    DiffSession S;
    StateSnapshot Snap;
    Snap.Partial = SnapItems(S, {MakeItem(S, "1", "a-b", "2", "c", "h", 0.9), MakeItem(S, "3", "a", "4", "b-c", "h", 0.8)});
    S.State().Import(Snap);
    S.State().Cleanup(CleanupSite::L3655);
    CHECK_TEXT_EQ(Triples(S, S.State().Items(Chooser::Partial)), "('a-b','c'," + Hex(0.9) + ")");
  }
  {
    // f"{None}-..." renders None as "None", so a None name collides with the literal name "None".
    DiffSession S;
    StateSnapshot Snap;
    Snap.Partial = SnapItems(S, {MakeItem(S, "1", std::nullopt, "2", "x", "h", 0.9), MakeItem(S, "3", "None", "4", "x", "h", 0.8)});
    S.State().Import(Snap);
    S.State().Cleanup(CleanupSite::L3655);
    CHECK_TEXT_EQ(Triples(S, S.State().Items(Chooser::Partial)), "(None,'x'," + Hex(0.9) + ")");
    // ... while the dicts keep None and "None" as different keys
    CHECK(S.State().Primary(kNoneName).has_value());
    CHECK(!S.State().Primary(Nm(S, "None")).has_value());
  }
}

// 02 Appendix A probe 10 (the spec authors' probe/unit.py): all six cleanup cases, ea1 '7' unless shown.
void TestProbe10() {
  DSig::Test::Suite("probe 10: the six cleanup cases");
  struct Spec {
    const char* Ea1;
    const char* N1;
    const char* N2;
    double R;
  };
  const auto Run = [](const std::vector<Spec>& Partial, const std::vector<Spec>& Best) {
    DiffSession S;
    StateSnapshot Snap;
    for (const Spec& P : Partial) {
      Snap.Partial.push_back(SnapItems(S, {MakeItem(S, P.Ea1, P.N1, "9", P.N2, "d", P.R, 1, 1)}).at(0));
    }
    for (const Spec& B : Best) {
      Snap.Best.push_back(SnapItems(S, {MakeItem(S, B.Ea1, B.N1, "9", B.N2, "d", B.R, 1, 1)}).at(0));
    }
    S.State().Import(Snap);
    S.State().Cleanup(CleanupSite::L3655);
    return "best " + Triples(S, S.State().Items(Chooser::Best)) + " partial " + Triples(S, S.State().Items(Chooser::Partial));
  };
  const std::string R9 = Hex(0.9);
  const std::string R7 = Hex(0.7);
  // doc example best [] partial [('X', 'A', 0.9), ('X', 'X', 0.7)]
  CHECK_TEXT_EQ(Run({{"7", "X", "A", 0.9}, {"7", "X", "X", 0.7}, {"7", "X", "B", 0.8}}, {}),
                "best  partial ('X','A'," + R9 + ")('X','X'," + R7 + ")");
  // no same-name best [] partial [('X', 'A', 0.9)]
  CHECK_TEXT_EQ(Run({{"7", "X", "A", 0.9}, {"7", "X", "B", 0.8}}, {}), "best  partial ('X','A'," + R9 + ")");
  // equal ratios w/ same-name best [] partial [('X', 'A', 0.7), ('X', 'X', 0.7)]
  CHECK_TEXT_EQ(Run({{"7", "X", "A", 0.7}, {"7", "X", "X", 0.7}, {"7", "X", "B", 0.7}}, {}),
                "best  partial ('X','A'," + R7 + ")('X','X'," + R7 + ")");
  // equal ratios w/o same-name best [] partial [('X', 'A', 0.7), ('X', 'B', 0.7)]
  CHECK_TEXT_EQ(Run({{"7", "X", "A", 0.7}, {"7", "X", "B", 0.7}}, {}),
                "best  partial ('X','A'," + R7 + ")('X','B'," + R7 + ")");
  // xcat tie best [('X', 'A', 1.0)] partial [('X', 'X', 0.7)]
  CHECK_TEXT_EQ(Run({{"7", "X", "X", 0.7}}, {{"7", "X", "A", 1.0}}),
                "best ('X','A'," + Hex(1.0) + ") partial ('X','X'," + R7 + ")");
  // dones-before-ea best [] partial [('X', 'A', 0.9)]
  CHECK_TEXT_EQ(Run({{"7", "X", "A", 0.9}, {"7", "Y", "B", 0.8}, {"8", "Y", "B", 0.8}}, {}), "best  partial ('X','A'," + R9 + ")");
}

// 02 Appendix A probe 6 (the spec authors' probe_internal.py): routing with check_match ratios
// [1.0, 0.6, 0.45, 0.3, 0.1], a fake IRatioProvider and a VectorRowSource.
void TestProbe6() {
  DSig::Test::Suite("probe 6: add_matches_internal routing and the row cap");
  const std::vector<double> Ratios = {1.0, 0.6, 0.45, 0.3, 0.1};
  struct Outcome {
    std::string Text;
    uint64_t Fetched = 0;
  };
  const auto Run = [&](const std::function<void(DiffSession&, RowSource&)>& Consume, int64_t MaxRows = kSqlMaxProcessedRows) {
    DiffSession S;
    FakeRatio Fake(S);
    S.SetRatioProvider(&Fake);
    S.MutableConfig().MaxProcessedRows = MaxRows;
    S.State().SetTotals(1000, 1000);
    std::vector<HeuristicRow> Rows;
    for (size_t K = 0; K < Ratios.size(); ++K) {
      const std::string Ea1 = std::to_string(100 + K);
      const std::string Ea2 = std::to_string(200 + K);
      Rows.push_back(MakeRow(S, Ea1, "sub_A" + std::to_string(K), Ea2, "sub_B" + std::to_string(K), "h"));
      Fake.Table[{Ea1, Ea2}] = Ratios[K];
    }
    VectorRowSource Source(std::move(Rows));
    Consume(S, Source);
    const auto List = [&](Chooser C) {
      std::string Out = "[";
      for (const Item& It : S.State().Items(C)) {
        Out += (Out.size() > 1 ? "," : "") + Hex(It.Ratio);
      }
      return Out + "]";
    };
    CHECK(!Fake.LastSource || *Fake.LastSource == MdSource::Sql);  // check_match uses the SQL md (H:57)
    return Outcome{"best " + List(Chooser::Best) + " partial " + List(Chooser::Partial) + " unreliable " +
                       List(Chooser::Unreliable),
                   Source.Fetched()};
  };
  const std::string H1 = Hex(1.0), H6 = Hex(0.6), H45 = Hex(0.45), H3 = Hex(0.3);
  // RATIO (val None)            {'best': [1.0], 'partial': [0.6], 'unreliable': []} fetched 5
  Outcome O = Run([](DiffSession& S, RowSource& R) { AddMatchesFromQueryRatio(S, R, Chooser::Best, Chooser::Partial); });
  CHECK_TEXT_EQ(O.Text, "best [" + H1 + "] partial [" + H6 + "] unreliable []");
  CHECK_NUM_EQ(O.Fetched, 5);
  // RATIO_MAX min=0.2           {'best': [1.0], 'partial': [0.6, 0.45, 0.3], 'unreliable': []} fetched 5
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesFromQueryRatioMax(S, R, Chooser::Best, Chooser::Partial, 0.2); });
  CHECK_TEXT_EQ(O.Text, "best [" + H1 + "] partial [" + H6 + "," + H45 + "," + H3 + "] unreliable []");
  CHECK_NUM_EQ(O.Fetched, 5);
  // RATIO_MAX min=0.7           {'best': [1.0], 'partial': [], 'unreliable': []} fetched 5
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesFromQueryRatioMax(S, R, Chooser::Best, Chooser::Partial, 0.7); });
  CHECK_TEXT_EQ(O.Text, "best [" + H1 + "] partial [] unreliable []");
  CHECK_NUM_EQ(O.Fetched, 5);
  // TRUSTED min=0.44            {'best': [1.0], 'partial': [0.6, 0.45], 'unreliable': []} fetched 5
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesFromQueryRatioMaxTrusted(S, R, 0.44); });
  CHECK_TEXT_EQ(O.Text, "best [" + H1 + "] partial [" + H6 + "," + H45 + "] unreliable []");
  CHECK_NUM_EQ(O.Fetched, 5);
  // Unreliable-cat RATIO        {'best': [], 'partial': [1.0], 'unreliable': [0.6]} fetched 5
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesFromQueryRatio(S, R, Chooser::Partial, Chooser::Unreliable); });
  CHECK_TEXT_EQ(O.Text, "best [] partial [" + H1 + "] unreliable [" + H6 + "]");
  CHECK_NUM_EQ(O.Fetched, 5);
  // brute force (partial=None)  {'best': [], 'partial': [], 'unreliable': [1.0]} fetched 5
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesInternal(S, R, Chooser::Unreliable, std::nullopt, 0.5); });
  CHECK_TEXT_EQ(O.Text, "best [] partial [] unreliable [" + H1 + "]");
  CHECK_NUM_EQ(O.Fetched, 5);
  // maxrows=3                   {'best': [1.0], 'partial': [0.6], 'unreliable': []} fetched 3
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesInternal(S, R, Chooser::Best, Chooser::Partial); }, 3);
  CHECK_TEXT_EQ(O.Text, "best [" + H1 + "] partial [" + H6 + "] unreliable []");
  CHECK_NUM_EQ(O.Fetched, 3);
  // maxrows=0                   {'best': [], 'partial': [], 'unreliable': []} fetched 0
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesInternal(S, R, Chooser::Best, Chooser::Partial); }, 0);
  CHECK_TEXT_EQ(O.Text, "best [] partial [] unreliable []");
  CHECK_NUM_EQ(O.Fetched, 0);
  // NO_FPS: every accepted row is best with the int ratio 1 (D:2074-2075), no cap, errors swallowed.
  O = Run([](DiffSession& S, RowSource& R) { AddMatchesFromQuery(S, R, Chooser::Best); }, 3);
  CHECK_TEXT_EQ(O.Text, "best [" + H1 + "," + H1 + "," + H1 + "," + H1 + "," + H1 + "] partial [] unreliable []");
  CHECK_NUM_EQ(O.Fetched, 5);
}

// The wrappers' all_functions_matched early return and error semantics (02 §11-§12).
void TestWrappers() {
  DSig::Test::Suite("add_matches_from_*: early return, NO_FPS swallows, RATIO* re-raise, int(None)");
  {
    DiffSession S;
    FakeRatio Fake(S);
    S.SetRatioProvider(&Fake);
    S.State().SetTotals(1, 50);
    S.State().AddMatch(Nm(S, "f"), Nm(S, "g"), 0.9, MakeItem(S, "1", "f", "2", "g", "h", 0.9), Chooser::Partial);
    CHECK(S.State().AllFunctionsMatched());  // len(matched_primary) == total_functions1
    std::vector<HeuristicRow> Rows = {MakeRow(S, "3", "a", "4", "b", "h")};
    VectorRowSource A(Rows), B(Rows), C(Rows), D(Rows), E(Rows);
    AddMatchesFromQuery(S, A, Chooser::Best);
    AddMatchesFromQueryRatio(S, B, Chooser::Best, Chooser::Partial);
    AddMatchesFromQueryRatioMax(S, C, Chooser::Best, Chooser::Partial, 0.5);
    AddMatchesFromQueryRatioMaxTrusted(S, D, 0.5);
    CHECK_NUM_EQ(A.Fetched() + B.Fetched() + C.Fetched() + D.Fetched(), 0);  // cur.execute never ran
    // add_matches_internal itself has no such check (D:1882-1948)
    Fake.Table[{"3", "4"}] = 0.8;
    AddMatchesInternal(S, E, Chooser::Best, Chooser::Partial);
    CHECK_NUM_EQ(E.Fetched(), 1);
    CHECK_NUM_EQ(S.State().Items(Chooser::Partial).size(), 2);
  }
  {
    DiffSession S;
    FakeRatio Fake(S);
    S.SetRatioProvider(&Fake);
    S.State().SetTotals(100, 100);
    Fake.Table[{"1", "2"}] = 0.9;
    Fake.Table[{"3", "4"}] = std::nullopt;  // check_ratio raises on the second row
    Fake.Table[{"5", "6"}] = 0.8;
    const std::vector<HeuristicRow> Rows = {MakeRow(S, "1", "a", "2", "b", "h"), MakeRow(S, "3", "c", "4", "d", "h"),
                                            MakeRow(S, "5", "e", "6", "f", "h")};
    VectorRowSource NoFps(Rows);
    CHECK(!ThrowsWouldRaise([&] { AddMatchesFromQuery(S, NoFps, Chooser::Best); }));  // D:2080-2081 swallows
    CHECK_NUM_EQ(NoFps.Fetched(), 2);                                                   // ... and stops there
    CHECK_NUM_EQ(S.State().Items(Chooser::Best).size(), 1);
    VectorRowSource Ratio(Rows);
    std::string Site;
    CHECK(ThrowsWouldRaise([&] { AddMatchesFromQueryRatio(S, Ratio, Chooser::Best, Chooser::Partial); }, &Site));
    CHECK_NUM_EQ(Ratio.Fetched(), 2);  // the adds before the raise are kept
  }
  {
    DiffSession S;
    FakeRatio Fake(S);
    S.SetRatioProvider(&Fake);
    S.State().SetTotals(100, 100);
    Fake.Table[{"1", "2"}] = 0.9;
    // int(row["nodes1"]) raises only after check_match accepted the row (D:1915)
    std::vector<HeuristicRow> Rows = {MakeRow(S, "1", "a", "2", "b", "h", std::nullopt, 3)};
    VectorRowSource Source(Rows);
    std::string Site;
    CHECK(ThrowsWouldRaise([&] { AddMatchesInternal(S, Source, Chooser::Best, Chooser::Partial); }, &Site));
    CHECK_TEXT_EQ(Site, "D:1915");
    CHECK_NUM_EQ(Fake.Calls, 1);
    CHECK_NUM_EQ(S.State().PrimarySize(), 0);
    // a rejected row never reaches int(): nullsub names skip check_ratio entirely
    std::vector<HeuristicRow> Nullsub = {MakeRow(S, "1", "nullsub_1", "2", "b", "h", std::nullopt, std::nullopt)};
    VectorRowSource NullsubSource(Nullsub);
    CHECK(!ThrowsWouldRaise([&] { AddMatchesInternal(S, NullsubSource, Chooser::Best, Chooser::Partial); }));
    CHECK_NUM_EQ(Fake.Calls, 1);
    // D:1935 "0x%x" % int(ea): a non-decimal address raises ValueError before add_match
    Fake.Table[{"0x10", "2"}] = 0.9;
    std::vector<HeuristicRow> Hex16 = {MakeRow(S, "0x10", "a", "2", "b", "h")};
    VectorRowSource HexSource(Hex16);
    CHECK(ThrowsWouldRaise([&] { AddMatchesInternal(S, HexSource, Chooser::Best, Chooser::Partial); }, &Site));
    CHECK_TEXT_EQ(Site, "D:1935 ValueError");
    CHECK_NUM_EQ(S.State().PrimarySize(), 0);
    // ... but NO_FPS has no int(ea) (D:2067-2075)
    Fake.Table[{"0x10", "2"}] = 1.0;
    VectorRowSource HexNoFps(Hex16);
    AddMatchesFromQuery(S, HexNoFps, Chooser::Best);
    CHECK_NUM_EQ(S.State().Items(Chooser::Best).size(), 1);
  }
}

// None names: Python raises AttributeError at .startswith (D:1392, D:1846) with short-circuit order.
void TestNoneNames() {
  DSig::Test::Suite("None names: the short-circuit order of the startswith tests");
  DiffSession S;
  MatchState& M = S.State();
  M.SetTotals(100, 100);
  std::string Site;
  CHECK(ThrowsWouldRaise([&] { (void)M.HasBetterMatch(kNoneName, Nm(S, "x"), 0.5); }, &Site));
  CHECK_TEXT_EQ(Site, "D:1392");
  CHECK(ThrowsWouldRaise([&] { (void)M.HasBetterMatch(Nm(S, "x"), kNoneName, 0.5); }));
  // name1 starts with sub_: `not name1.startswith("sub_") and ...` short-circuits before name2
  CHECK(!ThrowsWouldRaise([&] { (void)M.HasBetterMatch(Nm(S, "sub_1"), kNoneName, 0.5); }));
  // add_match: None == None forces 1.0 and skips has_better_match
  M.AddMatch(kNoneName, kNoneName, 0.4, MakeItem(S, "1", std::nullopt, "2", std::nullopt, "h", 0.4), Chooser::Partial);
  CHECK(M.Primary(kNoneName).has_value());
  CHECK_TEXT_EQ(Hex(M.Primary(kNoneName)->Ratio), Hex(1.0));
  // add_match below 1.0 with a None name raises before any change
  CHECK(ThrowsWouldRaise([&] {
    M.AddMatch(kNoneName, Nm(S, "y"), 0.4, MakeItem(S, "1", std::nullopt, "3", "y", "h", 0.4), Chooser::Partial);
  }));
  CHECK_NUM_EQ(M.Items(Chooser::Partial).size(), 1);
  // check_match: nullsub_ on name1 short-circuits a None name2
  FakeRatio Fake(S);
  S.SetRatioProvider(&Fake);
  CHECK(!CheckMatch(S, MakeRow(S, "1", "nullsub_1", "2", std::nullopt, "h")).has_value());
  CHECK(ThrowsWouldRaise([&] { (void)CheckMatch(S, MakeRow(S, "1", "a", "2", std::nullopt, "h")); }, &Site));
  CHECK_TEXT_EQ(Site, "D:1846");
  CHECK_NUM_EQ(Fake.Calls, 0);
}

// 01 E2 (the spec authors' drv/exp_final.py): multimatch split, the dropped same-name 0.9018889.
void TestE2() {
  DSig::Test::Suite("01 E2: final pass multimatch split");
  DiffSession S;
  StateSnapshot Snap;
  Snap.Flags.TotalFunctions1 = Snap.Flags.TotalFunctions2 = 100;
  const auto Si = [&](const char* Ea1, const char* N1, const char* Ea2, const char* N2, const char* Desc, double R) {
    return SnapItems(S, {MakeItem(S, Ea1, N1, Ea2, N2, Desc, R)}).at(0);
  };
  Snap.Best = {Si("400", "f400", "500", "g500", "best one", 1), Si("4096", "same", "4096", "same", "100% equal", 1)};
  Snap.Partial = {Si("100", "a1", "200", "b1", "mm-main", 0.8),       Si("100", "a1", "300", "b2", "mm-main", 0.8),
                  Si("600", "a6", "700", "b7", "mm-diff", 0.7),       Si("800", "a8", "700", "b7", "mm-diff", 0.7),
                  Si("900", "a9", "1000", "b10", "hi", 0.9),          Si("900", "a9", "1100", "b11", "lo", 0.6),
                  Si("1200", "dup", "1300", "dup2", "dup-lo", 0.55),  Si("1200", "dup", "1300", "dup2", "dup-hi", 0.65),
                  Si("1400", "nm", "1500", "nm", "same name", 0.9018889),
                  Si("1400", "zz", "1600", "zz2", "worse for 1400", 0.95),
                  Si("1700", "r1", "1800", "r2", "round", 0.123456789),
                  Si("4294967296", "big", "4294967297", "big2", "64bit", 0.51)};
  Snap.Unreliable = {Si("100", "a1", "200", "b1x", "dup ea pair diff names", 0.8)};
  S.State().Import(Snap);
  S.State().Cleanup(CleanupSite::L3655);
  StageFinalPass(S);
  const auto Pairs = [&](const std::vector<Item>& Items) {
    std::string Out;
    for (const Item& It : Items) {
      Out += "(" + std::string(S.Ids().AddrText(It.Ea1)) + "->" + std::string(S.Ids().AddrText(It.Ea2)) + ")";
    }
    return Out;
  };
  // Equal-ratio pairs sharing ea1 (100) or ea2 (700) went to multimatch, in first-seen order.
  CHECK_TEXT_EQ(Pairs(S.Final().Multimatch), "(100->200)(100->300)(600->700)(800->700)");
  CHECK_TEXT_EQ(Pairs(S.Final().Best), "(400->500)(4096->4096)");
  // The same-name pair 1400->1500 (0.9018889) is dropped because 1400->1600 has 0.95; the lower
  // ratio for ea1 900 (1100, 0.6) is dropped; the name-pair duplicate keeps only dup-hi.
  CHECK_TEXT_EQ(Pairs(S.Final().Partial), "(1400->1600)(900->1000)(1200->1300)(4294967296->4294967297)(1700->1800)");
  CHECK_TEXT_EQ(std::string(S.Ids().DescText(S.Final().Partial.at(2).Desc)), "dup-hi");
  CHECK(S.Final().Unreliable.empty());
  // Its names stay in matched_primary, so the function is not "unmatched" either (01 §9.4 item 1).
  CHECK(S.State().Primary(Nm(S, "nm")).has_value());
}

// 01 §9.4: the D:2933 KeyError is impossible under the default configuration (asserted on random
// default-shaped states), and reproduced on the non-default shape that triggers it.
void TestKeyErrorAnalysis() {
  DSig::Test::Suite("01 §9.4: KeyError impossibility under defaults");
  std::mt19937_64 Rng(0x5eed);
  const std::vector<std::string> Eas1 = {"1", "2", "3", "10", "11"};
  const std::vector<std::string> Eas2 = {"5", "6", "7", "50"};
  const std::vector<std::string> Names = {"sub_1", "sub_2", "f", "g", "h", "a-b", "c"};
  const std::vector<double> Partial = {0.9, 0.8, 0.8, 0.7, 0.5, 0.45, 0.3, 0.0, 0.99};
  int Raised = 0;
  int Multimatch = 0;
  for (int Round = 0; Round < 2000; ++Round) {
    DiffSession S;
    StateSnapshot Snap;
    const auto Pick = [&](const std::vector<std::string>& V) { return V[Rng() % V.size()]; };
    const int Count = static_cast<int>(Rng() % 12);
    for (int K = 0; K < Count; ++K) {
      const bool Best = Rng() % 3 == 0;
      const std::string N1 = Pick(Names);
      const std::string N2 = Rng() % 4 == 0 ? N1 : Pick(Names);
      const Item It = MakeItem(S, Pick(Eas1), N1, Pick(Eas2), N2, "d", Best ? 1.0 : Partial[Rng() % Partial.size()]);
      (Best ? Snap.Best : Snap.Partial).push_back(SnapItems(S, {It}).at(0));
    }
    S.State().Import(Snap);
    if (ThrowsWouldRaise([&] { StageFinalPass(S); })) {
      ++Raised;
    }
    Multimatch += S.Final().Multimatch.empty() ? 0 : 1;
  }
  CHECK_NUM_EQ(Raised, 0);
  CHECK(Multimatch > 0);
  DSig::Test::Note("2000 default-shaped states: 0 KeyError, " + std::to_string(Multimatch) + " with multimatches");
  // The shape of 01 §9.4: X (partial, same-name, 0.5) fails max_main behind Z (0.6) and its twin Y
  // (same ea1-ea2, other names, unreliable 1.0) is dones-skipped, so max_diff[ea2] is never set.
  DiffSession S;
  StateSnapshot Snap;
  Snap.Partial = SnapItems(S, {MakeItem(S, "1", "z1", "20", "z2", "z", 0.6), MakeItem(S, "1", "n", "2", "n", "x", 0.5)});
  Snap.Unreliable = SnapItems(S, {MakeItem(S, "1", "p", "2", "q", "y", 1.0)});
  S.State().Import(Snap);
  std::string Site;
  CHECK(ThrowsWouldRaise([&] { StageFinalPass(S); }, &Site));
  CHECK_TEXT_EQ(Site, "D:2933 KeyError");
  CHECK_NUM_EQ(S.Final().Partial.size(), 1);  // add_item calls before the raise are kept
}

// D:2742-2745: add_multimatches_to_chooser puts an ea into the ignore list only when one of its items
// is NEWLY added. multi_diff["50"] = [A, B] holds only items that multi_main already added (one shared
// dones, D:2905-2912), so "50" is not ignored and Z (3->50, dones-skipped in the first pass behind its
// lower best twin T, D:2853-2854) reaches the partial chooser. Real Diaphora gives the same result
// (probes.json "final_pass_ignore_only_on_new_add"); an unconditional ignore_list.add drops Z.
void TestIgnoreOnlyOnNewAdd() {
  DSig::Test::Suite("final pass: ignore flag only for newly added multimatch items");
  DiffSession S;
  StateSnapshot Snap;
  Snap.Flags.TotalFunctions1 = Snap.Flags.TotalFunctions2 = 100;
  Snap.Best = SnapItems(S, {MakeItem(S, "1", "a", "50", "e", "hA", 0.5), MakeItem(S, "1", "a", "51", "e1", "hA2", 0.5),
                            MakeItem(S, "2", "b", "50", "e", "hB", 0.5), MakeItem(S, "2", "b", "52", "e2", "hB2", 0.5),
                            MakeItem(S, "3", "c", "50", "e", "hT", 0.4)});
  Snap.Partial = SnapItems(S, {MakeItem(S, "3", "c2", "50", "e", "hZ", 0.9)});
  S.State().Import(Snap);
  StageFinalPass(S);
  const auto Pairs = [&](const std::vector<Item>& Items) {
    std::string Out;
    for (const Item& It : Items) {
      Out += "(" + std::string(S.Ids().AddrText(It.Ea1)) + "->" + std::string(S.Ids().AddrText(It.Ea2)) + ")";
    }
    return Out;
  };
  CHECK_TEXT_EQ(Pairs(S.Final().Multimatch), "(1->50)(1->51)(2->50)(2->52)");
  CHECK(S.Final().Best.empty());  // T fails max_diff["50"] = 0.5
  CHECK_TEXT_EQ(Pairs(S.Final().Partial), "(3->50)");
  if (S.Final().Partial.size() == 1) {
    CHECK_TEXT_EQ(std::string(S.Ids().DescText(S.Final().Partial[0].Desc)), "hZ");
  }
  CHECK(S.Final().Unreliable.empty());
}

void TestPyIntText() {
  DSig::Test::Suite("Python int() of address texts (D:280/D:286/D:288/D:1935)");
  using Detail::PyIntAsciiAccepts;
  // Py_ISSPACE (space, TAB, LF, VT, FF, CR) is stripped on both sides; the 0x1c-0x1f separators that
  // str.isspace() accepts are not (checked on the oracle's CPython 3.13.12: int("\x1c5") raises).
  for (const char* Ok : {"0", "10", "4294967296", " 10 ", "\t7\n", "\v5\f", "\r\n8 ", "1_0", "+12", "-13", "0014",
                         "1_2_3"}) {
    CHECK(PyIntAsciiAccepts(Ok));
  }
  for (const char* Bad : {"", " ", "0x10", "1_", "_1", "1__0", "+ 1", "1 2", "--1", "None", "1.0", "1e3", "+", "\x7f" "1",
                          "\x1c" "5", "5\x1f", "\x1d" "5", "\x1e" "5", "\x1c" "5\x1f", "+_1", "1_ "}) {
    CHECK(!PyIntAsciiAccepts(Bad));
  }
  CHECK(!PyIntAsciiAccepts(std::string_view("1\0" "2", 3)));
  CHECK(!PyIntAsciiAccepts(std::string_view("1\0", 2)));
  // No digit limit: diaphora.py runs sys.set_int_max_str_digits(0) when it is loaded (D:96-97), so
  // CPython's default 4300-digit limit does not apply (real-Diaphora vector cases *_int_digit_limit*).
  const std::string D4301(4301, '1');
  std::string Sep4301 = "1";  // "1_1_..._1": 4301 digits, 4300 underscores
  for (int K = 0; K < 4300; ++K) {
    Sep4301 += "_1";
  }
  for (const std::string& Long : {D4301, "-" + D4301, " \t" + D4301 + "\n", Sep4301, std::string(4301, '0'),
                                  std::string(100000, '9')}) {
    CHECK(PyIntAsciiAccepts(Long));
  }
  CHECK(!PyIntAsciiAccepts(D4301 + "x"));
  CHECK(!PyIntAsciiAccepts(D4301 + "_"));
  DiffSession S;
  std::string Site;
  CHECK(ThrowsWouldRaise([&] { Detail::RequirePyInt(S.Ids(), kNoneAddr, "D:280"); }, &Site));
  CHECK_TEXT_EQ(Site, "D:280 TypeError");
  CHECK(ThrowsWouldRaise([&] { Detail::RequirePyInt(S.Ids(), S.Ids().Addr("\x1c" "5"), "D:286"); }, &Site));
  CHECK_TEXT_EQ(Site, "D:286 ValueError");
  CHECK(!ThrowsWouldRaise([&] { Detail::RequirePyInt(S.Ids(), S.Ids().Addr("\v5\f"), "D:288"); }));
  CHECK(!ThrowsWouldRaise([&] { Detail::RequirePyInt(S.Ids(), S.Ids().Addr(D4301), "D:1935"); }));
  bool Refused = false;
  try {
    Detail::RequirePyInt(S.Ids(), S.Ids().Addr("\xd9\xa1\xd9\xa2"), "D:286");  // Arabic-Indic digits
  } catch (const UnsupportedInput&) {
    Refused = true;
  }
  CHECK(Refused);
}

void TestCountersAndSorting() {
  DSig::Test::Suite("all_functions_matched, get_total_matched_functions, get_sorted_results");
  DiffSession S;
  MatchState& M = S.State();
  M.SetTotals(2, 3);
  CHECK(!M.AllFunctionsMatched());
  M.AddMatch(Nm(S, "sub_1"), Nm(S, "sub_9"), 0.7, MakeItem(S, "1", "sub_1", "9", "sub_9", "a", 0.7), Chooser::Partial);
  M.AddMatch(Nm(S, "sub_2"), Nm(S, "sub_8"), 0.7, MakeItem(S, "2", "sub_2", "8", "sub_8", "b", 0.7), Chooser::Partial);
  CHECK(M.AllFunctionsMatched());  // len(matched_primary) == 2 == total_functions1
  M.AddMatch(Nm(S, "sub_3"), Nm(S, "sub_7"), 1.0, MakeItem(S, "3", "sub_3", "7", "sub_7", "c", 1.0), Chooser::Best);
  CHECK(M.AllFunctionsMatched());  // 3 == total_functions2
  M.AddMatch(Nm(S, "sub_4"), Nm(S, "sub_6"), 0.9, MakeItem(S, "4", "sub_4", "6", "sub_6", "d", 0.9), Chooser::Partial);
  CHECK(!M.AllFunctionsMatched());  // 4 != 2 and 4 != 3: `==`, not `>=` (02 §13)
  M.AddMatch(Nm(S, "sub_5"), Nm(S, "sub_5x"), 0.5, MakeItem(S, "5", "sub_5", "55", "sub_5x", "e", 0.5), Chooser::Unreliable);
  CHECK_NUM_EQ(M.TotalMatchedFunctions(), 4);  // best + partial items, unreliable excluded
  // stable descending: the two 0.7 items keep their insertion order, and the list is not modified
  const std::vector<Item> Sorted = M.SortedResults(Chooser::Partial);
  CHECK_TEXT_EQ(std::string(S.Ids().DescText(Sorted.at(0).Desc)) + std::string(S.Ids().DescText(Sorted.at(1).Desc)) +
                    std::string(S.Ids().DescText(Sorted.at(2).Desc)),
                "dab");
  CHECK_TEXT_EQ(std::string(S.Ids().DescText(M.Items(Chooser::Partial).at(0).Desc)), "a");
}

void TestExportImport() {
  DSig::Test::Suite("Export / Import round trip (dict insertion order kept)");
  DiffSession S;
  MatchState& M = S.State();
  M.SetTotals(7, 8);
  M.AddMatch(Nm(S, "b"), Nm(S, "x"), 0.9, MakeItem(S, "1", "b", "2", "x", "h", 0.9), Chooser::Partial);
  M.AddMatch(Nm(S, "a"), Nm(S, "y"), 1.0, MakeItem(S, "3", "a", "4", "y", "h", 1.0), Chooser::Best);
  M.AddMatch(Nm(S, "b"), Nm(S, "z"), 0.95, MakeItem(S, "1", "b", "5", "z", "h", 0.95), Chooser::Partial);
  M.AddMatch(kNoneName, kNoneName, 0.3, MakeItem(S, "9", std::nullopt, "9", std::nullopt, "h", 0.3), Chooser::Unreliable);
  const StateSnapshot First = M.Export();
  // re-assigning "b" keeps its first position (Python dict semantics)
  CHECK_TEXT_EQ(DictText(First.MatchedPrimary), "{b:z," + Hex(0.95) + "}{a:y," + Hex(1.0) + "}{<None>:<None>," + Hex(1.0) + "}");
  DiffSession T;
  T.State().Import(SnapshotFromJsonRoundTrip(First));
  const StateSnapshot Second = T.State().Export();
  CHECK_TEXT_EQ(StateText(Second), StateText(First));
  CHECK_NUM_EQ(Second.Flags.TotalFunctions1, 7);
  // the membership index is rebuilt by Import: the same item is a duplicate
  T.State().AddMatch(Nm(T, "b"), Nm(T, "x"), 0.9, MakeItem(T, "1", "b", "2", "x", "h", 0.9), Chooser::Partial);
  CHECK_NUM_EQ(T.State().Items(Chooser::Partial).size(), 2);
}

// ---------------------------------------------------------------------------------------------
// Trace events (tools/parity/README.md "add_match event" / "row event")

void TestTraceEvents(const std::string& Scratch) {
  DSig::Test::Suite("trace: add_match results and row decisions");
  DiffSession S;
  FakeRatio Fake(S);
  S.SetRatioProvider(&Fake);
  S.State().SetTotals(100, 100);
  const std::string Path = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / "trace_events.jsonl");
  TraceCapture Cap(S, Path);
  MatchState& M = S.State();
  // the ratio ARGUMENT is traced, not the forced 1.0 of a same-name pair (D:1350-1351)
  M.AddMatch(Nm(S, "foo"), Nm(S, "foo"), 0.7, MakeItem(S, "1", "foo", "2", "foo", "h", 0.7), Chooser::Partial);
  M.AddMatch(Nm(S, "foo"), Nm(S, "foo"), 0.7, MakeItem(S, "1", "foo", "2", "foo", "h", 0.7), Chooser::Partial);
  M.AddMatch(Nm(S, "sub_1"), Nm(S, "sub_9"), 0.8, MakeItem(S, "3", "sub_1", "9", "sub_9", "h", 0.8), std::nullopt);
  M.AddMatch(Nm(S, "sub_2"), Nm(S, "sub_9"), 0.5, MakeItem(S, "4", "sub_2", "9", "sub_9", "h", 0.5), Chooser::Partial);
  {
    ContextScope Scope(S, "heuristic:41");
    Fake.Table[{"5", "6"}] = 0.9;
    Fake.Table[{"7", "6"}] = 0.4;
    Fake.Table[{"8", "10"}] = 1.0;
    std::vector<HeuristicRow> Rows = {MakeRow(S, "5", "sub_5", "6", "sub_6", "Loop count"),      // accepted_partial
                                      MakeRow(S, "7", "sub_7", "6", "sub_6", "Loop count"),      // has_better
                                      MakeRow(S, "1", "foo", "11", "bar", "Loop count"),         // has_best
                                      MakeRow(S, "8", "nullsub_8", "10", "x", "Loop count"),     // nullsub
                                      MakeRow(S, "8", "sub_8", "10", "sub_10", "Loop count")};   // accepted_best
    VectorRowSource Source(Rows);
    AddMatchesFromQueryRatioMax(S, Source, Chooser::Best, Chooser::Partial, 0.2);
  }
  const std::vector<JsonValue> Events = Cap.Finish();
  std::vector<std::string> Lines;
  for (const JsonValue& E : Events) {
    const std::string Ev = E.At("ev").AsString();
    const JsonValue& Ctx = E.At("ctx");
    std::string Line = Ev + "|" + (Ctx.IsNull() ? std::string("null") : Ctx.AsString()) + "|";
    if (Ev == "add_match") {
      Line += std::to_string(E.At("seq").AsInt64()) + "|" + E.At("ea1").AsString() + "-" + E.At("ea2").AsString() + "|" +
              E.At("ratio_bits").AsString() + "|" + (E.At("chooser").IsNull() ? "null" : E.At("chooser").AsString()) +
              "|" + E.At("result").AsString();
    } else {
      Line += E.At("ea1").AsString() + "-" + E.At("ea2").AsString() + "|" + E.At("decision").AsString() + "|" +
              (E.At("ratio_bits").IsNull() ? "null" : E.At("ratio_bits").AsString());
    }
    Lines.push_back(Line);
  }
  const std::vector<std::string> Expected = {
      "add_match|null|0|1-2|" + Hex(0.7) + "|partial|appended",
      "add_match|null|1|1-2|" + Hex(0.7) + "|partial|duplicate",
      "add_match|null|2|3-9|" + Hex(0.8) + "|null|duplicate",
      "add_match|null|3|4-9|" + Hex(0.5) + "|partial|rejected_better",
      "row|heuristic:41|5-6|accepted_partial|" + Hex(0.9),
      "add_match|heuristic:41|4|5-6|" + Hex(0.9) + "|partial|appended",
      "row|heuristic:41|7-6|has_better|" + Hex(0.4),
      "row|heuristic:41|1-11|has_best|null",
      "row|heuristic:41|8-10|nullsub|null",
      "row|heuristic:41|8-10|accepted_best|" + Hex(1.0),
      "add_match|heuristic:41|5|8-10|" + Hex(1.0) + "|best|appended",
  };
  CHECK_NUM_EQ(Lines.size(), Expected.size());
  for (size_t K = 0; K < std::min(Lines.size(), Expected.size()); ++K) {
    CHECK_TEXT_EQ(Lines[K], Expected[K]);
  }
  // A raise inside check_match is a "raised" row event with a null ratio, and nothing else.
  {
    TraceCapture Raise(S, Path);
    Fake.Table[{"12", "13"}] = std::nullopt;
    std::vector<HeuristicRow> Rows = {MakeRow(S, "12", "sub_12", "13", "sub_13", "d")};
    VectorRowSource Source(Rows);
    CHECK(ThrowsWouldRaise([&] { AddMatchesInternal(S, Source, Chooser::Best, Chooser::Partial); }));
    const std::vector<JsonValue> Raised = Raise.Finish();
    CHECK_NUM_EQ(Raised.size(), 1);
    if (Raised.size() == 1) {
      CHECK_TEXT_EQ(Raised[0].At("decision").AsString(), "raised");
      CHECK(Raised[0].At("ratio_bits").IsNull());
    }
  }
  // Callers without a routing frame (find_same_name, search_small_differences): r == 1.0 is best.
  {
    TraceCapture Direct(S, Path);
    Fake.Table[{"14", "15"}] = 0.3;
    (void)CheckMatch(S, MakeRow(S, "14", "sub_14", "15", "sub_15", "d"));
    const std::vector<JsonValue> Out = Direct.Finish();
    CHECK_NUM_EQ(Out.size(), 1);
    if (Out.size() == 1) {
      CHECK_TEXT_EQ(Out[0].At("decision").AsString(), "accepted_partial");
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Vectors from the real Diaphora (tools/parity/gen_state_vectors.py)

OptText JOpt(const JsonValue& V) { return V.IsNull() ? OptText() : OptText(V.AsString()); }

double JRatio(const JsonValue& V) { return RatioFromBits(ParseRatioBits(V.AsString())); }

SnapItem JItem(const JsonValue& V) {
  const std::vector<JsonValue>& A = V.Items();
  SnapItem I;
  I.Ea1 = A.at(0).AsString();
  I.Name1 = JOpt(A.at(1));
  I.Ea2 = A.at(2).AsString();
  I.Name2 = JOpt(A.at(3));
  I.Desc = A.at(4).AsString();
  I.RatioBits = ParseRatioBits(A.at(5).AsString());
  I.Nodes1 = A.at(6).AsInt64();
  I.Nodes2 = A.at(7).AsInt64();
  return I;
}

std::vector<SnapItem> JItems(const JsonValue& V) {
  std::vector<SnapItem> Out;
  for (const JsonValue& I : V.Items()) {
    Out.push_back(JItem(I));
  }
  return Out;
}

std::vector<SnapMatched> JDict(const JsonValue& V) {
  std::vector<SnapMatched> Out;
  for (const JsonValue& R : V.Items()) {
    Out.push_back(SnapMatched{JOpt(R.Items().at(0)), JOpt(R.Items().at(1)), ParseRatioBits(R.Items().at(2).AsString())});
  }
  return Out;
}

StateSnapshot JState(const JsonValue& V) {
  StateSnapshot Snap;
  Snap.Best = JItems(V.At("best"));
  Snap.Partial = JItems(V.At("partial"));
  Snap.Unreliable = JItems(V.At("unreliable"));
  Snap.MatchedPrimary = JDict(V.At("mp"));
  Snap.MatchedSecondary = JDict(V.At("ms"));
  return Snap;
}

std::optional<Chooser> JChooser(const JsonValue& V) {
  if (V.IsNull()) {
    return std::nullopt;
  }
  const std::string& Text = V.AsString();
  if (Text == "best") {
    return Chooser::Best;
  }
  if (Text == "partial") {
    return Chooser::Partial;
  }
  if (Text == "unreliable") {
    return Chooser::Unreliable;
  }
  throw std::logic_error("unknown chooser " + Text);
}

Item ItemFromSnap(DiffSession& S, const SnapItem& I) {
  return Item{S.Ids().Addr(I.Ea1), Nm(S, I.Name1), S.Ids().Addr(I.Ea2), Nm(S, I.Name2), S.Ids().Desc(I.Desc),
              RatioFromBits(I.RatioBits), I.Nodes1, I.Nodes2};
}

std::string JEntryText(const JsonValue& V) {
  if (V.IsNull()) {
    return "missing";
  }
  return (V.Items().at(0).IsNull() ? std::string("<None>") : V.Items().at(0).AsString()) + "/" + V.Items().at(1).AsString();
}

std::string EntryText(const DiffSession& S, const std::optional<MatchedEntry>& E) {
  if (!E) {
    return "missing";
  }
  const auto Name = S.Ids().NameOrNone(E->Other);
  return (Name ? std::string(*Name) : std::string("<None>")) + "/" + Hex(E->Ratio);
}

std::string UnmatchedText(const std::optional<std::vector<SnapUnmatched>>& Rows) {
  if (!Rows) {
    return "None";
  }
  std::string Out = "[";
  for (const SnapUnmatched& R : *Rows) {
    Out += "(" + R.Ea + "," + R.Name.value_or("<None>") + ")";
  }
  return Out + "]";
}

std::optional<std::vector<SnapUnmatched>> JUnmatched(const JsonValue& V) {
  if (V.IsNull()) {
    return std::nullopt;
  }
  std::vector<SnapUnmatched> Out;
  for (const JsonValue& R : V.Items()) {
    Out.push_back(SnapUnmatched{R.Items().at(0).AsString(), JOpt(R.Items().at(1))});
  }
  return Out;
}

std::optional<std::vector<SnapUnmatched>> NativeUnmatched(const DiffSession& S,
                                                          const std::optional<std::vector<UnmatchedRow>>& Rows) {
  if (!Rows) {
    return std::nullopt;
  }
  std::vector<SnapUnmatched> Out;
  for (const UnmatchedRow& R : *Rows) {
    SnapUnmatched U;
    U.Ea = std::string(S.Ids().AddrKeyText(R.Ea));
    if (auto N = S.Ids().NameOrNone(R.Name)) {
      U.Name = std::string(*N);
    }
    Out.push_back(std::move(U));
  }
  return Out;
}

// A minimal export: `functions(id, name, address)` in the given order (rowid order), as TEXT or NULL.
std::string MakeFunctionsDb(const std::string& Path, const std::vector<std::pair<OptText, OptText>>& Rows) {
  std::error_code Error;
  fs::remove(DSig::Test::Utf8ToPath(Path), Error);
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(Path.c_str(), &Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    sqlite3_close(Db);
    return "cannot create " + Path;
  }
  std::string Failure;
  // db_support/schema.py:69-72: id integer primary key, name varchar(255), address text unique
  if (sqlite3_exec(Db, "create table functions (id integer primary key, name varchar(255), address text unique)", nullptr,
                   nullptr, nullptr) != SQLITE_OK) {
    Failure = sqlite3_errmsg(Db);
  }
  sqlite3_stmt* Insert = nullptr;
  if (Failure.empty() && sqlite3_prepare_v2(Db, "insert into functions (name, address) values (?, ?)", -1, &Insert,
                                            nullptr) != SQLITE_OK) {
    Failure = sqlite3_errmsg(Db);
  }
  for (const auto& [Name, Address] : Rows) {
    if (!Failure.empty()) {
      break;
    }
    const OptText* Values[2] = {&Name, &Address};
    for (int K = 0; K < 2; ++K) {
      if (*Values[K]) {
        sqlite3_bind_text(Insert, K + 1, (*Values[K])->data(), static_cast<int>((*Values[K])->size()), SQLITE_TRANSIENT);
      } else {
        sqlite3_bind_null(Insert, K + 1);
      }
    }
    if (sqlite3_step(Insert) != SQLITE_DONE) {
      Failure = sqlite3_errmsg(Db);
    }
    sqlite3_reset(Insert);
  }
  sqlite3_finalize(Insert);
  sqlite3_close(Db);
  return Failure;
}

struct VectorStats {
  int Cases = 0;
  int Ops = 0;
  int FailedCases = 0;
};

void ExpectText(const std::string& Actual, const std::string& Expected, const std::string& Where) {
  DSig::Test::ReportText(Actual == Expected, Where.c_str(), Actual, Expected, __FILE__, __LINE__);
}

std::string EventsText(const std::vector<JsonValue>& Events) {
  std::string Out;
  for (const JsonValue& E : Events) {
    if (E.At("ev").AsString() == "row") {
      Out += "row:" + E.At("decision").AsString() + ":" +
             (E.At("ratio_bits").IsNull() ? std::string("null") : E.At("ratio_bits").AsString()) + " ";
    } else {
      Out += "add:" + E.At("result").AsString() + ":" + E.At("ratio_bits").AsString() + ":" +
             (E.At("chooser").IsNull() ? std::string("null") : E.At("chooser").AsString()) + " ";
    }
  }
  return Out;
}

std::string ExpectedEventsText(const JsonValue& Events) {
  std::string Out;
  for (const JsonValue& E : Events.Items()) {
    const std::vector<JsonValue>& F = E.Items();
    if (F.at(0).AsString() == "row") {
      Out += "row:" + F.at(1).AsString() + ":" + (F.at(2).IsNull() ? std::string("null") : F.at(2).AsString()) + " ";
    } else {
      Out += "add:" + F.at(1).AsString() + ":" + F.at(2).AsString() + ":" +
             (F.at(3).IsNull() ? std::string("null") : F.at(3).AsString()) + " ";
    }
  }
  return Out;
}

void RunVectorOp(DiffSession& S, FakeRatio& Fake, const JsonValue& Op, const std::string& Where, const std::string& Scratch,
                 int CaseIndex) {
  (void)Fake;
  const std::string Kind = Op.At("op").AsString();
  const JsonValue& Expect = Op.At("expect");
  const std::string TracePath = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / "vector_trace.jsonl");
  if (Kind == "set_state") {
    StateSnapshot Snap = JState(Op.At("state"));
    Snap.Flags.TotalFunctions1 = S.State().Total1();
    Snap.Flags.TotalFunctions2 = S.State().Total2();
    S.State().Import(Snap);
  } else if (Kind == "set_totals") {
    S.State().SetTotals(Op.At("t1").AsInt64(), Op.At("t2").AsInt64());
  } else if (Kind == "add_match") {
    const NameId N1 = Nm(S, JOpt(Op.At("n1")));
    const NameId N2 = Nm(S, JOpt(Op.At("n2")));
    const std::optional<Chooser> C = JChooser(Op.At("chooser"));
    const Item It = ItemFromSnap(S, JItem(Op.At("item")));
    std::string Result;
    TraceCapture Cap(S, TracePath);
    if (ThrowsWouldRaise([&] { S.State().AddMatch(N1, N2, JRatio(Op.At("ratio")), It, C); })) {
      Result = "raised";
    }
    const std::vector<JsonValue> Events = Cap.Finish();
    if (Result.empty()) {
      Result = Events.size() == 1 ? Events[0].At("result").AsString() : "events:" + std::to_string(Events.size());
      if (Events.size() == 1) {
        ExpectText(Events[0].At("ratio_bits").AsString(), Op.At("ratio").AsString(), Where + " trace ratio_bits");
      }
    } else {
      ExpectText(std::to_string(Events.size()), "0", Where + " no event on raise");
    }
    ExpectText(Result, Expect.At("result").AsString(), Where + " result");
    ExpectText(EntryText(S, S.State().Primary(N1)), JEntryText(Expect.At("mp")), Where + " matched_primary[n1]");
    ExpectText(EntryText(S, S.State().Secondary(N2)), JEntryText(Expect.At("ms")), Where + " matched_secondary[n2]");
    if (C) {
      ExpectText(std::to_string(S.State().Items(*C).size()), std::to_string(Expect.At("len").AsInt64()), Where + " len");
    }
  } else if (Kind == "has_best_match") {
    const bool Value = S.State().HasBestMatch(Nm(S, JOpt(Op.At("n1"))), Nm(S, JOpt(Op.At("n2"))));
    ExpectText(Value ? "True" : "False", Expect.At("value").AsBool() ? "True" : "False", Where);
  } else if (Kind == "has_better_match") {
    bool Value = false;
    const bool Raised = ThrowsWouldRaise(
        [&] { Value = S.State().HasBetterMatch(Nm(S, JOpt(Op.At("n1"))), Nm(S, JOpt(Op.At("n2"))), JRatio(Op.At("ratio"))); });
    const std::string Actual = Raised ? "raised" : (Value ? "True" : "False");
    const std::string Expected =
        Expect.Find("raised") != nullptr ? "raised" : (Expect.At("value").AsBool() ? "True" : "False");
    ExpectText(Actual, Expected, Where);
  } else if (Kind == "all_functions_matched") {
    ExpectText(S.State().AllFunctionsMatched() ? "True" : "False", Expect.At("value").AsBool() ? "True" : "False", Where);
  } else if (Kind == "total_matched") {
    ExpectText(std::to_string(S.State().TotalMatchedFunctions()), std::to_string(Expect.At("value").AsInt64()), Where);
  } else if (Kind == "sorted_results") {
    const std::optional<Chooser> C = JChooser(Op.At("chooser"));
    ExpectText(ItemsText(SnapItems(S, S.State().SortedResults(*C))), ItemsText(JItems(Expect.At("items"))), Where);
  } else if (Kind == "cleanup") {
    S.State().Cleanup(CleanupSite::L3655);
    ExpectText(StateText(S.State().Export()), StateText(JState(Expect.At("state"))), Where);
  } else if (Kind == "state") {
    ExpectText(StateText(S.State().Export()), StateText(JState(Expect.At("state"))), Where);
  } else if (Kind == "final_pass") {
    const bool Raised = ThrowsWouldRaise([&] { StageFinalPass(S); });
    ExpectText(Raised ? "raised" : "ok", Expect.At("raised").IsNull() ? "ok" : "raised", Where + " raised");
    ExpectText(StateText(S.State().Export()), StateText(JState(Expect.At("state"))), Where + " state");
    const JsonValue& Choosers = Expect.At("choosers");
    ExpectText(ItemsText(SnapItems(S, S.Final().Best)), ItemsText(JItems(Choosers.At("best"))), Where + " best chooser");
    ExpectText(ItemsText(SnapItems(S, S.Final().Partial)), ItemsText(JItems(Choosers.At("partial"))), Where + " partial chooser");
    ExpectText(ItemsText(SnapItems(S, S.Final().Unreliable)), ItemsText(JItems(Choosers.At("unreliable"))),
               Where + " unreliable chooser");
    ExpectText(ItemsText(SnapItems(S, S.Final().Multimatch)), ItemsText(JItems(Choosers.At("multimatch"))),
               Where + " multimatch chooser");
  } else if (Kind == "consume") {
    std::vector<HeuristicRow> Rows;
    for (const JsonValue& R : Op.At("rows").Items()) {
      const std::vector<JsonValue>& F = R.Items();
      Rows.push_back(MakeRow(S, F.at(0).AsString(), JOpt(F.at(1)), F.at(2).AsString(), JOpt(F.at(3)), F.at(4).AsString(),
                             F.at(5).IsNull() ? std::optional<int64_t>() : std::optional<int64_t>(F.at(5).AsInt64()),
                             F.at(6).IsNull() ? std::optional<int64_t>() : std::optional<int64_t>(F.at(6).AsInt64())));
    }
    const JsonValue* MaxRows = Op.Find("maxrows");
    S.MutableConfig().MaxProcessedRows = MaxRows != nullptr ? MaxRows->AsInt64() : kSqlMaxProcessedRows;
    VectorRowSource Source(std::move(Rows));
    const std::string Which = Op.At("kind").AsString();
    const JsonValue* ValJson = Op.Find("val");
    const std::optional<double> Val =
        ValJson == nullptr || ValJson->IsNull() ? std::optional<double>() : std::optional<double>(ValJson->AsDouble());
    TraceCapture Cap(S, TracePath);
    const bool Raised = ThrowsWouldRaise([&] {
      if (Which == "internal") {
        AddMatchesInternal(S, Source, *JChooser(Op.At("best")), JChooser(Op.At("partial")), Val);
      } else if (Which == "from_query") {
        AddMatchesFromQuery(S, Source, *JChooser(Op.At("category")));
      } else if (Which == "ratio") {
        AddMatchesFromQueryRatio(S, Source, *JChooser(Op.At("best")), *JChooser(Op.At("partial")));
      } else if (Which == "ratio_max") {
        AddMatchesFromQueryRatioMax(S, Source, *JChooser(Op.At("best")), *JChooser(Op.At("partial")), Val.value());
      } else if (Which == "trusted") {
        AddMatchesFromQueryRatioMaxTrusted(S, Source, Val.value());
      } else {
        throw std::logic_error("unknown consume kind " + Which);
      }
    });
    S.MutableConfig().MaxProcessedRows = kSqlMaxProcessedRows;
    ExpectText(EventsText(Cap.Finish()), ExpectedEventsText(Expect.At("events")), Where + " events");
    ExpectText(Raised ? "raised" : "ok", Expect.At("raised").IsNull() ? "ok" : "raised", Where + " raised");
    ExpectText(std::to_string(Source.Fetched()), std::to_string(Expect.At("fetched").AsInt64()), Where + " fetched");
    const std::string NativeSizes = std::to_string(S.State().Items(Chooser::Best).size()) + "," +
                                    std::to_string(S.State().Items(Chooser::Partial).size()) + "," +
                                    std::to_string(S.State().Items(Chooser::Unreliable).size()) + "," +
                                    std::to_string(S.State().PrimarySize()) + "," + std::to_string(S.State().SecondarySize());
    std::string ExpectedSizes;
    for (const JsonValue& V : Expect.At("sizes").Items()) {
      ExpectedSizes += (ExpectedSizes.empty() ? "" : ",") + std::to_string(V.AsInt64());
    }
    ExpectText(NativeSizes, ExpectedSizes, Where + " sizes");
  } else if (Kind == "find_unmatched") {
    const auto Rows = [](const JsonValue& V) {
      std::vector<std::pair<OptText, OptText>> Out;
      for (const JsonValue& R : V.Items()) {
        Out.emplace_back(JOpt(R.Items().at(0)), JOpt(R.Items().at(1)));
      }
      return Out;
    };
    const fs::path Dir = DSig::Test::Utf8ToPath(Scratch);
    const std::string MainDb = DSig::Test::PathToUtf8(Dir / ("unmatched_main_" + std::to_string(CaseIndex) + ".sqlite"));
    const std::string DiffDb = DSig::Test::PathToUtf8(Dir / ("unmatched_diff_" + std::to_string(CaseIndex) + ".sqlite"));
    ExpectText(MakeFunctionsDb(MainDb, Rows(Op.At("main"))), "", Where + " main db");
    ExpectText(MakeFunctionsDb(DiffDb, Rows(Op.At("diff"))), "", Where + " diff db");
    S.Db().Open(MainDb, DiffDb);
    const bool Raised = ThrowsWouldRaise([&] { StageFindUnmatched(S); });
    S.Db().Close();
    ExpectText(Raised ? "raised" : "ok", Expect.At("raised").IsNull() ? "ok" : "raised", Where + " raised");
    ExpectText(UnmatchedText(NativeUnmatched(S, S.Final().UnmatchedPrimary)), UnmatchedText(JUnmatched(Expect.At("primary"))),
               Where + " primary (diff functions)");
    ExpectText(UnmatchedText(NativeUnmatched(S, S.Final().UnmatchedSecondary)),
               UnmatchedText(JUnmatched(Expect.At("secondary"))), Where + " secondary (main functions)");
  } else {
    DSig::Test::Report(false, ("unknown op " + Kind).c_str(), __FILE__, __LINE__);
  }
}

void RunVectorCase(const JsonValue& Case, const std::string& File, const std::string& Scratch, VectorStats& Stats) {
  DiffSession S;
  FakeRatio Fake(S);
  S.SetRatioProvider(&Fake);
  const std::string Name = Case.At("name").AsString();
  const std::vector<JsonValue>& Totals = Case.At("totals").Items();
  S.State().SetTotals(Totals.at(0).AsInt64(), Totals.at(1).AsInt64());
  for (const JsonValue& R : Case.At("ratios").Items()) {
    const JsonValue& Value = R.Items().at(2);
    Fake.Table[{R.Items().at(0).AsString(), R.Items().at(1).AsString()}] =
        Value.AsString() == "raise" ? std::optional<double>() : std::optional<double>(JRatio(Value));
  }
  const int FailedBefore = DSig::Test::ChecksFailed;
  int Index = 0;
  for (const JsonValue& Op : Case.At("ops").Items()) {
    const std::string Where = File + " " + Name + " op " + std::to_string(Index++) + " (" + Op.At("op").AsString() + ")";
    ++Stats.Ops;
    RunVectorOp(S, Fake, Op, Where, Scratch, Stats.Cases);
  }
  ++Stats.Cases;
  if (DSig::Test::ChecksFailed != FailedBefore) {
    ++Stats.FailedCases;
  }
}

void TestVectors(const std::string& Scratch) {
  DSig::Test::Suite("vectors from the real Diaphora (tests/diff/vectors/state)");
  const std::string Root = DSig::Test::TestDataDir();
  if (Root.empty()) {
    DSig::Test::Skip("state vectors", "DSIG_TEST_DATA_DIR is not set");
    return;
  }
  for (const char* File : {"probes.json", "random.json"}) {
    const fs::path Path = DSig::Test::Utf8ToPath(Root) / "vectors" / "state" / File;
    std::string Text;
    try {
      Text = Detail::ReadFileBytes(DSig::Test::PathToUtf8(Path));
    } catch (const IoFailure& Error) {
      DSig::Test::Report(false, ("cannot read " + DSig::Test::PathToUtf8(Path) + ": " + Error.What).c_str(), __FILE__,
                         __LINE__);
      continue;
    }
    const JsonValue Doc = JsonParse(Text);
    CHECK_TEXT_EQ(Doc.At("schema").AsString(), "dsig-state-vectors/1");
    VectorStats Stats;
    for (const JsonValue& Case : Doc.At("cases").Items()) {
      RunVectorCase(Case, File, Scratch, Stats);
    }
    DSig::Test::Note(std::string(File) + ": " + std::to_string(Stats.Cases) + " cases, " + std::to_string(Stats.Ops) +
                     " ops, " + std::to_string(Stats.FailedCases) + " failing cases (Diaphora " +
                     Doc.At("diaphora").AsString() + ")");
    CHECK(Stats.Cases > 0);
  }
}

// find_unmatched fetch errors (D:2332 fetchall decodes every TEXT cell) and refused storage classes.
void TestUnmatchedFetch(const std::string& Scratch) {
  DSig::Test::Suite("find_unmatched: fetch-time UTF-8 error, refused BLOB, label swap");
  const fs::path Dir = DSig::Test::Utf8ToPath(Scratch);
  const std::string MainDb = DSig::Test::PathToUtf8(Dir / "fetch_main.sqlite");
  const std::string DiffDb = DSig::Test::PathToUtf8(Dir / "fetch_diff.sqlite");
  CHECK_TEXT_EQ(MakeFunctionsDb(MainDb, {{OptText("a\xff"), OptText("10")}}), "");
  CHECK_TEXT_EQ(MakeFunctionsDb(DiffDb, {{OptText("b"), OptText("20")}}), "");
  {
    DiffSession S;
    S.Db().Open(MainDb, DiffDb);
    std::string Site;
    CHECK(ThrowsWouldRaise([&] { StageFindUnmatched(S); }, &Site));
    CHECK_TEXT_EQ(Site, "fetch");
    CHECK(!S.Final().UnmatchedSecondary.has_value());
  }
  {
    // a BLOB name is not a Python str; the port refuses it
    sqlite3* Db = nullptr;
    CHECK(sqlite3_open_v2(MainDb.c_str(), &Db, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    CHECK(sqlite3_exec(Db, "delete from functions; insert into functions (name, address) values (x'41', '10')", nullptr,
                       nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(Db);
    DiffSession S;
    S.Db().Open(MainDb, DiffDb);
    bool Refused = false;
    try {
      StageFindUnmatched(S);
    } catch (const UnsupportedInput&) {
      Refused = true;
    }
    CHECK(Refused);
  }
  {
    // labels: main functions -> UnmatchedSecondary (self.unmatched_second), diff -> UnmatchedPrimary
    CHECK_TEXT_EQ(MakeFunctionsDb(MainDb, {{OptText("m1"), OptText("1")}, {OptText("m2"), OptText("2")}}), "");
    CHECK_TEXT_EQ(MakeFunctionsDb(DiffDb, {{OptText("d1"), OptText("3")}}), "");
    DiffSession S;
    S.State().AddMatch(Nm(S, "m2"), Nm(S, "zz"), 0.9, MakeItem(S, "2", "m2", "9", "zz", "h", 0.9), Chooser::Partial);
    S.Db().Open(MainDb, DiffDb);
    StageFindUnmatched(S);
    CHECK_TEXT_EQ(UnmatchedText(NativeUnmatched(S, S.Final().UnmatchedSecondary)), "[(1,m1)]");
    CHECK_TEXT_EQ(UnmatchedText(NativeUnmatched(S, S.Final().UnmatchedPrimary)), "[(3,d1)]");
  }
}

}  // namespace

namespace {

// ---------------------------------------------------------------------------------------------
// Corpus replays on the oracle captures (S-L2)

// The export ids of a pair name "<ref>_vs_<target>", where the target may omit the ref's library
// prefix ("userenv-9168-pdb_vs_9278-nopdb" -> userenv-9278-nopdb).
std::optional<std::pair<std::string, std::string>> ExportIdsOfPair(const std::string& Pair) {
  const size_t Vs = Pair.find("_vs_");
  if (Vs == std::string::npos) {
    return std::nullopt;
  }
  const std::string Ref = Pair.substr(0, Vs);
  const std::string Tail = Pair.substr(Vs + 4);
  if (!DSig::Test::ExportAvailable(Ref)) {
    return std::nullopt;
  }
  if (DSig::Test::ExportAvailable(Tail)) {
    return std::make_pair(Ref, Tail);
  }
  const size_t Dash = Ref.find('-');
  if (Dash != std::string::npos && DSig::Test::ExportAvailable(Ref.substr(0, Dash + 1) + Tail)) {
    return std::make_pair(Ref, Ref.substr(0, Dash + 1) + Tail);
  }
  return std::nullopt;
}

// Runs find_unmatched's Path A query (kSqlUnmatchedMain, `select name, address from functions`) on
// an oracle export opened immutable=1 (no lock, no -wal/-shm is touched) and stores the rows, in the
// order that query returns them, as the rowid order of a scratch `functions(id, name, address)`
// table; the native stage then reads the scratch pair through the same verbatim SQL. The values
// keep their storage class (sqlite3_bind_value). Returns "" or an error; Plan gets the query plan.
std::string CopyUnmatchedRows(const std::string& ExportFile, const std::string& OutDb, std::string& Plan) {
  const std::string Uri = DiffDatabase::UriForPath(ExportFile, true) + "&immutable=1";
  sqlite3* Src = nullptr;
  if (sqlite3_open_v2(Uri.c_str(), &Src, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
    sqlite3_close(Src);
    return "cannot open " + ExportFile;
  }
  std::string Failure;
  const std::string Sql(kSqlUnmatchedMain);
  sqlite3_stmt* Explain = nullptr;
  if (sqlite3_prepare_v2(Src, ("explain query plan " + Sql).c_str(), -1, &Explain, nullptr) == SQLITE_OK) {
    while (sqlite3_step(Explain) == SQLITE_ROW) {
      Plan += (Plan.empty() ? "" : " / ") + std::string(reinterpret_cast<const char*>(sqlite3_column_text(Explain, 3)));
    }
  }
  sqlite3_finalize(Explain);
  std::error_code Error;
  fs::remove(DSig::Test::Utf8ToPath(OutDb), Error);
  sqlite3* Out = nullptr;
  if (sqlite3_open_v2(OutDb.c_str(), &Out, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
    Failure = "cannot create " + OutDb;
  }
  if (Failure.empty() &&
      sqlite3_exec(Out, "create table functions (id integer primary key, name varchar(255), address text unique); begin",
                   nullptr, nullptr, nullptr) != SQLITE_OK) {
    Failure = sqlite3_errmsg(Out);
  }
  sqlite3_stmt* Read = nullptr;
  sqlite3_stmt* Insert = nullptr;
  if (Failure.empty() && (sqlite3_prepare_v2(Src, Sql.c_str(), -1, &Read, nullptr) != SQLITE_OK ||
                          sqlite3_prepare_v2(Out, "insert into functions (name, address) values (?, ?)", -1, &Insert,
                                             nullptr) != SQLITE_OK)) {
    Failure = "prepare failed";
  }
  while (Failure.empty() && sqlite3_step(Read) == SQLITE_ROW) {
    sqlite3_bind_value(Insert, 1, sqlite3_column_value(Read, 0));
    sqlite3_bind_value(Insert, 2, sqlite3_column_value(Read, 1));
    if (sqlite3_step(Insert) != SQLITE_DONE) {
      Failure = sqlite3_errmsg(Out);
    }
    sqlite3_reset(Insert);
  }
  sqlite3_finalize(Read);
  sqlite3_finalize(Insert);
  if (Failure.empty() && sqlite3_exec(Out, "commit", nullptr, nullptr, nullptr) != SQLITE_OK) {
    Failure = sqlite3_errmsg(Out);
  }
  sqlite3_close(Out);
  sqlite3_close(Src);
  return Failure;
}

struct SnapshotFile {
  int64_t Seq = 0;
  std::string Path;
};

// snapshots/NNNNN_<sanitised point>.json of a capture, by sanitised point. Only finished files are
// listed: the oracle writes <name>.tmp and renames it (snapshot.py WriteJsonAtomic), so a .json
// file is complete, and a snapshot is never rewritten.
std::map<std::string, SnapshotFile> ListSnapshots(const fs::path& Dir) {
  static const std::regex Pattern("^([0-9]{5,})_(.+)\\.json$");
  std::map<std::string, SnapshotFile> Out;
  std::error_code Error;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Dir, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    std::smatch Match;
    if (!std::regex_match(Name, Match, Pattern)) {
      continue;
    }
    Out.try_emplace(Match[2].str(), SnapshotFile{std::stoll(Match[1].str()), DSig::Test::PathToUtf8(Entry.path())});
  }
  return Out;
}

struct ReplayCounts {
  int CleanupRun = 0;
  int CleanupPassed = 0;
  int FinalRun = 0;
  int FinalPassed = 0;
  int UnmatchedRun = 0;
  int UnmatchedPassed = 0;
};

bool CheckReplay(const std::string& What, const StateSnapshot& Oracle, const StateSnapshot& Native) {
  const DSig::Test::CompareReport Report = DSig::Test::CompareSnapshots(Oracle, Native, 10);
  DSig::Test::Report(Report.L2Equal, What.c_str(), __FILE__, __LINE__);
  if (!Report.L2Equal) {
    for (const std::string& Line : Report.Differences) {
      DSig::Test::Note("    " + Line);
    }
  }
  return Report.L2Equal;
}

ReplayCounts ReplayCapture(const std::string& Pair, const fs::path& Dir, const std::string& Scratch) {
  ReplayCounts Counts;
  const std::map<std::string, SnapshotFile> Files = ListSnapshots(Dir / "snapshots");
  // every before:cleanup:<site>:<n> whose after:cleanup:<site>:<n> exists, in point order
  static const std::regex CleanupPattern("^before_cleanup_([0-9]+)_([0-9]+)$");
  std::vector<std::tuple<int64_t, std::string, const SnapshotFile*, const SnapshotFile*>> Cleanups;
  for (const auto& [Name, File] : Files) {
    std::smatch Match;
    if (!std::regex_match(Name, Match, CleanupPattern)) {
      continue;
    }
    const auto After = Files.find("after_cleanup_" + Match[1].str() + "_" + Match[2].str());
    if (After != Files.end()) {
      Cleanups.emplace_back(File.Seq, "cleanup:" + Match[1].str() + ":" + Match[2].str(), &File, &After->second);
    }
  }
  std::sort(Cleanups.begin(), Cleanups.end(),
            [](const auto& A, const auto& B) { return std::get<0>(A) < std::get<0>(B); });
  for (const auto& [Seq, Base, BeforeFile, AfterFile] : Cleanups) {
    const StateSnapshot Before = ReadSnapshot(BeforeFile->Path);
    const StateSnapshot After = ReadSnapshot(AfterFile->Path);
    ++Counts.CleanupRun;
    CHECK_TEXT_EQ(Before.Point, "before:" + Base);
    DiffSession S;
    const StateSnapshot Native = RunReplay(S, Before, Base);
    if (CheckReplay(Pair + " " + Base, After, Native)) {
      ++Counts.CleanupPassed;
    }
  }
  // before:final_pass -> final pass -> after:final_pass (state and the raw chooser dumps)
  const auto BeforeFinal = Files.find("before_final_pass");
  const auto AfterFinal = Files.find("after_final_pass");
  if (BeforeFinal != Files.end() && AfterFinal != Files.end()) {
    const StateSnapshot Before = ReadSnapshot(BeforeFinal->second.Path);
    const StateSnapshot After = ReadSnapshot(AfterFinal->second.Path);
    ++Counts.FinalRun;
    CHECK(After.Choosers.has_value());
    DiffSession S;
    const StateSnapshot Native = RunReplay(S, Before, "final_pass");
    if (CheckReplay(Pair + " final_pass", After, Native)) {
      ++Counts.FinalPassed;
    }
    if (After.Choosers) {
      DSig::Test::Note(Pair + " final_pass choosers: best " + std::to_string(After.Choosers->Best.size()) + ", partial " +
                       std::to_string(After.Choosers->Partial.size()) + ", unreliable " +
                       std::to_string(After.Choosers->Unreliable.size()) + ", multimatch " +
                       std::to_string(After.Choosers->Multimatch.size()));
    }
  }
  // after:final_pass -> find_unmatched -> after:find_unmatched (needs the two exports)
  const auto AfterUnmatched = Files.find("after_find_unmatched");
  const auto Ids = ExportIdsOfPair(Pair);
  if (AfterFinal != Files.end() && AfterUnmatched != Files.end()) {
    if (!Ids) {
      DSig::Test::Note(Pair + " find_unmatched: skipped (exports not found)");
    } else {
      const fs::path Work = DSig::Test::Utf8ToPath(Scratch);
      const std::string MainDb = DSig::Test::PathToUtf8(Work / (Pair + "_main.sqlite"));
      const std::string DiffDb = DSig::Test::PathToUtf8(Work / (Pair + "_diff.sqlite"));
      std::string PlanMain;
      std::string PlanDiff;
      CHECK_TEXT_EQ(CopyUnmatchedRows(DSig::Test::ExportPath(Ids->first), MainDb, PlanMain), "");
      CHECK_TEXT_EQ(CopyUnmatchedRows(DSig::Test::ExportPath(Ids->second), DiffDb, PlanDiff), "");
      CHECK_TEXT_EQ(PlanMain, "SCAN functions");  // 01 §10.3 V7: a table scan in rowid order
      CHECK_TEXT_EQ(PlanDiff, "SCAN functions");
      const StateSnapshot Before = ReadSnapshot(AfterFinal->second.Path);
      const StateSnapshot After = ReadSnapshot(AfterUnmatched->second.Path);
      ++Counts.UnmatchedRun;
      DiffSession S;
      S.Db().Open(MainDb, DiffDb);
      const StateSnapshot Native = RunReplay(S, Before, "find_unmatched");
      S.Db().Close();
      if (CheckReplay(Pair + " find_unmatched", After, Native)) {
        ++Counts.UnmatchedPassed;
      }
      if (After.Unmatched) {
        const auto Size = [](const std::optional<std::vector<SnapUnmatched>>& Rows) {
          return Rows ? std::to_string(Rows->size()) : std::string("None");
        };
        DSig::Test::Note(Pair + " find_unmatched: primary (diff) " + Size(After.Unmatched->Primary) + ", secondary (main) " +
                         Size(After.Unmatched->Secondary));
      }
    }
  }
  return Counts;
}

// ---------------------------------------------------------------------------------------------
// Corpus consumer replays: every SQL heuristic of a capture recorded with --rows, re-consumed from its
// row events. The rows are exactly the ones the oracle's cursor fetched (one row event per
// check_match call, every fetched row calls check_match: D:1901-1906, D:2058-2063); names and nodes
// come from the exports (f.name name1 / f.nodes nodes1, H:51-56), the ratios check_match computed
// from the row events (a scripted provider: a nullsub / has_best row must never ask for one). The
// state goes from before:heuristic:<id> through the heuristic's add_matches_* wrapper (dispatched by
// the registry's ratio type, D:1524-1535) and must equal after:heuristic:<id> at S-L2, with the same
// row decisions and add_match results as the oracle's trace, event for event.

struct FunctionFacts {
  std::string Name;
  bool NameNull = false;
  std::optional<int64_t> Nodes;
};

// address TEXT -> (name, nodes) of one export, read through an immutable=1 connection.
std::map<std::string, FunctionFacts> ReadFunctionFacts(const std::string& ExportFile, std::string& Failure) {
  std::map<std::string, FunctionFacts> Out;
  const std::string Uri = DiffDatabase::UriForPath(ExportFile, true) + "&immutable=1";
  sqlite3* Db = nullptr;
  if (sqlite3_open_v2(Uri.c_str(), &Db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
    sqlite3_close(Db);
    Failure = "cannot open " + ExportFile;
    return Out;
  }
  sqlite3_stmt* Q = nullptr;
  if (sqlite3_prepare_v2(Db, "select address, name, nodes from functions", -1, &Q, nullptr) != SQLITE_OK) {
    Failure = sqlite3_errmsg(Db);
  }
  while (Failure.empty() && sqlite3_step(Q) == SQLITE_ROW) {
    FunctionFacts F;
    F.NameNull = sqlite3_column_type(Q, 1) == SQLITE_NULL;
    if (!F.NameNull) {
      F.Name.assign(reinterpret_cast<const char*>(sqlite3_column_text(Q, 1)), static_cast<size_t>(sqlite3_column_bytes(Q, 1)));
    }
    if (sqlite3_column_type(Q, 2) == SQLITE_INTEGER) {
      F.Nodes = sqlite3_column_int64(Q, 2);
    }
    const std::string Address(reinterpret_cast<const char*>(sqlite3_column_text(Q, 0)), static_cast<size_t>(sqlite3_column_bytes(Q, 0)));
    Out.emplace(Address, std::move(F));
  }
  sqlite3_finalize(Q);
  sqlite3_close(Db);
  return Out;
}

struct HeuristicSegment {
  int Id = -1;
  std::vector<JsonValue> Events;  // the row and add_match events between its two points
};

// The trace up to the loop's first cleanup (D:3655) or the final pass: every heuristic of the Best and
// Partial categories runs before them. Streams the file and stops there, so a long capture's trace
// (hundreds of MB, possibly still growing) is only read up to that point.
std::vector<HeuristicSegment> ReadHeuristicSegments(const std::string& TracePath, bool& HasRows) {
  std::vector<HeuristicSegment> Out;
  std::ifstream In(DSig::Test::Utf8ToPath(TracePath), std::ios::binary);
  std::string Line;
  HeuristicSegment* Open = nullptr;
  HasRows = false;
  static const std::string BeforeHeur = "\"name\":\"before:heuristic:";
  while (std::getline(In, Line)) {
    if (Line.find("\"ev\":\"point\"") != std::string::npos) {
      if (Line.find("\"name\":\"before:cleanup:3655:1\"") != std::string::npos ||
          Line.find("\"name\":\"before:final_pass\"") != std::string::npos) {
        break;
      }
      const size_t At = Line.find(BeforeHeur);
      if (At != std::string::npos) {
        Out.push_back(HeuristicSegment{std::stoi(Line.substr(At + BeforeHeur.size())), {}});
        Open = &Out.back();
      } else if (Line.find("\"name\":\"after:heuristic:") != std::string::npos) {
        Open = nullptr;
      }
      continue;
    }
    if (Open != nullptr && (Line.find("\"ev\":\"row\"") != std::string::npos ||
                            Line.find("\"ev\":\"add_match\"") != std::string::npos)) {
      JsonValue Event = JsonParse(Line);
      if (Event.At("ev").AsString() == "row") {
        HasRows = true;
      }
      Open->Events.push_back(std::move(Event));
    }
  }
  return Out;
}

struct ConsumerCounts {
  int Run = 0;
  int Passed = 0;
  int Rows = 0;
  int Adds = 0;
};

ConsumerCounts ReplayHeuristics(const std::string& Pair, const fs::path& Dir, const std::string& Scratch) {
  ConsumerCounts Counts;
  const auto Ids = ExportIdsOfPair(Pair);
  if (!Ids) {
    DSig::Test::Note(Pair + " heuristic consumer replays: skipped (exports not found)");
    return Counts;
  }
  bool HasRows = false;
  const std::vector<HeuristicSegment> Segments =
      ReadHeuristicSegments(DSig::Test::PathToUtf8(Dir / "trace.jsonl"), HasRows);
  if (Segments.empty() || !HasRows) {
    DSig::Test::Note(Pair + " heuristic consumer replays: none (no heuristic ran, or no row events)");
    return Counts;
  }
  std::string Failure;
  const std::map<std::string, FunctionFacts> Main = ReadFunctionFacts(DSig::Test::ExportPath(Ids->first), Failure);
  const std::map<std::string, FunctionFacts> Diff = ReadFunctionFacts(DSig::Test::ExportPath(Ids->second), Failure);
  CHECK_TEXT_EQ(Failure, "");
  const std::map<std::string, SnapshotFile> Files = ListSnapshots(Dir / "snapshots");
  const std::string TracePath = DSig::Test::PathToUtf8(DSig::Test::Utf8ToPath(Scratch) / "consumer_trace.jsonl");
  for (const HeuristicSegment& Segment : Segments) {
    const std::string Label = "heuristic:" + std::to_string(Segment.Id);
    const auto Before = Files.find("before_heuristic_" + std::to_string(Segment.Id));
    const auto After = Files.find("after_heuristic_" + std::to_string(Segment.Id));
    if (Before == Files.end() || After == Files.end()) {
      continue;
    }
    const HeuristicSpec& Spec = Heuristic(Segment.Id);
    DiffSession S;
    FakeRatio Fake(S);
    S.SetRatioProvider(&Fake);
    S.Restore(ReadSnapshot(Before->second.Path));
    // the rows, in fetch order
    std::vector<HeuristicRow> Rows;
    bool Complete = true;
    for (size_t K = 0; K < Segment.Events.size(); ++K) {
      const JsonValue& E = Segment.Events[K];
      if (E.At("ev").AsString() != "row") {
        continue;
      }
      const std::string Ea1 = E.At("ea1").AsString();
      const std::string Ea2 = E.At("ea2").AsString();
      const auto F1 = Main.find(Ea1);
      const auto F2 = Diff.find(Ea2);
      if (F1 == Main.end() || F2 == Diff.end()) {
        Complete = false;
        break;
      }
      // the description of an accepted row is the one its add_match carries (H10's UNION branches
      // differ from the heuristic name); a rejected row's description is never read
      std::string Desc(Spec.Name);
      if (K + 1 < Segment.Events.size() && Segment.Events[K + 1].At("ev").AsString() == "add_match") {
        Desc = Segment.Events[K + 1].At("desc").AsString();
      }
      Rows.push_back(MakeRow(S, Ea1, F1->second.NameNull ? OptText() : OptText(F1->second.Name), Ea2,
                             F2->second.NameNull ? OptText() : OptText(F2->second.Name), Desc, F1->second.Nodes,
                             F2->second.Nodes));
      if (!E.At("ratio_bits").IsNull()) {
        Fake.Table[{Ea1, Ea2}] = JRatio(E.At("ratio_bits"));
      }
    }
    CHECK(Complete);
    if (!Complete) {
      continue;
    }
    ++Counts.Run;
    Counts.Rows += static_cast<int>(Rows.size());
    VectorRowSource Source(std::move(Rows));
    std::string Actual;
    {
      ContextScope Scope(S, Label);
      TraceCapture Cap(S, TracePath);
      try {
        switch (Spec.RatioType) {  // D:1524-1535 with best="best", partial="partial" (D:1513-1515)
          case HeurType::NoFps:
            AddMatchesFromQuery(S, Source, Chooser::Best);
            break;
          case HeurType::Ratio:
            AddMatchesFromQueryRatio(S, Source, Chooser::Best, Chooser::Partial);
            break;
          case HeurType::RatioMax:
            AddMatchesFromQueryRatioMax(S, Source, Chooser::Best, Chooser::Partial, Spec.Min);
            break;
          case HeurType::RatioMaxTrusted:
            AddMatchesFromQueryRatioMaxTrusted(S, Source, Spec.Min);
            break;
        }
      } catch (const std::exception& Error) {
        DSig::Test::Report(false, (Pair + " " + Label + " threw: " + Error.what()).c_str(), __FILE__, __LINE__);
      }
      for (const JsonValue& E : Cap.Finish()) {
        Actual += JsonWrite(E) + "\n";
      }
    }
    std::string Expected;
    for (const JsonValue& E : Segment.Events) {
      // the oracle's add_match seq counts the whole run; compare everything else byte for byte
      JsonValue Copy = E;
      if (Copy.Find("seq") != nullptr) {
        Copy.Set("seq", JsonValue::Int(0));
      }
      Expected += JsonWrite(Copy) + "\n";
      Counts.Adds += Copy.At("ev").AsString() == "add_match" ? 1 : 0;
    }
    {
      // the native seq restarts in this fresh session; neutralise it the same way
      std::string Normalised;
      std::istringstream Lines(Actual);
      std::string Line;
      while (std::getline(Lines, Line)) {
        JsonValue E = JsonParse(Line);
        if (E.Find("seq") != nullptr) {
          E.Set("seq", JsonValue::Int(0));
        }
        Normalised += JsonWrite(E) + "\n";
      }
      Actual = std::move(Normalised);
    }
    bool EventsEqual = Actual == Expected;
    ExpectText(EventsEqual ? "equal" : Actual.substr(0, 2000), EventsEqual ? "equal" : Expected.substr(0, 2000),
               Pair + " " + Label + " trace events");
    const StateSnapshot Native = S.Snapshot("after:" + Label);
    if (CheckReplay(Pair + " " + Label + " state", ReadSnapshot(After->second.Path), Native) && EventsEqual) {
      ++Counts.Passed;
    }
  }
  return Counts;
}

void TestCorpusReplays(const std::string& Scratch) {
  DSig::Test::Suite("corpus replays (S-L2): cleanup, final_pass, find_unmatched, heuristic consumers");
  if (!DSig::Test::CorpusRoot()) {
    DSig::Test::Skip("corpus replays", "DSIG_CORPUS_ROOT is not set");
    return;
  }
  const fs::path Traces = DSig::Test::Utf8ToPath(DSig::Test::OracleDir()) / "traces";
  std::error_code Error;
  if (!fs::is_directory(Traces, Error)) {
    DSig::Test::Skip("corpus replays", "no oracle captures under " + DSig::Test::PathToUtf8(Traces));
    return;
  }
  std::vector<std::string> Names;
  for (const fs::directory_entry& Entry : fs::directory_iterator(Traces, Error)) {
    const std::string Name = DSig::Test::PathToUtf8(Entry.path().filename());
    if (Entry.is_directory(Error) && !Name.empty() && Name[0] != '_') {
      Names.push_back(Name);
    }
  }
  std::sort(Names.begin(), Names.end());
  int Captures = 0;
  for (const std::string& Name : Names) {
    const fs::path Dir = Traces / DSig::Test::Utf8ToPath(Name);
    std::string Pair = Name;
    const std::string Full = ".full";
    if (Name.size() > Full.size() && Name.compare(Name.size() - Full.size(), Full.size(), Full) == 0) {
      // A full re-capture: only used once it has finished. While it runs, its run.json / index.json
      // are not read at all; the finished markers are the instrumented .diaphora and the removed
      // work/ copies (tools/parity/README.md "oracle_trace.py run" step 5).
      Pair = Name.substr(0, Name.size() - Full.size());
      bool Complete = fs::exists(Dir / DSig::Test::Utf8ToPath(Pair + ".diaphora"), Error) && !fs::exists(Dir / "work", Error);
      if (Complete) {
        try {
          const JsonValue Run = JsonParse(Detail::ReadFileBytes(DSig::Test::PathToUtf8(Dir / "run.json")));
          Complete = Run.At("status").AsString() == "complete";
        } catch (const std::exception&) {
          Complete = false;
        }
      }
      if (!Complete) {
        DSig::Test::Note(Name + ": skipped (full capture not finished; its run.json was not read)");
        continue;
      }
    }
    if (!fs::is_directory(Dir / "snapshots", Error)) {
      continue;
    }
    ++Captures;
    const ReplayCounts C = ReplayCapture(Pair, Dir, Scratch);
    const ConsumerCounts H = ReplayHeuristics(Pair, Dir, Scratch);
    DSig::Test::Note(Name + ": cleanup " + std::to_string(C.CleanupPassed) + "/" + std::to_string(C.CleanupRun) +
                     ", final_pass " + std::to_string(C.FinalPassed) + "/" + std::to_string(C.FinalRun) +
                     ", find_unmatched " + std::to_string(C.UnmatchedPassed) + "/" + std::to_string(C.UnmatchedRun) +
                     ", heuristic consumers " + std::to_string(H.Passed) + "/" + std::to_string(H.Run) + " (" +
                     std::to_string(H.Rows) + " rows, " + std::to_string(H.Adds) + " add_match events) replays passed");
  }
  if (Captures == 0) {
    DSig::Test::Skip("corpus replays", "no capture has snapshots");
  }
}

void Run(const char* Name, const std::function<void()>& F) {
  try {
    F();
  } catch (const std::exception& Error) {
    DSig::Test::Report(false, (std::string(Name) + " threw: " + Error.what()).c_str(), __FILE__, __LINE__);
  }
}

}  // namespace

int main() {
  const std::string Scratch = DSig::Test::ScratchDir("diff_state");
  Run("probe 1", TestProbe1);
  Run("probe 10", TestProbe10);
  Run("probe 6", TestProbe6);
  Run("wrappers", TestWrappers);
  Run("None names", TestNoneNames);
  Run("E2", TestE2);
  Run("KeyError", TestKeyErrorAnalysis);
  Run("ignore only on add", TestIgnoreOnlyOnNewAdd);
  Run("int()", TestPyIntText);
  Run("counters", TestCountersAndSorting);
  Run("export/import", TestExportImport);
  Run("trace", [&] { TestTraceEvents(Scratch); });
  Run("unmatched fetch", [&] { TestUnmatchedFetch(Scratch); });
  Run("vectors", [&] { TestVectors(Scratch); });
  Run("corpus", [&] { TestCorpusReplays(Scratch); });
  DSig::Test::RemoveScratchDir(Scratch);
  return DSig::Test::Finish();
}
