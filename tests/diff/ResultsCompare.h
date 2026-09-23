#pragma once

// Result and snapshot comparison for C++ tests (plan §1.3):
//   L1   results as a multiset of (type, address, address2, name, name2, ratio, nodes1, nodes2,
//        description) and unmatched as a multiset of (type, address, name);
//   L2   L1 plus identical `line` values and stored row order (`order by rowid`) in both tables;
//   DDL  the sqlite_master (type, name, tbl_name, sql) rows;
//   S-L2 snapshots: all_matches lists in order with every field (ratios bit-exact), matched_primary /
//        matched_secondary as maps, the flags, and the choosers / unmatched dumps when present.
// config.date is always ignored; config.main_db / diff_db only when CompareConfigPaths is set.

#include <algorithm>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "dsigmatcher/diff/Database.h"
#include "dsigmatcher/diff/Snapshot.h"

namespace DSig::Test {

struct ResultsRow {
  std::string Type, Line, Address, Name, Address2, Name2, Ratio, Nodes1, Nodes2, Description;
  bool NameNull = false;
  bool Name2Null = false;
  auto Key() const {
    return std::tie(Type, Address, Address2, Name, Name2, Ratio, Nodes1, Nodes2, Description, NameNull, Name2Null);
  }
};

struct UnmatchedRowText {
  std::string Type, Line, Address, Name;
  bool NameNull = false;
  auto Key() const { return std::tie(Type, Address, Name, NameNull); }
};

struct SchemaRow {
  std::string Type, Name, TblName, Sql;
  bool operator==(const SchemaRow&) const = default;
};

struct ResultsFile {
  std::vector<SchemaRow> Schema;               // order by rowid
  std::vector<std::vector<std::string>> Config;  // main_db, diff_db, version, date
  std::vector<ResultsRow> Results;             // order by rowid
  std::vector<UnmatchedRowText> Unmatched;     // order by rowid
  bool AllText = true;                         // every results/unmatched value is TEXT (or NULL name)
  std::string Error;
};

inline ResultsFile ReadResultsFile(const std::string& Path) {
  ResultsFile File;
  Diff::DiffDatabase Db;
  try {
    Db.OpenSingle(Path);
    const auto Text = [](const Diff::Statement& S, int C) { return std::string(S.Text(C)); };
    {
      Diff::Statement S = Db.Prepare("select type, name, tbl_name, sql from sqlite_master order by rowid");
      while (S.Step()) {
        File.Schema.push_back(SchemaRow{Text(S, 0), Text(S, 1), Text(S, 2), Text(S, 3)});
      }
    }
    {
      Diff::Statement S = Db.Prepare("select main_db, diff_db, version, date from config order by rowid");
      while (S.Step()) {
        File.Config.push_back({Text(S, 0), Text(S, 1), Text(S, 2), Text(S, 3)});
      }
    }
    {
      Diff::Statement S = Db.Prepare(
          "select type, line, address, name, address2, name2, ratio, nodes1, nodes2, description from results "
          "order by rowid");
      while (S.Step()) {
        for (int C = 0; C < 10; ++C) {
          if (S.Type(C) != Diff::SqlType::Text && !(S.Type(C) == Diff::SqlType::Null && (C == 3 || C == 5))) {
            File.AllText = false;
          }
        }
        ResultsRow Row;
        Row.Type = Text(S, 0);
        Row.Line = Text(S, 1);
        Row.Address = Text(S, 2);
        Row.Name = Text(S, 3);
        Row.Address2 = Text(S, 4);
        Row.Name2 = Text(S, 5);
        Row.Ratio = Text(S, 6);
        Row.Nodes1 = Text(S, 7);
        Row.Nodes2 = Text(S, 8);
        Row.Description = Text(S, 9);
        Row.NameNull = S.IsNull(3);
        Row.Name2Null = S.IsNull(5);
        File.Results.push_back(std::move(Row));
      }
    }
    {
      Diff::Statement S = Db.Prepare("select type, line, address, name from unmatched order by rowid");
      while (S.Step()) {
        for (int C = 0; C < 4; ++C) {
          if (S.Type(C) != Diff::SqlType::Text && !(S.Type(C) == Diff::SqlType::Null && C == 3)) {
            File.AllText = false;
          }
        }
        UnmatchedRowText Row;
        Row.Type = Text(S, 0);
        Row.Line = Text(S, 1);
        Row.Address = Text(S, 2);
        Row.Name = Text(S, 3);
        Row.NameNull = S.IsNull(3);
        File.Unmatched.push_back(std::move(Row));
      }
    }
  } catch (const std::exception& Failure) {
    File.Error = Failure.what();
  }
  return File;
}

struct CompareReport {
  bool DdlEqual = true;
  bool L1Equal = true;
  bool L2Equal = true;
  std::vector<std::string> Differences;  // at most MaxDiffs entries

  void Note(size_t MaxDiffs, const std::string& Text) {
    if (Differences.size() < MaxDiffs) {
      Differences.push_back(Text);
    }
  }
};

inline std::string Describe(const ResultsRow& R) {
  return R.Type + " " + R.Line + " " + R.Address + " " + (R.NameNull ? "None" : R.Name) + " " + R.Address2 + " " +
         (R.Name2Null ? "None" : R.Name2) + " " + R.Ratio + " " + R.Nodes1 + " " + R.Nodes2 + " " + R.Description;
}

inline CompareReport CompareResults(const ResultsFile& Oracle, const ResultsFile& Native, size_t MaxDiffs = 20,
                                    bool CompareConfigPaths = false) {
  CompareReport Report;
  if (!Oracle.Error.empty() || !Native.Error.empty()) {
    Report.DdlEqual = Report.L1Equal = Report.L2Equal = false;
    Report.Note(MaxDiffs, "read error: oracle '" + Oracle.Error + "' native '" + Native.Error + "'");
    return Report;
  }
  if (Oracle.Schema != Native.Schema) {
    Report.DdlEqual = false;
    Report.Note(MaxDiffs, "sqlite_master differs");
  }
  if (Oracle.Config.size() != Native.Config.size()) {
    Report.L1Equal = Report.L2Equal = false;
    Report.Note(MaxDiffs, "config row count differs");
  } else {
    for (size_t I = 0; I < Oracle.Config.size(); ++I) {
      const bool Same = Oracle.Config[I][2] == Native.Config[I][2] &&
                        (!CompareConfigPaths ||
                         (Oracle.Config[I][0] == Native.Config[I][0] && Oracle.Config[I][1] == Native.Config[I][1]));
      if (!Same) {
        Report.L1Equal = Report.L2Equal = false;
        Report.Note(MaxDiffs, "config row differs");
      }
    }
  }
  // L1: multisets
  auto SortedResults = [](std::vector<ResultsRow> Rows) {
    std::sort(Rows.begin(), Rows.end(), [](const ResultsRow& A, const ResultsRow& B) { return A.Key() < B.Key(); });
    return Rows;
  };
  auto SortedUnmatched = [](std::vector<UnmatchedRowText> Rows) {
    std::sort(Rows.begin(), Rows.end(),
              [](const UnmatchedRowText& A, const UnmatchedRowText& B) { return A.Key() < B.Key(); });
    return Rows;
  };
  const auto O1 = SortedResults(Oracle.Results);
  const auto N1 = SortedResults(Native.Results);
  if (O1.size() != N1.size() ||
      !std::equal(O1.begin(), O1.end(), N1.begin(), [](const ResultsRow& A, const ResultsRow& B) { return A.Key() == B.Key(); })) {
    Report.L1Equal = Report.L2Equal = false;
    Report.Note(MaxDiffs, "results multiset differs (" + std::to_string(O1.size()) + " oracle rows, " +
                              std::to_string(N1.size()) + " native rows)");
  }
  const auto O2 = SortedUnmatched(Oracle.Unmatched);
  const auto N2 = SortedUnmatched(Native.Unmatched);
  if (O2.size() != N2.size() || !std::equal(O2.begin(), O2.end(), N2.begin(), [](const UnmatchedRowText& A,
                                                                              const UnmatchedRowText& B) {
        return A.Key() == B.Key();
      })) {
    Report.L1Equal = Report.L2Equal = false;
    Report.Note(MaxDiffs, "unmatched multiset differs");
  }
  // L2: rowid order and line values
  const size_t Rows = std::min(Oracle.Results.size(), Native.Results.size());
  for (size_t I = 0; I < Rows; ++I) {
    const ResultsRow& A = Oracle.Results[I];
    const ResultsRow& B = Native.Results[I];
    if (A.Key() != B.Key() || A.Line != B.Line) {
      Report.L2Equal = false;
      Report.Note(MaxDiffs, "results row " + std::to_string(I) + ": oracle [" + Describe(A) + "] native [" +
                                Describe(B) + "]");
    }
  }
  if (Oracle.Results.size() != Native.Results.size()) {
    Report.L2Equal = false;
  }
  const size_t UnRows = std::min(Oracle.Unmatched.size(), Native.Unmatched.size());
  for (size_t I = 0; I < UnRows; ++I) {
    const UnmatchedRowText& A = Oracle.Unmatched[I];
    const UnmatchedRowText& B = Native.Unmatched[I];
    if (A.Key() != B.Key() || A.Line != B.Line) {
      Report.L2Equal = false;
      Report.Note(MaxDiffs, "unmatched row " + std::to_string(I) + " differs: oracle " + A.Type + " " + A.Line +
                                " " + A.Address + " native " + B.Type + " " + B.Line + " " + B.Address);
    }
  }
  if (Oracle.Unmatched.size() != Native.Unmatched.size()) {
    Report.L2Equal = false;
  }
  return Report;
}

// S-L2 snapshot comparison. With CompareLabels (the default) the point name and the outer-loop
// iteration must match too, as tools/parity/snapshot.py CompareSnapshots requires; seq, producer and
// pair are never compared.
inline CompareReport CompareSnapshots(const Diff::StateSnapshot& Oracle, const Diff::StateSnapshot& Native,
                                      size_t MaxDiffs = 20, bool CompareLabels = true) {
  CompareReport Report;
  const auto Fail = [&](const std::string& Text) {
    Report.L2Equal = false;
    Report.L1Equal = false;
    Report.Note(MaxDiffs, Text);
  };
  if (CompareLabels) {
    if (Oracle.Point != Native.Point) {
      Fail("point: oracle " + Oracle.Point + " native " + Native.Point);
    }
    if (Oracle.Iteration != Native.Iteration) {
      const auto Text = [](const std::optional<int64_t>& I) { return I ? std::to_string(*I) : std::string("null"); };
      Fail("iteration: oracle " + Text(Oracle.Iteration) + " native " + Text(Native.Iteration));
    }
  }
  const auto ItemText = [](const Diff::SnapItem& I) {
    return I.Ea1 + "," + I.Name1.value_or("None") + "," + I.Ea2 + "," + I.Name2.value_or("None") + "," + I.Desc +
           "," + Diff::RatioBitsHex(Diff::RatioFromBits(I.RatioBits)) + "," + std::to_string(I.Nodes1) + "," +
           std::to_string(I.Nodes2);
  };
  const auto Lists = [&](const char* Name, const std::vector<Diff::SnapItem>& A, const std::vector<Diff::SnapItem>& B) {
    if (A.size() != B.size()) {
      Fail(std::string(Name) + ": " + std::to_string(A.size()) + " oracle items, " + std::to_string(B.size()) +
           " native items");
    }
    const size_t N = std::min(A.size(), B.size());
    for (size_t I = 0; I < N; ++I) {
      if (!(A[I] == B[I])) {
        Fail(std::string(Name) + "[" + std::to_string(I) + "]: oracle [" + ItemText(A[I]) + "] native [" +
             ItemText(B[I]) + "]");
      }
    }
  };
  if (!(Oracle.Flags == Native.Flags)) {
    Fail("flags differ");
  }
  Lists("best", Oracle.Best, Native.Best);
  Lists("partial", Oracle.Partial, Native.Partial);
  Lists("unreliable", Oracle.Unreliable, Native.Unreliable);
  const auto Map = [](const std::vector<Diff::SnapMatched>& Entries) {
    std::map<std::optional<std::string>, std::pair<std::optional<std::string>, uint64_t>> Out;
    for (const auto& E : Entries) {
      Out[E.Key] = {E.Other, E.RatioBits};
    }
    return Out;
  };
  if (Map(Oracle.MatchedPrimary) != Map(Native.MatchedPrimary)) {
    Fail("matched_primary differs");
  }
  if (Map(Oracle.MatchedSecondary) != Map(Native.MatchedSecondary)) {
    Fail("matched_secondary differs");
  }
  if (Oracle.Choosers.has_value() != Native.Choosers.has_value()) {
    Fail("choosers present on one side only");
  } else if (Oracle.Choosers) {
    Lists("choosers.best", Oracle.Choosers->Best, Native.Choosers->Best);
    Lists("choosers.partial", Oracle.Choosers->Partial, Native.Choosers->Partial);
    Lists("choosers.unreliable", Oracle.Choosers->Unreliable, Native.Choosers->Unreliable);
    Lists("choosers.multimatch", Oracle.Choosers->Multimatch, Native.Choosers->Multimatch);
  }
  if (Oracle.Unmatched.has_value() != Native.Unmatched.has_value()) {
    Fail("unmatched present on one side only");
  } else if (Oracle.Unmatched && !(*Oracle.Unmatched == *Native.Unmatched)) {
    Fail("unmatched differs");
  }
  if (Oracle.RatiosCache && Native.RatiosCache) {
    std::map<std::string, uint64_t> A;
    std::map<std::string, uint64_t> B;
    for (const auto& E : *Oracle.RatiosCache) {
      A[E.Key] = E.RatioBits;
    }
    for (const auto& E : *Native.RatiosCache) {
      B[E.Key] = E.RatioBits;
    }
    if (A != B) {
      Fail("ratios_cache differs");
    }
  }
  return Report;
}

}
