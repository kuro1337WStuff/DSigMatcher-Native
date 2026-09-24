#pragma once

// Readers for the committed artefacts tools/parity/make_fixture.py writes:
// expected_results.tsv / expected_unmatched.tsv (the .diaphora rows real Diaphora wrote, in rowid
// order) and the after_final_pass.json / after_find_unmatched.json chooser dumps (state snapshots,
// tools/parity/README.md). Used by diff_writer and diff_parity.
//
// TSV: a header line, then one line per row; `\N` is NULL; `\\`, `\t`, `\n`, `\r` escape a
// backslash, TAB, LF and CR inside a value.

#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "diff/CorpusPaths.h"
#include "diff/ResultsCompare.h"
#include "dsigmatcher/diff/Interner.h"
#include "dsigmatcher/diff/ResultsWriter.h"
#include "dsigmatcher/diff/Snapshot.h"

namespace DSig::Test {

// sqlite_master of every .diaphora file: save_results' four statements (D:2387-2403) as SQLite stores
// them (01 §11.1): the leading keywords upper-cased, the rest verbatim, including the newline and the
// 19 spaces of indentation in the results DDL.
inline std::vector<SchemaRow> DiaphoraSchema() {
  return {
      {"table", "config", "config", "CREATE TABLE config (main_db text, diff_db text, version text, date text)"},
      {"table", "results", "results",
       "CREATE TABLE results (type, line, address, name, address2, name2,\n"
       "                   ratio, nodes1, nodes2, description)"},
      {"index", "uq_results", "results", "CREATE UNIQUE INDEX uq_results on results(address, address2)"},
      {"table", "unmatched", "unmatched", "CREATE TABLE unmatched (type, line, address, name)"},
  };
}

inline bool ReadTextFile(const std::string& Path, std::string& Out) {
  std::ifstream In(Utf8ToPath(Path), std::ios::binary);
  if (!In) {
    return false;
  }
  std::ostringstream Buffer;
  Buffer << In.rdbuf();
  Out = Buffer.str();
  return true;
}

// One TSV field; false on a malformed escape.
inline bool UnescapeTsvField(std::string_view In, std::string& Out, bool& Null) {
  Out.clear();
  Null = In == "\\N";
  if (Null) {
    return true;
  }
  for (size_t I = 0; I < In.size(); ++I) {
    if (In[I] != '\\') {
      Out.push_back(In[I]);
      continue;
    }
    if (++I == In.size()) {
      return false;
    }
    switch (In[I]) {
      case '\\': Out.push_back('\\'); break;
      case 't': Out.push_back('\t'); break;
      case 'n': Out.push_back('\n'); break;
      case 'r': Out.push_back('\r'); break;
      default: return false;
    }
  }
  return true;
}

// Rows of a TSV file after its header line; each field is (text, is-null).
inline bool ReadTsv(const std::string& Path, size_t Columns, std::vector<std::vector<std::pair<std::string, bool>>>& Rows,
                    std::string& Error) {
  std::string Text;
  if (!ReadTextFile(Path, Text)) {
    Error = "cannot read " + Path;
    return false;
  }
  std::istringstream Lines(Text);
  std::string Line;
  bool Header = true;
  while (std::getline(Lines, Line)) {
    if (!Line.empty() && Line.back() == '\r') {
      Line.pop_back();  // a CR can only end a line: a CR inside a value is escaped as \r
    }
    if (Header) {
      Header = false;
      continue;
    }
    if (Line.empty()) {
      continue;
    }
    std::vector<std::pair<std::string, bool>> Row;
    size_t Start = 0;
    while (true) {
      const size_t Tab = Line.find('\t', Start);
      const std::string_view Field =
          std::string_view(Line).substr(Start, Tab == std::string::npos ? std::string::npos : Tab - Start);
      std::string Value;
      bool Null = false;
      if (!UnescapeTsvField(Field, Value, Null)) {
        Error = "bad escape in " + Path;
        return false;
      }
      Row.emplace_back(std::move(Value), Null);
      if (Tab == std::string::npos) {
        break;
      }
      Start = Tab + 1;
    }
    if (Row.size() != Columns) {
      Error = "wrong column count in " + Path;
      return false;
    }
    Rows.push_back(std::move(Row));
  }
  return true;
}

// The expected .diaphora of a fixture directory as a ResultsFile (ResultsCompare.h): Diaphora's DDL,
// one config row (only `version` is known; the paths and the date are never committed), the rows.
inline ResultsFile ReadExpectedFixture(const std::string& Dir) {
  ResultsFile File;
  File.Schema = DiaphoraSchema();
  File.Config.push_back({"", "", "3.4", ""});
  std::vector<std::vector<std::pair<std::string, bool>>> Rows;
  if (!ReadTsv(PathToUtf8(Utf8ToPath(Dir) / "expected_results.tsv"), 10, Rows, File.Error)) {
    return File;
  }
  for (const auto& R : Rows) {
    ResultsRow Row;
    Row.Type = R[0].first;
    Row.Line = R[1].first;
    Row.Address = R[2].first;
    Row.Name = R[3].first;
    Row.NameNull = R[3].second;
    Row.Address2 = R[4].first;
    Row.Name2 = R[5].first;
    Row.Name2Null = R[5].second;
    Row.Ratio = R[6].first;
    Row.Nodes1 = R[7].first;
    Row.Nodes2 = R[8].first;
    Row.Description = R[9].first;
    File.Results.push_back(std::move(Row));
  }
  Rows.clear();
  if (!ReadTsv(PathToUtf8(Utf8ToPath(Dir) / "expected_unmatched.tsv"), 4, Rows, File.Error)) {
    return File;
  }
  for (const auto& R : Rows) {
    UnmatchedRowText Row;
    Row.Type = R[0].first;
    Row.Line = R[1].first;
    Row.Address = R[2].first;
    Row.Name = R[3].first;
    Row.NameNull = R[3].second;
    File.Unmatched.push_back(std::move(Row));
  }
  return File;
}

// FinalResults from the after:final_pass chooser dump and the after:find_unmatched dump (snapshot schema of
// tools/parity/README.md), interned into Ids. Items keep their add_item order.
inline Diff::Item ItemFromSnap(Diff::Interners& Ids, const Diff::SnapItem& In) {
  Diff::Item Out;
  Out.Ea1 = Ids.Addr(In.Ea1);
  Out.Name1 = In.Name1 ? Ids.Name(*In.Name1) : Diff::kNoneName;
  Out.Ea2 = Ids.Addr(In.Ea2);
  Out.Name2 = In.Name2 ? Ids.Name(*In.Name2) : Diff::kNoneName;
  Out.Desc = Ids.Desc(In.Desc);
  Out.Ratio = Diff::RatioFromBits(In.RatioBits);
  Out.Nodes1 = In.Nodes1;
  Out.Nodes2 = In.Nodes2;
  return Out;
}

inline std::vector<Diff::Item> ItemsFromSnap(Diff::Interners& Ids, const std::vector<Diff::SnapItem>& In) {
  std::vector<Diff::Item> Out;
  for (const Diff::SnapItem& It : In) {
    Out.push_back(ItemFromSnap(Ids, It));
  }
  return Out;
}

inline std::optional<std::vector<Diff::UnmatchedRow>> UnmatchedFromSnap(
    Diff::Interners& Ids, const std::optional<std::vector<Diff::SnapUnmatched>>& In) {
  if (!In) {
    return std::nullopt;
  }
  std::vector<Diff::UnmatchedRow> Out;
  for (const Diff::SnapUnmatched& Row : *In) {
    Out.push_back(Diff::UnmatchedRow{Ids.Addr(Row.Ea), Row.Name ? Ids.Name(*Row.Name) : Diff::kNoneName});
  }
  return Out;
}

// Throws std::runtime_error when a dump is missing from the snapshots.
inline Diff::FinalResults FinalResultsFromDumps(Diff::Interners& Ids, const Diff::StateSnapshot& FinalPass,
                                                const Diff::StateSnapshot& FindUnmatched) {
  if (!FinalPass.Choosers || !FindUnmatched.Unmatched) {
    throw std::runtime_error("after:final_pass needs `choosers` and after:find_unmatched needs `unmatched`");
  }
  Diff::FinalResults R;
  R.Best = ItemsFromSnap(Ids, FinalPass.Choosers->Best);
  R.Partial = ItemsFromSnap(Ids, FinalPass.Choosers->Partial);
  R.Unreliable = ItemsFromSnap(Ids, FinalPass.Choosers->Unreliable);
  R.Multimatch = ItemsFromSnap(Ids, FinalPass.Choosers->Multimatch);
  R.UnmatchedPrimary = UnmatchedFromSnap(Ids, FindUnmatched.Unmatched->Primary);
  R.UnmatchedSecondary = UnmatchedFromSnap(Ids, FindUnmatched.Unmatched->Secondary);
  return R;
}

}
