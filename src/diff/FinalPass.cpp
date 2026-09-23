// final_pass (lane L1): D:2937-2948 = cleanup_matches (D:2945), find_multimatches (D:2887-2914) with
// find_unresolved_multimatches (D:2839-2885) and add_multimatches_to_chooser (D:2732-2747), then
// add_final_chooser_items (D:2916-2935). Spec: 01 §9-§10.2, 02 §16, 06 §12-§15, 07 §10.12.
// D: = diaphora.py at 3.4.2-4-g621ec26.
//
// Unlike cleanup (keyed by NAME), this pass is keyed by ADDRESS text (item[0] / item[2]) and uses the
// raw item ratios; the same-name fake plays no part (02 §16). The chooser lists of S.Final() receive
// the items in CChooser.add_item order; the "%05lu" line numbers, "%08x" addresses and "%.7f"
// ratios are the writer's (L4), except that the int() of each address is evaluated here, where
// add_item evaluates it (D:286, D:288), so a Python ValueError is raised at the same point.

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "StateDetail.h"
#include "dsigmatcher/diff/Errors.h"
#include "dsigmatcher/diff/Pipeline.h"
#include "dsigmatcher/diff/Stages.h"

namespace DSig::Diff {

namespace {

// A Python dict {ea: [items]} in insertion order (multi_main / multi_diff, D:2893-2894).
struct MultiDict {
  std::vector<AddrId> Order;
  std::unordered_map<AddrId, std::vector<Item>> Map;

  // try: multi[ea].append(item) except KeyError: multi[ea] = [item]  (D:2866-2869, D:2880-2883)
  void Append(AddrId Ea, const Item& It) {
    auto [Found, Inserted] = Map.try_emplace(Ea);
    if (Inserted) {
      Order.push_back(Ea);
    }
    Found->second.push_back(It);
  }
};

std::string EaPairKey(const Interners& Ids, AddrId Ea1, AddrId Ea2) {
  // f"{ea1}-{ea2}" (D:2852, D:2741): the address texts; a None address renders as "None".
  std::string Key(Ids.AddrKeyText(Ea1));
  Key += '-';
  Key += Ids.AddrKeyText(Ea2);
  return Key;
}

// CChooser.add_item (D:275-296) for a result chooser: "%08x" % int(item.ea) (D:286) and
// "%08x" % int(item.ea2) (D:288) are evaluated before the row is appended. CChooser.Item.__init__
// (D:237-245) also runs int(nodes1) / int(nodes2), which cannot raise on the integers items carry.
void AddChooserItem(DiffSession& S, std::vector<Item>& Chooser, const Item& It) {
  Detail::RequirePyInt(S.Ids(), It.Ea1, "D:286");
  Detail::RequirePyInt(S.Ids(), It.Ea2, "D:288");
  Chooser.push_back(It);
}

// add_multimatches_to_chooser (D:2732-2747), called for multi_main then multi_diff with ONE shared
// `dones` (D:2905-2912). An ea goes into the ignore list only when at least one of its items was
// newly added to the multimatch chooser (D:2742-2745).
void AddMultimatchesToChooser(DiffSession& S, const MultiDict& Multi, std::unordered_set<AddrId>& IgnoreList,
                              std::unordered_set<std::string>& Dones) {
  for (const AddrId Ea : Multi.Order) {                     // D:2737 `for ea in multi` (insertion order)
    const std::vector<Item>& Items = Multi.Map.at(Ea);
    if (Items.size() > 1) {                                 // D:2738
      for (const Item& Match : Items) {                     // D:2739
        // D:2740 itemize_for_chooser (D:2718-2730): its locals are misnamed, but the positional call
        // Item(ea, name, ea2, name2, desc, ratio, nodes1, nodes2) maps item[4] to the description,
        // item[5] to the ratio and item[6]/item[7] to the nodes, so the item is unchanged (01 §9.3).
        std::string Key = EaPairKey(S.Ids(), Match.Ea1, Match.Ea2);  // D:2741
        if (Dones.count(Key) == 0) {                                  // D:2742
          Dones.insert(std::move(Key));                               // D:2743
          AddChooserItem(S, S.Final().Multimatch, Match);             // D:2744
          IgnoreList.insert(Ea);                                      // D:2745
        }
      }
    }
  }
}

}

void StageFinalPass(DiffSession& S) {
  // D:2945
  S.Cleanup(CleanupSite::L2945);

  // D:2947 find_multimatches (D:2887-2914).
  const Interners& Ids = S.Ids();
  std::unordered_map<AddrId, double> MaxMain;  // D:2891
  std::unordered_map<AddrId, double> MaxDiff;  // D:2892
  MultiDict MultiMain;                         // D:2893
  MultiDict MultiDiff;                         // D:2894
  {
    // D:2897-2900 find_unresolved_multimatches (D:2839-2885).
    std::unordered_set<std::string> Dones;                       // D:2844
    for (const Chooser Category : {Chooser::Best, Chooser::Partial, Chooser::Unreliable}) {  // D:2845
      for (const Item& Match : S.State().SortedResults(Category)) {                          // D:2846-2847
        std::string Key = EaPairKey(Ids, Match.Ea1, Match.Ea2);   // D:2848-2852
        if (Dones.count(Key) != 0) {                              // D:2853-2854
          continue;
        }
        Dones.insert(std::move(Key));                             // D:2855
        const auto MainMax = MaxMain.try_emplace(Match.Ea1, Match.Ratio).first;  // D:2857-2858
        if (MainMax->second > Match.Ratio) {                         // D:2861-2862 (skips the diff side too)
          continue;
        }
        MainMax->second = Match.Ratio;                               // D:2863
        MultiMain.Append(Match.Ea1, Match);                       // D:2865-2869 item = [ea2, ratio, match]
        const auto DiffMax = MaxDiff.try_emplace(Match.Ea2, Match.Ratio).first;  // D:2871-2872
        if (DiffMax->second > Match.Ratio) {                         // D:2875-2876
          continue;
        }
        DiffMax->second = Match.Ratio;                               // D:2877
        MultiDiff.Append(Match.Ea2, Match);                       // D:2879-2883 item = [ea1, ratio, match]
      }
    }
  }
  // D:2903-2912: multimatch chooser and ignore lists, sharing one dones set.
  std::unordered_set<AddrId> IgnoreMain;       // D:2903
  std::unordered_set<AddrId> IgnoreDiff;       // D:2904
  std::unordered_set<std::string> MultiDones;  // D:2905
  AddMultimatchesToChooser(S, MultiMain, IgnoreMain, MultiDones);  // D:2907-2909
  AddMultimatchesToChooser(S, MultiDiff, IgnoreDiff, MultiDones);  // D:2910-2912

  // D:2948 add_final_chooser_items (D:2916-2935).
  for (const Chooser Category : {Chooser::Best, Chooser::Partial, Chooser::Unreliable}) {  // D:2925
    std::vector<Item>& Target = Category == Chooser::Best      ? S.Final().Best
                                : Category == Chooser::Partial ? S.Final().Partial
                                                               : S.Final().Unreliable;  // D:2920-2924 CHOOSERS
    for (const Item& Match : S.State().SortedResults(Category)) {  // D:2926-2927
      // D:2928 item = itemize_for_chooser(match): the same fields (see above).
      if (IgnoreMain.count(Match.Ea1) != 0 || IgnoreDiff.count(Match.Ea2) != 0) {  // D:2929-2930
        continue;
      }
      // D:2931 max_main[item.ea]: every item's ea1 was seen by the first pass, whose first visit sets
      // max_main before any `continue` (01 §9.4), so this lookup cannot miss; it raises KeyError if
      // it ever did.
      const auto MainMax = MaxMain.find(Match.Ea1);
      if (MainMax == MaxMain.end()) {
        throw DiaphoraWouldRaise("D:2931 KeyError", std::string(Ids.AddrKeyText(Match.Ea1)));
      }
      if (Match.Ratio < MainMax->second) {  // D:2931-2932
        continue;
      }
      // D:2933 max_diff[item.ea2]: a miss (KeyError) needs an item that was dones-skipped behind a
      // same ea1-ea2 twin in an EARLIER category with a lower ratio that failed the max_main test
      // (01 §9.4). Under the default configuration unreliable is always empty, best items are 1.0 and
      // partial items are below 1.0, so this is unreachable; it is still reproduced as Python's raise.
      const auto DiffMax = MaxDiff.find(Match.Ea2);
      if (DiffMax == MaxDiff.end()) {
        throw DiaphoraWouldRaise("D:2933 KeyError", std::string(Ids.AddrKeyText(Match.Ea2)));
      }
      if (Match.Ratio < DiffMax->second) {  // D:2933-2934
        continue;
      }
      AddChooserItem(S, Target, Match);  // D:2935 CHOOSERS[key].add_item(item)
    }
  }
}

}
