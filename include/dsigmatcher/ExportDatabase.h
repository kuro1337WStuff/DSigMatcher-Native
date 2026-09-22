#pragma once

#include <string>

#include "dsigmatcher/Types.h"

namespace DSig {

struct LoadResult {
  bool Ok = false;
  std::string Error;
  int64_t RowsRead = 0;
};

class ExportDatabase {
public:
  LoadResult Load(const std::string& Path, FunctionTable& OutTable, ProgramInfo& OutProgram);
};

}
