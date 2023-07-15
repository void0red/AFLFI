//
// Created by void0red on 23-7-6.
//

#include "utils.h"
#include <fstream>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/Support/Debug.h>

void ReadLists(const std::string &list, std::vector<std::string> &out) {
  std::ifstream f(list);
  std::string   line;
  if (f.is_open()) {
    while (std::getline(f, line)) {
      out.push_back(line);
    }
  }
}

void ReadErrFunc(const std::string               &name,
                 std::unordered_set<std::string> &out) {
  std::ifstream f(name);
  if (!f.is_open()) return;

  std::string buf;
  while (std::getline(f, buf)) {
    if (buf.empty() || buf[0] == '#') continue;
    out.insert(buf.substr(0, buf.find(',')));
  }
}

void ReadErrLoc(const std::string &name, std::unordered_set<uint64_t> &out) {
  std::ifstream f(name);
  if (!f.is_open()) return;

  std::string buf;
  while (std::getline(f, buf)) {
    if (buf.empty() || buf[0] == '#') continue;
    buf = buf.substr(0, buf.find(','));
    out.insert(std::stoull(buf));
  }
}

bool IsIgnoreFunction(const llvm::Function *F) {
  // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
  // fuzzing campaign installations, e.g. oss-fuzz

  static constexpr const char *ignoreList[] = {

      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan",
      "ign.",
      "__afl",
      "_fini",
      "__libc_",
      "__asan",
      "__msan",
      "__cmplog",
      "__sancov",
      "__san",
      "__cxx_",
      "__decide_deferred",
      "_GLOBAL",
      "_ZZN6__asan",
      "_ZZN6__lsan",
      "msan.",
      "LLVMFuzzerM",
      "LLVMFuzzerC",
      "LLVMFuzzerI",
      "maybe_duplicate_stderr",
      "discard_output",
      "close_stdout",
      "dup_and_close_stderr",
      "maybe_close_fd_mask",
      "ExecuteFilesOnyByOne"

  };

  for (auto const &ignoreListFunc : ignoreList) {
    if (F->getName().startswith(ignoreListFunc)) { return true; }
  }

  static constexpr const char *ignoreSubstringList[] = {

      "__asan", "__msan",       "__ubsan",    "__lsan",  "__san", "__sanitize",
      "__cxx",  "DebugCounter", "DwarfDebug", "DebugLoc"

  };

  for (auto const &ignoreListFunc : ignoreSubstringList) {
    // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
    if (llvm::StringRef::npos != F->getName().find(ignoreListFunc)) {
      return true;
    }
  }

  return false;
}

bool LocHash(const llvm::Instruction *inst, uint64_t &out) {
  if (llvm::DILocation *Loc = inst->getDebugLoc()) {
    auto     dir = Loc->getDirectory();
    auto     file = Loc->getFilename();
    unsigned line = Loc->getLine();
    if (file.empty()) {
      auto inlineLoc = Loc->getInlinedAt();
      if (inlineLoc) {
        line = inlineLoc->getLine();
        file = inlineLoc->getFilename();
        dir = inlineLoc->getDirectory();
      }
    }
    out = llvm::hash_combine(llvm::hash_value(dir), llvm::hash_value(file),
                             llvm::hash_value(line),
                             llvm::hash_value(inst->getType()->getTypeID()));
    return true;
  }
  // llvm::errs() << "Check Debug Info: ";
  // inst->print(llvm::errs());
  // llvm::errs() << '\n';
  return false;
}

bool BasicBlockHash(const llvm::BasicBlock *bb, uint64_t &out) {
  for (auto &inst : *bb) {
    if (inst.getDebugLoc()) { return LocHash(&inst, out); }
  }
  // llvm::errs() << "Check Debug Info: \n";
  // bb->print(llvm::errs());
  // llvm::errs() << '\n';
  return false;
}
