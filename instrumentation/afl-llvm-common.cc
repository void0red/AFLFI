#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <fnmatch.h>

#include <list>
#include <string>
#include <fstream>
#include <cmath>

#include <llvm/Support/raw_ostream.h>

#define IS_EXTERN extern
#include "afl-llvm-common.h"

using namespace llvm;

static std::list<std::string> allowListFiles;
static std::list<std::string> allowListFunctions;
static std::list<std::string> denyListFiles;
static std::list<std::string> denyListFunctions;

char *getBBName(const llvm::BasicBlock *BB) {

  static char *name;

  if (!BB->getName().empty()) {

    name = strdup(BB->getName().str().c_str());
    return name;

  }

  std::string        Str;
  raw_string_ostream OS(Str);

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
  BB->printAsOperand(OS, false);
#endif
  name = strdup(OS.str().c_str());
  return name;

}

/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */
bool isIgnoreFunction(const llvm::Function *F) {

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
    if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }

  }

  return false;

}

void initInstrumentList() {

  char *allowlist = getenv("AFL_LLVM_ALLOWLIST");
  if (!allowlist) allowlist = getenv("AFL_LLVM_INSTRUMENT_FILE");
  if (!allowlist) allowlist = getenv("AFL_LLVM_WHITELIST");
  char *denylist = getenv("AFL_LLVM_DENYLIST");
  if (!denylist) denylist = getenv("AFL_LLVM_BLOCKLIST");

  if (allowlist && denylist)
    FATAL(
        "You can only specify either AFL_LLVM_ALLOWLIST or AFL_LLVM_DENYLIST "
        "but not both!");

  if (allowlist) {

    std::string   line;
    std::ifstream fileStream;
    fileStream.open(allowlist);
    if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_ALLOWLIST");
    getline(fileStream, line);

    while (fileStream) {

      int         is_file = -1;
      std::size_t npos;
      std::string original_line = line;

      line.erase(std::remove_if(line.begin(), line.end(), ::isspace),
                 line.end());

      // remove # and following
      if ((npos = line.find("#")) != std::string::npos)
        line = line.substr(0, npos);

      if (line.compare(0, 4, "fun:") == 0) {

        is_file = 0;
        line = line.substr(4);

      } else if (line.compare(0, 9, "function:") == 0) {

        is_file = 0;
        line = line.substr(9);

      } else if (line.compare(0, 4, "src:") == 0) {

        is_file = 1;
        line = line.substr(4);

      } else if (line.compare(0, 7, "source:") == 0) {

        is_file = 1;
        line = line.substr(7);

      }

      if (line.find(":") != std::string::npos) {

        FATAL("invalid line in AFL_LLVM_ALLOWLIST: %s", original_line.c_str());

      }

      if (line.length() > 0) {

        // if the entry contains / or . it must be a file
        if (is_file == -1)
          if (line.find("/") != std::string::npos ||
              line.find(".") != std::string::npos)
            is_file = 1;
        // otherwise it is a function

        if (is_file == 1)
          allowListFiles.push_back(line);
        else
          allowListFunctions.push_back(line);

      }

      getline(fileStream, line);

    }

    if (debug)
      DEBUGF("loaded allowlist with %zu file and %zu function entries\n",
             allowListFiles.size(), allowListFunctions.size());

  }

  if (denylist) {

    std::string   line;
    std::ifstream fileStream;
    fileStream.open(denylist);
    if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_DENYLIST");
    getline(fileStream, line);

    while (fileStream) {

      int         is_file = -1;
      std::size_t npos;
      std::string original_line = line;

      line.erase(std::remove_if(line.begin(), line.end(), ::isspace),
                 line.end());

      // remove # and following
      if ((npos = line.find("#")) != std::string::npos)
        line = line.substr(0, npos);

      if (line.compare(0, 4, "fun:") == 0) {

        is_file = 0;
        line = line.substr(4);

      } else if (line.compare(0, 9, "function:") == 0) {

        is_file = 0;
        line = line.substr(9);

      } else if (line.compare(0, 4, "src:") == 0) {

        is_file = 1;
        line = line.substr(4);

      } else if (line.compare(0, 7, "source:") == 0) {

        is_file = 1;
        line = line.substr(7);

      }

      if (line.find(":") != std::string::npos) {

        FATAL("invalid line in AFL_LLVM_DENYLIST: %s", original_line.c_str());

      }

      if (line.length() > 0) {

        // if the entry contains / or . it must be a file
        if (is_file == -1)
          if (line.find("/") != std::string::npos ||
              line.find(".") != std::string::npos)
            is_file = 1;
        // otherwise it is a function

        if (is_file == 1)
          denyListFiles.push_back(line);
        else
          denyListFunctions.push_back(line);

      }

      getline(fileStream, line);

    }

    if (debug)
      DEBUGF("loaded denylist with %zu file and %zu function entries\n",
             denyListFiles.size(), denyListFunctions.size());

  }

}

void scanForDangerousFunctions(llvm::Module *M) {

  if (!M) return;

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 9)

  for (GlobalIFunc &IF : M->ifuncs()) {

    StringRef ifunc_name = IF.getName();
    Constant *r = IF.getResolver();
    if (r->getNumOperands() == 0) { continue; }
    StringRef r_name = cast<Function>(r->getOperand(0))->getName();
    if (!be_quiet)
      fprintf(stderr,
              "Note: Found an ifunc with name %s that points to resolver "
              "function %s, we will not instrument this, putting it into the "
              "block list.\n",
              ifunc_name.str().c_str(), r_name.str().c_str());
    denyListFunctions.push_back(r_name.str());

  }

  GlobalVariable *GV = M->getNamedGlobal("llvm.global_ctors");
  if (GV && !GV->isDeclaration() && !GV->hasLocalLinkage()) {

    ConstantArray *InitList = dyn_cast<ConstantArray>(GV->getInitializer());

    if (InitList) {

      for (unsigned i = 0, e = InitList->getNumOperands(); i != e; ++i) {

        if (ConstantStruct *CS =
                dyn_cast<ConstantStruct>(InitList->getOperand(i))) {

          if (CS->getNumOperands() >= 2) {

            if (CS->getOperand(1)->isNullValue())
              break;  // Found a null terminator, stop here.

            ConstantInt *CI = dyn_cast<ConstantInt>(CS->getOperand(0));
            int          Priority = CI ? CI->getSExtValue() : 0;

            Constant *FP = CS->getOperand(1);
            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(FP))
              if (CE->isCast()) FP = CE->getOperand(0);
            if (Function *F = dyn_cast<Function>(FP)) {

              if (!F->isDeclaration() &&
                  strncmp(F->getName().str().c_str(), "__afl", 5) != 0) {

                if (!be_quiet)
                  fprintf(stderr,
                          "Note: Found constructor function %s with prio "
                          "%u, we will not instrument this, putting it into a "
                          "block list.\n",
                          F->getName().str().c_str(), Priority);
                denyListFunctions.push_back(F->getName().str());

              }

            }

          }

        }

      }

    }

  }

#endif

}

static std::string getSourceName(llvm::Function *F) {

  // let's try to get the filename for the function
  auto                 bb = &F->getEntryBlock();
  BasicBlock::iterator IP = bb->getFirstInsertionPt();
  IRBuilder<>          IRB(&(*IP));
  DebugLoc             Loc = IP->getDebugLoc();

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
  if (Loc) {

    StringRef   instFilename;
    DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

    if (cDILoc) { instFilename = cDILoc->getFilename(); }

    if (instFilename.str().empty() && cDILoc) {

      /* If the original location is empty, try using the inlined location
       */
      DILocation *oDILoc = cDILoc->getInlinedAt();
      if (oDILoc) { instFilename = oDILoc->getFilename(); }

    }

    return instFilename.str();

  }

#else
  if (!Loc.isUnknown()) {

    DILocation cDILoc(Loc.getAsMDNode(F->getContext()));

    StringRef instFilename = cDILoc.getFilename();

    /* Continue only if we know where we actually are */
    return instFilename.str();

  }

#endif

  return std::string("");

}

bool isInInstrumentList(llvm::Function *F, std::string Filename) {

  bool return_default = true;

  // is this a function with code? If it is external we don't instrument it
  // anyway and it can't be in the instrument file list. Or if it is it is
  // ignored.
  if (!F->size() || isIgnoreFunction(F)) return false;

  if (!denyListFiles.empty() || !denyListFunctions.empty()) {

    if (!denyListFunctions.empty()) {

      std::string instFunction = F->getName().str();

      for (std::list<std::string>::iterator it = denyListFunctions.begin();
           it != denyListFunctions.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. We also allow UNIX-style pattern
         * matching */

        if (instFunction.length() >= it->length()) {

          if (fnmatch(("*" + *it).c_str(), instFunction.c_str(), 0) == 0) {

            if (debug)
              DEBUGF(
                  "Function %s is in the deny function list, not instrumenting "
                  "... \n",
                  instFunction.c_str());
            return false;

          }

        }

      }

    }

    if (!denyListFiles.empty()) {

      std::string source_file = getSourceName(F);

      if (source_file.empty()) { source_file = Filename; }

      if (!source_file.empty()) {

        for (std::list<std::string>::iterator it = denyListFiles.begin();
             it != denyListFiles.end(); ++it) {

          /* We don't check for filename equality here because
           * filenames might actually be full paths. Instead we
           * check that the actual filename ends in the filename
           * specified in the list. We also allow UNIX-style pattern
           * matching */

          if (source_file.length() >= it->length()) {

            if (fnmatch(("*" + *it).c_str(), source_file.c_str(), 0) == 0) {

              return false;

            }

          }

        }

      } else {

        // we could not find out the location. in this case we say it is not
        // in the instrument file list
        if (!be_quiet)
          WARNF(
              "No debug information found for function %s, will be "
              "instrumented (recompile with -g -O[1-3] and use a modern llvm).",
              F->getName().str().c_str());

      }

    }

  }

  // if we do not have a instrument file list return true
  if (!allowListFiles.empty() || !allowListFunctions.empty()) {

    return_default = false;

    if (!allowListFunctions.empty()) {

      std::string instFunction = F->getName().str();

      for (std::list<std::string>::iterator it = allowListFunctions.begin();
           it != allowListFunctions.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. We also allow UNIX-style pattern
         * matching */

        if (instFunction.length() >= it->length()) {

          if (fnmatch(("*" + *it).c_str(), instFunction.c_str(), 0) == 0) {

            if (debug)
              DEBUGF(
                  "Function %s is in the allow function list, instrumenting "
                  "... \n",
                  instFunction.c_str());
            return true;

          }

        }

      }

    }

    if (!allowListFiles.empty()) {

      std::string source_file = getSourceName(F);

      if (source_file.empty()) { source_file = Filename; }

      if (!source_file.empty()) {

        for (std::list<std::string>::iterator it = allowListFiles.begin();
             it != allowListFiles.end(); ++it) {

          /* We don't check for filename equality here because
           * filenames might actually be full paths. Instead we
           * check that the actual filename ends in the filename
           * specified in the list. We also allow UNIX-style pattern
           * matching */

          if (source_file.length() >= it->length()) {

            if (fnmatch(("*" + *it).c_str(), source_file.c_str(), 0) == 0) {

              if (debug)
                DEBUGF(
                    "Function %s is in the allowlist (%s), instrumenting ... "
                    "\n",
                    F->getName().str().c_str(), source_file.c_str());
              return true;

            }

          }

        }

      } else {

        // we could not find out the location. In this case we say it is not
        // in the instrument file list
        if (!be_quiet)
          WARNF(
              "No debug information found for function %s, will not be "
              "instrumented (recompile with -g -O[1-3] and use a modern llvm).",
              F->getName().str().c_str());
        return false;

      }

    }

  }

  return return_default;

}

// Calculate the number of average collisions that would occur if all
// location IDs would be assigned randomly (like normal afl/AFL++).
// This uses the "balls in bins" algorithm.
unsigned long long int calculateCollisions(uint32_t edges) {

  double                 bins = MAP_SIZE;
  double                 balls = edges;
  double                 step1 = 1 - (1 / bins);
  double                 step2 = pow(step1, balls);
  double                 step3 = bins * step2;
  double                 step4 = round(step3);
  unsigned long long int empty = step4;
  unsigned long long int collisions = edges - (MAP_SIZE - empty);
  return collisions;

}

#include <llvm/IR/InstIterator.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugLoc.h>

llvm::Instruction *InstPlugin::setNoSanitize(llvm::Instruction *v) {
  v->setMetadata(noSanitizeKindId, noSanitizeNode);
  return v;
}

void InstPlugin::runOnModule(llvm::Module &M) {
  if (auto *f = getenv("FJ_FUNC")) {
    loadErrFunc(f);
    DEBUGF("Load %ld from %s\n", errorFuncs.size(), f);
  }
  if (auto *f = getenv("FJ_LOC")) {
    loadErrLoc(f);
    DEBUGF("Load %ld from %s\n", errorLocs.size(), f);
  }
  if (auto *f = getenv("FJ_DIS")) {
    loadDistance(f);
    DEBUGF("Load %ld from %s\n", distance.size(), f);
  }

  if (errorLocs.empty() && errorFuncs.empty()) return;

  fifuzz = getenv("FJ_FIFUZZ") != nullptr;

  IRBuilder<> IRB(M.getContext());
  if (!fifuzz) {
    FaultInjectionControlFunc = M.getOrInsertFunction(
        FaultInjectionControlName, IRB.getInt1Ty(), IRB.getVoidTy());
  } else {
    FaultInjectionControlFunc = M.getOrInsertFunction(
        FaultInjectionControlName, IRB.getInt1Ty(), IRB.getInt64Ty());
    FaultInjectionTraceFunc = M.getOrInsertFunction(
        FaultInjectionTraceName, IRB.getVoidTy(), IRB.getInt64Ty());
  }

  noSanitizeKindId = M.getMDKindID("nosanitize");
  noSanitizeNode = MDNode::get(M.getContext(), None);

  CollectInsertPoint(&M);

  if (fifuzz) InsertTrace(&M);

  InsertControl(&M);
}

hash_code InstPlugin::getLocHash(llvm::CallInst *callInst) {
  auto *Func = callInst->getParent();
  auto *Callee = callInst->getCalledFunction();
  auto  ret = llvm::hash_combine(llvm::hash_value(Func->getName()),
                                 llvm::hash_value(Callee->getName()));
  if (DILocation *Loc = callInst->getDebugLoc()) {
    StringRef Dir = Loc->getDirectory();
    StringRef File = Loc->getFilename();
    unsigned  Line = Loc->getLine();
    return llvm::hash_combine(ret, llvm::hash_value(Dir),
                              llvm::hash_value(File), llvm::hash_value(Line));
  }
  return ret;
}

void InstPlugin::CollectInsertPoint(llvm::Module *m) {
  for (auto &func : m->functions()) {
    int counter = 0;
    if (func.empty() || func.isIntrinsic() || isIgnoreFunction(&func)) continue;

    auto *entry = &*func.getEntryBlock().getFirstInsertionPt();
    for (auto &inst : instructions(func)) {
      auto *retInst = dyn_cast<ReturnInst>(&inst);
      if (fifuzz && retInst) {
        entryExit[entry].insert(retInst);
        continue;
      }

      auto *callInst = dyn_cast<CallInst>(&inst);
      if (!callInst) continue;

      auto *callee =
          dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts());
      if (!callee || callee->isIntrinsic() || !callee->hasName() ||
          isIgnoreFunction(callee))
        continue;

      if (fifuzz) callSite.insert(callInst);

      if (!callee->getReturnType()->isIntOrPtrTy()) continue;

      auto fn = callee->getName().split('.').first.str();

      if (errorFuncs.find(fn) != errorFuncs.end()) {
        errorSite[callInst] = counter++;
        callSite.erase(callInst);
        continue;
      }

      DILocation *Loc = callInst->getDebugLoc();
      if (!Loc) continue;

      if (errorLocs.count(getLocHash(callInst))) {
        errorSite[callInst] = counter++;
        callSite.erase(callInst);
      }
    }
  }
}

void InstPlugin::InsertControl(llvm::Module *m) {
  IRBuilder<> IRB(m->getContext());
  for (const auto &pair : errorSite) {
    auto   es = pair.first;
    Value *zero{nullptr};
    auto   retType = es->getType();
    if (retType->isPointerTy())
      zero = ConstantPointerNull::get(cast<PointerType>(retType));
    else
      zero = ConstantInt::get(retType, -1, true);

    IRB.SetInsertPoint(es);
    CallInst *check;
    if (!fifuzz) {
      check = IRB.CreateCall(FaultInjectionControlFunc);
    } else {
      check = IRB.CreateCall(
          FaultInjectionControlFunc,
          IRB.getInt64(getInsertID(es, InsertType::ErrorCollect)));
    }

    setNoSanitize(check);
    auto cmp = IRB.CreateICmpEQ(check, IRB.getInt1(false));
    setNoSanitize(cast<CmpInst>(cmp));

    auto thenTerm = SplitBlockAndInsertIfThen(cmp, es, false);
    setNoSanitize(thenTerm);
    auto nextBlock = thenTerm->getSuccessor(0);
    IRB.SetInsertPoint(nextBlock, nextBlock->getFirstInsertionPt());

    auto phi = IRB.CreatePHI(es->getType(), 2);
    setNoSanitize(phi);

    es->moveBefore(thenTerm);
    es->replaceAllUsesWith(phi);

    phi->addIncoming(es, thenTerm->getParent());
    phi->addIncoming(zero, check->getParent());
  }
}

uint64_t InstPlugin::getInsertID(llvm::Instruction     *inst,
                                 InstPlugin::InsertType ty) {
  auto *Func = inst->getParent();
  auto  ret = llvm::hash_combine(llvm::hash_value(Func->getName()));
  if (DILocation *Loc = inst->getDebugLoc()) {
    StringRef Dir = Loc->getDirectory();
    StringRef File = Loc->getFilename();
    unsigned  Line = Loc->getLine();
    ret = llvm::hash_combine(ret, llvm::hash_value(Dir), llvm::hash_value(File),
                             llvm::hash_value(Line));
  }
  return (static_cast<uint64_t>(ty) << 56) | (ret >> 8);
}

void InstPlugin::InsertTrace(llvm::Module *m) {
  IRBuilder<> IRB(m->getContext());
  for (const auto &pair : entryExit) {
    IRB.SetInsertPoint(pair.first);
    auto v = getInsertID(pair.first, InsertType::FuncEntry);
    auto call = IRB.CreateCall(FaultInjectionTraceFunc, IRB.getInt64(v));
    setNoSanitize(call);

    for (const auto et : pair.second) {
      IRB.SetInsertPoint(et);
      auto call2 = IRB.CreateCall(
          FaultInjectionTraceFunc,
          IRB.getInt64((static_cast<uint64_t>(InsertType::FuncExit) << 56) |
                       (v >> 8)));
      setNoSanitize(call2);
    }
  }

  for (const auto cs : callSite) {
    IRB.SetInsertPoint(cs);
    auto v = getInsertID(cs, InsertType::CallEntry);
    auto call = IRB.CreateCall(FaultInjectionTraceFunc, IRB.getInt64(v));
    setNoSanitize(call);

    IRB.SetInsertPoint(cs->getNextNode());
    auto call2 = IRB.CreateCall(
        FaultInjectionTraceFunc,
        IRB.getInt64((static_cast<uint64_t>(InsertType::CallExit) << 56) |
                     (v >> 8)));
    setNoSanitize(call2);
  }
}

bool InstPlugin::loadErrFunc(const char *name) {
  if (name == nullptr) return false;
  std::ifstream f(name);
  if (!f.is_open()) return false;

  std::string buf;
  while (std::getline(f, buf)) {
    StringRef bufp(buf);
    if (bufp.startswith("#")) continue;
    auto idx = bufp.find(',');
    if (idx != StringRef::npos) bufp = bufp.substr(0, idx);
    errorFuncs.insert(bufp.trim().str());
  }
  return true;
}

bool InstPlugin::loadErrLoc(const char *name) {
  if (name == nullptr) return false;
  std::ifstream f(name);
  if (!f.is_open()) return false;

  std::string buf;
  while (std::getline(f, buf)) {
    StringRef bufp(buf);
    if (bufp.startswith("#")) continue;
    auto idx = bufp.find(',');
    if (idx != StringRef::npos) bufp = bufp.substr(0, idx);
    unsigned long long v = 0;
    if (getAsUnsignedInteger(bufp.trim(), 10, v)) continue;
    errorLocs.insert({v});
  }
  return true;
}

bool InstPlugin::loadDistance(const char *name) {
  if (name == nullptr) return false;
  std::ifstream f(name);
  if (!f.is_open()) return false;

  std::string buf;
  while (std::getline(f, buf)) {
    StringRef bufp(buf);
    auto      i = bufp.split(',');
    if (i.second.empty()) continue;
    unsigned long long dis = 0;
    if (getAsUnsignedInteger(i.second.trim(), 10, dis)) continue;
    distance[i.first.trim().str()] = dis;
  }
  return true;
}

PreservedAnalyses FaultInjectionPass::run(Module                &M,
                                          ModuleAnalysisManager &MAM) {
  auto plugin = std::make_shared<InstPlugin>();
  plugin->runOnModule(M);
  return PreservedAnalyses::none();
}