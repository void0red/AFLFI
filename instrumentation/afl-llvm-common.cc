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
// location IDs would be assigned randomly (like normal afl/afl++).
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

#include <cstdint>
static const uint16_t crc16tab[256]= {
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

uint16_t crc16(const char *buf,unsigned int len) {
  unsigned int counter;
  uint16_t crc = 0;
  for (counter = 0; counter < len; counter++)
    crc = (crc<<8) ^ crc16tab[((crc>>8) ^ *buf++)&0x00FF];
  return crc;
}

bool InstPlugin::validCmpInst(llvm::CmpInst *cmpInst) {
  auto op0 = cmpInst->getOperand(0);
  auto op1 = cmpInst->getOperand(1);
  if (!(isa<ConstantPointerNull>(op0) || isa<ConstantPointerNull>(op1) ||
        isa<ConstantInt>(op0) || isa<ConstantInt>(op1)))
    return false;

  for (auto u : cmpInst->users()) {
    if (auto *brInst = dyn_cast<BranchInst>(u)) {
      if (brInst->getNumSuccessors() > 1) return true;
    }
  }
  return false;
}

bool InstPlugin::isErrorSite(llvm::CallInst *callInst, bool strict) {
  std::vector<Value *> workList(callInst->user_begin(), callInst->user_end());
  std::unordered_set<Instruction *> visited;
  while (!workList.empty()) {
    auto *inst = dyn_cast<Instruction>(workList.back());
    workList.pop_back();
    if (!inst) continue;
    if (visited.find(inst) != visited.end()) continue;
    visited.insert(inst);

    if (auto *cmpInst = dyn_cast<CmpInst>(inst)) {
      if (validCmpInst(cmpInst)) {
        return true;
      }
    } else if (isa<CastInst>(inst) || isa<SelectInst>(inst) ||
               isa<PHINode>(inst)) {
      workList.insert(workList.end(), inst->user_begin(), inst->user_end());
    }

    if (!strict) {
      if (auto *storeInst = dyn_cast<StoreInst>(inst)) {
        // step 1: use memoryssa to find the load use
        bool  find = false;
        auto &mSSA = FAM.getResult<MemorySSAAnalysis>(*inst->getFunction()).getMSSA();
        auto *storeMA = mSSA.getMemoryAccess(inst);
        // if we need to consider memoryuse of memoryphi?
        std::vector<Value *> toFindUse(storeMA->user_begin(),
                                       storeMA->user_end());
        while (!toFindUse.empty()) {
          auto *back = toFindUse.back();
          toFindUse.pop_back();
          if (auto *mu = dyn_cast<MemoryUse>(back)) {
            auto *loadInst = dyn_cast<LoadInst>(mu->getMemoryInst());
            if (!loadInst) continue;
            find = true;
            workList.insert(workList.end(), loadInst->user_begin(),
                            loadInst->user_end());
          }
        }

        if (find) continue;

        auto ptr =
            storeInst->getPointerOperand()->stripPointerCastsAndAliases();
        find = false;
        for (auto next = storeInst->getNextNode(); next != nullptr && !find;
             next = next->getNextNode()) {
          auto *loadInst = dyn_cast<LoadInst>(next);
          if (!loadInst ||
              loadInst->getPointerOperand()->stripPointerCastsAndAliases() !=
                  ptr)
            continue;
          find = true;
          workList.insert(workList.end(), loadInst->user_begin(),
                          loadInst->user_end());
        }
      }
    }
  }
  return false;
}

llvm::Instruction *InstPlugin::setNoSanitize(llvm::Instruction *v) {
  v->setMetadata(noSanitizeKindId, noSanitizeNode);
  return v;
}

uint64_t InstPlugin::getInsertID(llvm::StringRef file, llvm::StringRef func,
                                 InstPlugin::InsertType ty, uint64_t cnt) {
  return (static_cast<uint64_t>(ty) << 56) |
         ((uint64_t)crc16(file.data(), file.size()) << 40) |
         ((uint64_t)crc16(func.data(), func.size()) << 24) | cnt;
}

void InstPlugin::runOnModule() {
  const auto &logDir = "/tmp/ErrorSite/";
  sys::fs::create_directory(logDir);
  const auto &logName =
      std::to_string(std::hash<std::string>{}(M.getSourceFileName()));
  if (logFile.is_open()) logFile.close();
  logFile.open(logDir + logName, std::ios_base::out | std::ios_base::trunc);

  IRBuilder<> IRB(M.getContext());
  FaultInjectionTraceFunc = M.getOrInsertFunction(
      FaultInjectionTraceName, IRB.getVoidTy(), IRB.getInt64Ty());
  FaultInjectionControlFunc = M.getOrInsertFunction(
      FaultInjectionControlName, IRB.getInt1Ty(), IRB.getInt64Ty());
  noSanitizeKindId = M.getMDKindID("nosanitize");
  noSanitizeNode = MDNode::get(M.getContext(), None);

  preDefined = loadErrorPoint(ep_file);

  CollectInsertPoint(&M);
  logFile << M.getSourceFileName() << " Total " << errorSite.size()
          << " ErrorSite\n";
  InsertTrace(&M);
  InsertControl(&M);
}

static std::vector<const char *> blackList{
    "bcmp",        "memchr",    "memchr_inv", "memcmp",     "memscan", "stpcpy",  "strcasecmp", "strcat",
    "strchr",      "strchrnul", "strcmp",     "strcpy",     "strcspn", "strlcat", "strlcpy",    "strlen",
    "strncasecmp", "strncat",   "strnchr",    "strnchrnul", "strncmp", "strncpy", "strnlen",    "strnstr",
    "strpbrk",     "strrchr",   "strscpy",    "strsep",     "strspn",  "strst"};

void InstPlugin::CollectInsertPoint(llvm::Module *m, bool strict) {
  for (auto &func : m->functions()) {
    if (func.empty() || func.isIntrinsic() || isIgnoreFunction(&func)) continue;
    auto entry = &*func.getEntryBlock().getFirstInsertionPt();
    for (auto &inst : instructions(func)) {
      if (auto *callInst = dyn_cast<CallInst>(&inst)) {
        auto *callee = dyn_cast<Function>(
            callInst->getCalledOperand()->stripPointerCasts());
        if (!callee || callee->isIntrinsic() || isIgnoreFunction(callee))
          continue;

        callSite.insert(callInst);

        if (!callee->empty() || !callee->getReturnType()->isIntOrPtrTy() ||
            callee->getReturnType()->isIntegerTy(1))
          continue;

        auto fn = callee->getName();

        if (std::any_of(blackList.begin(), blackList.end(), [=](const char* prefix){
              return fn.startswith_insensitive(prefix);
            }))
          continue;

        if (!preDefined && isErrorSite(callInst, strict)) {
          errorSite.insert(callInst);
          callSite.erase(callInst);
        }
      } else if (auto *retInst = dyn_cast<ReturnInst>(&inst)) {
        entryExit[entry].insert(retInst);
      }
    }
  }
}

void InstPlugin::InsertTrace(llvm::Module *m) {
  IRBuilder<> IRB(m->getContext());
  auto       &sourceName = m->getSourceFileName();
  std::string        tmp;
  raw_string_ostream ostream(tmp);

  for (const auto &pair : entryExit) {
    auto funcName = pair.first->getFunction()->getName();
    IRB.SetInsertPoint(pair.first);
    auto v = getInsertID(sourceName, funcName, InsertType::FuncEntry, counter);
    auto call = IRB.CreateCall(FaultInjectionTraceFunc, IRB.getInt64(v));
    setNoSanitize(call);

    tmp.clear();
    pair.first->getDebugLoc().print(ostream);
    logFile << v << ',' << tmp << '\n';

    for (const auto et : pair.second) {
      IRB.SetInsertPoint(et);
      auto v2 =
          getInsertID(sourceName, funcName, InsertType::FuncExit, counter);
      auto call2 = IRB.CreateCall(FaultInjectionTraceFunc, IRB.getInt64(v2));
      setNoSanitize(call2);

      tmp.clear();
      et->getDebugLoc().print(ostream);
      logFile << v2 << ',' << tmp << '\n';
    }
    counter++;
  }

  for (const auto cs : callSite) {
    auto funcName = cs->getFunction()->getName();
    IRB.SetInsertPoint(cs);
    auto v = getInsertID(sourceName, funcName, InsertType::CallEntry, counter);
    auto call = IRB.CreateCall(FaultInjectionTraceFunc, IRB.getInt64(v));
    setNoSanitize(call);

    tmp.clear();
    cs->getDebugLoc().print(ostream);
    logFile << v << ',' << tmp << '\n';

    IRB.SetInsertPoint(cs->getNextNode());
    auto v2 = getInsertID(sourceName, funcName, InsertType::CallExit, counter);
    auto call2 = IRB.CreateCall(FaultInjectionTraceFunc, IRB.getInt64(v2));
    setNoSanitize(call2);
    tmp.clear();
    cs->getNextNode()->getDebugLoc().print(ostream);
    logFile << v2 << ',' << tmp << '\n';

    counter++;
  }
}

void InstPlugin::InsertControl(llvm::Module *m) {
  IRBuilder<> IRB(m->getContext());
  auto       &sourceName = m->getSourceFileName();

  for (const auto es : errorSite) {
    auto   funcName = es->getFunction()->getName();
    Value *zero{nullptr};
    auto   retType = es->getType();
    if (retType->isPointerTy())
      zero = ConstantPointerNull::get(cast<PointerType>(retType));
    else
      zero = ConstantInt::get(retType, -1, true);

    IRB.SetInsertPoint(es);
    auto v =
        getInsertID(sourceName, funcName, InsertType::ErrorCollect, counter);
    auto call = IRB.CreateCall(FaultInjectionTraceFunc, IRB.getInt64(v));
    setNoSanitize(call);

    std::string        tmp;
    raw_string_ostream ostream(tmp);
    es->getDebugLoc().print(ostream);
    logFile << v << ',' << tmp << '\n';

    auto check = IRB.CreateCall(FaultInjectionControlFunc, IRB.getInt64(v));
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

    counter++;
  }
}

bool InstPlugin::loadErrorPoint(llvm::StringRef file){
  if (file.empty() || file == "none") return false;
  // avoid complex data structure, we use ',' to sep, e.g.
  // callee, caller, line
  std::ifstream ifstream(file.data());
  if(!ifstream.is_open()) return false;

  std::unordered_map<std::string, std::tuple<std::string, unsigned int>> target;
  std::string buf;
  while (std::getline(ifstream, buf)){
    StringRef bufp(buf);
    auto i = bufp.split(',');
    if (i.second.empty()) continue ;
    auto ii = i.second.split(',');
    if (ii.second.empty()) continue ;
    unsigned long long lineno = 0;
    if (getAsUnsignedInteger(ii.second.trim(), 10, lineno)) continue ;
    target[i.first.trim().str()] = {ii.first.trim().str(), lineno};
  }
  dbgs() << "Load error point file " << file << " Size " << target.size() << '\n';
  if (target.empty()) return false;

  for (auto &func: M){
    auto callerName = func.getName().str();
    for (auto &inst: instructions(func)){
      auto *callInst = dyn_cast<CallInst>(&inst);
      if (!callInst) continue ;
      auto callee = callInst->getCalledFunction();
      if (!callee || !callee->hasName()) continue ;
      auto calleeName = callee->getName().str();
      auto iter = target.find(calleeName);
      if (iter == target.end()) continue ;
      auto line = callInst->getDebugLoc().getLine();
      if (std::get<0>(iter->second) == "*" ||
          (std::get<0>(iter->second) == callerName &&
           std::get<1>(iter->second) == line)){
        errorSite.insert(callInst);
      }
    }
  }

  return true;
}

PreservedAnalyses FaultInjectionPass::run(Module &M,
                                          ModuleAnalysisManager &MAM) {
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  // FAM.registerPass([] { return MemorySSAAnalysis(); });
  InstPlugin plugin(M, MAM, FAM, EPF);
  plugin.runOnModule();
  return PreservedAnalyses::none();
}
// opt -load-pass-plugin