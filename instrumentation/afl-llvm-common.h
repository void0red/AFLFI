#ifndef __AFLLLVMCOMMON_H
#define __AFLLLVMCOMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <optional>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

#if LLVM_VERSION_MAJOR >= 11
  #define MNAME M.getSourceFileName()
  #define FMNAME F.getParent()->getSourceFileName()
  #if LLVM_VERSION_MAJOR >= 16
  // None becomes deprecated
  // the standard std::nullopt_t is recommended instead
  // from C++17 and onwards.
  constexpr std::nullopt_t None = std::nullopt;
  #endif
#else
  #define MNAME std::string("")
  #define FMNAME std::string("")
#endif

char *getBBName(const llvm::BasicBlock *BB);
bool  isIgnoreFunction(const llvm::Function *F);
void  initInstrumentList();
bool  isInInstrumentList(llvm::Function *F, std::string Filename);
unsigned long long int calculateCollisions(uint32_t edges);
void                   scanForDangerousFunctions(llvm::Module *M);

#ifndef IS_EXTERN
  #define IS_EXTERN
#endif

IS_EXTERN int debug;
IS_EXTERN int be_quiet;

#undef IS_EXTERN

#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/IR/InstIterator.h"
#include <unordered_set>
#include <unordered_map>

class InstPlugin {
 private:
  const char *FaultInjectionTraceName = "__fault_injection_trace";
  const char *FaultInjectionControlName = "__fault_injection_control";
  const char *FaultInjectionDistanceName = "__fault_injection_distance";

  llvm::FunctionCallee FaultInjectionTraceFunc;
  llvm::FunctionCallee FaultInjectionControlFunc;
  llvm::FunctionCallee FaultInjectionDistanceFunc;

  unsigned      noSanitizeKindId{0};
  llvm::MDNode *noSanitizeNode{nullptr};

  bool preDefined{false};

  enum class InsertType {
    FuncEntry = 0xE0,
    FuncExit = 0xE1,
    CallEntry = 0xE2,
    CallExit = 0xE3,
    ErrorCollect = 0xE4,
    ErrorBranch = 0xE5,
  };

  llvm::Instruction *setNoSanitize(llvm::Instruction *v);

  uint64_t counter{0};

  static uint64_t getInsertID(llvm::StringRef file, llvm::StringRef func,
                              InsertType ty, uint64_t cnt);

  static bool validCmpInst(llvm::CmpInst *cmpInst);

  bool loadErrorPoint(llvm::StringRef file);

  std::unordered_map<std::string, unsigned> distance;

  bool loadDistance(llvm::StringRef file);

  std::ofstream logFile;

  llvm::Module&M;

  llvm::ModuleAnalysisManager &MAM;

  llvm::FunctionAnalysisManager&FAM;

  std::string ep_file;
  std::string dis_file;

 public:
  using InstSet = std::unordered_set<llvm::CallInst *>;
  using EntryExit = std::unordered_map<llvm::Instruction *,
                                       std::unordered_set<llvm::Instruction *>>;

  InstSet   errorSite, callSite;
  EntryExit entryExit;

  InstPlugin(llvm::Module &M, llvm::ModuleAnalysisManager &MAM,
             llvm::FunctionAnalysisManager &FAM);

  void runOnModule();

  void CollectInsertPoint(llvm::Module *m, bool strict = false);

  void InsertTrace(llvm::Module *m);

  void InsertControl(llvm::Module *m);

  bool isErrorSite(llvm::CallInst *callInst, bool strict = false);
};

class FaultInjectionPass : public llvm::PassInfoMixin<FaultInjectionPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
};

#endif

