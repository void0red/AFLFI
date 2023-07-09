//
// Created by void0red on 23-7-3.
//
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include "utils.h"

using namespace llvm;
class InstPlugin {
 private:
  const char *FaultInjectionControlName = "__fault_injection_control";
  const char *FaultInjectionTraceName = "__fault_injection_trace";

  llvm::FunctionCallee FaultInjectionControlFunc;
  llvm::FunctionCallee FaultInjectionTraceFunc;

  bool fifuzz{false};
  enum class InsertType {
    FuncEntry = 0xE0,
    FuncExit = 0xE1,
    CallEntry = 0xE2,
    CallExit = 0xE3,
    ErrorCollect = 0xE4,
  };

  unsigned           noSanitizeKindId{0};
  llvm::MDNode      *noSanitizeNode{nullptr};
  llvm::Instruction *setNoSanitize(llvm::Instruction *v);

  std::unordered_set<uint64_t>    errorLocs;
  std::unordered_set<std::string> errorFuncs;

  std::unordered_map<llvm::CallInst *, uint32_t> errorSite;
  std::unordered_set<llvm::CallInst *>           callSite;
  std::unordered_map<llvm::Instruction *,
                     std::unordered_set<llvm::Instruction *>>
      entryExit;

  void CollectInsertPoint(llvm::Module *m);

  void InsertControl(llvm::Module *m);

  void InsertTrace(llvm::Module *m);

  static uint64_t getInsertID(llvm::Instruction *inst, InsertType ty);

 public:
  void runOnModule(llvm::Module &M);
};

struct FaultInjectionPass : public llvm::PassInfoMixin<FaultInjectionPass> {
  InstPlugin              plugin;
  llvm::PreservedAnalyses run(llvm::Module                &M,
                              llvm::ModuleAnalysisManager &MAM) {
    plugin.runOnModule(M);
    return PreservedAnalyses::none();
  }
  static bool isRequired() {
    return true;
  }
};
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "FaultInjectionPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(FaultInjectionPass());
                });
          }};
}

struct LegacyFaultInjectionPass : public llvm::ModulePass {
  static char ID;
  InstPlugin  plugin;
  LegacyFaultInjectionPass() : ModulePass(ID) {
  }
  bool runOnModule(llvm::Module &M) override {
    plugin.runOnModule(M);
    return true;
  }
};
char LegacyFaultInjectionPass::ID = 0;

static void X(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
  PM.add(new LegacyFaultInjectionPass());
}

static RegisterStandardPasses Y(PassManagerBuilder::EP_OptimizerLast, X);

static RegisterStandardPasses Y0(PassManagerBuilder::EP_EnabledOnOptLevel0, X);

llvm::Instruction *InstPlugin::setNoSanitize(llvm::Instruction *v) {
  v->setMetadata(noSanitizeKindId, noSanitizeNode);
  return v;
}

void InstPlugin::runOnModule(llvm::Module &M) {
  if (auto *f = getenv("FJ_FUNC")) {
    ReadErrFunc(f, errorFuncs);
    printf("Load %ld from %s\n", errorFuncs.size(), f);
  }
  if (auto *f = getenv("FJ_LOC")) {
    ReadErrLoc(f, errorLocs);
    printf("Load %ld from %s\n", errorLocs.size(), f);
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

void InstPlugin::CollectInsertPoint(llvm::Module *m) {
  for (auto &func : m->functions()) {
    int counter = 0;
    if (func.empty() || func.isIntrinsic() || IsIgnoreFunction(&func)) continue;

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
          IsIgnoreFunction(callee))
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
      uint64_t hs;
      if (!LocHash(callInst, hs)) continue;
      if (errorLocs.count(hs)) {
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