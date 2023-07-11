//
// Created by void0red on 23-7-5.
//
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/SourceMgr.h>
#include <fstream>
#include <unordered_map>
#include "graph/graph.hpp"
#include "graph/search/dijkstra.hpp"
#include "threadpool.h"
#include "utils.h"

using namespace llvm;
static cl::OptionCategory   DefaultCat("default category");
static cl::opt<std::string> InputList("list", cl::Required,
                                      cl::desc("<list file>"),
                                      cl::cat(DefaultCat));
static cl::opt<std::string> FuncFile("func", cl::Optional,
                                     cl::desc("<func file>"),
                                     cl::init("func.txt"), cl::cat(DefaultCat));

static cl::opt<std::string> LocFile("loc", cl::Optional, cl::desc("<loc file>"),
                                    cl::init("loc.txt"), cl::cat(DefaultCat));

static cl::opt<std::string> DisFile("dis", cl::Optional,
                                    cl::desc("<out dis file>"),
                                    cl::init("dis.txt"), cl::cat(DefaultCat));

template <typename T>
struct PointerIndexer {
  int64_t operator()(T *state) {
    return (int64_t)state;
  }
};

class Runner {
  std::vector<std::unique_ptr<Module>> modules;

  ThreadPool pool;

  std::unordered_set<std::string> targetFuncName;
  std::unordered_set<uint64_t>    targetLocHash;

  std::unordered_set<const llvm::Function *> targetFunc;
  std::unordered_set<llvm::BasicBlock *>     targetBB;

  using CallGraphTy = xmotion::Graph<const llvm::Function *, double,
                                     PointerIndexer<const llvm::Function>>;

  CallGraphTy callGraph;

  std::unordered_map<std::string, std::unordered_set<const llvm::Function *>>
      declareFunc, definedFunc;

  std::unordered_map<uint64_t, uint64_t> distance;

  void buildGraph(Module *M) {
    LoopAnalysisManager     LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager    CGAM;
    ModuleAnalysisManager   MAM;
    PassBuilder             PB;
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
    ModulePassManager MPM =
        PB.buildPerModuleDefaultPipeline(OptimizationLevel::O2);
    MPM.run(*M, MAM);

    // build sub callgraph
    auto &CGA = MAM.getResult<CallGraphAnalysis>(*M);
    for (auto &pair : CGA) {
      if (!pair.first) continue;
      auto to = pair.second->getFunction();
      if (pair.first->isIntrinsic() || to->isIntrinsic() ||
          !pair.first->hasName())
        continue;

      auto counter = 1;
      for (auto &BB : *to) {
        for (auto &Inst : BB) {
          if (auto *callInst = dyn_cast<CallInst>(&Inst)) {
            auto *callee = callInst->getCalledFunction();
            if (!callee || callee->isIntrinsic()) continue;
            uint64_t hs;
            if (!LocHash(callInst, hs)) continue;
            if (targetLocHash.find(hs) != targetLocHash.end()) {
              counter += 1;
              targetBB.insert(&BB);
              targetFunc.insert(to);
            }
          }
        }
      }

      callGraph.AddEdge(pair.first, pair.second->getFunction(), 1.0 / counter);
      auto fn = pair.first->getName().str();
      if (targetFuncName.find(fn) != targetFuncName.end()) {
        targetFunc.insert(pair.first);
      }
      if (pair.first->isDeclaration()) {
        declareFunc[fn].insert(pair.first);
      } else {
        definedFunc[fn].insert(pair.first);
      }
    }
  }

  // merge sub callgraph
  void buildGraphFinal() {
    for (auto &pair : definedFunc) {
      auto iter = declareFunc.find(pair.first);
      if (iter == declareFunc.end()) continue;
      for (auto from : pair.second) {
        for (auto to : iter->second) {
          callGraph.AddEdge(from, to, 0);
        }
      }
    }
  }

  bool loadFile(const std::string &file) {
    SMDiagnostic Err;
    auto        *Ctx = new LLVMContext();
    auto         M = parseIRFile(file, Err, *Ctx);
    if (!M) {
      Err.print("distance", dbgs());
      return false;
    }
    buildGraph(M.get());
    dbgs() << "Load " << file << '\n';
    modules.emplace_back(std::move(M));
    return true;
  }

  void processOnFunction(Function *Func) {
    for (auto &BB : *Func) {
      uint64_t hs;
      if (!BasicBlockHash(&BB, hs)) continue;
      if (targetBB.find(&BB) != targetBB.end()) {
        distance[hs] = 0;
        continue;
      }
      double avg_min = -1;
      for (auto &Inst : BB) {
        double dis = 0;
        double cnt = 0;
        if (auto *callInst = dyn_cast<CallInst>(&Inst)) {
          auto *callee = callInst->getCalledFunction();
          if (!callee) continue;
          for (auto &to : targetFunc) {
            auto length = xmotion::Dijkstra::FindMinPath(
                &callGraph, const_cast<const Function *>(callee), to);
            if (length < 0) continue;
            dis += 1.0 / (1.0 + length);
            cnt += 1;
          }
          double avg = cnt / dis;
          if (avg > 0) {
            if (avg_min < 0 || avg < avg_min) avg_min = avg;
          }
        }
      }
      if (avg_min > 0) { distance[hs] = avg_min * 100; }
    }
  }

 public:
  explicit Runner(int i) : pool(i) {
    ReadErrFunc(FuncFile, targetFuncName);
    ReadErrLoc(LocFile, targetLocHash);
    dbgs() << "Load Func " << targetFuncName.size() << ", Loc "
           << targetLocHash.size() << '\n';
  }

  void loadFiles(ArrayRef<std::string> files) {
    int counter = 0;
    for (auto &file : files) {
      if (loadFile(file)) counter++;
    }
    buildGraphFinal();
    dbgs() << "target Func: " << targetFunc.size()
           << " target BB: " << targetBB.size() << '\n';
  }

  void execute() {
    std::mutex                     mu;
    int                            task = 0;
    std::vector<std::future<void>> res;
    for (auto &m : modules) {
      for (auto &func : m->functions()) {
        if (func.isIntrinsic() || func.isDeclaration()) continue;
        auto ptr = &func;
        res.emplace_back(pool.enqueue([this, ptr, &task, &mu] {
          this->processOnFunction(ptr);
          std::unique_lock<std::mutex> lock(mu);
          task += 1;
          dbgs() << "\rtask done " << task << " functions";
        }));
      }
    }
    pool.wait(res);
  }

  void dump_distance(llvm::raw_ostream &OS) {
    for (auto &pair : distance) {
      OS << pair.first << ',' << pair.second << '\n';
    }
  }
};

int main(int argc, char *argv[]) {
  cl::HideUnrelatedOptions(DefaultCat);
  cl::ParseCommandLineOptions(argc, argv);
  std::vector<std::string> files;
  ReadLists(InputList, files);
  auto runner = std::make_unique<Runner>(std::thread::hardware_concurrency());
  runner->loadFiles(files);
  runner->execute();
  std::error_code EC;
  raw_fd_ostream  out(DisFile, EC);
  runner->dump_distance(out);
}