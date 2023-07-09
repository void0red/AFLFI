//
// Created by void0red on 23-7-5.
//
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/Module.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Analysis/CallGraph.h>
#include <fstream>
#include <unordered_map>
#include "threadpool.h"
#include "utils.h"
#include "graph/graph.hpp"
#include "graph/search/dijkstra.hpp"

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

const int BB_DIS_M = 10;

class Runner {
  std::vector<std::unique_ptr<Module>> modules;

  ThreadPool pool;
  std::mutex mu;

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
      if (pair.first->isIntrinsic() || to->isIntrinsic() || !pair.first->hasName()) continue;
      callGraph.AddEdge(pair.first, pair.second->getFunction(), 1);
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

    for (auto &Func : *M) {
      for (auto &BB : Func) {
        for (auto &Inst : BB) {
          if (auto *callInst = dyn_cast<CallInst>(&Inst)) {
            auto *callee = callInst->getCalledFunction();
            if (!callee || callee->isIntrinsic()) continue;
            uint64_t hs;
            if (!LocHash(callInst, hs)) continue;
            if (targetLocHash.find(hs) != targetLocHash.end()) {
              targetBB.insert(&BB);
              targetFunc.insert(&Func);
            }
          }
        }
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

  void processModule(Module *m) {
    for (auto &Func : *m) {
      if (Func.isIntrinsic() || Func.isDeclaration()) continue;

      std::unordered_map<BasicBlock *, double> bbDistance;

      for (auto &BB : Func) {
        if (targetBB.find(&BB) != targetBB.end()) continue;

        double min_avg = -1;
        for (auto &Inst : BB) {
          double dis = 0;
          double cnt = 0;
          if (auto *callInst = dyn_cast<CallInst>(&Inst)) {
            auto *callee = callInst->getCalledFunction();
            if (!callee) continue;
            for (auto &to : targetFunc) {
              auto path = xmotion::Dijkstra::Search(
                  &callGraph, const_cast<const Function *>(callee), to);
              if (path.empty()) continue;
              dis += 1.0 / (1.0 + (int)path.size());
              cnt += 1;
            }
            double avg = cnt / dis;
            if (avg > 0) {
              if (min_avg < 0 || avg < min_avg) min_avg = avg;
            }
          }
        }
        if (min_avg > 0) bbDistance[&BB] = min_avg;
      }

      auto getDistance = [&](BasicBlock *bb) -> double {
        if (targetBB.find(bb) != targetBB.end()) return 0;
        auto iter = bbDistance.find(bb);
        if (iter != bbDistance.end()) { return BB_DIS_M * iter->second; }
        return -1;
      };

      for (auto &BB : Func) {
        uint64_t hs;
        if (!BasicBlockHash(&BB, hs)) continue;
        auto dis = getDistance(&BB);
        if (dis == 0) continue;
        if (dis != -1) {
          distance[hs] = dis * 1000;
        } else {
          dis = 0;
          int cnt = 0;

          std::vector<std::pair<BasicBlock *, int>> succs;
          std::unordered_set<BasicBlock*> visited;
          for (auto bb : successors(&BB)) {
            visited.insert(bb);
            succs.emplace_back(bb, 1);
          }
            

          while (!succs.empty()) {
            auto pair = succs.back();
            succs.pop_back();
            for (auto succ : successors(pair.first)) {
              if (visited.find(succ) != visited.end())
                continue;
              visited.insert(succ);
              succs.emplace_back(succ, pair.second + 1);
            }
            auto tmp_dis = getDistance(pair.first);
            if (tmp_dis == -1) continue;
            dis += 1.0 / (1.0 + dis + pair.second);
            cnt += 1;
          }
          if (dis == 0) continue;
          distance[hs] = cnt / dis * 1000;
        }
      }
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
    dbgs() << "target Func: " << targetFunc.size() << " target BB: " << targetBB.size() << '\n';
  }

  void execute() {
    std::mutex mu;
    int task = 0;
    std::vector<std::future<void>> res;
    for (auto &m : modules) {
      auto *ptr = m.get();
      res.emplace_back(pool.enqueue([this, ptr, &task, &mu] { 
        this->processModule(ptr);
        std::unique_lock<std::mutex> lock(mu);
        task += 1;
        dbgs() << "\rtask done " << task << "/" << modules.size();
      }));
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