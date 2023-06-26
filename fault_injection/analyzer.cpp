//
// Created by void0red on 23-6-6.
//
#include <llvm/Analysis/MemorySSA.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/CommandLine.h>
#include <condition_variable>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static std::vector<const char *> blackList{
    "bcmp",    "memchr",      "memchr_inv", "memcmp",  "memscan",
    "stpcpy",  "strcasecmp",  "strcat",     "strchr",  "strchrnul",
    "strcmp",  "strcpy",      "strcspn",    "strlcat", "strlcpy",
    "strlen",  "strncasecmp", "strncat",    "strnchr", "strnchrnul",
    "strncmp", "strncpy",     "strnlen",    "strnstr", "strpbrk",
    "strrchr", "strscpy",     "strsep",     "strspn",  "strstr",
    "strtok",  "atoi",        "printf",     "scanf",   "memcpy",
    "memmove", "atol",        "strto",
};

class ThreadPool {
 public:
  ThreadPool(size_t threads) : stop(false) {
    for (size_t i = 0; i < threads; ++i)
      workers.emplace_back([this] {
        for (;;) {
          std::function<void()> task;

          {
            std::unique_lock<std::mutex> lock(this->queue_mutex);
            this->condition.wait(
                lock, [this] { return this->stop || !this->tasks.empty(); });
            if (this->stop && this->tasks.empty()) return;
            task = std::move(this->tasks.front());
            this->tasks.pop();
          }

          task();
          task_size.fetch_sub(1);
          done.notify_one();
        }
      });
  }

  template <class F, class... Args>
  auto enqueue(F &&f, Args &&...args)
      -> std::future<typename std::result_of<F(Args...)>::type> {
    using return_type = typename std::result_of<F(Args...)>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<return_type> res = task->get_future();
    {
      std::unique_lock<std::mutex> lock(queue_mutex);

      // don't allow enqueueing after stopping the pool
      if (stop) throw std::runtime_error("enqueue on stopped ThreadPool");

      tasks.emplace([task]() { (*task)(); });
      task_size.fetch_add(1);
    }
    condition.notify_one();
    return res;
  }

  void join() {
    {
      std::unique_lock<std::mutex> lock(queue_mutex);
      stop = true;
    }
    condition.notify_all();
    for (std::thread &worker : workers)
      worker.join();
  }

  void wait() {
    std::unique_lock<std::mutex> lock(queue_mutex);
    done.wait(lock, [this] { return task_size == 0; });
  }

 private:
  // need to keep track of threads so we can join them
  std::vector<std::thread> workers;
  // the task queue
  std::queue<std::function<void()>> tasks;

  // synchronization
  std::mutex              queue_mutex;
  std::condition_variable condition;
  bool                    stop;
  std::atomic<uint32_t>   task_size;
  std::condition_variable done;
};

using namespace llvm;

static cl::OptionCategory    DefaultCat("default category");
static cl::list<std::string> InputFiles(cl::Positional, cl::ZeroOrMore,
                                        cl::desc("<input file(s)>"),
                                        cl::cat(DefaultCat));
static cl::opt<std::string>  InputList("list", cl::Optional,
                                       cl::desc("<list file>"),
                                       cl::cat(DefaultCat));

static cl::opt<std::string> OutputFile("out-log", cl::Optional,
                                       cl::init("analyzer.log"),
                                       cl::desc("<output analyzer log>"),
                                       cl::cat(DefaultCat));

static cl::opt<std::string> OutputDefinedFile("out-def", cl::Optional,
                                              cl::init("defined.log"),
                                              cl::desc("<output defined log>"),
                                              cl::cat(DefaultCat));

static cl::opt<bool> hDebug("debug", cl::cat(DefaultCat), cl::Hidden);

struct ErrorHandler {
  CallInst              *callInst;
  std::vector<hash_code> data;
  bool                   checked{false};

  explicit ErrorHandler(CallInst *callInst) : callInst(callInst) {
  }

  ErrorHandler(CallInst *callInst, ArrayRef<BasicBlock *> BBs)
      : callInst(callInst) {
    setEH(BBs);
  }

  void setEH(ArrayRef<BasicBlock *> BBs) {
    if (BBs.empty()) return;
    for (auto *bb : BBs) {
      for (auto &inst : *bb) {
        if (isa<IntrinsicInst>(&inst)) continue;
        data.emplace_back(getHash(inst));
      }
    }
    checked = true;
  }

  hash_code getLocHash() const {
    auto *Func = callInst->getParent();
    auto *Callee =
        dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts());
    std::string fn, cn;
    if (Func->hasName()) { fn = Func->getName().str(); }
    if (Callee->hasName()) { cn = Callee->getName().str(); }
    auto ret = llvm::hash_combine(llvm::hash_value(fn), llvm::hash_value(cn));
    if (DILocation *Loc = callInst->getDebugLoc()) {
      StringRef Dir = Loc->getDirectory();
      StringRef File = Loc->getFilename();
      unsigned  Line = Loc->getLine();
      return llvm::hash_combine(ret, llvm::hash_value(Dir),
                                llvm::hash_value(File), llvm::hash_value(Line));
    }
    return ret;
  }

  double similarity(ErrorHandler *other) {
    if (this == other) return 0;

    auto size1 = this->data.size();
    auto size2 = other->data.size();

    if (size1 == 0 && size2 == 0) return 1;

    if (size1 == 0 || size2 == 0) return 0;

    auto   ed = edit_distance(this->data, other->data);
    double value = 1 - (ed * 1.0) / std::max(size1, size2);

    return value;
  }

 private:
  static hash_code getHash(const Instruction &Inst) {
    SmallVector<Type *, 4> OperTypes;
    for (Value *V : Inst.operands())
      OperTypes.push_back(V->getType());

    if (auto *cmpInst = dyn_cast<CmpInst>(&Inst))
      return llvm::hash_combine(
          llvm::hash_value(Inst.getOpcode()), llvm::hash_value(Inst.getType()),
          llvm::hash_value(cmpInst->getPredicate()),
          llvm::hash_combine_range(OperTypes.begin(), OperTypes.end()));

    if (auto *callInst = dyn_cast<CallInst>(&Inst)) {
      auto *callee =
          dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts());
      if (!callee || callee->isIntrinsic() || !callee->hasName()) goto default_;
      std::string FunctionName = callee->getName().str();
      return llvm::hash_combine(
          llvm::hash_value(Inst.getOpcode()), llvm::hash_value(Inst.getType()),
          llvm::hash_value(Inst.getType()), llvm::hash_value(FunctionName),
          llvm::hash_combine_range(OperTypes.begin(), OperTypes.end()));
    }
  default_:
    return llvm::hash_combine(
        llvm::hash_value(Inst.getOpcode()), llvm::hash_value(Inst.getType()),
        llvm::hash_combine_range(OperTypes.begin(), OperTypes.end()));
  }

  static unsigned edit_distance(ArrayRef<hash_code> a, ArrayRef<hash_code> b) {
    int      pos1 = a.size();
    int      pos2 = b.size();
    unsigned dp[pos1 + 1][pos2 + 1];

    for (int i = 0; i <= pos1; ++i) {
      dp[i][0] = i;
    }
    for (int i = 0; i <= pos2; ++i) {
      dp[0][i] = i;
    }
    for (int i = 1; i <= pos1; ++i) {
      for (int j = 1; j <= pos2; ++j) {
        dp[i][j] = std::min(dp[i - 1][j] + 1, dp[i][j - 1] + 1);
        dp[i][j] =
            std::min(dp[i][j], dp[i - 1][j - 1] + (a[i - 1] != b[j - 1]));
      }
    }
    return dp[pos1][pos2];
  }
};

struct Node {
  llvm::Instruction         *inst;
  std::unordered_set<Node *> inComing;
  std::unordered_set<Node *> outComing;

  explicit Node(llvm::Instruction *inst) : inst(inst) {
  }

  bool addOut(Node *node) {
    this->outComing.insert(node);
    node->inComing.insert(this);
    return true;
  }
};

class DataFlowGraph {
  llvm::Instruction                              *root;
  llvm::MemorySSA                                &mSSA;
  llvm::DominatorTree                            &DT;
  std::vector<llvm::Instruction *>                workList;
  std::unordered_map<llvm::Instruction *, Node *> inst2Node;
  std::unordered_set<Node *>                      nodeSet;
  std::unordered_set<llvm::Value *>               visited;

  using Path = std::vector<Node *>;
  using BBVec = std::vector<BasicBlock *>;

  std::vector<Path> checkedPath;
  bool              isReturn{false};

  bool elemVisited(llvm::Value *elem, bool noInsert = false) {
    if (visited.find(elem) == visited.end()) {
      if (!noInsert) visited.insert(elem);
      return false;
    }
    return true;
  }

  void handleStore(llvm::StoreInst *inst) {
    auto *storeMA = mSSA.getMemoryAccess(inst);
    auto  storeNode = getNode(inst);

    // opt -passes='print<memoryssa>' -disable-output
    std::vector<Value *> toFindUse(storeMA->user_begin(), storeMA->user_end());
    // we ignore the callInst can modify the mem, so we also check the mem
    // layout in the same block
    for (auto i = inst->getNextNonDebugInstruction(); i;
         i = i->getNextNonDebugInstruction()) {
      if (isa<CallInst>(i)) {
        auto *callMA = mSSA.getMemoryAccess(i);
        if (!callMA || callMA == storeMA) continue;
        toFindUse.insert(toFindUse.end(), callMA->user_begin(),
                         callMA->user_end());
      } else {
        break;
      }
    }
    bool find = false;
    while (!toFindUse.empty()) {
      auto *back = toFindUse.back();
      toFindUse.pop_back();
      if (elemVisited(back)) continue;
      if (auto *mu = dyn_cast<MemoryUse>(back)) {
        if (auto *loadInst = dyn_cast<LoadInst>(mu->getMemoryInst())) {
          storeNode->addOut(getNode(loadInst));
          workList.push_back(loadInst);
          find = true;
        }
      } else if (auto *md = dyn_cast<MemoryDef>(back)) {
        if (hDebug) {
          dbgs() << "MemoryDef :";
          md->getMemoryInst()->print(dbgs());
          dbgs() << '\n';
        }
        if (isa_and_nonnull<CallInst>(md->getMemoryInst())) {
          toFindUse.insert(toFindUse.end(), md->user_begin(), md->user_end());
        }
      } else if (auto *mphi = dyn_cast<MemoryPhi>(back)) {
        toFindUse.insert(toFindUse.end(), mphi->user_begin(), mphi->user_end());
      }
    }
    if (!find) {
      // use legacy method, load and store share the same addr
      auto storePtr = inst->getPointerOperand()->stripPointerCasts();
      for (auto ni = inst->getNextNonDebugInstruction(); ni;
           ni = ni->getNextNonDebugInstruction()) {
        if (auto *loadInst = dyn_cast<LoadInst>(ni)) {
          if (loadInst->getPointerOperand()->stripPointerCasts() == storePtr) {
            storeNode->addOut(getNode(loadInst));
            workList.push_back(loadInst);
            find = true;
          }
        }
      }
    }

    if (hDebug && !find) {
      dbgs() << "Can't find load for ";
      inst->print(dbgs());
      dbgs() << '\n';
    }
  }

  bool backwardSave(Node *node, std::vector<Path> &saved) {
    using Stack = std::vector<Node *>;
    Stack              mainStack{node};
    std::vector<Stack> auxStack{
        Stack{node->inComing.begin(), node->inComing.end()}};
    auto end = getNode(root);

    while (!mainStack.empty()) {
      auto &auxTop = auxStack.back();
      if (!auxTop.empty()) {
        auto *n = auxTop.back();
        auxTop.pop_back();
        mainStack.push_back(n);
        auto nAdj = n->inComing;
        for (auto i : mainStack) {
          auto iter = nAdj.find(i);
          if (iter != nAdj.end()) { nAdj.erase(iter); }
        }
        auxStack.emplace_back(nAdj.begin(), nAdj.end());
      } else {
        mainStack.pop_back();
        auxStack.pop_back();
        continue;
      }
      if (mainStack.back() == end) { saved.emplace_back(Path{mainStack}); }
    }
    return true;
  }

  static bool extractIntValue(llvm::Value *v, int64_t &ret) {
    if (auto *ci = dyn_cast<ConstantInt>(v)) {
      ret = ci->getValue().sextOrTrunc(64).getSExtValue();
      return true;
    } else if (auto *ce = dyn_cast<ConstantExpr>(v)) {
      if (auto *i = dyn_cast<ConstantInt>(ce->getOperand(0))) {
        ret = i->getValue().sextOrTrunc(64).getSExtValue();
        return true;
      }
    } else if (isa<ConstantPointerNull>(v)) {
      ret = 0;
      return true;
    }
    return false;
  }

  static llvm::Value *getCmpConstant(llvm::CmpInst *inst, int64_t &cmpValue) {
    if (!inst) return nullptr;
    auto op0 = inst->getOperand(0);
    auto op1 = inst->getOperand(1);
    if (extractIntValue(op0, cmpValue)) return op0;
    if (extractIntValue(op1, cmpValue)) return op1;
    return nullptr;
  }

#define MAX_BLOCK_SIZE 64

  BBVec collectSuccBB(llvm::BasicBlock *bb) {
    BBVec                     ret{bb};
    std::vector<BasicBlock *> work(succ_begin(bb), succ_end(bb));
    while (!work.empty()) {
      auto *front = work.front();
      work.erase(work.begin());
      if (DT.dominates(bb, front)) {
        ret.push_back(bb);
        work.insert(work.end(), succ_end(front), succ_end(front));
      }
    }
    return ret;
  }

  std::unique_ptr<ErrorHandler> check(Path &p) {
    auto *callInst = dyn_cast<CallInst>(root);
    auto  ret = std::make_unique<ErrorHandler>(callInst);
    auto  retType = callInst->getCalledFunction()->getReturnType();

    CmpInst     *cmpInst{nullptr};
    Value       *cmpConstant{nullptr};
    Instruction *termInst = p.front()->inst;

    if (auto *branchInst = dyn_cast<BranchInst>(termInst)) {
      cmpInst = dyn_cast<CmpInst>(branchInst->getCondition());
    } else if (auto *switchInst = dyn_cast<SwitchInst>(termInst)) {
      cmpInst = dyn_cast<CmpInst>(switchInst->getCondition());
    }

    /*
     * ugly pattern
     *
     * if (x == -N)
     * if (x > 0), if (x > -1)
     * if (x >= 0)
     *
     * if (x != 0)
     * if (x < 0), if (x < 1)
     * if (x <= 0)
     *
     * if (x == nullptr)
     * if (!x)
     *
     * if (foo(x))
     */

    BBVec eh;

    if (cmpInst) {
      int64_t cmpValue = 0;
      cmpConstant = getCmpConstant(cmpInst, cmpValue);
      if (!cmpConstant) return ret;

      auto pred = cmpInst->getPredicate();
      if (retType->isIntegerTy()) {
        if ((pred == ICmpInst::ICMP_EQ && cmpValue <= 0) ||
            (pred == ICmpInst::ICMP_SGT &&
             ((cmpValue == 0) || (cmpValue == -1))) ||
            (pred == ICmpInst::ICMP_SGE && cmpValue == 0)) {
          eh = collectSuccBB(termInst->getSuccessor(1));
        } else if ((pred == ICmpInst::ICMP_NE && cmpValue == 0) ||
                   (pred == ICmpInst::ICMP_SLT &&
                    ((cmpValue == 0) || (cmpValue == 1))) ||
                   (pred == ICmpInst::ICMP_SLE && cmpValue == 0)) {
          eh = collectSuccBB(termInst->getSuccessor(0));
        }
      } else if (retType->isPointerTy()) {
        if (pred == CmpInst::ICMP_EQ && cmpValue == 0) {
          eh = collectSuccBB(termInst->getSuccessor(0));
        } else if (pred == CmpInst::ICMP_NE && cmpValue == 0) {
          eh = collectSuccBB(termInst->getSuccessor(1));
        }
      }
    } else {
      // emmm, it may be wrong
      eh = collectSuccBB(termInst->getSuccessor(1));
    }

    if (eh.empty() || eh.size() > MAX_BLOCK_SIZE) return ret;

    ret->setEH(eh);
    return ret;
  }

  Node *getNode(llvm::Instruction *inst) {
    auto iter = inst2Node.find(inst);
    if (iter != inst2Node.end()) return iter->second;
    auto node = new Node(inst);
    inst2Node[inst] = node;
    return node;
  }

 public:
  DataFlowGraph(llvm::Instruction *inst, llvm::MemorySSA &mSSA,
                llvm::DominatorTree &dt)
      : root(inst), mSSA(mSSA), DT(dt), workList({inst}) {
    while (!workList.empty()) {
      auto *i = workList.back();
      workList.pop_back();
      if (elemVisited(i)) continue;
      if (hDebug) {
        i->print(dbgs());
        dbgs() << '\n';
      }

      auto n = getNode(i);

      for (auto u : i->users()) {
        auto *uInst = dyn_cast<Instruction>(u);
        if (!uInst || elemVisited(uInst, true)) continue;
        auto uNode = getNode(uInst);
        n->addOut(uNode);

        if (hDebug) {
          dbgs() << "Child ";
          u->print(dbgs());
          dbgs() << '\n';
        }

        if (auto *storeInst = dyn_cast<StoreInst>(uInst)) {
          handleStore(storeInst);
        } else if (auto *gep = dyn_cast<GEPOperator>(uInst)) {
          if (gep->getPointerOperand() != i) continue;
          // need more check
          workList.push_back(uInst);
        } else if (auto *bo = dyn_cast<BinaryOperator>(uInst)) {
          if (isa<Constant>(bo->getOperand(0)) ||
              isa<Constant>(bo->getOperand(1)))
            workList.push_back(uInst);
        } else if (auto *brInst = dyn_cast<BranchInst>(uInst)) {
          assert(brInst->getCondition() == i);
          backwardSave(uNode, checkedPath);
        } else if (auto *switchInst = dyn_cast<SwitchInst>(uInst)) {
          assert(switchInst->getCondition() == i);
          backwardSave(uNode, checkedPath);
        } else if (isa<ReturnInst>(uInst)) {
          isReturn = true;
        } else if (isa<CmpInst>(uInst) || isa<LoadInst>(uInst) ||
                   isa<PHINode>(uInst) || isa<PtrToIntInst>(uInst) ||
                   isa<CastInst>(uInst) || isa<SelectInst>(uInst)) {
          workList.push_back(uInst);
        }
      }
    }
  }

  ErrorHandler *Eval() {
    auto   ret = std::make_unique<ErrorHandler>(dyn_cast<CallInst>(root));
    size_t size = std::numeric_limits<size_t>::max();
    if (hDebug) {
      dbgs() << "Find " << checkedPath.size() << " paths: ";
      root->print(dbgs());
      dbgs() << '\n';
    }
    for (auto &p : checkedPath) {
      auto &&eh = check(p);
      if ((!ret->checked && eh->checked) ||
          (ret->checked && eh->checked && eh->data.size() < size)) {
        size = eh->data.size();
        ret.swap(eh);
      }
    }
    if (!ret->checked && isReturn) ret->checked = true;
    return ret.release();
  }

  ~DataFlowGraph() {
    for (auto node : nodeSet) {
      delete node;
    }
  }
};

struct Analyzer : AnalysisInfoMixin<Analyzer> {
  using Result = std::vector<ErrorHandler *>;

  Result run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM) {
    Result ret;
    for (auto &inst : instructions(F)) {
      auto *callInst = dyn_cast<CallInst>(&inst);
      if (!callInst) continue;
      auto *callee = callInst->getCalledFunction();
      if (!callee || callee->isIntrinsic() ||
          !callee->getReturnType()->isIntOrPtrTy() || !callee->hasName())
        continue;

      if (std::any_of(blackList.begin(), blackList.end(),
                      [callee](const std::string &s) {
                        return callee->getName().find(s) != StringRef::npos;
                      }))
        continue;

      if (hDebug) {
        dbgs() << "Check " << callee->getName() << " In " << F.getName()
               << '\n';
      }

      auto cg = std::make_unique<DataFlowGraph>(
          callInst, FAM.getResult<MemorySSAAnalysis>(F).getMSSA(),
          FAM.getResult<DominatorTreeAnalysis>(F));
      ret.push_back(cg->Eval());
    }
    return ret;
  }

  static bool isRequired() {
    return true;
  }

 private:
  static llvm::AnalysisKey Key;
  friend struct llvm::AnalysisInfoMixin<Analyzer>;
};

AnalysisKey Analyzer::Key;

static void ReadLists(const std::string &list, std::vector<std::string> &out) {
  std::ifstream f(list);
  std::string   line;
  if (f.is_open()) {
    while (std::getline(f, line)) {
      out.push_back(line);
    }
  }
}

class Runner {
  std::vector<std::unique_ptr<Module>> modules;
  ThreadPool                           pool;

  std::mutex                                                   mu;
  std::unordered_map<std::string, std::vector<ErrorHandler *>> checked,
      unchecked;
  std::unordered_set<std::string> definedFuncs;
  // sort by checked percentage
  std::vector<std::pair<std::string, double>> errFuncs;
  // sort by similarity
  std::unordered_map<ErrorHandler *, double> sims;

  void runOnModule(Module *M) {
    LoopAnalysisManager     LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager    CGAM;
    ModuleAnalysisManager   MAM;

    FAM.registerPass([] { return Analyzer(); });

    PassBuilder PB;
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
    ModulePassManager MPM =
        PB.buildPerModuleDefaultPipeline(OptimizationLevel::O2);

    MPM.run(*M, MAM);

    for (auto &F : *M) {
      if (F.isIntrinsic() || F.empty()) continue;
      if (F.hasName()) {
        std::lock_guard<std::mutex> guard(mu);
        definedFuncs.insert(F.getName().str());
      }
      runOnFunction(&F, FAM);
    }
  }

  void runOnFunction(Function *F, FunctionAnalysisManager &FAM) {
    // may be cost
    auto &res = FAM.getResult<Analyzer>(*F);

    std::lock_guard<std::mutex> guard(mu);
    for (auto *eh : res) {
      auto *callee = eh->callInst->getCalledFunction();
      if (!callee || !callee->hasName()) continue;
      auto fn = callee->getName().str();
      if (eh->checked) {
        checked[fn].push_back(eh);
      } else {
        unchecked[fn].push_back(eh);
      }
    }
  }

  void calcSimilarity(ArrayRef<ErrorHandler *> callee) {
    int                 size = callee.size();
    std::vector<double> sim(size, 0);
    for (int i = 0; i < size; ++i) {
      for (int j = i + 1; j < size; ++j) {
        auto v = callee[i]->similarity(callee[j]);
        sim[i] += v;
        sim[j] += v;
      }
    }
    std::lock_guard<std::mutex> guard(mu);
    for (int i = 0; i < size; ++i) {
      sims[callee[i]] = sim[i] / size;
    }
  }

 public:
  explicit Runner(int i) : pool(i) {
  }

  bool loadFile(const std::string &file) {
    SMDiagnostic Err;
    auto        *Ctx = new LLVMContext();
    auto         M = parseIRFile(file, Err, *Ctx);
    if (!M) {
      Err.print("analyzer", dbgs());
      return false;
    }
    dbgs() << "Load " << file << '\n';
    modules.emplace_back(std::move(M));
    return true;
  }

  void loadFiles(ArrayRef<std::string> files) {
    int counter = 0;
    for (auto &file : files) {
      if (loadFile(file)) counter++;
    }
    dbgs() << "parse " << counter << " files\n";
  }

  void execute() {
    for (auto &m : modules) {
      auto *ptr = m.get();
      pool.enqueue([this, ptr] { this->runOnModule(ptr); });
    }
    pool.wait();

    // calc checked percentage
    for (auto &pair : checked) {
      auto   c = pair.second.size();
      auto   uc = unchecked[pair.first].size();
      double v = (1.0f * c) / (1.0f * (c + uc));
      errFuncs.emplace_back(pair.first, v);

      auto &ehs = pair.second;
      pool.enqueue([this, ehs] { this->calcSimilarity(ehs); });
    }

    using elem = decltype(errFuncs)::value_type;
    std::sort(errFuncs.begin(), errFuncs.end(),
              [](const elem &a, const elem &b) { return a.second > b.second; });

    // calc similarity
    pool.wait();
  }

  void dump_analyzer_log(llvm::raw_ostream &OS) {
    char buf[16];
    for (auto &pair : errFuncs) {
      OS << "# " << pair.first << ',' << checked[pair.first].size() << ','
         << unchecked[pair.first].size() << ',';
      snprintf(buf, sizeof(buf), "%0.3lf", pair.second);
      OS << buf << '\n';
      for (auto eh : unchecked[pair.first]) {
        OS << eh->getLocHash() << ',';
        auto &loc = eh->callInst->getDebugLoc();
        loc.print(OS);
        OS << '\n';
      }
      for (auto eh : checked[pair.first]) {
        snprintf(buf, sizeof(buf), "%0.3lf", sims[eh]);
        OS << eh->getLocHash() << ',' << buf << '\n';
      }
    }
  }

  void dump_defined_func(llvm::raw_ostream &OS) {
    for (auto &fn : definedFuncs) {
      OS << fn << '\n';
    }
  }

  ~Runner() {
    pool.join();
  }
};

int main(int argc, char *argv[]) {
  cl::HideUnrelatedOptions(DefaultCat);
  cl::ParseCommandLineOptions(argc, argv);

  std::vector<std::string> files(InputFiles);
  if (!InputList.empty()) ReadLists(InputList, files);

  auto runner = std::make_unique<Runner>(std::thread::hardware_concurrency());
  runner->loadFiles(files);
  runner->execute();
  std::error_code EC;
  raw_fd_ostream  out(OutputFile, EC);
  runner->dump_analyzer_log(out);

  raw_fd_ostream out2(OutputDefinedFile, EC);
  runner->dump_defined_func(out2);
}