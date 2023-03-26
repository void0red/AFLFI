//
// Created by void0red on 23-3-22.
//
#include <iostream>
#include <fstream>
#include <iomanip>
#include <unordered_map>

#include <llvm/IRReader/IRReader.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include "DataFlowGraph.h"
#include "threadpool.h"

using namespace llvm;

static std::vector<const char *> blackPrefix{"__sanitizer_", "__asan_", "__kasan_"};
// nm -j --defined-only lib/string.o
static std::vector<const char *> blackList{
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
        "ExecuteFilesOnyByOne"};
#define ___GFP_NOFAIL 0x8000u

static bool is_alloc_nofail(llvm::CallInst *callInst) {
    static std::unordered_map<std::string, int> alloc_fun = {{"__kmalloc",              1},
                                                             {"kmem_cache_alloc_trace", 1},
                                                             {"alloc_skb",              1},
                                                             {"alloc_pages",            0}};
    auto fn = dyn_cast<Function>(callInst->getCalledOperand())->getName().str();
    auto iter = alloc_fun.find(fn);
    if (iter != alloc_fun.end()) {
        auto parm = callInst->getArgOperand(iter->second);
        if (auto prot = dyn_cast<ConstantInt>(parm)) {
            if (prot->getZExtValue() & ___GFP_NOFAIL)
                return true;
        }
    }
    return false;
}

static char *getBBName(const llvm::BasicBlock *BB) {
    static char *name;

    if (!BB->getName().empty()) {
        name = strdup(BB->getName().str().c_str());
        return name;
    }

    std::string Str;
    raw_string_ostream OS(Str);
    BB->printAsOperand(OS, false);
    name = strdup(OS.str().c_str());
    return name;
}

static std::mutex globalLock;
static unsigned func2IntCounter = 0xabcd0000;
static std::unordered_map<std::string, unsigned> func2Int;

class Path;

static std::unordered_map<std::string, std::vector<Path *>> errorHandling;

template<typename T>
static unsigned edit_distance(T &a, size_t pos1, T &b, size_t pos2) {
    unsigned dp[128][128];
    for (int i = 0; i <= pos1; ++i) {
        dp[i][0] = i;
    }
    for (int i = 0; i <= pos2; ++i) {
        dp[0][i] = i;
    }
    for (int i = 1; i <= pos1; ++i) {
        for (int j = 1; j <= pos2; ++j) {
            dp[i][j] = std::min(dp[i - 1][j] + 1, dp[i][j - 1] + 1);
            dp[i][j] = std::min(dp[i][j], dp[i - 1][j - 1] + (a[i - 1] != b[j - 1]));
        }
    }
    return dp[pos1][pos2];
}

struct Path {
    llvm::CallInst *cs;
    std::vector<llvm::Instruction *> data;
    std::vector<unsigned> sequence;

    explicit Path(llvm::CallInst *CS) : cs(CS) {};

    Path(llvm::CallInst *CS, std::vector<llvm::Instruction *> &a) : cs(CS), data(std::move(a)) {
        for (auto i: data) {
            if (auto *callInst = dyn_cast<CallInst>(i)) {
                auto *callee = dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts());
                if (callee && callee->hasName()) {
                    auto fn = callee->getName().str();
                    auto iter = func2Int.find(fn);
                    if (iter == func2Int.end()) {
                        func2Int[fn] = func2IntCounter;
                        sequence.push_back(func2IntCounter);
                        func2IntCounter += 1;
                    } else {
                        sequence.push_back(iter->second);
                    }
                    continue;
                }
            }
            // handle other inst
            sequence.push_back(i->getOpcode());
        }
    }

    double similarity(Path *other) {
        if (this == other)
            return 0;

        auto size1 = this->sequence.size();
        auto size2 = other->sequence.size();

        if (size1 == 0 && size2 == 0)
            return 1;

        if (size1 == 0 || size2 == 0)
            return 0;

        auto ed = edit_distance(this->sequence, size1, other->sequence, size2);
        auto value = 1 - (ed * 1.0) / std::max(size1, size2);

        return value;
    }
};

void collectOnCallee(std::string fn, CallInst* callInst, MemorySSA& mssa) {
    auto DFG = std::make_unique<DFG::DataFlowGraph>(callInst, mssa);
    DFG->build();
    {
        std::lock_guard<std::mutex> guard(globalLock);
        if (DFG->errorHandling.empty()) {
            errorHandling[fn].push_back(new Path(callInst));
        } else {
            auto path = new Path(callInst, DFG->errorHandling);
            errorHandling[fn].push_back(path);
        }
    }
}

static int counter = 0;

void processEachCallee(const std::string &callee, const std::vector<Path *> &a, std::ofstream &OS) {
    std::string tmp;
    llvm::raw_string_ostream ostream(tmp);

    auto size = a.size();
    for (int i = 0; i < size; ++i) {
        auto cs = a[i]->cs;
        double sum = 0;
        for (int j = 0; i != j && j < size; ++j) {
            sum += a[i]->similarity(a[j]);
        }
        auto avg = sum / size;
        auto &loc = cs->getDebugLoc();
        auto line = -1;
        if (loc) {
            ostream << "# ";
            loc.print(ostream);
            ostream << '\n';
            line = loc.getLine();
        }
        char avgformat[16] = {0};
        snprintf(avgformat, sizeof(avgformat), "%.7f", avg);
        ostream << cs->getFunction()->getName().str() << ',' <<
                //                getBBName(cs->getParent()) << ',' <<
                line << ',' <<
                avgformat << '\n';
    }
    {
        std::lock_guard<std::mutex> guard(globalLock);
        OS << "# " << callee << ":\n" << tmp << '\n';
        if ((++counter) % 100 == 0)
            dbgs() << "Finish " << counter << '\n';
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2)
        return -1;
    SMDiagnostic Err;
    LLVMContext Ctx;
    auto M = parseIRFile(argv[1], Err, Ctx);
    if (!M) {
        Err.print(argv[0], errs());
        errs() << '\n';
    }

    PassBuilder PB;

    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;

    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
    auto MPM = PB.buildPerModuleDefaultPipeline(OptimizationLevel::O1);
//    MPM.addPass(createModuleToFunctionPassAdaptor(CFGOnlyPrinterPass()));
    MPM.run(*M, MAM);

    dbgs() << "Success Load " << M->getSourceFileName() << '\n';

    ThreadPool pool(std::thread::hardware_concurrency());

    for (auto &F: M->functions()) {
        if (F.empty() || F.isIntrinsic())continue;
        if (F.hasName()) {
            auto fn = F.getName();
            if (std::any_of(blackPrefix.begin(), blackPrefix.end(),
                            [&](llvm::StringRef prefix) { return fn.startswith_insensitive(prefix); }) ||
                std::any_of(blackList.begin(), blackList.end(),
                            [&](llvm::StringRef s) { return fn == s || fn.startswith_insensitive(s); }))
                continue;
        }
        for (auto &inst: instructions(F)) {
            if (auto *callInst = dyn_cast<CallInst>(&inst)) {
                auto *callee = dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts());
                if (!callee || callee->isIntrinsic() || !callee->hasName())
                    continue;
                if (!callee->getReturnType()->isIntOrPtrTy() || callee->getReturnType()->isIntegerTy(1))
                    continue;
                auto fn = callee->getName();
                if (std::any_of(blackPrefix.begin(), blackPrefix.end(),
                                [&](llvm::StringRef prefix) { return fn.startswith_insensitive(prefix); }) ||
                    std::any_of(blackList.begin(), blackList.end(),
                                [&](llvm::StringRef s) { return fn == s || fn.startswith_insensitive(s); }))
                    continue;
                if (is_alloc_nofail(callInst))
                    continue;
                auto &mssa = FAM.getResult<MemorySSAAnalysis>(F).getMSSA();
                pool.enqueue(collectOnCallee, fn.str(), callInst, std::ref(mssa));
            }
        }
    }
    pool.join();

    dbgs() << "Success Parse " << errorHandling.size() << " Callee\n";

    ThreadPool pool2(std::thread::hardware_concurrency());

    std::ofstream output_file("result.txt", std::ios::out | std::ios::trunc);

    for (auto &pair: errorHandling) {
        pool2.enqueue(processEachCallee, pair.first, std::ref(pair.second), std::ref(output_file));
    }
    pool2.join();

    return 0;
}