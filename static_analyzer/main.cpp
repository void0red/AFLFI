#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

#include <llvm/IRReader/IRReader.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include "DataFlowGraph.h"
#include "threadpool.h"

static std::vector<const char *> blackPrefix{"__sanitizer_", "__asan_", "__kasan_"};
// nm -j --defined-only lib/string.o
static std::vector<const char *> blackList{
        "bcmp", "memchr", "memchr_inv", "memcmp", "memscan", "stpcpy", "strcasecmp", "strcat",
        "strchr", "strchrnul", "strcmp", "strcpy", "strcspn", "strlcat", "strlcpy", "strlen",
        "strncasecmp", "strncat", "strnchr", "strnchrnul", "strncmp", "strncpy", "strnlen", "strnstr",
        "strpbrk", "strrchr", "strscpy", "strsep", "strspn", "strst"};

using namespace llvm;

static std::unordered_map<std::string, std::unordered_set<llvm::CallInst *>> checked, unchecked;
static std::mutex lock1, lock2, errlock;

struct ThreadData {
    Module *m{};
    LLVMContext Ctx;
};
using ThreadDataPtr = std::unique_ptr<ThreadData>;

ThreadDataPtr process(StringRef path) {
    SMDiagnostic Err;
    auto ret = std::make_unique<ThreadData>();
    auto m = parseIRFile(path, Err, ret->Ctx).release();
    if (!m) {
        std::lock_guard<std::mutex> guard(errlock);
        Err.print("Analysis", errs());
        errs() << '\n';
        return nullptr;
    }
    ret->m = m;

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
    auto MM = PB.buildPerModuleDefaultPipeline(OptimizationLevel::O0);
    MM.run(*m, MAM);

    for (auto &func: m->functions()) {
        if (func.empty() || func.isIntrinsic())
            continue;

        for (auto &inst: instructions(func)) {
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
                auto &mssa = FAM.getResult<MemorySSAAnalysis>(func).getMSSA();
                auto DFG = std::make_unique<DFG::DataFlowGraph>(callInst, mssa);
//                if (func.getName() == "setts_init" && fn == "av_packet_alloc") {
//                    DFG->debug = true;
//                }
                DFG->build();

                if (DFG->isCheckedOrReturn()) {
                    std::lock_guard<std::mutex> guard(lock1);
                    checked[fn.str()].insert(callInst);
                } else {
                    std::lock_guard<std::mutex> guard(lock2);
                    unchecked[fn.str()].insert(callInst);
                }
            }
        }
    }

    return ret;
}

std::vector<std::string> getFiles(llvm::StringRef path) {
    std::vector<std::string> ret;
    std::ifstream f(path.data());
    if (f.is_open()) {
        std::string buf;
        while (std::getline(f, buf)) {
            if (llvm::sys::fs::exists(buf)) {
                ret.push_back(buf);
            }
        }
    } else {
        exit(-1);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc < 2)
        return -1;
    std::vector<std::future<ThreadDataPtr>> module_wrappers;
    ThreadPool pool(std::thread::hardware_concurrency());
    if (argc == 2) {
        auto &&files = getFiles(argv[1]);
        for (auto &file: files) {
            module_wrappers.emplace_back(pool.enqueue(process, file));
        }
    } else {
        for (auto i = 1; i < argc; ++i) {
            module_wrappers.emplace_back(pool.enqueue(process, argv[i]));
        }
    }
    std::vector<ThreadDataPtr> finished_modules;
    for (auto &ft: module_wrappers) {
        auto m = ft.get();
        if (m) {
            finished_modules.emplace_back(std::move(m));
        }
    }
    pool.join();
    dbgs() << "Finish Analysis " << finished_modules.size() << " Modules\n";

    std::vector<std::pair<std::string, double>> unchecked_rate;
    for (const auto &i: checked) {
        const auto &iter = unchecked.find(i.first);
        if (iter != unchecked.end()) {
            auto unchecked_count = iter->second.size();
            auto checked_count = i.second.size();
            unchecked_rate.emplace_back(i.first, unchecked_count * 1.0 / (unchecked_count + checked_count));
        }
    }
    std::sort(unchecked_rate.begin(), unchecked_rate.end(),
              [](decltype(unchecked_rate)::value_type &a, decltype(unchecked_rate)::value_type &b) {
                  return a.second < b.second;
              });
    std::ofstream output_file("result.txt", std::ios::out | std::ios::trunc);
    for (auto &i: unchecked_rate) {
        output_file << "# " << i.first <<
                    " Checked: " << checked[i.first].size() <<
                    " Unchecked: " << unchecked[i.first].size() <<
                    " Rate: " << i.second << '\n';
        for (auto &cs: unchecked[i.first]) {
            auto &loc = cs->getDebugLoc();
            if (loc) {
                std::string tmp;
                llvm::raw_string_ostream ostream(tmp);
                loc.print(ostream);
                output_file << "# " << tmp << '\n';
                output_file << i.first << ',' << cs->getFunction()->getName().str() << ',' << loc.getLine() << '\n';
            } else {
                output_file << "# " << cs->getModule()->getSourceFileName() << '\n';
            }
        }
        output_file << '\n';
    }

    return 0;
}
