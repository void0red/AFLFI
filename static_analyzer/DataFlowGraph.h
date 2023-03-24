//
// Created by void0red on 1/12/23.
//

#ifndef FAULTINST_DATAFLOWGRAPH_H
#define FAULTINST_DATAFLOWGRAPH_H

#include <functional>
#include <llvm/Analysis/MemorySSA.h>
#include <llvm/IR/Instructions.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace DFG {
    struct CallCheck {
        llvm::CallInst *callInst;
        llvm::CmpInst *cmpInst;
        llvm::Value *cmpConstant;

        llvm::BranchInst *branchInst;
        llvm::SwitchInst *switchInst;

        enum class ReturnKind {
            INVALID,
            NULLPTR,
            NEGATIVE,
            NEGATIVE_PTR,
            CONCRETE,
        };
        ReturnKind retKind;

        CallCheck(llvm::CallInst *callInst, llvm::CmpInst *cmpInst, llvm::BranchInst *branchInst,
                  llvm::SwitchInst *switchInst, llvm::Value *cmpConstant, CallCheck::ReturnKind retKind);

        void print(llvm::raw_ostream &OS);

        static llvm::Value *getCmpConstant(llvm::CmpInst *inst, int64_t &cmpValue);

        static std::string returnKindString(ReturnKind rk);

        // to check if exist ZERO and NEGATIVE ret
        bool conflict(CallCheck *other);
    };

    using CallCheckPtr = std::unique_ptr<CallCheck>;

    struct Node {
        llvm::Instruction *inst;
        std::unordered_set<Node *> inComing;
        std::unordered_set<Node *> outComing;

        explicit Node(llvm::Instruction *inst);

        bool addOut(Node *node);
    };

    struct Path {
        std::vector<Node *> data;

        void print(llvm::raw_ostream &OS);
    };

    class DataFlowGraph {
        llvm::Instruction *root;
        llvm::MemorySSA &mSSA;
        std::unordered_map<llvm::Instruction *, Node *> inst2Node;
        std::unordered_set<Node *> nodeSet;
        std::vector<llvm::Instruction *> workList;
        std::unordered_set<llvm::Value *> visited;

        std::unordered_set<Path *> pathSet;
        std::unordered_map<llvm::Instruction *, Path *> checkMap, retMap;

        bool elemVisited(llvm::Value *elem, bool noInsert = false);

        void handleStore(llvm::StoreInst *inst);

        bool cachePath(Node *node, std::unordered_map<llvm::Instruction *, Path *> &saved);

        CallCheckPtr extractCallCheck(struct Path *p);
    public:
        bool debug = false;
        using InstVec = std::vector<llvm::Instruction *>;
        using DepthInstVecMap = std::unordered_map<int, std::vector<InstVec>>;

        static bool collectSuccInst(llvm::BasicBlock *bb, DepthInstVecMap &ret, int depth = 0);

        DataFlowGraph(llvm::Instruction *inst, llvm::MemorySSA &mSSA);

        Node *getNode(llvm::Instruction *inst);

        CallCheckPtr callCheck;

        InstVec errorHandling;

        void build();

        bool isCheckedOrReturn();

        ~DataFlowGraph();
    };
} // namespace DFG

#endif // FAULTINST_DATAFLOWGRAPH_H
