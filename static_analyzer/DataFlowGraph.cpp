//
// Created by void0red on 1/12/23.
//

#include "DataFlowGraph.h"
#include <llvm/Analysis/MemorySSA.h>
#include <llvm/IR/Operator.h>

using namespace llvm;
using namespace DFG;

Node::Node(llvm::Instruction *inst) : inst(inst) {}

bool Node::addOut(Node *node) {
    this->outComing.insert(node);
    node->inComing.insert(this);
    return true;
}

DataFlowGraph::DataFlowGraph(llvm::Instruction *inst, llvm::MemorySSA &mSSA) : root(inst), mSSA(mSSA) {
    workList.push_back(inst);
}

bool DataFlowGraph::elemVisited(llvm::Value *elem, bool noInsert) {
    if (visited.find(elem) == visited.end()) {
        if (!noInsert)
            visited.insert(elem);
        return false;
    }
    return true;
}

void DataFlowGraph::build() {
    while (!workList.empty()) {
        auto *i = workList.back();
        workList.pop_back();
        if (elemVisited(i))
            continue;
        if (debug) {
            i->print(dbgs());
            dbgs() << '\n';
        }

        auto n = getNode(i);

        for (auto u: i->users()) {
            auto *uInst = dyn_cast<Instruction>(u);
            if (!uInst || elemVisited(uInst, true))
                continue;
            auto uNode = getNode(uInst);
            n->addOut(uNode);

            if (debug) {
                dbgs() << "Child ";
                u->print(dbgs());
                dbgs() << '\n';
            }

            if (auto *storeInst = dyn_cast<StoreInst>(uInst)) {
                handleStore(storeInst);
            } else if (auto *gep = dyn_cast<GEPOperator>(uInst)) {
                if (gep->getPointerOperand() != i)
                    continue;
                // need more check
                workList.push_back(uInst);
            } else if (auto *bo = dyn_cast<BinaryOperator>(uInst)) {
                if (isa<Constant>(bo->getOperand(0)) || isa<Constant>(bo->getOperand(1)))
                    workList.push_back(uInst);
            } else if (auto *brInst = dyn_cast<BranchInst>(uInst)) {
                assert(brInst->getCondition() == i);
                cachePath(uNode, checkMap);
            } else if (auto *switchInst = dyn_cast<SwitchInst>(uInst)) {
                assert(switchInst->getCondition() == i);
                cachePath(uNode, checkMap);
            } else if (isa<ReturnInst>(uInst)) {
                cachePath(uNode, retMap);
            } else if (isa<CmpInst>(uInst) || isa<LoadInst>(uInst) || isa<PHINode>(uInst) || isa<PtrToIntInst>(uInst) ||
                       isa<CastInst>(uInst) || isa<SelectInst>(uInst)) {
                workList.push_back(uInst);
            } else if (isa<CallInst>(uInst) || isa<ExtractValueInst>(uInst) || isa<InsertValueInst>(uInst) ||
                       isa<ExtractElementInst>(uInst) || isa<InsertElementInst>(uInst) || isa<CallBrInst>(uInst) ||
                       isa<FreezeInst>(uInst)) {
                // ignore
                continue;
            } else {
//                dbgs() << "#### Unhandled #####\n";
//                uInst->getDebugLoc().print(dbgs());
//                dbgs() << '\n';
//                uInst->print(dbgs());
//                dbgs() << "\n\n";
            }
        }
    }

    auto max_size = INT_MAX;
    for (auto &iter: checkMap) {
        if (debug) {
            dbgs() << "#### Path ####\n";
            iter.second->print(dbgs());
            dbgs() << '\n';
        }
        auto c = extractCallCheck(iter.second);
        auto size = iter.second->data.size();
        if (c && size < max_size) {
            max_size = size;
            callCheck = std::move(c);
        }
    }
}

bool DataFlowGraph::isCheckedOrReturn() { return callCheck || !retMap.empty(); }

void DataFlowGraph::handleStore(llvm::StoreInst *inst) {
    auto *storeMA = mSSA.getMemoryAccess(inst);
    auto storeNode = getNode(inst);

    //opt -passes='print<memoryssa>' -disable-output
    std::vector<Value *> toFindUse(storeMA->user_begin(), storeMA->user_end());
    // we ignore the callInst can modify the mem, so we also check the mem layout in the same block
    for (auto i = inst->getNextNonDebugInstruction(); i; i = i->getNextNonDebugInstruction()) {
        if (isa<CallInst>(i)) {
            auto *callMA = mSSA.getMemoryAccess(i);
            if (!callMA || callMA == storeMA) continue;
            toFindUse.insert(toFindUse.end(), callMA->user_begin(), callMA->user_end());
        } else {
            break;
        }
    }
    bool find = false;
    while (!toFindUse.empty()) {
        auto *back = toFindUse.back();
        toFindUse.pop_back();
        if (elemVisited(back))continue;
        if (auto *mu = dyn_cast<MemoryUse>(back)) {
            if (auto *loadInst = dyn_cast<LoadInst>(mu->getMemoryInst())) {
                storeNode->addOut(getNode(loadInst));
                workList.push_back(loadInst);
                find = true;
            }
        } else if (auto *md = dyn_cast<MemoryDef>(back)) {
            if (debug) {
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
        for (auto ni = inst->getNextNonDebugInstruction(); ni; ni = ni->getNextNonDebugInstruction()) {
            if (auto *loadInst = dyn_cast<LoadInst>(ni)) {
                if (loadInst->getPointerOperand()->stripPointerCasts() == storePtr) {
                    storeNode->addOut(getNode(loadInst));
                    workList.push_back(loadInst);
                    find = true;
                }
            }
        }
    }

    if (debug && !find) {
        dbgs() << "Can't find load for ";
        inst->print(dbgs());
        dbgs() << '\n';
        mSSA.print(dbgs());
    }
}

Node *DataFlowGraph::getNode(llvm::Instruction *inst) {
    auto iter = inst2Node.find(inst);
    if (iter != inst2Node.end())
        return iter->second;
    auto node = new Node(inst);
    inst2Node[inst] = node;
    return node;
}

bool DataFlowGraph::cachePath(Node *node, std::unordered_map<llvm::Instruction *, Path *> &saved) {
    auto check = saved.find(node->inst);
    assert(check == saved.end());

    using Stack = std::vector<Node *>;
    Stack mainStack{node};
    std::vector<Stack> auxStack{Stack{node->inComing.begin(), node->inComing.end()}};
    auto end = getNode(root);

    while (!mainStack.empty()) {
        auto &auxTop = auxStack.back();
        if (!auxTop.empty()) {
            auto *n = auxTop.back();
            auxTop.pop_back();
            mainStack.push_back(n);
            auto nAdj = n->inComing;
            for (auto i: mainStack) {
                auto iter = nAdj.find(i);
                if (iter != nAdj.end()) {
                    nAdj.erase(iter);
                }
            }
            auxStack.emplace_back(nAdj.begin(), nAdj.end());
        } else {
            mainStack.pop_back();
            auxStack.pop_back();
            continue;
        }
        if (mainStack.back() == end) {
            auto p = new Path{mainStack};
            pathSet.insert(p);
            saved[node->inst] = p;
        }
    }
    return true;
}

#define MAX_COLLECT_DEPTH 5
#define MAX_PATH_LENGTH 120

bool DataFlowGraph::collectSuccInst(llvm::BasicBlock *bb, DepthInstVecMap &ret, int depth) {
    if (depth > MAX_COLLECT_DEPTH)
        return false;
    InstVec tmp;
    for (auto &inst: *bb) {
        if (inst.isDebugOrPseudoInst())
            continue;
        tmp.push_back(&inst);
    }
    auto term = bb->getTerminator();
    auto exist_one = false;
    for (auto succ: successors(term)) {
        DepthInstVecMap subRet;
        auto ok = collectSuccInst(succ, subRet, depth + 1);
        if (ok) {
            exist_one = true;
            for (auto &i: subRet) {
                for (auto &j: i.second) {
                    InstVec subVec(tmp);
                    subVec.insert(subVec.end(), j.begin(), j.end());
                    ret[i.first].emplace_back(subVec);
                }
            }
        }
    }
    if (!exist_one && !tmp.empty()) {
        ret[depth].emplace_back(tmp);
    }
    return !ret.empty();
}

DataFlowGraph::~DataFlowGraph() {
    for (auto node: nodeSet) {
        delete node;
    }
    for (auto path: pathSet) {
        delete path;
    }
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

CallCheck::CallCheck(llvm::CallInst *callInst, llvm::CmpInst *cmpInst, llvm::BranchInst *branchInst,
                     llvm::SwitchInst *switchInst, llvm::Value *cmpConstant, CallCheck::ReturnKind retKind)
        : callInst(callInst), cmpInst(cmpInst), cmpConstant(cmpConstant), branchInst(branchInst),
          switchInst(switchInst),
          retKind(retKind) {}

llvm::Value *CallCheck::getCmpConstant(llvm::CmpInst *inst, int64_t &cmpValue) {
    if (!inst)
        return nullptr;
    auto op0 = inst->getOperand(0);
    auto op1 = inst->getOperand(1);
    if (extractIntValue(op0, cmpValue))
        return op0;
    if (extractIntValue(op1, cmpValue))
        return op1;
    return nullptr;
}

void CallCheck::print(raw_ostream &OS) {
    callInst->print(OS);
    OS << '\n';
    if (cmpInst) {
        cmpInst->print(OS);
        OS << '\n';
    }
    if (branchInst) {
        branchInst->print(OS);
    } else if (switchInst) {
        switchInst->print(OS);
    }

    OS << '\n';
}

// need null check
CallCheckPtr DataFlowGraph::extractCallCheck(struct Path *p) {
    auto *callInst = dyn_cast<CallInst>(p->data.back()->inst);
    auto retType = callInst->getCalledFunction()->getReturnType();

    CmpInst *cmpInst{nullptr};
    BranchInst *branchInst{nullptr};
    SwitchInst *switchInst{nullptr};

    Value *cmpConstant{nullptr};
    CallCheck::ReturnKind retKind{CallCheck::ReturnKind::INVALID};

    Instruction *termInst{nullptr};

    auto fInst = p->data.front()->inst;
    if ((branchInst = dyn_cast<BranchInst>(fInst))) {
        cmpInst = dyn_cast<CmpInst>(branchInst->getCondition());
        termInst = branchInst;
    } else if ((switchInst = dyn_cast<SwitchInst>(fInst))) {
        cmpInst = dyn_cast<CmpInst>(switchInst->getCondition());
        termInst = switchInst;
    }

    if (cmpInst) {
        int64_t cmpValue;
        cmpConstant = CallCheck::getCmpConstant(cmpInst, cmpValue);
        if (!cmpConstant)
            return nullptr;

        auto pred = cmpInst->getPredicate();
        auto ok = false;
        DepthInstVecMap insts_map;

        /*
         * ugly code:
         *
         * if (ret < 0) {error handling}
         * if (ret == -1) {error handling}
         * if (!ret) {error handling}
         * if (ret == NULL) {error handling}
         *
         */
        if (retType->isIntegerTy()) {
            if (cmpValue == 0 && (pred == ICmpInst::ICMP_SGT || pred == ICmpInst::ICMP_SGE)) {
                retKind = CallCheck::ReturnKind::NEGATIVE;
                ok = collectSuccInst(termInst->getSuccessor(1), insts_map);
            } else if (cmpValue == 0 && (pred == ICmpInst::ICMP_SLE || pred == ICmpInst::ICMP_SLT)) {
                retKind = CallCheck::ReturnKind::NEGATIVE;
                ok = collectSuccInst(termInst->getSuccessor(0), insts_map);
            } else if (cmpValue < 0 && pred == ICmpInst::ICMP_EQ) {
                retKind = CallCheck::ReturnKind::NEGATIVE;
                ok = collectSuccInst(termInst->getSuccessor(0), insts_map);
            } else {
                return nullptr;
            }
        } else if (retType->isPointerTy()) {
            if (pred == CmpInst::ICMP_EQ && cmpValue == 0) {
                retKind = CallCheck::ReturnKind::NULLPTR;
                ok = collectSuccInst(termInst->getSuccessor(0), insts_map);
            } else if (pred == CmpInst::ICMP_NE && cmpValue == 0) {
                retKind = CallCheck::ReturnKind::NULLPTR;
                ok = collectSuccInst(termInst->getSuccessor(1), insts_map);
            } else {
                return nullptr;
            }
        }
        // find the min depth succ inst
        int min_depth = INT_MAX;
        for (auto &pair: insts_map) {
            if (pair.first < min_depth) {
                min_depth = pair.first;
            }
        }
        int min_path_length = INT_MAX;
        for (auto &i: insts_map[min_depth]) {
            if (i.size() < min_path_length && i.size() < MAX_PATH_LENGTH) {
                min_path_length = i.size();
                errorHandling = i;
            }
        }
    } else {
        if (retType->isIntegerTy()) {
            retKind = CallCheck::ReturnKind::NEGATIVE;
        }
    }

    return std::make_unique<CallCheck>(callInst, cmpInst, branchInst, switchInst, cmpConstant, retKind);
}

bool CallCheck::conflict(CallCheck *other) {
    if (this == other)
        return false;
    if (retKind == ReturnKind::NULLPTR &&
        (other->retKind == ReturnKind::NEGATIVE || other->retKind == ReturnKind::NEGATIVE_PTR))
        return true;
    if ((retKind == ReturnKind::NEGATIVE || retKind == ReturnKind::NEGATIVE_PTR) &&
        other->retKind == ReturnKind::NULLPTR)
        return true;
    return false;
}

std::string CallCheck::returnKindString(CallCheck::ReturnKind rk) {
    static const char *name[] = {"INVALID", "NULLPTR", "NEGATIVE", "NEGATIVE_PTR", "CONCRETE"};
    return name[int(rk)];
}

void Path::print(raw_ostream &OS) {
    for (auto node: data) {
        node->inst->print(OS);
        OS << '\n';
    }
}
