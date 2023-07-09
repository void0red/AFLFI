//
// Created by void0red on 23-7-6.
//

#ifndef ANALYZER_UTILS_H
#define ANALYZER_UTILS_H
#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
void ReadLists(const std::string &list, std::vector<std::string> &out);
void ReadErrFunc(const std::string &name, std::unordered_set<std::string> &out);
void ReadErrLoc(const std::string &name, std::unordered_set<uint64_t> &out);
bool IsIgnoreFunction(const llvm::Function *F);
bool LocHash(const llvm::Instruction *inst, uint64_t &out);
bool BasicBlockHash(const llvm::BasicBlock *bb, uint64_t &out);
#endif  // ANALYZER_UTILS_H