#!/usr/bin/env bash
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1
export FJ_ERR=errs.filter.txt
make