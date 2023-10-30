use `make` to compile all code

Here are some tools for evaluation, see more in fault_injection/evaluation.md

1. fault_injection/cc.py: compile target project, generate bitcode and instrumentation
2. fault_injection/build/analyzer: main static analyzer, generate error sites list
3. fault_injection/build/distance: distance calculator
4. fault_injection/analyzer.py: preprocess for fuzzing, do some filter
5. fault_injection/runner.py: SFI driver
6. fault_injection/fuzz.py: main fuzzer
