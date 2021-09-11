# Call Logger

An example of a modified Windows debugger that will attach to a running Wesnoth process, locate all call instructions and change them to an int3 instruction. When the breakpoint is hit, the location will be logged and the instruction will be restored. Then, after the instruction is executed, an int3 instruction will be rewritten to the location.
    
The code and approach are discussed in the article at: https://gamehacking.academy/lesson/42
