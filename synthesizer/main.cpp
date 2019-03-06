#include <utility>

#include <iostream>
#include <memory>
#include <unicorn/unicorn.h>
#include <vector>
#include <functional>

#include "UnicornEngine.h"
#include "Grammar.h"

using namespace std;

int main() {
    // load memory dump
    // Binary binary;
    std::vector<uint8_t> code;
    code.push_back(0x55);

    // execute instructions in memory dump
    UnicornEngine ue(UC_ARCH_X86, UC_MODE_64);

    setup_vm(ue, std::move(code));

    ue.execute();

    // build grammar


    // get input output pairs

    // create Monte Carlo Search Tree

    // simplify using Z3 Prover

    return 0;
}