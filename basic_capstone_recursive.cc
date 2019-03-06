#include <iostream>
#include <queue>
#include <string>
#include <capstone/capstone.h>
#include <map>

#include "loader/loader.h"

using namespace std;

int disasm(Binary* bin);
void print_ins(cs_insn *ins);
bool is_cs_cflow_group(uint8_t g);
bool is_cs_cflow_ins(cs_insn *ins);
bool is_cs_unconditional_cflow_ins(cs_insn *ins);

uint64_t get_cs_ins_immediate_target(cs_insn *ins);

int main(int argc, char* argv[])
{
    Binary bin;

    std::string fname;

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    fname.assign(argv[1]);

    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
        return 1;
    }

    if (disasm(&bin) < 0) {
        return 1;
    }

    unload_binary(&bin);

    return 0;
}

int disasm(Binary *bin) {
    csh dis;
    cs_insn * cs_ins;
    Section *text;
    size_t n;
    const uint8_t *pc;
    uint64_t addr, offset, target;

    queue<uint64_t> Q;
    map<uint64_t, bool> seen;

    text = bin->get_text_section();

    if (!text) {
        cerr << "Nothing to disassemble\n";
        return 0;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
        cerr << "Failed to open Capstone\n";
        return -1;
    }

    cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

    cs_ins = cs_malloc(dis);

    if (!cs_ins) {
        cerr << "Out of memory\n";
        cs_close(&dis);
        return -1;
    }

    addr = bin->entry;
    if (text->contains(addr)) Q.push(addr);
    cout << "entry point: 0x" << hex << addr << "\n";

    for (auto &sym : bin->symbols) {
        if (sym.type == Symbol::SYM_TYPE_FUNC
        && text->contains(sym.addr)) {
            Q.push(sym.addr);
            cout << "function symbol: " << sym.addr << "\n";
        }
    }

    while (!Q.empty()) {
        addr = Q.front();
        Q.pop();

        if (seen[addr]) continue;

        offset = addr - text->vma;
        pc = text->bytes + offset;
        n = text->size - offset;

        while (cs_disasm_iter(dis, &pc, &n, &addr, cs_ins)) {
            if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0) {
                break;
            }

            seen[cs_ins->address] = true;
            print_ins(cs_ins);

            if (is_cs_cflow_ins(cs_ins)) {
                target = get_cs_ins_immediate_target(cs_ins);
                if (target && !seen[target] && text->contains(target)) {
                    Q.push(target);
                    cout << " -> new target: " << target << "\n";
                }

                if (is_cs_unconditional_cflow_ins(cs_ins)) {
                    break;
                }
            } else if (cs_ins->id == X86_INS_HLT) break;
        }

        cout << "-----------\n";
    }

    cs_free(cs_ins, 1);
    cs_close(&dis);

    return 0;
}