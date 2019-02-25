#include <iostream>
#include <string>
#include <capstone/capstone.h>

#include "loader.h"

int disasm(Binary *bin);

using namespace std;

int main(int argc, char **argv) {
    Binary bin;
    std::string fname;

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <binary>\n";
        return -1;
    }

    fname.assign(argv[1]);

    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0)
    {
        return -1;
    }

    if (disasm(&bin) < 0)
        return -1;

    unload_binary(&bin);

    return 0;
}

int disasm(Binary *bin) {
    csh dis;
    cs_insn *insns;
    Section *text;
    size_t n;

    text = bin->get_text_section();

    if (!text) {
        cerr << "Nothing to disassemble\n";
        return -1;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
        cerr << "Failed to open capstone\n";
        return 0;
    }

    n = cs_disasm(dis, text->bytes, text->size, text->vma, 0, &insns);

    if (n <= 0) {
        cerr << "Disassembly error: " << cs_strerror(cs_errno(dis)) <<"\n";
        return -1;
    }

    for (size_t i = 0; i < n; ++i) {
        cout << hex << insns[i].address << "\n";
    }

    cs_free(insns, n);
    cs_close(&dis);

    return 0;
}