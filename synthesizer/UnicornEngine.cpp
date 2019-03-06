#include "UnicornEngine.h"

#include <iostream>

using namespace std;

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    std::cout << "address "  << address << std::endl;
}

UnicornEngine::UnicornEngine(uc_arch arch, uc_mode mode) {
    uc_engine *engine;
    uc_open(arch, mode, &engine);
    m_pEngine.reset(engine);

    uc_hook_add(m_pEngine.get(), &m_hook, UC_HOOK_CODE, reinterpret_cast<void *>(hook_code), nullptr, 0, 0);
}

void UnicornEngine::memory_map(uint64_t address, size_t size, uint32_t perms) {
    uc_mem_map(m_pEngine.get(), address, size, perms);
}

void UnicornEngine::execute() {
    auto err = uc_emu_start(m_pEngine.get(), 0, 0, 0, 0);

    if (err) {
        cerr << "Failed on uc_emu_start() with error: " << err << "\n";
    }
}

void UnicornEngine::add_code_hook(const code_hook_fn func) {
    m_code_hook_functions.push_back(func);
}

void setup_vm(UnicornEngine &engine, std::vector <uint8_t> &&code) {
    engine.memory_map(0, code.size(), UC_PROT_ALL);
    engine.memory_map(1000, 1000, UC_PROT_READ | UC_PROT_WRITE);
    engine.memory_write(0, std::move(code));
    engine.write_register(UC_X86_REG_RSP, 2000);
    engine.write_register(UC_X86_REG_RBP, 2000);
    engine.add_code_hook([](uint64_t addr, uint32_t size) {

    });
}
