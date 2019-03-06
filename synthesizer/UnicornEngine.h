#ifndef SYNTHESIZE_UNICORNENGINE_H
#define SYNTHESIZE_UNICORNENGINE_H

#include <unicorn/unicorn.h>
#include <vector>
#include <memory>
#include <functional>

class UnicornEngine {
public:
    using code_hook_fn = std::function<void(uint64_t, uint32_t)>;
public:
    UnicornEngine(uc_arch arch, uc_mode mode);

    void execute();

    void memory_map(uint64_t address, size_t size, uint32_t perms);

    template <typename T>
    void memory_write(uint64_t address, std::vector<T>&& bytes) {
        uc_mem_write(m_pEngine.get(), address, &bytes.at(0), bytes.size());
    }

    template <typename T = int>
    void write_register(int regid, const T value) {
        uc_reg_write(m_pEngine.get(), regid, &value);
    }

    template <typename T = int>
    T read_register(int regid)
    {
        T value;
        uc_reg_read(m_pEngine.get(), regid, &value);
        return value;
    }

    void add_code_hook(const code_hook_fn func);

private:
    std::unique_ptr<uc_engine, void(*)(uc_engine*)> m_pEngine{nullptr, [] (uc_engine* uc) { uc_close(uc); }};
    std::vector<code_hook_fn> m_code_hook_functions;
    uc_hook m_hook{};
};

void setup_vm(UnicornEngine& engine, std::vector<uint8_t>&& code);


#endif //SYNTHESIZE_UNICORNENGINE_H
