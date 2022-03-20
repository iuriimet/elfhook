#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
// ZZZ
//#include <string.h>
//#include <unistd.h>
//#include <sys/mman.h>
//#include <algorithm>
// #include <list>
//#include <functional>
//#include <utility>
#include <string>
#include <execinfo.h>
//#include <regex>
#include <stdexcept>
#include <cassert>

#include "libelfmem.h"

#include "elffuzz.h"
#include "logger.h"

using namespace std;

namespace ns_elffuzz {

//ElfHook::ElfHook(elfmem_t* elf, const string& hook_so, const string& hook_proc, const void* hook_proc_addr) :
//    m_elf(elf), m_hook_so(hook_so), m_hook_proc(hook_proc), m_hook_proc_addr(hook_proc_addr)
//{
//    assert(m_elf);
//    assert(m_hook_proc_addr);
//    //m_orig_addr = elfmem_hook_reltab(m_elf, m_hook_so.c_str(), m_hook_proc.c_str(), m_hook_proc_addr);
//    if (!m_orig_addr) {
//        throw runtime_error(string("Can't hook proc " + m_hook_proc + " in " + m_hook_so));
//    }
//    LOG_D("ElfHook for %s in %s at %p", m_hook_proc.c_str(), m_hook_so.c_str(), m_orig_addr);
//}

//ElfHook::ElfHook(ElfHook&& obj) :
//    m_elf(obj.m_elf), m_hook_so(obj.m_hook_so), m_hook_proc(obj.m_hook_proc), m_hook_proc_addr(obj.m_hook_proc_addr), m_orig_addr(obj.m_orig_addr)
//{
//    obj.m_elf = nullptr;
//}
//ElfHook& ElfHook::operator=(ElfHook&& obj)
//{
//    m_elf = obj.m_elf;
//    m_hook_so = obj.m_hook_so;
//    m_hook_proc = obj.m_hook_proc;
//    m_hook_proc_addr = obj.m_hook_proc_addr;
//    m_orig_addr = obj.m_orig_addr;
//    obj.m_elf = nullptr;
//    return *this;
//}

//ElfHook::~ElfHook()
//{
//    if (m_elf) {
//        elfmem_hook_reltab(m_elf, m_hook_so.c_str(), m_hook_proc.c_str(), m_orig_addr);
//        LOG_D("ElfHook for %s in %s at %p removed", m_hook_proc.c_str(), m_hook_so.c_str(), m_orig_addr);
//    }
//}




ElfFuzz::ElfFuzz(const std::string& exe_name, const string& fuzz_so, const string& fuzz_sym) : m_fuzz_so(fuzz_so), m_fuzz_sym(fuzz_sym)
{
    m_elf = elfmem_create(exe_name.c_str());
    if (!m_elf) {
        throw runtime_error(string("Can't create elfmem object"));
    }
    m_fuzz_sym_addr = elfmem_find_sym_by_name(m_elf, m_fuzz_so.c_str(), m_fuzz_sym.c_str());
    if (!m_fuzz_sym_addr) {
        throw runtime_error(string("Can't find proc " + m_fuzz_sym + " in " + m_fuzz_so));
    }
    LOG_D("ElfFuzz for %s in %s at %p", m_fuzz_sym.c_str(), m_fuzz_so.c_str(), m_fuzz_sym_addr);
}

ElfFuzz::ElfFuzz(ElfFuzz&& obj) :
    m_fuzz_so(obj.m_fuzz_so), m_fuzz_sym(obj.m_fuzz_sym), m_elf(obj.m_elf), m_fuzz_sym_addr(obj.m_fuzz_sym_addr),
    m_hook_so(obj.m_hook_so), m_hook_sym(obj.m_hook_sym), m_hook_subst_addr(obj.m_hook_subst_addr), m_hook_sym_addr(obj.m_hook_sym_addr)
{
    obj.m_elf = nullptr;
    obj.m_hook_subst_addr = nullptr;
    obj.m_hook_sym_addr = nullptr;
}
ElfFuzz& ElfFuzz::operator=(ElfFuzz&& obj)
{
    m_fuzz_so = obj.m_fuzz_so;
    m_fuzz_sym = obj.m_fuzz_sym;
    m_elf = obj.m_elf;
    m_fuzz_sym_addr = obj.m_fuzz_sym_addr;
    m_hook_so = obj.m_hook_so;
    m_hook_sym = obj.m_hook_sym;
    m_hook_subst_addr = obj.m_hook_subst_addr;
    m_hook_sym_addr = obj.m_hook_sym_addr;
    obj.m_elf = nullptr;
    obj.m_hook_subst_addr = nullptr;
    obj.m_hook_sym_addr = nullptr;
    return *this;
}

ElfFuzz::~ElfFuzz()
{
    if (m_elf) {
        delHook(nullptr);
        elfmem_destroy(m_elf);
        LOG_D("ElfFuzz for %s in %s at %p removed", m_fuzz_sym.c_str(), m_fuzz_so.c_str(), m_fuzz_sym_addr);
    }
}

const void* ElfFuzz::addHook(const std::string& hook_so, const std::string& hook_sym, const void* hook_subst_addr)
{
    const void* res = nullptr;
    assert(hook_subst_addr);
    delHook(nullptr);
    if (m_elf && ((res = elfmem_hook_reltab(m_elf, hook_so.c_str(), hook_sym.c_str(), hook_subst_addr)))) {
        m_hook_so = hook_so;
        m_hook_sym = hook_sym;
        m_hook_subst_addr = hook_subst_addr;
        m_hook_sym_addr = res;
    }

//    if ((res = (m_elf && ( (m_hook_sym_addr = elfmem_hook_reltab(m_elf, hook_so.c_str(), hook_sym.c_str(), hook_subst_addr))  )))) {
//        m_hook_so = hook_so;
//        m_hook_sym = hook_sym;
//        m_hook_subst_addr = hook_subst_addr;
//    }

    return res;
}

void ElfFuzz::delHook(const void* hook_addr)
{
    if (m_elf && m_hook_sym_addr) {
        elfmem_hook_reltab(m_elf, m_hook_so.c_str(), m_hook_sym.c_str(), m_hook_sym_addr);
        m_hook_sym_addr = nullptr;
    }
}



/*
bool ElfFuzz::addHook(const string& hook_so, const string& hook_proc, const void* hook_proc_addr, size_t* hook_id)
{
    if (!hook_proc_addr || !hook_id) {
        LOG_W("ElfFuzz hook : invalid args");
        return false;
    }
    size_t id = hash<string>{}(hook_so + hook_proc);
    if (m_hook_map.find(id) != m_hook_map.end()) {
        LOG_W("ElfFuzz hook for %s in %s already exists", hook_so.c_str(), hook_proc.c_str());
        return false;
    }
    m_hook_map.emplace(id, ElfHook{m_elf, hook_so, hook_proc, hook_proc_addr});
    *hook_id = id;
    return true;
}
bool ElfFuzz::delHook(size_t hook_id)
{
    LOG_D("ZZZ ======================== delHook 1 %ld", hook_id);
    auto it = m_hook_map.find(hook_id);
    LOG_D("ZZZ ======================== delHook 2");
    if (it == m_hook_map.end()) {
        LOG_D("ZZZ ======================== delHook 3");
        return false;
    }
    LOG_D("ZZZ ======================== delHook 4");
    m_hook_map.erase(it);
    return true;
}
bool ElfFuzz::checkHook(size_t hook_id) const
{
    list<StackItem> stack = callStack();
    LOG_D("ZZZ QWEQWEQWE ");
//    for (const StackItem& si : stack) {
//        LOG_D("ZZZ ====================== %s - %s : %d - %d", si.m_object.c_str(), si.m_symbol.c_str(), (int)si.m_address, (int)si.m_offset);
//    }
//    for (auto it : stack) {
//        std::cout << it << std::endl;
//    }

    return false;
}
*/


/*
#define BT_BUF_SIZE 256

list<StackItem> ElfFuzz::callStack()
{
    list<StackItem> res;

    void* buffer[BT_BUF_SIZE];
    int nptrs = backtrace(buffer, BT_BUF_SIZE);
    if (nptrs > 0) {
        char** symbols = backtrace_symbols(buffer, nptrs);
        if (symbols) {
            const regex re("^(\\S+)\\((\\S*)\\+0x([0-9a-fA-F]+)\\)\\s+\\[0x([0-9a-fA-F]+)\\]$");

            for (int i = 0; i < nptrs; i++) {
                try {
                    string sym(symbols[i]);
                    smatch rm;
                    if (regex_match(sym, rm, re) && (rm.size() == 5)) {
                        off_t off = stoul(rm[3].str(), nullptr, 16);
                        uintptr_t addr = stoul(rm[4].str(), nullptr, 16);

                        // res.push_back({rm[1].str(), demangle(rm[2].str()), addr - off, off});
                        res.push_back({rm[1].str(), rm[2].str(), addr - off, off});
                    }
                } catch (const regex_error& e) {
                    LOG_E("Backtrace error: %s", e.what());
                }
            }

            free(symbols);
        }
    }

    return res;
}

#ifdef __GNUG__
#include <cxxabi.h>
string ElfFuzz::demangle(const string& name)
{
    int status = -4;
    unique_ptr<char, void(*)(void*)> res{
        abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status),
                free};
    return (status == 0) ? res.get() : name;
}
#else
string ElfFuzz::demangle(const string& name)
{
    return name;
}
#endif // __GNUG__
*/


} // namespace ns_elffuzz
