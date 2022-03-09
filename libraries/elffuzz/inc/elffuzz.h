#ifndef __ELFFUZZ_H__
#define __ELFFUZZ_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>
#include <iostream>
#include <list>
#include <map>
#include <functional>
// ZZZ
//#include <cassert>

#include "libelfmem.h"

namespace ns_elffuzz {

struct StackItem
{
    StackItem(const std::string& object, const std::string& symbol, uintptr_t address, off_t offset) :
        m_object(object), m_symbol(symbol), m_address(address), m_offset(offset) {
    }
    ~StackItem() = default;

    friend std::ostream& operator<<(std::ostream& os, const StackItem& item) {
        os << "Stack item:\n" <<
              "\tobject:\t\t" << item.m_object << "\n" <<
              "\tsymbol:\t\t" << item.m_symbol << "\n" <<
              "\taddress:\t" << "0x" << item.m_address << std::hex << "\n" <<
              "\toffset:\t\t" << "0x" << item.m_offset << std::hex << std::endl;
        return os;
    }

    std::string m_object;
    std::string m_symbol;
    uintptr_t m_address;
    off_t m_offset;
};

class ElfHook
{
public:
    ElfHook(elfmem_t* elf, const std::string& hook_so, const std::string& hook_proc, const void* hook_proc_addr);

    ElfHook(const ElfHook& obj) = delete;
    ElfHook& operator=(const ElfHook& obj) = delete;

    ElfHook(ElfHook&& obj);
    ElfHook& operator=(ElfHook&& obj);

    virtual ~ElfHook();

private:
    elfmem_t* m_elf;
    std::string m_hook_so;
    std::string m_hook_proc;
    const void* m_hook_proc_addr;
    const void* m_orig_addr;
};

class ElfFuzz
{
public:
    ElfFuzz(const std::string& fuzz_so, const std::string& fuzz_proc);

    ElfFuzz(const ElfFuzz& obj) = delete;
    ElfFuzz& operator=(const ElfFuzz& obj) = delete;

    ElfFuzz(ElfFuzz&& obj);
    ElfFuzz& operator=(ElfFuzz&& obj);

    virtual ~ElfFuzz();

    bool addHook(const std::string& hook_so, const std::string& hook_proc, const void* hook_proc_addr, std::size_t* hook_id);
    bool delHook(std::size_t hook_id);
    bool checkHook(std::size_t hook_id) const;

private:
    static std::list<StackItem> callStack();
    static std::string demangle(const std::string& name);

    std::string m_fuzz_so;
    std::string m_fuzz_proc;
    elfmem_t* m_elf;
    const void* m_fuzz_proc_addr;
    std::map<std::size_t, ElfHook> m_hook_map;
};

} // namespace ns_elffuzz

#endif // __ELFFUZZ_H__
