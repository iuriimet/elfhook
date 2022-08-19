#ifndef __ELFFUZZ_H__
#define __ELFFUZZ_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <list>
#include <string>
#include <cassert>

#include "elfmem.h"
#include "elffuzz_def.h"

namespace ns_elffuzz {

struct hookProcInfo
{
    std::string proc_name;  // sym_name
    const void* proc_addr;  // subst_addr
};

struct hookProcData
{
    hookProcInfo info;
    const void* proc_addr;  // orig_addr
    bool checkState() const {
        return (!info.proc_name.empty() && info.proc_addr && proc_addr);
    }
};

struct hookData
{
    std::string so_name;
    std::list<hookProcData> data;
    bool checkState() const {
        if (so_name.empty()) return false;
        for (const auto& it : data) if (it.checkState()) return true;
        return false;
    }
};

class ElfFuzz
{
public:
    ElfFuzz(const std::string& fuzz_so, const std::string& fuzz_sym = "");

    ElfFuzz(const ElfFuzz& obj) = delete;
    ElfFuzz& operator=(const ElfFuzz& obj) = delete;

    ElfFuzz(ElfFuzz&& obj);
    ElfFuzz& operator=(ElfFuzz&& obj);

    virtual ~ElfFuzz();

    std::list<hookData> setHooks(const std::list<hookProcInfo>& info) const;
    void delHooks(const std::list<hookData>& data) const;
    static bool isHookInstalled(const std::list<hookData>& data) {
        for (const auto& it : data) {
            if (it.checkState()) return true;
        }
        return false;
    }

    bool checkCallStack();

private:
    std::string m_fuzz_so;
    std::string m_fuzz_sym;
    ns_elfmem::ElfMem* m_elf;
    std::list<std::string> m_so_info;
};

} // namespace ns_elffuzz

#endif // __ELFFUZZ_H__
