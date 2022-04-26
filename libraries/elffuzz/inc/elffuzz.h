#ifndef __ELFFUZZ_H__
#define __ELFFUZZ_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>

#include "elfmem.h"
#include "elffuzz_def.h"

namespace ns_elffuzz {

class ElfFuzz
{
public:
    ElfFuzz(const std::string& fuzz_so, const std::string& fuzz_sym);

    ElfFuzz(const ElfFuzz& obj) = delete;
    ElfFuzz& operator=(const ElfFuzz& obj) = delete;

    ElfFuzz(ElfFuzz&& obj);
    ElfFuzz& operator=(ElfFuzz&& obj);

    virtual ~ElfFuzz();

    fp_malloc_t setMallocHook(fp_malloc_t subst_addr);
    bool remMallocHook();

    fp_calloc_t setCallocHook(fp_calloc_t subst_addr);
    bool remCallocHook();

    bool checkCallStack();

private:
    std::string m_fuzz_so;
    std::string m_fuzz_sym;
    ns_elfmem::ElfMem* m_elf;
    fp_malloc_t m_malloc_orig_addr;
    fp_calloc_t m_calloc_orig_addr;
};

} // namespace ns_elffuzz

#endif // __ELFFUZZ_H__
