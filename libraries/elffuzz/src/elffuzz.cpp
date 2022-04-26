#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <string>
#include <stdexcept>
#include <cassert>

#include "elfmem_def.h"
#include "elfmem.h"
#include "elfutils.h"
#include "elffuzz_def.h"
#include "elffuzz.h"
#include "logger.h"

using namespace std;

namespace ns_elffuzz {

ElfFuzz::ElfFuzz(const string& fuzz_so, const string& fuzz_sym) :
    m_fuzz_so(fuzz_so), m_fuzz_sym(fuzz_sym), m_elf(nullptr), m_malloc_orig_addr(nullptr), m_calloc_orig_addr(nullptr)
{
    m_elf = new ns_elfmem::ElfMem();
    if (!m_elf) {
        throw runtime_error(string("Can't create elfmem object"));
    }
}

ElfFuzz::ElfFuzz(ElfFuzz&& obj) :
    m_fuzz_so(obj.m_fuzz_so), m_fuzz_sym(obj.m_fuzz_sym), m_elf(obj.m_elf), m_malloc_orig_addr(obj.m_malloc_orig_addr), m_calloc_orig_addr(obj.m_calloc_orig_addr)
{
    obj.m_elf = nullptr;
    obj.m_malloc_orig_addr = nullptr;
    obj.m_calloc_orig_addr = nullptr;
}
ElfFuzz& ElfFuzz::operator=(ElfFuzz&& obj)
{
    m_fuzz_so = obj.m_fuzz_so;
    m_fuzz_sym = obj.m_fuzz_sym;
    m_elf = obj.m_elf;
    m_malloc_orig_addr = obj.m_malloc_orig_addr;
    m_calloc_orig_addr = obj.m_calloc_orig_addr;
    obj.m_elf = nullptr;
    obj.m_malloc_orig_addr = nullptr;
    obj.m_calloc_orig_addr = nullptr;
    return *this;
}

ElfFuzz::~ElfFuzz()
{
    remMallocHook();
    remCallocHook();
    if (m_elf) delete m_elf;
}

fp_malloc_t ElfFuzz::setMallocHook(fp_malloc_t subst_addr)
{
    assert(subst_addr);
    if (!m_elf || m_malloc_orig_addr) return nullptr;
    return (m_malloc_orig_addr = (fp_malloc_t)m_elf->hookRel(m_fuzz_so.c_str(), "malloc", (const void*)subst_addr));
}
bool ElfFuzz::remMallocHook()
{
    bool res = false;
    if (m_elf && m_malloc_orig_addr && m_elf->hookRel(m_fuzz_so.c_str(), "malloc", (const void*)m_malloc_orig_addr)) {
        m_malloc_orig_addr = nullptr;
        res = true;
    }
    return res;
}

fp_calloc_t ElfFuzz::setCallocHook(fp_calloc_t subst_addr)
{
    assert(subst_addr);
    if (!m_elf || m_calloc_orig_addr) return nullptr;
    return (m_calloc_orig_addr = (fp_calloc_t)m_elf->hookRel(m_fuzz_so.c_str(), "calloc", (const void*)subst_addr));
}
bool ElfFuzz::remCallocHook()
{
    bool res = false;
    if (m_elf && m_calloc_orig_addr && m_elf->hookRel(m_fuzz_so.c_str(), "calloc", (const void*)m_calloc_orig_addr)) {
        m_calloc_orig_addr = nullptr;
        res = true;
    }
    return res;
}

bool ElfFuzz::checkCallStack()
{
    bool res = false;
    if (m_elf) {
        StackItem si[32];
        CallStack st{.m_nitems = 32, .m_items = si};
        m_elf->callStack(&st);
        ns_elfmem::ElfUtils::printStack(&st);
        for (size_t i = 0; i < st.m_nitems; i++) {
            if ((res = (strstr(st.m_items[i].m_info.m_object, m_fuzz_so.c_str()) &&
                        strstr(st.m_items[i].m_info.m_symbol, m_fuzz_sym.c_str())))) break;
        }
    }
    return res;
}

} // namespace ns_elffuzz
