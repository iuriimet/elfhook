#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <list>
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

//ElfFuzz::ElfFuzz(const string& fuzz_so, const string& fuzz_sym) :
//    m_fuzz_so(fuzz_so), m_fuzz_sym(fuzz_sym), m_elf(nullptr)
//{
//    m_elf = new ns_elfmem::ElfMem();
//    if (!m_elf) {
//        throw runtime_error(string("Can't create elfmem object"));
//    }
//    m_so_info = m_elf->soNames();
//}

static const char* s_skipped_so[] = {"libdlog.so", "libprotobuf.so"};

ElfFuzz::ElfFuzz() :
    m_fuzz_so(""), m_fuzz_sym(""), m_elf(nullptr)
{
    m_elf = new ns_elfmem::ElfMem();
    if (!m_elf) {
        throw runtime_error(string("Can't create elfmem object"));
    }
    m_so_info = m_elf->soNames();
    for (const char* so : s_skipped_so) {
        m_so_info.remove_if([so](string& s){return s.find(so) != string::npos;});
    }
}

ElfFuzz::ElfFuzz(ElfFuzz&& obj) :
    m_fuzz_so(obj.m_fuzz_so), m_fuzz_sym(obj.m_fuzz_sym), m_elf(obj.m_elf), m_so_info(obj.m_so_info)
{
    obj.m_elf = nullptr;
    m_so_info.clear();
}
ElfFuzz& ElfFuzz::operator=(ElfFuzz&& obj)
{
    m_fuzz_so = obj.m_fuzz_so;
    m_fuzz_sym = obj.m_fuzz_sym;
    m_elf = obj.m_elf;
    obj.m_elf = nullptr;
    m_so_info = obj.m_so_info;
    m_so_info.clear();
    return *this;
}

ElfFuzz::~ElfFuzz()
{
    if (m_elf) delete m_elf;
}

std::list<hookData> ElfFuzz::setHooks(const std::list<hookProcInfo>& info) const
{
    std::list<hookData> res;

    for (const auto& it : m_so_info) res.push_back({it, {}});

    for (auto& it : res) {
        for (const auto& itt : info) {
            const void* addr = m_elf->hookRel(it.so_name.c_str(), itt.proc_name.c_str(), itt.proc_addr);
            if (addr) it.data.push_back({itt, addr});
        }
    }

    return res;
}
void ElfFuzz::delHooks(const std::list<hookData>& data) const
{
    for (const auto& it : data) {
        assert(!it.so_name.empty());
        for (const auto& itt : it.data) {
            assert(itt.checkState());
            m_elf->hookRel(it.so_name.c_str(), itt.info.proc_name.c_str(), itt.proc_addr);
        }
    }
}

//bool ElfFuzz::checkCallStack()
//{
//    StackItem si[32];
//    CallStack st{.m_nitems = 32, .m_items = si};
//    m_elf->callStack(&st);
////    ns_elfmem::ElfUtils::printStack(&st);
//    for (size_t i = 0; i < st.m_nitems; i++) {
//        if (strstr(st.m_items[i].m_info.m_object, m_fuzz_so.c_str())) {
//            if (m_fuzz_sym.empty() ||
//                    strstr(st.m_items[i].m_info.m_symbol, m_fuzz_sym.c_str())) return true;
//        }
//    }
//    return false;
//}

} // namespace ns_elffuzz
