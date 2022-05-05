#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <execinfo.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <stdexcept>
#include <cassert>

#include "elfmem_def.h"
#include "elfmem.h"
#include "elfutils.h"
#include "logger.h"

using namespace std;

namespace ns_elfmem {

#define BT_BUF_SIZE 256

ElfMem::ElfBin::ElfBin(uintptr_t beg_addr, uintptr_t end_addr, const char* name)
{
    assert(beg_addr != 0);
    assert(end_addr != 0);
    assert(name);

    m_beg_addr = beg_addr;
    m_end_addr = end_addr;
    m_name = name;

    m_ehdr = ElfUtils::findEHDR((const void*)m_beg_addr);
    if (!m_ehdr || m_ehdr->e_type != ET_DYN) {
        throw runtime_error("Could not found object header!");
    }

//    off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;

    m_phdr = ElfUtils::findPHDR(m_ehdr, PT_DYNAMIC);
    if (!m_phdr) {
        throw runtime_error("Dynamic section is missing!");
    }

    m_strtab = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_STRTAB);
    if (!m_strtab) {
        throw runtime_error("DT_STRTAB is missing!");
    }
//    m_strings = (const char*)(off + m_strtab->d_un.d_ptr);
    m_strings = (const char*)m_strtab->d_un.d_ptr;

//    const ELF_DYN_T* soname = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_SONAME);
//    if (!soname) {
//        throw runtime_error("DT_SONAME is missing!");
//    }
//    m_name = (const char*)(m_strings + soname->d_un.d_val);

    m_symtab = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_SYMTAB);
    if (!m_symtab) {
        throw runtime_error("DT_SYMTAB is missing!");
    }
//    m_symbols = (const ELF_SYM_T*)(off + m_symtab->d_un.d_ptr);
    m_symbols = (const ELF_SYM_T*)m_symtab->d_un.d_ptr;

//    const ELF_DYN_T* pltrel = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_PLTREL);
//    if (!pltrel || (pltrel->d_un.d_val != DT_REL && pltrel->d_un.d_val != DT_RELA)) {
//        throw runtime_error("DT_PLTREL is missing or it has incorrect type!");
//    }
//    m_reltype = pltrel->d_un.d_val;

    LOG_D("ZZZ === New ElfBin %s", m_name);
}

const void* ElfMem::ElfBin::findSymByName(const char* sym_name) const
{
    const void* res = nullptr;
    assert(sym_name);
    LOG_D("Try to find sym '%s' in '%s' - NOT IMPLEMENTED", sym_name, m_name);
    return res;
}
const char* ElfMem::ElfBin::findSymByAddr(uintptr_t addr, uintptr_t* sym_addr) const
{
    const char* res = nullptr;
    assert(addr != 0);
    LOG_D("Try to find sym at '%p' in '%s' loaded at %p : %p - NOT IMPLEMENTED",
          (const void*)addr, m_name, (const void*)m_beg_addr, (const void*)m_end_addr);
    return res;
}

ElfMem::ElfSo::ElfSo(uintptr_t beg_addr, uintptr_t end_addr) : ElfMem::ElfBin(beg_addr, end_addr)
{
    const ELF_DYN_T* soname = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_SONAME);
    if (!soname) {
        throw runtime_error("DT_SONAME is missing!");
    }
    m_name = (const char*)(m_strings + soname->d_un.d_val);

    const ELF_DYN_T* pltrel = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_PLTREL);
    if (!pltrel || (pltrel->d_un.d_val != DT_REL && pltrel->d_un.d_val != DT_RELA)) {
        throw runtime_error("DT_PLTREL is missing or it has incorrect type!");
    }
    m_reltype = pltrel->d_un.d_val;

    LOG_D("ZZZ === New ElfSo %s", m_name);
}

const void* ElfMem::ElfSo::findSymByName(const char* sym_name) const
{
    const void* res = nullptr;

    assert(sym_name);

    LOG_D("Try to find sym '%s' in '%s'", sym_name, m_name);

    for(ELF_SYM_T* sym = (ELF_SYM_T*)m_symbols; CHECK_SYM_ATTR(sym->st_info); sym++) {

        if(ELF_ST_BIND(sym->st_info) != STB_GLOBAL || ELF_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        if(strcmp((const char*)(m_strings + sym->st_name), sym_name) == 0) {
            off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;
            res = (const void*)(off + sym->st_value);
            LOG_D("Symbol '%s' found at '%p'", sym_name, res);
            break;
        }
    }

    return res;
}
const char* ElfMem::ElfSo::findSymByAddr(uintptr_t addr, uintptr_t* sym_addr) const
{
    const char* res = nullptr;

    assert(addr != 0);

    LOG_D("Try to find sym at '%p' in '%s' loaded at %p : %p",
          (const void*)addr, m_name, (const void*)m_beg_addr, (const void*)m_end_addr);

    if (addr >= m_beg_addr && addr < m_end_addr) {

        for(ELF_SYM_T* sym = (ELF_SYM_T*)m_symbols; CHECK_SYM_ATTR(sym->st_info); sym++) {
            int stb = ELF_ST_BIND(sym->st_info);
            int stt = ELF_ST_TYPE(sym->st_info);
            if ((stb != STB_LOCAL && stb != STB_GLOBAL && stb != STB_WEAK) || stt != STT_FUNC) continue;

            off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;
            uintptr_t badd = (uintptr_t)(off + sym->st_value);
            uintptr_t eadd = (uintptr_t)(badd + sym->st_size);
            if (addr >= badd && addr <= eadd) {
                res = (const char*)(m_strings + sym->st_name);
                if (sym_addr) *sym_addr = badd;
                LOG_D("Symbol '%s' found at '%p'", res, (const void*)badd);
                break;
            }
        }
    }

    return res;
}

const void* ElfMem::ElfSo::hookRel(const char* sym_name, const void* subst_addr) const
{
    const void* res = nullptr;

    assert(sym_name);
    assert(subst_addr);

    LOG_D("Try to hook proc '%s' in '%s'", sym_name, m_name);

    const ELF_DYN_T* jmprel = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_JMPREL);
    const ELF_DYN_T* pltrelsz = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_PLTRELSZ);
    if (jmprel && pltrelsz) {
        res = (m_reltype == DT_REL) ?
              hookRelTab((const ELF_REL_T*)jmprel->d_un.d_ptr, pltrelsz->d_un.d_val / sizeof(ELF_REL_T),
                         R_X86_64_JUMP_SLOT, sym_name, subst_addr) :
              hookRelTab((const ELF_RELA_T*)jmprel->d_un.d_ptr, pltrelsz->d_un.d_val / sizeof(ELF_RELA_T),
                         R_X86_64_JUMP_SLOT, sym_name, subst_addr);
    } else {
        LOG_D("DT_JMPREL(DT_PLTRELSZ) table is missing!");
    }

    if (res) {
        LOG_D("'%s' in '%s' HOOKED!", sym_name, m_name);
    }

    return res;
}

ElfMem::ElfMem() : m_name(), m_bin(nullptr)
{
    m_name = readComm();
    if (m_name.empty()) {
        throw runtime_error("Can't find binary name!");
    }
    makeBinList();
    LOG_D("Binary name : %s, Mahine : %d, MachineType : %d, EncodingType : %d", getName(), getMachine(), getMachineType(), getEncodingType());
}

Machine ElfMem::getMachine()
{
    const ELF_EHDR_T* ehdr = ElfUtils::findEHDR((const void*)getMachine);
    return (ehdr) ? (Machine)ehdr->e_machine : MACHINE_UNKNOWN;
}
MachineType ElfMem::getMachineType()
{
    const ELF_EHDR_T* ehdr = ElfUtils::findEHDR((const void*)getMachineType);
    return (ehdr) ? (MachineType)ehdr->e_ident[EI_CLASS] : MACHINE_TYPE_UNKNOWN;
}
EncodingType ElfMem::getEncodingType()
{
    const ELF_EHDR_T* ehdr = ElfUtils::findEHDR((const void*)getEncodingType);
    return (ehdr) ? (EncodingType)ehdr->e_ident[EI_DATA] : ENCODING_TYPE_UNKNOWN;
}

const void* ElfMem::findSymByName(const char* bin_name, const char* sym_name) const
{
    assert(bin_name);
    assert(sym_name);
    if (strcmp(m_bin->getName(), bin_name) == 0) {
        return m_bin->findSymByName(sym_name);
    }
    auto it = find_if(m_so_list.begin(), m_so_list.end(),
                           [bin_name](const ElfSo& so){return (strstr(so.getName(), bin_name) != nullptr);});
    return (it != m_so_list.cend()) ? it->findSymByName(sym_name) : nullptr;
}
const char* ElfMem::findSymByAddr(uintptr_t addr, SymInfo* info) const
{
    const char* obj = nullptr;
    const char* sym = nullptr;
    uintptr_t sym_addr = 0;

    assert(addr != 0);

    if ((sym = m_bin->findSymByAddr(addr, &sym_addr))) {
        obj = m_bin->getName();
    } else {
        for (const ElfSo& so : m_so_list) {
            if ((sym = so.findSymByAddr(addr, &sym_addr))) {
                obj = so.getName();
                break;
            }
        }
    }

    if (sym && obj && (sym_addr != 0) && info) *info = SymInfo{obj, sym, sym_addr};

    return sym;
}

const void* ElfMem::hookRel(const char* so_name, const char* sym_name, const void* subst_addr) const
{
    assert(so_name);
    assert(sym_name);
    assert(subst_addr);
    auto it = find_if(m_so_list.begin(), m_so_list.end(),
                           [so_name](const ElfSo& so){return (strstr(so.getName(), so_name) != nullptr);});
    return (it != m_so_list.cend()) ? it->hookRel(sym_name, subst_addr) : nullptr;
}

int ElfMem::callStack(CallStack* stack) const
{
    assert(stack);

    void* buffer[BT_BUF_SIZE];
    size_t nptrs = backtrace(buffer, BT_BUF_SIZE);
    stack->m_nitems = (stack->m_nitems < nptrs) ? stack->m_nitems : nptrs;

    for (size_t i = 0; i < stack->m_nitems; i++) {
        stack->m_items[i].m_info.m_object = stack->m_items[i].m_info.m_symbol = "unknown";
        stack->m_items[i].m_info.m_address = (uintptr_t)buffer[i];

        findSymByAddr((uintptr_t)buffer[i], &stack->m_items[i].m_info);

        stack->m_items[i].m_offset = (uintptr_t)buffer[i] - stack->m_items[i].m_info.m_address;

    }

    return stack->m_nitems;
}

string ElfMem::readComm()
{
    string res;
    FILE* file = NULL;
    if((file = fopen("/proc/self/comm", "r")) != NULL)
    {
        char buf[1024] = {0};
        if (fgets(buf, sizeof(buf), file)) res = string(buf, strlen(buf) - 1); // to remove '\n' term sym
        fclose(file);
    }
    return res;
}
void ElfMem::makeBinList()
{
    FILE* file = nullptr;

    if ((file = fopen("/proc/self/maps", "r")) != NULL) {

        char buf[1024] = {0};
        uintptr_t beg;
        uintptr_t end;

        while(fgets(buf, sizeof(buf), file)) {

            if(strstr(buf, "r-xp") == 0)
                continue;

#ifdef __x86_64
            if (sscanf(buf, "%lx-%lx %*s %*s %*s %*s %s", &beg, &end, buf) == 3) {
#else
            if (sscanf(buf, "%x-%x %*s %*s %*s %*s %s", &beg, &end, buf) == 3) {
#endif
                if (strstr(buf, ".so")) {
                    LOG_D("Shared object %s was found at %p:%p", buf, (void*)beg, (void*)end);

                    try {
                        m_so_list.emplace_back(ElfSo{beg, end});
                    } catch (const exception& e) {
                        LOG_D("Could not create shared : %s", e.what());
                    }
                } else if (strstr(buf, getName())) {
                    LOG_D("Executable %s was found at %p:%p", buf, (void*)beg, (void*)end);

                    try {
                        m_bin = new ElfBin(beg, end, getName());
                    } catch (const exception& e) {
                        LOG_D("Could not create executable : %s", e.what());
                    }
                }
            }
        }

        fclose(file);
    }
}

//#ifdef __GNUG__
//#include <cxxabi.h>
//string ElfMem::demangle(const string& name)
//{
//    int status = -1;
//    unique_ptr<char, void(*)(void*)> res{abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status), free};
//    return (status == 0) ? res.get() : name;
//}
//#else
//string ElfMem::demangle(const string& name)
//{
//    return name;
//}
//#endif // __GNUG__

} // namespace ns_elfmem
