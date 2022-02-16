#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <algorithm>
#include <stdexcept>
// #include <assert.h>

#include "elfmem_def.h"
#include "elfmem.h"
#include "elfutils.h"
#include "logger.h"

using namespace std;

namespace ns_elfmem {

ElfMem::ElfSo::ElfSo(const void* base_addr)
{
    // assert(base_addr);

    m_ehdr = ElfUtils::findEHDR((const void*)base_addr);
    if (!m_ehdr || m_ehdr->e_type != ET_DYN) {
        throw runtime_error("Could not found shared object header!");
    }

//    off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;

//    const ELF_PHDR_T* load = ElfUtils::findPHDR(m_ehdr, PT_LOAD);

    m_phdr = ElfUtils::findPHDR(m_ehdr, PT_DYNAMIC);
    if (!m_phdr) {
        throw runtime_error("Dynamic section is missing!");
    }

    m_strtab = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_STRTAB);
    if (!m_strtab) {
        throw runtime_error("DT_STRTAB is missing!");
    }
    m_strings = (const char*)m_strtab->d_un.d_ptr;
//    m_strings = (const char*)(off + m_strtab->d_un.d_ptr);

    const ELF_DYN_T* soname = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_SONAME);
    if (!soname) {
        throw runtime_error("DT_SONAME is missing!");
    }
    m_name = (const char*)(m_strings + soname->d_un.d_val);

    m_symtab = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_SYMTAB);
    if (!m_symtab) {
        throw runtime_error("DT_SYMTAB is missing!");
    }
    m_symbols = (const ELF_SYM_T*)m_symtab->d_un.d_ptr;
//    m_symbols = (const ELF_SYM_T*)(off + m_symtab->d_un.d_ptr);

    const ELF_DYN_T* pltrel = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_PLTREL);
    if (!pltrel || (pltrel->d_un.d_val != DT_REL && pltrel->d_un.d_val != DT_RELA)) {
        throw runtime_error("DT_PLTREL is missing or it has incorrect type!");
    }
    m_reltype = pltrel->d_un.d_val;
}

const void* ElfMem::ElfSo::hookRel(const char* proc_name, const void* subst_addr) const
{
    const void* res = nullptr;

    // assert(proc_name);
    // assert(subst_addr);

    LOG_D("Try to hook proc '%s' in '%s'", proc_name, m_name);

    const ELF_DYN_T* jmprel = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_JMPREL);
    const ELF_DYN_T* pltrelsz = ElfUtils::findDynTAB(m_ehdr, m_phdr, DT_PLTRELSZ);
    if (jmprel && pltrelsz) {
//        ElfUtils::printDynTAB(jmprel);
//        ElfUtils::printDynTAB(pltrelsz);
        res = (m_reltype == DT_REL) ?
              hookRelTab((const ELF_REL_T*)jmprel->d_un.d_ptr, pltrelsz->d_un.d_val / sizeof(ELF_REL_T),
                         R_X86_64_JUMP_SLOT, proc_name, subst_addr) :
              hookRelTab((const ELF_RELA_T*)jmprel->d_un.d_ptr, pltrelsz->d_un.d_val / sizeof(ELF_RELA_T),
                         R_X86_64_JUMP_SLOT, proc_name, subst_addr);


//        R_AARCH64_JUMP_SLOT

//        off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;
//        res = (m_reltype == DT_REL) ?
//              hookRelTab((const ELF_REL_T*)(off + jmprel->d_un.d_ptr), pltrelsz->d_un.d_val / sizeof(ELF_REL_T),
//                         R_X86_64_JUMP_SLOT, proc_name, subst_addr) :
//              hookRelTab((const ELF_RELA_T*)(off + jmprel->d_un.d_ptr), pltrelsz->d_un.d_val / sizeof(ELF_RELA_T),
//                         R_X86_64_JUMP_SLOT, proc_name, subst_addr);

    } else {
        LOG_D("DT_JMPREL(DT_PLTRELSZ) table is missing!");
    }

    if (res) {
        LOG_D("'%s' in '%s' HOOKED!", proc_name, m_name);
    }

    return res;
}

bool ElfMem::ElfSo::hookSym(const char* proc_name, const void* subst_addr) const
{
    bool res = false;

    // assert(proc_name);
    // assert(subst_addr);

    LOG_D("Try to hook proc '%s' in '%s'", proc_name, m_name);

    for(ELF_SYM_T* sym = (ELF_SYM_T*)m_symbols; CHECK_SYM_ATTR(sym->st_info); sym++)
    {
        if(ELF32_ST_BIND(sym->st_info) != STB_GLOBAL || ELF32_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        if(strcmp((const char*)(m_strings + sym->st_name), proc_name) == 0) {
            off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;
            res = rewriteProc((void*)(off + sym->st_value), subst_addr);
            break;
        }
    }

    if (res) {
        LOG_D("'%s' in '%s' HOOKED!", proc_name, m_name);
    }

    return res;
}

//void* findLibcProc(const char* procName)
//{

//    void* libc = dlopen("libc.so", RTLD_NOW);
//    return dlsym(libc, procName);
//}

void ElfMem::ElfSo::rewriteProc(void* proc_addr, const void* buff, size_t size)
{
    int psize = getpagesize();
    mprotect((void*)((uintptr_t)proc_addr & (UINTPTR_MAX^(psize-1))), psize, PROT_WRITE|PROT_READ|PROT_EXEC);
    memcpy(proc_addr, buff, size);
    mprotect((void*)((uintptr_t)proc_addr & (UINTPTR_MAX^(psize-1))), psize, PROT_READ|PROT_EXEC);
}
bool ElfMem::ElfSo::rewriteProc(void* proc_addr, const void* subst_addr) const
{
    bool res = true;
    switch(m_ehdr->e_machine)
    {
    case MACHINE_X86_64:
        {
            unsigned char cmd[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
            memcpy((void*)&cmd[2], (const void*)&subst_addr, sizeof(subst_addr));
            rewriteProc(proc_addr, (const void*)cmd, sizeof(cmd));
        }
        break;
//    case MACHINE_ARM:
//        {
//            unsigned char cmd[] = {0x04, 0xf0, 0x1f, 0xe5, 0x00, 0x00, 0x00, 0x00};
//            memcpy((void*)&cmd[4], (const void*)&subst_addr, sizeof(subst_addr));
//            rewriteProc(proc_addr, (const void*)cmd, sizeof(cmd));
//        }
//        break;
    case MACHINE_AARCH64:
        {
            unsigned char cmd[] = {0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            memcpy((void*)&cmd[8], (const void*)&subst_addr, sizeof(subst_addr));
            rewriteProc(proc_addr, (const void*)cmd, sizeof(cmd));
        }
        break;
    default:
        res = false;
        break;
    }
    return res;
}

ElfMem::ElfMem()
{
    LOG_D("Mahine : %d, MachineType : %d, EncodingType : %d", getMachine(), getMachineType(), getEncodingType());
//    ElfUtils::printMaps();
    makeSoList();
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

const void* ElfMem::soHookRel(const char* so_name, const char* proc_name, const void* subst_addr) const
{
    // assert(so_name);
    // assert(proc_name);
    // assert(subst_addr);
    auto it = std::find_if(m_solist.begin(), m_solist.end(),
                           [so_name](const ElfSo& so){return (strstr(so.getName(), so_name) != nullptr);});
    return (it != m_solist.cend()) ? it->hookRel(proc_name, subst_addr) : nullptr;
}

bool ElfMem::soHookSym(const char* so_name, const char* proc_name, const void* subst_addr) const
{
    // assert(so_name);
    // assert(proc_name);
    // assert(subst_addr);
    auto it = std::find_if(m_solist.cbegin(), m_solist.cend(),
                           [so_name](const ElfSo& so){return (strstr(so.getName(), so_name) != nullptr);});
    return (it != m_solist.cend()) ? it->hookSym(proc_name, subst_addr) : false;
}

void ElfMem::makeSoList()
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
                if(strstr(buf, ".so") == 0)
                    continue;

                LOG_D("Shared object %s was found at %p", buf, (void*)beg);

                try {
                    m_solist.emplace_back(ElfSo{(const void*)beg});
                } catch (const exception& e) {
                    LOG_D("Could not create shared : %s", e.what());
                }
            }
        }

        fclose(file);
    }
}

} // namespace ns_elfmem
