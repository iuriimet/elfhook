#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <execinfo.h>
#include <string>
#include <list>
#include <regex>
#include <cassert>

#include "elfmem_def.h"
#include "elfutils.h"
#include "logger.h"

namespace ns_elfmem {

#define BT_BUF_SIZE 256

const ELF_EHDR_T* ElfUtils::findEHDR(const void* addr)
{
    assert(addr);
    int psize = getpagesize();
    uintptr_t res = (uintptr_t)addr & (UINTPTR_MAX^(psize-1));
    for( ; !getEHDR((const void*)res); res-=psize);
    return (const ELF_EHDR_T*)res;
}

const ELF_PHDR_T* ElfUtils::findPHDR(const ELF_EHDR_T* ehdr, uint32_t type)
{
    assert(ehdr);
    const ELF_PHDR_T* res = (const ELF_PHDR_T*)((uintptr_t)ehdr + ehdr->e_phoff);
    for(int n = ehdr->e_phnum; n > 0 && res->p_type != type; n--, res++);
    return (res->p_type == type) ? res : nullptr;
}

const ELF_DYN_T* ElfUtils::findDynTAB(const ELF_EHDR_T* ehdr, const ELF_PHDR_T* phdr, int type)
{
    assert(ehdr);
    assert(phdr);
    off_t off = ehdr->e_type == ET_DYN ? (off_t)ehdr : 0;
    const ELF_DYN_T* res = (const ELF_DYN_T*)(off + phdr->p_vaddr);
    for( ; res->d_tag != type && res->d_tag != DT_NULL; res++);
    return (res->d_tag == type) ? res : nullptr;
}

std::list<StackItem> ElfUtils::callStack()
{
    std::list<StackItem> res;

    void* buffer[BT_BUF_SIZE];
    int nptrs = backtrace(buffer, BT_BUF_SIZE);
    if (nptrs > 0) {
        char** symbols = backtrace_symbols(buffer, nptrs);
        if (symbols) {
            const std::regex re("^(\\S+)\\((\\S*)\\+0x([0-9a-fA-F]+)\\)\\s+\\[0x([0-9a-fA-F]+)\\]$");

            for (int i = 0; i < nptrs; i++) {
                try {
                    std::string sym(symbols[i]);
                    std::smatch rm;
                    if (std::regex_match(sym, rm, re) && (rm.size() == 5)) {
                        off_t off = std::stoul(rm[3].str(), nullptr, 16);
                        uintptr_t addr = std::stoul(rm[4].str(), nullptr, 16);

                        res.push_back({rm[1].str(), demangle(rm[2].str()), addr - off, off});
                    }
                } catch (const std::regex_error &e) {
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
std::string ElfUtils::demangle(std::string name)
{
    int status = -4;
    std::unique_ptr<char, void(*)(void*)> res{
        abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status),
                std::free};
    return (status == 0) ? res.get() : name;
}
#else
std::string ElfUtils::demangle(std::string name)
{
    return name;
}
#endif // __GNUG__




//static char** ElfUtils::backTrace()
//{
//    void* buffer[BT_BUF_SIZE];
//    return backtrace_symbols(buffer, backtrace(buffer, BT_BUF_SIZE));
//}



//void ElfUtils::printMaps()
//{
//    FILE* file = NULL;
//    if((file = fopen("/proc/self/maps", "r")) != NULL)
//    {
//        char buf[1024] = {0};
//        LOG_D("-------------------- MAPS ------------------------");
//        while(fgets(buf, sizeof(buf), file))
//            LOG_D("%s", buf);
//        LOG_D("-------------------- MAPS ------------------------");
//        fclose(file);
//    }
//}

//void ElfUtils::printEHDR(const ELF_EHDR_T* ehdr)
//{
//    LOG_D("-------------------- EHDR ------------------------");
//    LOG_D("header addr:    %p", (void*)ehdr);
//    LOG_D("header size:    %d", (int)sizeof(ELF_EHDR_T));
//    LOG_D("e_ident:        %s", ehdr->e_ident);
//    LOG_D("e_type:         %d", ehdr->e_type);
//    LOG_D("e_machine:      %d", ehdr->e_machine);
//    LOG_D("e_version:      %d", ehdr->e_version);
//    LOG_D("e_entry:        %p", (void*)ehdr->e_entry);
//    LOG_D("e_phoff:        0x%lx", (off_t)ehdr->e_phoff);
//    LOG_D("e_shoff:        0x%lx", (off_t)ehdr->e_shoff);
//    LOG_D("e_flags:        %d", ehdr->e_flags);
//    LOG_D("e_ehsize:       %d", ehdr->e_ehsize & 0xffff);
//    LOG_D("e_phentsize:    %d", ehdr->e_phentsize);
//    LOG_D("e_phnum:        %d", ehdr->e_phnum);
//    LOG_D("e_shentsize:    %d", ehdr->e_shentsize);
//    LOG_D("e_shnum:        %d", ehdr->e_shnum);
//    LOG_D("e_shstrndx:     %d", ehdr->e_shstrndx);
//    LOG_D("-------------------- EHDR ------------------------");
//}

//void ElfUtils::printPHDR(const ELF_PHDR_T* phdr)
//{
//    LOG_D("-------------------- PHDR ------------------------");
//    LOG_D("header size:    %d", (int)sizeof(ELF_PHDR_T));
//    LOG_D("p_type:         0x%x", phdr->p_type);
//    LOG_D("p_flags:        %d", phdr->p_flags);
//    LOG_D("p_offset:       0x%lx", (off_t)phdr->p_offset);
//    LOG_D("p_vaddr:        %p", (void*)phdr->p_vaddr);
//    LOG_D("p_paddr:        %p", (void*)phdr->p_paddr);
//    LOG_D("p_filesz:       %ld", phdr->p_filesz);
//    LOG_D("p_memsz:        %ld", phdr->p_memsz);
//    LOG_D("p_align:        %ld", phdr->p_align);
//    LOG_D("-------------------- PHDR ------------------------");
//}

//void ElfUtils::printDynTAB(const ELF_DYN_T* dyn)
//{
//    LOG_D("-------------------- DYN -------------------------");
//    LOG_D("table addr:     %p", (void*)dyn);
//    LOG_D("table size:     %d", (int)sizeof(ELF_DYN_T));
//    LOG_D("d_tag:          %ld", dyn->d_tag);
//    LOG_D("d_un->d_val:    %ld", dyn->d_un.d_val);
//    LOG_D("d_un->d_ptr:    0x%lx", dyn->d_un.d_ptr);
//    LOG_D("-------------------- DYN -------------------------");
//}

//void ElfUtils::printSymTAB(const ELF_SYM_T* sym)
//{
//    LOG_D("-------------------- SYM -------------------------");
//    LOG_D("table addr:     %p", (void*)sym);
//    LOG_D("table size:     %d", (int)sizeof(ELF_SYM_T));
//    LOG_D("st_name:        %d", sym->st_name);
//    LOG_D("st_info:        %d", sym->st_info);
//    LOG_D("ELF_ST_BIND:    %d", ELF_ST_BIND(sym->st_info));
//    LOG_D("ELF_ST_TYPE:    %d", ELF_ST_TYPE(sym->st_info));
//    LOG_D("st_other:       %d", sym->st_other);
//    LOG_D("st_shndx:       %d", sym->st_shndx);
//    LOG_D("st_value:       0x%lx", sym->st_value);
//    LOG_D("st_size:        %ld", sym->st_size);
//    LOG_D("-------------------- SYM -------------------------");
//}

//static void printRelTAB(const ELF_REL_T* rel)
//{
//    LOG_D("-------------------- REL ------------------------");
//    LOG_D("table addr:     %p", (void*)rel);
//    LOG_D("table size:     %d", (int)sizeof(ELF_RELA_T));
//    LOG_D("r_offset:       0x%lx", rel->r_offset);
//    LOG_D("r_info:         %ld", rel->r_info);
//    LOG_D("ELF_R_TYPE:     %ld", ELF_R_TYPE(rel->r_info));
//    LOG_D("ELF_R_SYM:      %ld", ELF_R_SYM(rel->r_info));
//    LOG_D("-------------------- REL ------------------------");
//}
//static void printRelaTAB(const ELF_RELA_T* rela)
//{
//    LOG_D("-------------------- RELA ------------------------");
//    LOG_D("table addr:     %p", (void*)rela);
//    LOG_D("table size:     %d", (int)sizeof(ELF_RELA_T));
//    LOG_D("r_offset:       0x%lx", rela->r_offset);
//    LOG_D("r_info:         %ld", rela->r_info);
//    LOG_D("ELF_R_TYPE:     %ld", ELF_R_TYPE(rela->r_info));
//    LOG_D("ELF_R_SYM:      %ld", ELF_R_SYM(rela->r_info));
//    LOG_D("r_addend:       0x%lx", rela->r_addend);
//    LOG_D("-------------------- RELA ------------------------");
//}

} // namespace ns_elfmem
