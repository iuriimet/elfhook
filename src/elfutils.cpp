#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <assert.h>

#include "elfmem_def.h"
#include "elfutils.h"
#include "logger.h"

const ELF_EHDR_T* ElfUtils::findEHDR(const void* addr)
{
    assert(addr);
    int psize = getpagesize();
    uintptr_t res = (uintptr_t)addr & (UINTPTR_MAX^(psize-1));
    for( ; !getEHDR((const void*)res); res-=psize);
    return (const ELF_EHDR_T*)res;
}

const ELF_PHDR_T* ElfUtils::findPHDR(const ELF_EHDR_T* ehdr, int type)
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

void ElfUtils::printMaps()
{
    FILE* file = NULL;
    if((file = fopen("/proc/self/maps", "r")) != NULL)
    {
        char buf[1024] = {0};
        LOGD("-------------------- MAPS ------------------------");
        while(fgets(buf, sizeof(buf), file))
            LOGD("%s", buf);
        LOGD("-------------------- MAPS ------------------------");
        fclose(file);
    }
}

void ElfUtils::printEHDR(const ELF_EHDR_T* ehdr)
{
//    LOGD("-------------------- EHDR ------------------------");
//    LOGD("header addr:    %p", (void*)ehdr);
//    LOGD("header size:    %d", (int)sizeof(ELF_EHDR_T));
//    LOGD("e_ident:        %s", ehdr->e_ident);
//    LOGD("e_type:         %d", ehdr->e_type);
//    LOGD("e_machine:      %d", ehdr->e_machine);
//    LOGD("e_version:      %d", ehdr->e_version);
//    LOGD("e_entry:        %p", (void*)ehdr->e_entry);
//    LOGD("e_phoff:        0x%lx", (off_t)ehdr->e_phoff);
//    LOGD("e_shoff:        0x%lx", (off_t)ehdr->e_shoff);
//    LOGD("e_flags:        %d", ehdr->e_flags);
//    LOGD("e_ehsize:       %d", ehdr->e_ehsize & 0xffff);
//    LOGD("e_phentsize:    %d", ehdr->e_phentsize);
//    LOGD("e_phnum:        %d", ehdr->e_phnum);
//    LOGD("e_shentsize:    %d", ehdr->e_shentsize);
//    LOGD("e_shnum:        %d", ehdr->e_shnum);
//    LOGD("e_shstrndx:     %d", ehdr->e_shstrndx);
//    LOGD("-------------------- EHDR ------------------------");
}

void ElfUtils::printPHDR(const ELF_PHDR_T* phdr)
{
//    LOGD("-------------------- PHDR ------------------------");
//    LOGD("header size:    %d", (int)sizeof(ELF_PHDR_T));
//    LOGD("p_type:         0x%x", phdr->p_type);
//    LOGD("p_flags:        %d", phdr->p_flags);
//    LOGD("p_offset:       0x%lx", (off_t)phdr->p_offset);
//    LOGD("p_vaddr:        %p", (void*)phdr->p_vaddr);
//    LOGD("p_paddr:        %p", (void*)phdr->p_paddr);
//    LOGD("p_filesz:       %ld", phdr->p_filesz);
//    LOGD("p_memsz:        %ld", phdr->p_memsz);
//    LOGD("p_align:        %ld", phdr->p_align);
//    LOGD("-------------------- PHDR ------------------------");
}

void ElfUtils::printDynTAB(const ELF_DYN_T* dyn)
{
//    LOGD("-------------------- DYN -------------------------");
//    LOGD("table addr:     %p", (void*)dyn);
//    LOGD("table size:     %d", (int)sizeof(ELF_DYN_T));
//    LOGD("d_tag:          %ld", dyn->d_tag);
//    LOGD("d_un->d_val:    %ld", dyn->d_un.d_val);
//    LOGD("d_un->d_ptr:    0x%lx", dyn->d_un.d_ptr);
//    LOGD("-------------------- DYN -------------------------");
}

void ElfUtils::printSymTAB(const ELF_SYM_T* sym)
{
//    LOGD("-------------------- SYM -------------------------");
//    LOGD("table addr:     %p", (void*)sym);
//    LOGD("table size:     %d", (int)sizeof(ELF_SYM_T));
//    LOGD("st_name:        %d", sym->st_name);
//    LOGD("st_info:        %d", sym->st_info);
//    LOGD("ELF_ST_BIND:    %d", ELF_ST_BIND(sym->st_info));
//    LOGD("ELF_ST_TYPE:    %d", ELF_ST_TYPE(sym->st_info));
//    LOGD("st_other:       %d", sym->st_other);
//    LOGD("st_shndx:       %d", sym->st_shndx);
//    LOGD("st_value:       0x%lx", sym->st_value);
//    LOGD("st_size:        %ld", sym->st_size);
//    LOGD("-------------------- SYM -------------------------");
}

static void printRelTAB(const ELF_REL_T* rel)
{
//    LOGD("-------------------- REL ------------------------");
//    LOGD("table addr:     %p", (void*)rel);
//    LOGD("table size:     %d", (int)sizeof(ELF_RELA_T));
//    LOGD("r_offset:       0x%lx", rel->r_offset);
//    LOGD("r_info:         %ld", rel->r_info);
//    LOGD("ELF_R_TYPE:     %ld", ELF_R_TYPE(rel->r_info));
//    LOGD("ELF_R_SYM:      %ld", ELF_R_SYM(rel->r_info));
//    LOGD("-------------------- REL ------------------------");
}
static void printRelaTAB(const ELF_RELA_T* rela)
{
//    LOGD("-------------------- RELA ------------------------");
//    LOGD("table addr:     %p", (void*)rela);
//    LOGD("table size:     %d", (int)sizeof(ELF_RELA_T));
//    LOGD("r_offset:       0x%lx", rela->r_offset);
//    LOGD("r_info:         %ld", rela->r_info);
//    LOGD("ELF_R_TYPE:     %ld", ELF_R_TYPE(rela->r_info));
//    LOGD("ELF_R_SYM:      %ld", ELF_R_SYM(rela->r_info));
//    LOGD("r_addend:       0x%lx", rela->r_addend);
//    LOGD("-------------------- RELA ------------------------");
}
