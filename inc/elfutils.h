#ifndef __ELFUTILS_H__
#define __ELFUTILS_H__

#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <assert.h>

#include "elfmem_def.h"

class ElfUtils
{
public:
    static const ELF_EHDR_T* findEHDR(const void* addr);

    static inline const ELF_EHDR_T* getEHDR(const void* addr) {
        assert(addr);
        const ELF_EHDR_T* res = (const ELF_EHDR_T*)addr;
        return (strncmp((const char*)res->e_ident, ELFMAG, SELFMAG) == 0) ? res : nullptr;
    }

    static const ELF_PHDR_T* findPHDR(const ELF_EHDR_T* ehdr, int type);

    static const ELF_DYN_T* findDynTAB(const ELF_EHDR_T* ehdr, const ELF_PHDR_T* phdr, int type);

    static void printMaps();

    static void printEHDR(const ELF_EHDR_T* ehdr);

    static void printPHDR(const ELF_PHDR_T* phdr);

    static void printDynTAB(const ELF_DYN_T* dyn);

    static void printSymTAB(const ELF_SYM_T* sym);

    static void printRelTAB(const ELF_REL_T* rel);
    static void printRelaTAB(const ELF_RELA_T* rela);
};

#endif // __ELFUTILS_H__
