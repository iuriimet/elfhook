#ifndef __ELFMEM_H__
#define __ELFMEM_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <list>
// #include <assert.h>

#include "elfmem_def.h"

class ElfMem
{
    class ElfSo
    {
    public:
        ElfSo(const void* base_addr);
        ~ElfSo() = default;

        inline const char* getName() const {
            return m_name;
        }

        const void* hookRel(const char* proc_name, const void* subst_addr) const;

        bool hookSym(const char* proc_name, const void* subst_addr) const;

    private:

        template <typename RELT>
        const void* hookRelTab(const RELT* reltab, int relcnt, uint64_t reltype,
                               const char* proc_name, const void* subst_addr) const {
            // assert(reltab);
            // assert(proc_name);
            // assert(subst_addr);

            const void* res = nullptr;

            for (; !res && relcnt > 0; relcnt--, reltab++) {

                if (ELF_R_TYPE(reltab->r_info) != reltype)
                    continue;

                const ELF_SYM_T* sym = (const ELF_SYM_T*)(m_symbols + ELF_R_SYM(reltab->r_info));
                if (ELF_ST_BIND(sym->st_info) != STB_GLOBAL || ELF_ST_TYPE(sym->st_info) != STT_FUNC)
                    continue;

                if (strcmp((const char*)(m_strings + sym->st_name), proc_name) == 0) {
                    off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;
                    const void* ptr = (const void*)(off + reltab->r_offset);
                    res = (const void*)(*(uintptr_t*)(ptr));
                    *(uintptr_t*)(ptr) = (uintptr_t)subst_addr;
                }
            }

            return res;
        }

        static void rewriteProc(void* proc_addr, const void* buff, size_t size);
        bool rewriteProc(void* proc_addr, const void* subst_addr) const;

        const ELF_EHDR_T* m_ehdr;
        const ELF_PHDR_T* m_phdr;
        const ELF_DYN_T* m_strtab;
        const char* m_strings;
        const char* m_name;
        const ELF_DYN_T* m_symtab;
        const ELF_SYM_T* m_symbols;
        int m_reltype;
    };

public:
    ElfMem();
    virtual ~ElfMem() = default;

    static Machine getMachine();
    static MachineType getMachineType();
    static EncodingType getEncodingType();

    const void* soHookRel(const char* so_name, const char* proc_name, const void* subst_addr) const;

    bool soHookSym(const char* so_name, const char* proc_name, const void* subst_addr) const;

private:
    void makeSoList();

    std::list<ElfSo> m_solist;
};

#endif // __ELFMEM_H__
