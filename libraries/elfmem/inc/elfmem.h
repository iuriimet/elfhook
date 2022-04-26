#ifndef __ELFMEM_H__
#define __ELFMEM_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <string>
#include <list>
#include <cassert>

#include "elfmem_def.h"


namespace ns_elfmem {

class ElfMem
{
    class ElfBin
    {
    public:
        ElfBin(uintptr_t beg_addr, uintptr_t end_addr, const char* name = "");
        virtual ~ElfBin() = default;

        inline const char* getName() const {return m_name;}

        virtual const void* findSymByName(const char* sym_name) const;
        virtual const char* findSymByAddr(uintptr_t addr, uintptr_t* sym_addr = nullptr) const;

    protected:
        uintptr_t m_beg_addr;
        uintptr_t m_end_addr;
        const char* m_name;
        const ELF_EHDR_T* m_ehdr;
        const ELF_PHDR_T* m_phdr;
        const ELF_DYN_T* m_strtab;
        const char* m_strings;
        const ELF_DYN_T* m_symtab;
        const ELF_SYM_T* m_symbols;
    };

    class ElfSo : public ElfBin
    {
    public:
        ElfSo(uintptr_t beg_addr, uintptr_t end_addr);
        ~ElfSo() = default;

        const void* findSymByName(const char* sym_name) const override;
        const char* findSymByAddr(uintptr_t addr, uintptr_t* sym_addr = nullptr) const override;

        const void* hookRel(const char* sym_name, const void* subst_addr) const;

    private:

        template <typename RELT>
        const void* hookRelTab(const RELT* reltab, int relcnt, uint64_t reltype,
                               const char* sym_name, const void* subst_addr) const {
             assert(reltab);
             assert(sym_name);
             assert(subst_addr);

            const void* res = nullptr;

            for (; !res && relcnt > 0; relcnt--, reltab++) {

                if (ELF_R_TYPE(reltab->r_info) != reltype)
                    continue;

                const ELF_SYM_T* sym = (const ELF_SYM_T*)(m_symbols + ELF_R_SYM(reltab->r_info));
                if (ELF_ST_BIND(sym->st_info) != STB_GLOBAL || ELF_ST_TYPE(sym->st_info) != STT_FUNC)
                    continue;

                if (strcmp((const char*)(m_strings + sym->st_name), sym_name) == 0) {
                    off_t off = m_ehdr->e_type == ET_DYN ? (off_t)m_ehdr : 0;
                    const void* ptr = (const void*)(off + reltab->r_offset);
                    res = (const void*)(*(uintptr_t*)(ptr));
                    *(uintptr_t*)(ptr) = (uintptr_t)subst_addr;
                }
            }

            return res;
        }

        int m_reltype;
    };

public:
    ElfMem();
    virtual ~ElfMem() {if (m_bin) delete m_bin;}

    const char* getName() {return m_name.c_str();}
    static Machine getMachine();
    static MachineType getMachineType();
    static EncodingType getEncodingType();

    const void* findSymByName(const char* bin_name, const char* sym_name) const;
    const char* findSymByAddr(uintptr_t addr, SymInfo* info) const;

    const void* hookRel(const char* so_name, const char* sym_name, const void* subst_addr) const;

    int callStack(CallStack* stack) const;

private:
    static std::string readComm();
    void makeBinList();

//    static std::string demangle(const std::string& name);

    std::string m_name;
    ElfBin* m_bin;
    std::list<ElfSo> m_so_list;
};

} // namespace ns_elfmem

#endif // __ELFMEM_H__
