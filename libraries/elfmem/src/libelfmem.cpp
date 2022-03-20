#include <stdlib.h>

#include "elfmem_def.h"
#include "elfmem.h"
#include "libelfmem.h"

struct elfmem
{
    void* obj;
};

elfmem_t* elfmem_create(const char* exe_name)
{
    elfmem_t* res = new elfmem_t();
    if (res) {
        res->obj = new ns_elfmem::ElfMem(exe_name);
    }
    return res;
}
void elfmem_destroy(elfmem_t* obj)
{
    if (obj) {
        if (obj->obj)
            delete static_cast<ns_elfmem::ElfMem*>(obj->obj);
        delete obj;
    }
}

Machine elfmem_machine(elfmem_t* obj)
{
    Machine res = MACHINE_UNKNOWN;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->getMachine();
    }
    return res;
}
MachineType elfmem_machine_type(elfmem_t* obj)
{
    MachineType res = MACHINE_TYPE_UNKNOWN;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->getMachineType();
    }
    return res;
}
EncodingType elfmem_encoding_type(elfmem_t* obj)
{
    EncodingType res = ENCODING_TYPE_UNKNOWN;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->getEncodingType();
    }
    return res;
}

const void* elfmem_find_sym_by_name(elfmem_t* obj, const char* bin_name, const char* sym_name)
{
    const void* res = NULL;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->findSymByName(bin_name, sym_name);
    }
    return res;
}

const char* elfmem_find_sym_by_addr(elfmem_t* obj, uintptr_t addr, uintptr_t* sym_addr)
{
    const char* res = NULL;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->findSymByAddr(addr, sym_addr);
    }
    return res;
}


const void* elfmem_hook_reltab(elfmem_t* obj, const char* so_name, const char* sym_name, const void* subst_addr)
{
    const void* res = NULL;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->hookRel(so_name, sym_name, subst_addr);
    }
    return res;
}
