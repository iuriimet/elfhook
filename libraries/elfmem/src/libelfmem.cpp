#include <stdlib.h>

#include "elfmem_def.h"
#include "elfmem.h"
#include "libelfmem.h"

struct elfmem
{
    void* obj;
};

elfmem_t* elfmem_create(void)
{
    elfmem_t* res = new elfmem_t();
    if (res) {
        res->obj = new ns_elfmem::ElfMem();
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

const void* elfmem_hook_reltab(elfmem_t* obj, const char* so_name, const char* proc_name, const void* subst_addr)
{
    const void* res = NULL;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->soHookRel(so_name, proc_name, subst_addr);
    }
    return res;
}
