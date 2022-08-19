#include <stdlib.h>
#include <stdexcept>

#include "elfmem_def.h"
#include "elfmem.h"
#include "libelfmem.h"

#include "logger.h"

struct elfmem
{
    void* obj;
};

elfmem_t* elfmem_create(void)
{
    elfmem_t* res = NULL;
    try {
        res = new elfmem_t();
        res->obj = new ns_elfmem::ElfMem();
    } catch (const std::exception& e) {
        LOG_W("%s", e.what());
        elfmem_destroy(res);
        res = NULL;
    }
    return res;
}
void elfmem_destroy(elfmem_t* obj)
{
    if (obj) {
        if (obj->obj) {
            delete static_cast<ns_elfmem::ElfMem*>(obj->obj);
            obj->obj = NULL;
        }
        delete obj;
    }
}

const char* elfmem_name(elfmem_t* obj)
{
    const char* res = NULL;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->getName();
    }
    return res;
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

const char* elfmem_find_sym_by_addr(elfmem_t* obj, uintptr_t addr, SymInfo* info)
{
    const char* res = NULL;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->findSymByAddr(addr, info);
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

int elfmem_callstack(elfmem_t* obj, CallStack* stack)
{
    int res = 0;
    if (obj && obj->obj) {
        res = (static_cast<ns_elfmem::ElfMem*>(obj->obj))->callStack(stack);
    }
    return res;
}
