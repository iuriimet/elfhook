#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdexcept>

#include "elffuzz.h"
#include "libelffuzz.h"

#include "logger.h"

struct elffuzz
{
    void* obj;
};

elffuzz_t* elffuzz_create(const char* exe_name, const char* so_name, const char* proc_name)
{
    elffuzz_t* res = new elffuzz_t();
    if (res) {
        try {
            res->obj = new ns_elffuzz::ElfFuzz(exe_name, so_name, proc_name);
        } catch (const std::exception& e) {
            LOG_W("%s", e.what());
            elffuzz_destroy(res);
            res = nullptr;
        }
    }
    return res;
}
void elffuzz_destroy(elffuzz_t* obj)
{
    if (obj) {
        if (obj->obj)
            delete static_cast<ns_elffuzz::ElfFuzz*>(obj->obj);
        delete obj;
    }
}

const void* elffuzz_add_hook(elffuzz_t* obj, const char* so_name, const char* sym_name, const void* subst_addr)
{
    const void* res = nullptr;
    if (obj && obj->obj) {
        res = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->addHook(so_name, sym_name, subst_addr);
    }
    return res;
}
void elffuzz_del_hook(elffuzz_t* obj, const void* hook_addr)
{
    if (obj && obj->obj) {
        (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->delHook(hook_addr);
    }
}




/*
bool elffuzz_add_hook(elffuzz_t* obj, const char* so_name, const char* proc_name, const void* subst_addr, size_t* hook_id)
{
    bool res = false;
    if (obj && obj->obj) {
        res = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->addHook(so_name, proc_name, subst_addr, hook_id);
    }
    return res;
}
bool elffuzz_del_hook(elffuzz_t* obj, size_t hook_id)
{
    bool res = false;
    if (obj && obj->obj) {
        res = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->delHook(hook_id);
    }
    return res;
}
bool elffuzz_check_hook(elffuzz_t* obj, size_t hook_id)
{
    bool res = false;
    if (obj && obj->obj) {
        res = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->checkHook(hook_id);
    }
    return res;
}
*/
