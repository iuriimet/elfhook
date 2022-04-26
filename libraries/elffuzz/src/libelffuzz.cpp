#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdexcept>
#include <cassert>

#include "elffuzz_def.h"
#include "elffuzz.h"
#include "libelffuzz.h"

#include "logger.h"

struct elffuzz
{
    void* obj;
};

static elffuzz_t* s_elffuzz = NULL;
static fp_malloc_t s_malloc_orig_fp = NULL;
static int s_malloc_hook_call_idx = 0;
static int s_malloc_hook_call_cnt = 0;
static fp_calloc_t s_calloc_orig_fp = NULL;
static int s_calloc_hook_call_idx = 0;
static int s_calloc_hook_call_cnt = 0;

static void* elffuzz_malloc(size_t size)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    assert(s_malloc_orig_fp);

    LOG_D("ELFFUZZ : elffuzz_malloc: orig_fp - %p, hook_call_idx - %d, hook_call_cnt - %d",
          s_malloc_orig_fp, s_malloc_hook_call_idx, s_malloc_hook_call_cnt);

    return ((static_cast<ns_elffuzz::ElfFuzz*>(s_elffuzz->obj))->checkCallStack() &&
            s_malloc_hook_call_idx == s_malloc_hook_call_cnt++) ? NULL : s_malloc_orig_fp(size);
}

static void* elffuzz_calloc(size_t nmemb, size_t size)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    assert(s_calloc_orig_fp);

    LOG_D("ELFFUZZ : elffuzz_calloc: orig_fp - %p, hook_call_idx - %d, hook_call_cnt - %d",
          s_calloc_orig_fp, s_calloc_hook_call_idx, s_calloc_hook_call_cnt);

    return ((static_cast<ns_elffuzz::ElfFuzz*>(s_elffuzz->obj))->checkCallStack() &&
            s_calloc_hook_call_idx == s_calloc_hook_call_cnt++) ? NULL : s_calloc_orig_fp(nmemb, size);
}

elffuzz_t* elffuzz_init(const char* so_name, const char* proc_name)
{
    LOG_D("ELFFUZZ : elffuzz_init : so_name = %s, proc_name = %s", so_name, proc_name);
    if (!s_elffuzz) {
        try {
            s_elffuzz = new elffuzz_t();
            s_elffuzz->obj = new ns_elffuzz::ElfFuzz(so_name, proc_name);
        } catch (const std::exception& e) {
            LOG_W("%s", e.what());
            elffuzz_done(s_elffuzz);
            s_elffuzz = NULL;
        }
    }
    return s_elffuzz;
}
void elffuzz_done(elffuzz_t* obj)
{
    LOG_D("ELFFUZZ : elffuzz_done");
    if (obj) {
        if (obj->obj) {
            delete static_cast<ns_elffuzz::ElfFuzz*>(obj->obj);
            obj->obj = NULL;
        }
        delete obj;
    }
}

bool elffuzz_set_malloc_hook(elffuzz_t* obj, int hook_call_idx)
{
    bool res = false;
    LOG_D("ELFFUZZ : elffuzz_set_malloc_hook : hook_call_idx = %d", hook_call_idx);
    if (!s_malloc_orig_fp && obj && obj->obj) {
         if ((s_malloc_orig_fp = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setMallocHook((fp_malloc_t)elffuzz_malloc))) {
             LOG_D("ELFFUZZ: elffuzz_set_malloc_hook - OK");
             s_malloc_hook_call_idx = hook_call_idx;
             s_malloc_hook_call_cnt = 0;
             res = true;
         }
    }
    return res;
}
void elffuzz_rem_malloc_hook(elffuzz_t* obj)
{
    LOG_D("ELFFUZZ : elffuzz_rem_malloc_hook");
    if (s_malloc_orig_fp && obj && obj->obj && (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->remMallocHook()) {
        LOG_D("ELFFUZZ: elffuzz_rem_malloc_hook - OK");
        s_malloc_orig_fp = NULL;
    }
}

bool elffuzz_set_calloc_hook(elffuzz_t* obj, int hook_call_idx)
{
    bool res = false;
    LOG_D("ELFFUZZ : elffuzz_set_calloc_hook : hook_call_idx = %d", hook_call_idx);
    if (!s_calloc_orig_fp && obj && obj->obj) {
         if ((s_calloc_orig_fp = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setCallocHook((fp_calloc_t)elffuzz_calloc))) {
             LOG_D("ELFFUZZ: elffuzz_set_calloc_hook - OK");
             s_calloc_hook_call_idx = hook_call_idx;
             s_calloc_hook_call_cnt = 0;
             res = true;
         }
    }
    return res;
}
void elffuzz_rem_calloc_hook(elffuzz_t* obj)
{
    LOG_D("ELFFUZZ : elffuzz_rem_calloc_hook");
    if (s_calloc_orig_fp && obj && obj->obj && (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->remCallocHook()) {
        LOG_D("ELFFUZZ: elffuzz_rem_calloc_hook - OK");
        s_calloc_orig_fp = NULL;
    }
}

//bool elffuzz_check_callstack(elffuzz_t* obj)
//{
//    bool res = false;
//    if (obj && obj->obj) {
//        res = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->checkCallStack();
//    }
//    return res;
//}
