#ifndef __LIBELFFUZZ_H__
#define __LIBELFFUZZ_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "elffuzz_def.h"

#ifdef __cplusplus
extern "C" {
#endif

struct elffuzz;
typedef struct elffuzz elffuzz_t;

elffuzz_t* elffuzz_init(const char* so_name, const char* proc_name);
void elffuzz_done(elffuzz_t* obj);

bool elffuzz_set_malloc_hook(elffuzz_t* obj, int hook_call_idx);
void elffuzz_rem_malloc_hook(elffuzz_t* obj);

bool elffuzz_set_calloc_hook(elffuzz_t* obj, int hook_call_idx);
void elffuzz_rem_calloc_hook(elffuzz_t* obj);

//bool elffuzz_check_callstack(elffuzz_t* obj);

#ifdef __cplusplus
}
#endif

#endif // __LIBELFFUZZ_H__
