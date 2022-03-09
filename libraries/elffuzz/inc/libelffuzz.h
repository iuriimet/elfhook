#ifndef __LIBELFFUZZ_H__
#define __LIBELFFUZZ_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct elffuzz;
typedef struct elffuzz elffuzz_t;

elffuzz_t* elffuzz_create(const char* so_name, const char* proc_name);
void elffuzz_destroy(elffuzz_t* obj);

bool elffuzz_add_hook(elffuzz_t* obj, const char* so_name, const char* proc_name, const void* subst_addr, size_t* hook_id);
bool elffuzz_del_hook(elffuzz_t* obj, size_t hook_id);
bool elffuzz_check_hook(elffuzz_t* obj, size_t hook_id);

#ifdef __cplusplus
}
#endif

#endif // __LIBELFFUZZ_H__
