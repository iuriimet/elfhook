#ifndef __LIBELFMEM_H__
#define __LIBELFMEM_H__

#include <stdlib.h>

#include "elfmem_def.h"

#ifdef __cplusplus
extern "C" {
#endif

struct elfmem;
typedef struct elfmem elfmem_t;

elfmem_t* elfmem_create(const char* exe_name);
void elfmem_destroy(elfmem_t* obj);

Machine elfmem_machine(elfmem_t* obj);
MachineType elfmem_machine_type(elfmem_t* obj);
EncodingType elfmem_encoding_type(elfmem_t* obj);

const void* elfmem_find_sym_by_name(elfmem_t* obj, const char* bin_name, const char* sym_name);
const char* elfmem_find_sym_by_addr(elfmem_t* obj, uintptr_t addr, uintptr_t* sym_addr);

const void* elfmem_hook_reltab(elfmem_t* obj, const char* so_name, const char* sym_name, const void* subst_addr);

#ifdef __cplusplus
}
#endif

#endif // __LIBELFMEM_H__
