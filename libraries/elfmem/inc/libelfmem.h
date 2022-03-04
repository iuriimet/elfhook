#ifndef __LIBELFMEM_H__
#define __LIBELFMEM_H__

#include "elfmem_def.h"

#ifdef __cplusplus
extern "C" {
#endif

struct elfmem;
typedef struct elfmem elfmem_t;

elfmem_t* elfmem_create(void);
void elfmem_destroy(elfmem_t* obj);

Machine elfmem_machine(elfmem_t* obj);
MachineType elfmem_machine_type(elfmem_t* obj);
EncodingType elfmem_encoding_type(elfmem_t* obj);

const void* elfmem_hook_reltab(elfmem_t* obj, const char* so_name, const char* proc_name, const void* subst_addr);

const void* elfmem_find_sym(elfmem_t* obj, const char* so_name, const char* proc_name);



//void elfmem_print_sym(elfmem_t* obj, const char* so_name);

#ifdef __cplusplus
}
#endif

#endif // __LIBELFMEM_H__
