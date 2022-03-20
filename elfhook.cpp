#include <stdio.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libtest.h"


// ZZZ for elfmem lib
/*
#include "elfmem_def.h"
#include "libelfmem.h"

#include "logger.h"

static elfmem_t* s_elf = nullptr;

#define BT_BUF_SIZE 128
void print_call_stack(void)
{
    int nptrs;
    void* buffer[BT_BUF_SIZE];
    char** strings;

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    printf("backtrace() returned %d addresses\n", nptrs);
    for (int i = 0; i < nptrs; i++) {
        printf("ZZZ ========================== backtrace item : %d - %p\n", i, buffer[i]);
        // LOG_D("sym at %p : %s", buffer[i], elfmem_find_sym_by_addr(s_elf, (uintptr_t)buffer[i]));
    }


    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(-1);
    }

    for (int j = 0; j < nptrs; j++)
        printf("%s\n", strings[j]);

    free(strings);
}

//int hooked_puts_1(const char* s)
//{
//    puts(s);
//    puts("!!! HOOKED 111 !!!");
//    print_call_stack();
//    return 0;
//}

//int hooked_puts_2(const char* s)
//{
//    puts(s);
//    puts("!!! HOOKED 222 !!!");
//    print_call_stack();
//    return 0;
//}

void* hooked_malloc(size_t size)
{
    static int cnt = 0;
    puts("!!! hooked_malloc !!!");
    print_call_stack();
    return nullptr;
//    return (++cnt == 1) ? nullptr : malloc(size);
}

int main()
{
    s_elf = elfmem_create("elfhook");
    if (s_elf) {
        LOG_D("Machine %d", elfmem_machine(s_elf));
        LOG_D("Machine Type %d", elfmem_machine_type(s_elf));
        LOG_D("Encoding Type %d", elfmem_encoding_type(s_elf));

        LOG_D("test sym at %p", elfmem_find_sym_by_name(s_elf, "libtest.so", "test"));
        LOG_D("test_2 sym at %p", elfmem_find_sym_by_name(s_elf, "libtest.so", "test_2"));


//        // Hook for libtest.so
//        // original call
//        test();

//        // hook 1
//        const void* orig_addr_1 = elfmem_hook_reltab(s_elf, "libtest.so", "puts", (const void*)hooked_puts_1);
//        LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr_1, (const void*)hooked_puts_1);
//        test();

//        // hook 2
//        const void* hook_addr_11 = elfmem_hook_reltab(s_elf, "libtest.so", "puts", (const void*)hooked_puts_2);
//        LOG_D("Hook 1 Addr %p : Hook 2 Addr %p ", (const void*)hook_addr_11, (const void*)hooked_puts_2);
//        test();

//        // restore original
//        const void* hook_addr_12 = elfmem_hook_reltab(s_elf, "libtest.so", "puts", (const void*)orig_addr_1);
//        LOG_D("Hook 2 Addr %p : Orig Addr %p ", (const void*)hook_addr_12, (const void*)orig_addr_1);
//        test();



        // Hook for libstdc++.so
        // original call
        test_2();

        // hook 3
        const void* orig_addr_2 = elfmem_hook_reltab(s_elf, "libstdc++.so.6", "malloc", (const void*)hooked_malloc);
        LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr_2, (const void*)hooked_malloc);
        test_2();

        // restore original
        const void* hook_addr_22 = elfmem_hook_reltab(s_elf, "libstdc++.so.6", "malloc", (const void*)orig_addr_2);
        LOG_D("Hook Addr %p : Orig Addr %p ", (const void*)hook_addr_22, (const void*)orig_addr_2);
        test_2();

        elfmem_destroy(s_elf);
    }

    return 0;
}
*/






// ZZZ for elfhook lib
#include "libelffuzz.h"

#include "logger.h"


//#define BT_BUF_SIZE 128
//void print_call_stack(void)
//{
//    int nptrs;
//    void* buffer[BT_BUF_SIZE];
//    char** strings;

//    nptrs = backtrace(buffer, BT_BUF_SIZE);
//    printf("backtrace() returned %d addresses\n", nptrs);

//    /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
//       would produce similar output to the following: */

//    strings = backtrace_symbols(buffer, nptrs);
//    if (strings == NULL) {
//        perror("backtrace_symbols");
//        exit(-1);
//    }

//    for (int j = 0; j < nptrs; j++)
//        printf("%s\n", strings[j]);

//    free(strings);
//}


static elffuzz_t* s_elf;

void* hooked_malloc(size_t size)
{
    puts("!!!!!! hooked_malloc !!!!!!");
    return malloc(size);
}

int main()
{
    // to link libtest
    test();



    s_elf = elffuzz_create("elfhook", "libtest.so", "test_2");
    if (s_elf) {
        const void* id = elffuzz_add_hook(s_elf, "libstdc++.so.6", "malloc", (const void*)hooked_malloc);
        if (id)
            puts("ZZZ === elffuzz_add_hook OKK");
        else
            puts("ZZZ === elffuzz_add_hook ERR");

        test_2();

        elffuzz_del_hook(s_elf, id);
        test_2();

        elffuzz_destroy(s_elf);
    }
    return 0;
}




