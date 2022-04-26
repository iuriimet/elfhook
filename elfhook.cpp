#include <stdio.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>

#include "libtest.h"

#include "logger.h"




/*
// ZZZ for elfmem lib
#include "elfmem_def.h"
#include "libelfmem.h"

static elfmem_t* s_elf = nullptr;


int hooked_puts_1(const char* s)
{
    puts(s);
    puts("!!! HOOKED 111 !!!");
    StackItem si[12];
    CallStack st{.m_nitems = 12, .m_items = si};
    elfmem_callstack(s_elf, &st);
    for (int i = 0; i < st.m_nitems; i++){
        LOG_D("stack item : obj = %s, sym = %s, add = %p, off = %ld", st.m_items[i].m_info.m_object, st.m_items[i].m_info.m_symbol, (const void*)st.m_items[i].m_info.m_address, st.m_items[i].m_offset);
    }
    return 0;
}

int hooked_puts_2(const char* s)
{
    puts(s);
    puts("!!! HOOKED 222 !!!");
    StackItem si[12];
    CallStack st{.m_nitems = 12, .m_items = si};
    elfmem_callstack(s_elf, &st);
    for (int i = 0; i < st.m_nitems; i++){
        LOG_D("stack item : obj = %s, sym = %s, add = %p, off = %ld", st.m_items[i].m_info.m_object, st.m_items[i].m_info.m_symbol, (const void*)st.m_items[i].m_info.m_address, st.m_items[i].m_offset);
    }
    return 0;
}

void* hooked_malloc_1(size_t size)
{
    std::cout << "!!! hooked_malloc_1 BEG !!!" << std::endl;
    StackItem si[12];
    CallStack st{.m_nitems = 12, .m_items = si};
    elfmem_callstack(s_elf, &st);
    for (int i = 0; i < st.m_nitems; i++){
        LOG_D("stack item : obj = %s, sym = %s, add = %p, off = %ld", st.m_items[i].m_info.m_object, st.m_items[i].m_info.m_symbol, (const void*)st.m_items[i].m_info.m_address, st.m_items[i].m_offset);
    }
    std::cout << "!!! hooked_malloc_1 END !!!" << std::endl;
    return nullptr;
}

void* hooked_malloc_2(size_t size)
{
    std::cout << "!!! hooked_malloc_2 BEG !!!" << std::endl;
    StackItem si[16];
    CallStack st{.m_nitems = 16, .m_items = si};
    elfmem_callstack(s_elf, &st);
    for (int i = 0; i < st.m_nitems; i++){
        LOG_D("stack item : obj = %s, sym = %s, add = %p, off = %ld", st.m_items[i].m_info.m_object, st.m_items[i].m_info.m_symbol, (const void*)st.m_items[i].m_info.m_address, st.m_items[i].m_offset);
    }
    std::cout << "!!! hooked_malloc_2 END !!!" << std::endl;
    return malloc(size);
}

int main()
{
    s_elf = elfmem_create();
    if (s_elf) {
        LOG_D("Bin name %s", elfmem_name(s_elf));
        LOG_D("Machine %d", elfmem_machine(s_elf));
        LOG_D("Machine Type %d", elfmem_machine_type(s_elf));
        LOG_D("Encoding Type %d", elfmem_encoding_type(s_elf));

        LOG_D("test_11 sym at %p", elfmem_find_sym_by_name(s_elf, "libtest.so", "test_11"));
        LOG_D("test_12 sym at %p", elfmem_find_sym_by_name(s_elf, "libtest.so", "test_12"));
        LOG_D("test_13 sym at %p", elfmem_find_sym_by_name(s_elf, "libtest.so", "test_13"));
        LOG_D("test_14 sym at %p", elfmem_find_sym_by_name(s_elf, "libtest.so", "test_14"));
        LOG_D("test_21 sym at %p", elfmem_find_sym_by_name(s_elf, "libtest.so", "test_21"));
        LOG_D("hooked_puts_1 sym at %p", elfmem_find_sym_by_name(s_elf, "elfhook", "hooked_puts_1"));

        // Hook for libtest.so
        // original call
        test_11();

        // hook 1
        const void* orig_addr_1 = elfmem_hook_reltab(s_elf, "libtest.so", "puts", (const void*)hooked_puts_1);
        LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr_1, (const void*)hooked_puts_1);
        test_11();

        // hook 2
        const void* hook_addr_11 = elfmem_hook_reltab(s_elf, "libtest.so", "puts", (const void*)hooked_puts_2);
        LOG_D("Hook 1 Addr %p : Hook 2 Addr %p ", (const void*)hook_addr_11, (const void*)hooked_puts_2);
        test_11();

        // restore original
        const void* hook_addr_12 = elfmem_hook_reltab(s_elf, "libtest.so", "puts", (const void*)orig_addr_1);
        LOG_D("Hook 2 Addr %p : Orig Addr %p ", (const void*)hook_addr_12, (const void*)orig_addr_1);
        test_11();



        // Hook for libstdc++.so
        // original call
        test_12();

        // hook 3
        const void* orig_addr_2 = elfmem_hook_reltab(s_elf, "libstdc++.so.6", "malloc", (const void*)hooked_malloc_1);
        LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr_2, (const void*)hooked_malloc_1);
        test_12();

        // restore original
        const void* hook_addr_21 = elfmem_hook_reltab(s_elf, "libstdc++.so.6", "malloc", (const void*)orig_addr_2);
        LOG_D("Hook Addr %p : Orig Addr %p ", (const void*)hook_addr_21, (const void*)orig_addr_2);
        test_12();



        // Hook for libstdc++.so
        // original call
        test_13();

        // hook 4
        const void* orig_addr_3 = elfmem_hook_reltab(s_elf, "libstdc++.so.6", "malloc", (const void*)hooked_malloc_2);
        LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr_3, (const void*)hooked_malloc_2);
        test_13();
        test_14();

        // restore original
        const void* hook_addr_31 = elfmem_hook_reltab(s_elf, "libstdc++.so.6", "malloc", (const void*)orig_addr_3);
        LOG_D("Hook Addr %p : Orig Addr %p ", (const void*)hook_addr_31, (const void*)orig_addr_3);
        test_13();


        elfmem_destroy(s_elf);
    }

    return 0;
}
*/





// ZZZ for elfhook lib
#include "elffuzz_def.h"
#include "libelffuzz.h"

static elffuzz_t* s_elf = nullptr;

int main()
{
    // to link libtest
    test_21();

    s_elf = elffuzz_init("libtest.so", "test_21");
    if (s_elf) {

        elffuzz_set_malloc_hook(s_elf, 0);
        elffuzz_set_calloc_hook(s_elf, 1);
        test_21();
        elffuzz_rem_malloc_hook(s_elf);
        elffuzz_rem_calloc_hook(s_elf);

        elffuzz_set_malloc_hook(s_elf, 1);
        elffuzz_set_calloc_hook(s_elf, 0);
        test_21();

        elffuzz_done(s_elf);
    }
    return 0;
}

