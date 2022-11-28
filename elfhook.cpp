#include <stdio.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>

#include "libtest.h"

#include "common.h"
#include "elffuzz_def.h"
#include "libelffuzz.h"

#include "logger.h"

//// ZZZ move to common.h
//#define XSTR(s) STR(s)
//#define STR(s)  #s

#define TEST(__prefix, __test_name, __hook_idx, ...) \
    static void test_##__test_name(elffuzz_t* elf) {\
        std::cout << "\n\nZZZ <<< TEST '" XSTR(__prefix) << "_" << XSTR(__test_name) << "' BEGIN" << std::endl; \
        test_##__prefix##_##__test_name(__VA_ARGS__); \
        elffuzz_set_hooks(elf, (__hook_idx)); \
        test_##__prefix##_##__test_name(__VA_ARGS__); \
        elffuzz_del_hooks(elf); \
        test_##__prefix##_##__test_name(__VA_ARGS__); \
        std::cout << "\n\nZZZ >>> TEST '" << XSTR(__test_name) << "' END\n\n" << std::endl; \
    }


TEST(syscall, open, 0)
TEST(syscall, read, 1)
TEST(syscall, write, 1, 'a')
TEST(syscall, pread, 1)
TEST(syscall, pwrite, 1)
TEST(syscall, stat, 0)
TEST(syscall, lseek, 1)
TEST(syscall, lseek64, 1)
TEST(syscall, mmap, 2)
TEST(syscall, pipe, 0)
TEST(syscall, dup, 1)
TEST(libc, malloc, 0)



//static void test_ioctl(elffuzz_t* elf)
//{
//    std::cout << "\n\nZZZ ======================================================= TEST IOCTL BEG" << std::endl;
//    test_syscall_ioctl();
//    elffuzz_set_syscall_hooks(elf, 1);
//    test_syscall_ioctl();
//    elffuzz_del_syscall_hooks(elf);
//    test_syscall_ioctl();
//    std::cout << "ZZZ ======================================================= TEST IOCTL END\n\n" << std::endl;
//}

static void test_all(elffuzz_t* elf)
{
    test_open(elf);
    test_read(elf);
    test_write(elf);
    test_pread(elf);
    test_pwrite(elf);
    test_stat(elf);
    test_lseek(elf);
    test_lseek64(elf);
    test_mmap(elf);
    test_pipe(elf);
    test_dup(elf);
    test_malloc(elf);
}

int main(int argc, char* argv[])
{
    elffuzz_t* elf = elffuzz_init();
    if (elf) {
        if (argc != 2) {
            test_all(elf);
        } else {
            if (std::string(argv[1]) == "--open") test_open(elf);
            else if (std::string(argv[1]) == "--read") test_read(elf);
            else if (std::string(argv[1]) == "--write") test_write(elf);
            else if (std::string(argv[1]) == "--pread") test_pread(elf);
            else if (std::string(argv[1]) == "--pwrite") test_pwrite(elf);
            else if (std::string(argv[1]) == "--stat") test_stat(elf);
            else if (std::string(argv[1]) == "--lseek") test_lseek(elf);
            else if (std::string(argv[1]) == "--lseek64") test_lseek64(elf);
            else if (std::string(argv[1]) == "--mmap") test_mmap(elf);
            else if (std::string(argv[1]) == "--pipe") test_pipe(elf);
            else if (std::string(argv[1]) == "--dup") test_dup(elf);
            else if (std::string(argv[1]) == "--malloc") test_malloc(elf);
            else if (std::string(argv[1]) == "--all") test_all(elf);
        }

        elffuzz_done(elf);
    }

    return 0;
}






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
    for (size_t i = 0; i < st.m_nitems; i++){
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
    for (size_t i  = 0; i < st.m_nitems; i++){
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
    for (size_t i = 0; i < st.m_nitems; i++){
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
    for (size_t i = 0; i < st.m_nitems; i++){
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
        const void* orig_addr_2 = elfmem_hook_reltab(s_elf, "libstdc++.so", "malloc", (const void*)hooked_malloc_1);
        LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr_2, (const void*)hooked_malloc_1);
        test_12();

        // restore original
        const void* hook_addr_21 = elfmem_hook_reltab(s_elf, "libstdc++.so", "malloc", (const void*)orig_addr_2);
        LOG_D("Hook Addr %p : Orig Addr %p ", (const void*)hook_addr_21, (const void*)orig_addr_2);
        test_12();



        // Hook for libstdc++.so
        // original call
        test_13();

        // hook 4
        const void* orig_addr_3 = elfmem_hook_reltab(s_elf, "libstdc++.so", "malloc", (const void*)hooked_malloc_2);
        LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr_3, (const void*)hooked_malloc_2);
        test_13();
        test_14();

        // restore original
        const void* hook_addr_31 = elfmem_hook_reltab(s_elf, "libstdc++.so", "malloc", (const void*)orig_addr_3);
        LOG_D("Hook Addr %p : Orig Addr %p ", (const void*)hook_addr_31, (const void*)orig_addr_3);
        test_13();


        elfmem_destroy(s_elf);
    }

    return 0;
}
*/
