#include <stdio.h>

#include "libtest.h"

#include "elfmem_def.h"
#include "elfmem.h"
#include "logger.h"

int hooked_puts_1(const char* s)
{
    puts(s);
    puts("!!! HOOKED 111 !!!");
    return 0;
}

int hooked_puts_2(const char* s)
{
    puts(s);
    puts("!!! HOOKED 222 !!!");
    return 0;
}

//void hooked_libtest()
//{
//    LOG_D("!!! libtest HOOKED !!!");
//}

int main()
{
    ElfMem elf;

    // original call
    libtest();

    // hook 1
    const void* orig_addr = elf.soHookRel("libtest.so", "puts", (const void*)hooked_puts_1);
    LOG_D("Orig Addr %p : Hook Addr %p", (const void*)orig_addr, (const void*)hooked_puts_1);
    libtest();

    // hook 2
    const void* hook_addr_1 = elf.soHookRel("libtest.so", "puts", (const void*)hooked_puts_2);
    LOG_D("Hook 1 Addr %p : Hook 2 Addr %p ", (const void*)hook_addr_1, (const void*)hooked_puts_2);
    libtest();

    // restore original
    const void* hook_addr_2 = elf.soHookRel("libtest.so", "puts", (const void*)orig_addr);
    LOG_D("Hook 2 Addr %p : Orig Addr %p ", (const void*)hook_addr_2, (const void*)orig_addr);
    libtest();

//    elf.soHookSym("libtest.so", "libtest", (const void*)hooked_libtest);
//    libtest();

    return 0;
}
