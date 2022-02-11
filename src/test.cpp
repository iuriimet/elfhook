#include <stdio.h>

#include "libtest.h"

#include "elfmem_def.h"
#include "elfmem.h"
#include "logger.h"

int hooked_puts(const char* s)
{
    puts(s);
    puts("!!! HOOKED !!!");
}

void hooked_libtest()
{
    LOGD("!!! libtest HOOKED !!!");
}

int main()
{
    ElfMem elf;

    libtest();
    elf.soHookRel("libTEST_LIB.so", "puts", (const void*)hooked_puts);
    libtest();

    elf.soHookSym("libTEST_LIB.so", "libtest", (const void*)hooked_libtest);
    libtest();

    return 0;
}
