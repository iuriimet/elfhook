#include <stdio.h>

#include "libtest.h"

#ifdef __cplusplus
extern "C"
{
#endif

void libtest(void)
{
    puts("libtest: original puts()");
}

#ifdef __cplusplus
}
#endif
