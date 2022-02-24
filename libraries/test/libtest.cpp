#include <stdio.h>
#include <iostream>

#include "libtest.h"

//#ifdef __cplusplus
//extern "C"
//{
//#endif

void test(void)
{
    puts("libtest:test - original puts()");
}

void test_2(void)
{
    std::cout << "libtest:test_2 - original call" << std::endl;
    int* arr = new int[5];
    delete [] arr;
}

//#ifdef __cplusplus
//}
//#endif
