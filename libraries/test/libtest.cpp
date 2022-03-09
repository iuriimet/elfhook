#include <stdio.h>
#include <iostream>
#include <new>

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
    int* arr = new(std::nothrow) int[5];
    if (arr) {
        std::cout << "alloc : success" << std::endl;
        delete [] arr;
    } else {
        std::cout << "alloc : failed" << std::endl;
    }
}

//#ifdef __cplusplus
//}
//#endif
