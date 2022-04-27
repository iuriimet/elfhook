#include <stdio.h>
#include <iostream>
#include <new>
#include <vector>

#include "libtest.h"

//#ifdef __cplusplus
//extern "C"
//{
//#endif

void test_11(void)
{
    // qwe
    puts("libtest:test_11 - original puts()");
}

void test_12(void)
{
    std::cout << "libtest:test_12 - original call" << std::endl;
    int* arr = new(std::nothrow) int[5];
    if (arr) {
        std::cout << "libtest:test_12 - alloc : success" << std::endl;
        delete [] arr;
    } else {
        std::cout << "libtest:test_12 - alloc : failed" << std::endl;
    }

    // qwe
}

struct test_struct_13 {
    const char* txt;
    int val;
};
struct test_struct_14 {
    const char* txt;
};

void test_13(void)
{
    std::cout << "libtest:test_13 - original call" << std::endl;
    static const std::vector<test_struct_13> s_vec_13 = {{"1",1}};
//    static const test_struct_13 s_arr[] = {{"1",1}};
}

void test_14(void)
{
    std::cout << "libtest:test_14 - original call" << std::endl;
    static const std::vector<test_struct_14> s_vec_14 = {{"2"},{"3"}};
//    static const test_struct_13 s_arr[] = {{"1",1},{"2",2}};
}

void test_21(void)
{
    std::cout << "libtest:test_21 - original call" << std::endl;

    void* p1 = malloc(5);
    if (p1) {
        std::cout << "libtest:test_21 - malloc : success" << std::endl;
        free(p1);
    } else {
        std::cout << "libtest:test_21 - malloc : failed" << std::endl;
    }

    void* p2 = calloc(5, 5);
    if (p2) {
        std::cout << "libtest:test_21 - calloc : success" << std::endl;
        free(p2);
    } else {
        std::cout << "libtest:test_21 - calloc : failed" << std::endl;
    }
}

//#ifdef __cplusplus
//}
//#endif
