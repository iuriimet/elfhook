#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <new>
#include <vector>

#include "libtest.h"

//#ifdef __cplusplus
//extern "C"
//{
//#endif


static const char* s_test_file_path_name = "/home/iuriim/tmp/qwe.txt";

void test_open_close(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_open_close: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        int rr = close(fd);
        std::cout << "ZZZ ========================= test_open_close: CLOSE RESULT : " << rr << std::endl;
    }
}
void test_read(void)
{
    char c;
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_read: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        int rr = read(fd, &c, 1);
        std::cout << "ZZZ ========================= test_read: READ RESULT : " << rr << std::endl;
        if (rr != -1)
            std::cout << "ZZZ ========================= test_read: READ CONTENT : " << c << std::endl;
        rr = close(fd);
        std::cout << "ZZZ ========================= test_read: CLOSE RESULT : " << rr << std::endl;
    }
}
void test_write(char c)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_write: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        int rr = write(fd, &c, 1);
        std::cout << "ZZZ ========================= test_write: WRITE RESULT : " << rr << std::endl;
        rr = close(fd);
        std::cout << "ZZZ ========================= test_write: CLOSE RESULT : " << rr << std::endl;
    }
}






//void test_11(void)
//{
//    // qwe
//    puts("libtest:test_11 - original puts()");
//}

//void test_12(void)
//{
//    std::cout << "libtest:test_12 - original call" << std::endl;
//    int* arr = new(std::nothrow) int[5];
//    if (arr) {
//        std::cout << "libtest:test_12 - alloc : success" << std::endl;
//        delete [] arr;
//    } else {
//        std::cout << "libtest:test_12 - alloc : failed" << std::endl;
//    }

//    // qwe
//}

//struct test_struct_13 {
//    const char* txt;
//    int val;
//};
//struct test_struct_14 {
//    const char* txt;
//};

//void test_13(void)
//{
//    std::cout << "libtest:test_13 - original call" << std::endl;
//    static const std::vector<test_struct_13> s_vec_13 = {{"1",1}};
////    static const test_struct_13 s_arr[] = {{"1",1}};
//}

//void test_14(void)
//{
//    std::cout << "libtest:test_14 - original call" << std::endl;
//    static const std::vector<test_struct_14> s_vec_14 = {{"2"},{"3"}};
////    static const test_struct_13 s_arr[] = {{"1",1},{"2",2}};
//}

//void test_21(void)
//{
//    std::cout << "libtest:test_21 - original call" << std::endl;

//    void* p1 = malloc(5);
//    if (p1) {
//        std::cout << "libtest:test_21 - malloc : success" << std::endl;
//        free(p1);
//    } else {
//        std::cout << "libtest:test_21 - malloc : failed" << std::endl;
//    }

//    void* p2 = calloc(5, 5);
//    if (p2) {
//        std::cout << "libtest:test_21 - calloc : success" << std::endl;
//        free(p2);
//    } else {
//        std::cout << "libtest:test_21 - calloc : failed" << std::endl;
//    }
//}

//#ifdef __cplusplus
//}
//#endif
