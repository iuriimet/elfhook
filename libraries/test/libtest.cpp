#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>
#include <new>
#include <vector>
#include <errno.h>

#include "libtest.h"

//#ifdef __cplusplus
//extern "C"
//{
//#endif


static const char* s_test_file_path_name = "/home/iuriim/tmp/qwe.txt";


void test_syscall_open(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_open: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) close(fd);
}
void test_syscall_read(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_read: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        char rc;
        int rr = read(fd, &rc, 1);
        std::cout << "ZZZ ========================= test_syscall_read: READ RESULT : " << rr << std::endl;
        if (rr != -1)
            std::cout << "ZZZ ========================= test_syscall_read: READ CONTENT : " << rc << std::endl;
        close(fd);
    }
}
void test_syscall_write(char c)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_write: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        int rr = write(fd, &c, 1);
        std::cout << "ZZZ ========================= test_syscall_write: WRITE RESULT : " << rr << std::endl;
        close(fd);
    }
}
void test_syscall_pread(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_pread: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        char buf[4];
        ssize_t rr = pread(fd, buf, sizeof(buf), 0);
        std::cout << "ZZZ ========================= test_syscall_pread: PREAD RESULT : " << rr << std::endl;
        close(fd);
    }
}
void test_syscall_pwrite(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_pwrite: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        const char* buf = "qwe";
        ssize_t rr = pwrite(fd, buf, strlen(buf), 0);
        std::cout << "ZZZ ========================= test_syscall_pwrite: PWRITE RESULT : " << rr << std::endl;
        close(fd);
    }
}

void test_syscall_stat(void)
{
    struct stat sb;
    int r = stat(s_test_file_path_name, &sb);
    std::cout << "ZZZ ========================= test_syscall_stat: RESULT : " << r << std::endl;
    if (r != -1) {
        std::cout << "ZZZ ========================= test_syscall_stat: UID:GID " << sb.st_uid << " : " << sb.st_gid << std::endl;
    }
}

void test_syscall_lseek(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_lseek: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        off_t sr = lseek(fd, 1, SEEK_SET);
        std::cout << "ZZZ ========================= test_syscall_lseek: SEEK RESULT : " << sr << std::endl;
        close(fd);
    }
}
void test_syscall_lseek64(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_lseek64: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        off_t sr = lseek64(fd, 1, SEEK_SET);
        std::cout << "ZZZ ========================= test_syscall_lseek64: SEEK RESULT : " << sr << std::endl;
        close(fd);
    }
}

void test_syscall_mmap(void)
{
    int fd = open(s_test_file_path_name, O_RDONLY);
    std::cout << "ZZZ ========================= test_syscall_mmap: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        struct stat sb;
        int sr = fstat(fd, &sb);
        std::cout << "ZZZ ========================= test_syscall_mmap: FSTAT RESULT : " << sr << std::endl;
        if (sr != -1) {
            off_t offset = 0;
            off_t pa_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
            size_t length = sb.st_size - offset;
            void* mr = mmap(NULL, length + offset - pa_offset, PROT_READ, MAP_PRIVATE, fd, pa_offset);
            std::cout << "ZZZ ========================= test_syscall_mmap: MMAP RESULT : " << mr << std::endl;
            if (mr) {
                munmap(mr, length + offset - pa_offset);
            }
        }
        close(fd);
    }
}

void test_syscall_pipe(void)
{
    int fd[2];
    int pr = pipe(fd);
    std::cout << "ZZZ ========================= test_syscall_pipe: PIPE RESULT : " << pr << std::endl;

//    if (pr != -1) {
//        pid_t pid = fork();
//        std::cout << "ZZZ ========================= test_syscall_pipe: FORK RESULT : " << pid << std::endl;

//        switch (pid) {
//        case -1:
//            break;
//        case 0:
//            {
//                const char* str = "qwe";
//                close(fd[0]);
//                int wr = write(fd[1], str, (strlen(str)+1));
//                std::cout << "ZZZ ========================= test_syscall_pipe: WRITE RESULT : " << wr << std::endl;
//            }
//            break;
//        default:
//            {
//                char buf[16];
//                close(fd[1]);
//                int rr = read(fd[0], buf, sizeof(buf));
//                std::cout << "ZZZ ========================= test_syscall_pipe: READ RESULT : " << rr << " : " << buf << std::endl;
//                int stat;
//                waitpid(pid, &stat, 0);
//            }
//            break;
//        }
//    }
}

void test_syscall_dup(void)
{
    int fd = open(s_test_file_path_name, O_RDWR);
    std::cout << "ZZZ ========================= test_syscall_dup: OPEN RESULT : " << fd << std::endl;
    if (fd != -1) {
        int dup_fd = dup(fd);
        std::cout << "ZZZ ========================= test_syscall_dup: DUP RESULT : " << dup_fd << std::endl;
        close(fd);
        close(dup_fd);
    }
}

void test_libc_malloc(void)
{
    void* ptr = malloc(4);
    std::cout << "ZZZ ========================= test_libc_malloc: MALLOC RESULT : " << ptr << std::endl;
    if (ptr) free(ptr);
}








//#define MY_IOCTL _IOWR('a', 1, int)
//#define RD_VALUE _IOR('a', 'b', int*)
//void test_syscall_ioctl(void)
//{
//    int fd = open("/dev/random", O_RDWR);
//    std::cout << "ZZZ ========================= test_syscall_ioctl: OPEN RESULT : " << fd << std::endl;
//    if (fd != -1) {
//        int wv = 1;
//        int rr = ioctl(fd, MY_IOCTL, wv);
//        std::cout << "ZZZ ========================= test_syscall_ioctl: IOCTL 1 RESULT : " << rr << " : " << errno << std::endl;
////        int rv = 0;
////        rr = ioctl(fd, RD_VALUE, (int*)&rv);
////        std::cout << "ZZZ ========================= test_syscall_ioctl: IOCTL 2 RESULT : " << rr << std::endl;
//        close(fd);
//    }
//}




//void test_open_syscall(void)
//{
//    pid_t tid = syscall(SYS_gettid);
//    std::cout << "ZZZ ========================= test_open_syscall: tid : " << tid << std::endl;
//    /*
//    int fd = open(s_test_file_path_name, O_RDWR);
//    std::cout << "ZZZ ========================= test_open_close: OPEN RESULT : " << fd << std::endl;
//    if (fd != -1) {
//        int rr = close(fd);
//        std::cout << "ZZZ ========================= test_open_close: CLOSE RESULT : " << rr << std::endl;
//    }
//    */
//}








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
