#ifndef __LIBTEST_H__
#define __LIBTEST_H__

#ifdef __cplusplus
extern "C"
{
#endif


void test_syscall_open(void);
void test_syscall_read(void);
void test_syscall_write(char c);
void test_syscall_pread(void);
void test_syscall_pwrite(void);

void test_syscall_stat(void);

void test_syscall_lseek(void);
void test_syscall_lseek64(void);

void test_syscall_mmap(void);

void test_syscall_pipe(void);

void test_syscall_dup(void);

void test_libc_malloc(void);










//void test_syscall_ioctl(void);




//void test_open_syscall(void);




//void test_11(void);

//void test_12(void);

//void test_13(void);
//void test_14(void);

//void test_21(void);



#ifdef __cplusplus
}
#endif

#endif // __LIBTEST_H__
