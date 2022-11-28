#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>
#include <list>
#include <stdexcept>
#include <cassert>

#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
//#include <sys/syscall.h>
#include <unistd.h>

#include "common.h"
#include "elffuzz_def.h"
#include "elffuzz.h"
#include "libelffuzz.h"
#include "logger.h"


struct elffuzz
{
    void* obj;
};


static elffuzz_t* s_elffuzz = NULL;
static std::list<ns_elffuzz::hookData> s_syscall_hooks_data = {};
static std::list<ns_elffuzz::hookData> s_libc_hooks_data = {};
static int s_hooks_call_idx = -1;
static int s_hooks_call_cnt = 0;


static void set_syscall_hooks(elffuzz_t* obj);
static void del_syscall_hooks(elffuzz_t* obj);
static void set_libc_hooks(elffuzz_t* obj);
static void del_libc_hooks(elffuzz_t* obj);

static inline bool hook_triggered()
{
    return (s_hooks_call_idx == s_hooks_call_cnt++);
}


#define CB1(prefix, type, name, res, type1, arg1) \
    static type cb_##prefix##_##name(type1 arg1) { \
        LOG_D("ELFFUZZ : cb_%s_%s: hook_call_idx - %d, hook_call_cnt - %d", XSTR(prefix), XSTR(name), s_hooks_call_idx, s_hooks_call_cnt); \
        return (s_elffuzz && s_elffuzz->obj && hook_triggered()) ? res : name(arg1); \
    }
#define CB2(prefix, type, name, res, type1, arg1, type2, arg2) \
    static type cb_##prefix##_##name(type1 arg1, type2 arg2) { \
        LOG_D("ELFFUZZ : cb_%s_%s: hook_call_idx - %d, hook_call_cnt - %d", XSTR(prefix), XSTR(name), s_hooks_call_idx, s_hooks_call_cnt); \
        return (s_elffuzz && s_elffuzz->obj && hook_triggered()) ? res : name(arg1, arg2); \
    }
#define CB3(prefix, type, name, res, type1, arg1, type2, arg2, type3, arg3) \
    static type cb_##prefix##_##name(type1 arg1, type2 arg2, type3 arg3) { \
        LOG_D("ELFFUZZ : cb_%s_%s: hook_call_idx - %d, hook_call_cnt - %d", XSTR(prefix), XSTR(name), s_hooks_call_idx, s_hooks_call_cnt); \
        return (s_elffuzz && s_elffuzz->obj && hook_triggered()) ? res : name(arg1, arg2, arg3); \
    }
#define CB4(prefix, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
    static type cb_##prefix##_##name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
        LOG_D("ELFFUZZ : cb_%s_%s: hook_call_idx - %d, hook_call_cnt - %d", XSTR(prefix), XSTR(name), s_hooks_call_idx, s_hooks_call_cnt); \
        return (s_elffuzz && s_elffuzz->obj && hook_triggered()) ? res : name(arg1, arg2, arg3, arg4); \
    }
#define CB5(prefix, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
    static type cb_##prefix##_##name(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) { \
        LOG_D("ELFFUZZ : cb_%s_%s: hook_call_idx - %d, hook_call_cnt - %d", XSTR(prefix), XSTR(name), s_hooks_call_idx, s_hooks_call_cnt); \
        return (s_elffuzz && s_elffuzz->obj && hook_triggered()) ? res : name(arg1, arg2, arg3, arg4, arg5); \
    }
#define CB6(prefix, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
    static type cb_##prefix##_##name (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) { \
        LOG_D("ELFFUZZ : cb_%s_%s: hook_call_idx - %d, hook_call_cnt - %d", XSTR(prefix), XSTR(name), s_hooks_call_idx, s_hooks_call_cnt); \
        return (s_elffuzz && s_elffuzz->obj && hook_triggered()) ? res : name(arg1, arg2, arg3, arg4, arg5, arg6); \
    }


#define CB_SYSCALL1(type, name, res, type1, arg1) \
    CB1(syscall, type, name, res, type1, arg1)
#define CB_SYSCALL2(type, name, res, type1, arg1, type2, arg2) \
    CB2(syscall, type, name, res, type1, arg1, type2, arg2)
#define CB_SYSCALL3(type, name, res, type1, arg1, type2, arg2, type3, arg3) \
    CB3(syscall, type, name, res, type1, arg1, type2, arg2, type3, arg3)
#define CB_SYSCALL4(type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
    CB4(syscall, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4)
#define CB_SYSCALL5(type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
    CB5(syscall, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)
#define CB_SYSCALL6(type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
    CB6(syscall, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6)


CB_SYSCALL3(int, open, -1, const char*, pathname, int, flags, mode_t, mode)
CB_SYSCALL3(ssize_t, read, -1, int, fd, void*, buf, size_t, count)
CB_SYSCALL3(ssize_t, write, -1, int, fd, const void*, buf, size_t, count)
CB_SYSCALL4(ssize_t, pread, -1, int, fd, void*, buf, size_t, count, off_t, offset)
CB_SYSCALL4(ssize_t, pwrite, -1, int, fd, const void*, buf, size_t, count, off_t, offset)

CB_SYSCALL2(int, stat, -1, const char*, path, struct stat*, buf)
CB_SYSCALL3(int, __xstat, -1, int, ver, const char*, path, struct stat*, buf)
CB_SYSCALL3(int, __xstat64, -1, int, ver, const char*, path, struct stat64*, buf)
CB_SYSCALL2(int, fstat, -1, int, fd, struct stat*, buf)
CB_SYSCALL3(int, __fxstat, -1, int, ver, int, fd, struct stat*, buf)
CB_SYSCALL3(int, __fxstat64, -1, int, ver, int, fd, struct stat64*, buf)
CB_SYSCALL2(int, lstat, -1, const char*, path, struct stat*, buf)
CB_SYSCALL3(int, __lxstat, -1, int, ver, const char*, path, struct stat*, buf)
CB_SYSCALL3(int, __lxstat64, -1, int, ver, const char*, path, struct stat64*, buf)

CB_SYSCALL3(int, poll, -1, struct pollfd*, fds, nfds_t, nfds, int, timeout)
CB_SYSCALL4(int, ppoll, -1, struct pollfd*, fds, nfds_t, nfds, const struct timespec*, tmo_p, const sigset_t*, sigmask)

CB_SYSCALL3(off_t, lseek, -1, int, fd, off_t, offset, int, whence)
CB_SYSCALL3(off64_t, lseek64, -1, int, fd, off64_t, offset, int, whence)

CB_SYSCALL6(void*, mmap, NULL, void*, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)
CB_SYSCALL3(int, mprotect, -1, void*, addr, size_t, len, int, prot)
CB_SYSCALL5(void*, mremap, NULL, void*, old_address, size_t, old_size, size_t, new_size, int, flags, void*, new_address)
CB_SYSCALL3(int, msync, -1, void*, addr, size_t, length, int, flags)

CB_SYSCALL3(int, sigaction, -1, int, signum, const struct sigaction*, act, struct sigaction*, oldact)

CB_SYSCALL3(int, ioctl, -1, int, fd, int, cmd, void*, arg)

CB_SYSCALL1(int, pipe, -1, int*, pipefd)
CB_SYSCALL2(int, pipe2, -1, int*, pipefd, int, flags)

CB_SYSCALL1(int, dup, -1, int, oldfd)
CB_SYSCALL2(int, dup2, -1, int, oldfd, int, newfd)
CB_SYSCALL3(int, dup3, -1, int, oldfd, int, newfd, int, flags)

CB_SYSCALL3(int, socket, -1, int, domain, int, type, int, protocol)
CB_SYSCALL3(int, bind, -1, int, sockfd, const struct sockaddr*, addr, socklen_t, addrlen)
CB_SYSCALL2(int, listen, -1, int, sockfd, int, backlog)
CB_SYSCALL3(int, connect, -1, int, sockfd, const struct sockaddr*, addr, socklen_t, addrlen)
CB_SYSCALL3(int, accept, -1, int, sockfd, struct sockaddr*, addr, socklen_t*, addrlen)
CB_SYSCALL4(int, accept4, -1, int, sockfd, struct sockaddr*, addr, socklen_t*, addrlen, int, flags)
CB_SYSCALL4(ssize_t, send, -1, int, sockfd, const void*, buf, size_t, len, int, flags)
CB_SYSCALL6(ssize_t, sendto, -1, int, sockfd, const void*, buf, size_t, len, int, flags, const struct sockaddr*, dest_addr, socklen_t, addrlen)
CB_SYSCALL3(ssize_t, sendmsg, -1, int, sockfd, const struct msghdr*, msg, int, flags)
CB_SYSCALL4(int, sendmmsg, -1, int, sockfd, struct mmsghdr*, msgvec, unsigned int, vlen, int, flags)
CB_SYSCALL4(ssize_t, sendfile, -1, int, out_fd, int, in_fd, off_t*, offset, size_t, count)
CB_SYSCALL4(ssize_t, recv, -1, int, sockfd, void*, buf, size_t, len, int, flags)
CB_SYSCALL6(ssize_t, recvfrom, -1, int, sockfd, void*, buf, size_t, len, int, flags, struct sockaddr*, src_addr, socklen_t*, addrlen)
CB_SYSCALL3(ssize_t, recvmsg, -1, int, sockfd, struct msghdr*, msg, int, flags)
CB_SYSCALL5(int, recvmmsg, -1, int, sockfd, struct mmsghdr*, msgvec, unsigned int, vlen, unsigned int, flags, struct timespec*, timeout)
CB_SYSCALL3(int, getsockname, -1, int, sockfd, struct sockaddr*, addr, socklen_t*, addrlen)
CB_SYSCALL3(int, getpeername, -1, int, sockfd, struct sockaddr*, addr, socklen_t*, addrlen)
CB_SYSCALL5(int, getsockopt, -1, int, sockfd, int, level, int, optname, void*, optval, socklen_t*, optlen)
CB_SYSCALL5(int, setsockopt, -1, int, sockfd, int, level, int, optname, const void*, optval, socklen_t, optlen)
CB_SYSCALL4(int, socketpair, -1, int, domain, int, type, int, protocol, int*, sv)

CB_SYSCALL3(int, semget, -1, key_t, key, int, nsems, int, semflg)
CB_SYSCALL3(int, semop, -1, int, semid, struct sembuf*, sops, unsigned, nsops)
CB_SYSCALL4(int, semtimedop, -1, int, semid, struct sembuf*, sops, unsigned, nsops, struct timespec*, timeout)
CB_SYSCALL4(int, semctl, -1, int, semid, int, semnum, int, cmd, unsigned long, arg)

CB_SYSCALL3(void*, shmat, NULL, int, shmid, const void*, shmaddr, int, shmflg)

CB_SYSCALL2(int, msgget, -1, key_t, key, int, msgflg)
CB_SYSCALL4(int, msgsnd, -1, int, msqid, const void*, msgp, size_t, msgsz, int, msgflg)
CB_SYSCALL5(ssize_t, msgrcv, -1, int, msqid, void*, msgp, size_t, msgsz, long, msgtyp, int, msgflg)
CB_SYSCALL3(int, msgctl, -1, int, msqid, int, cmd, struct msqid_ds*, buf)

//[ 72] = { 3,	TD,		SEN(fcntl),			"fcntl"			},
//[ 73] = { 2,	TD,		SEN(flock),			"flock"			},
//[ 74] = { 1,	TD,		SEN(fsync),			"fsync"			},
//[ 75] = { 1,	TD,		SEN(fdatasync),			"fdatasync"		},
//[ 76] = { 2,	TF,		SEN(truncate),			"truncate"		},
//[ 77] = { 2,	TD,		SEN(ftruncate),			"ftruncate"		},
//SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
//int fcntl(int fd, int cmd, ... /* arg */ );



static const std::list<ns_elffuzz::hookProcInfo> s_syscall_hooks_info = {
    {"open", (const void*)cb_syscall_open},
    {"read", (const void*)cb_syscall_read},
    {"write", (const void*)cb_syscall_write},
    {"pread", (const void*)cb_syscall_pread},
    {"pwrite", (const void*)cb_syscall_pwrite},

    {"stat", (const void*)cb_syscall_stat},
    {"__xstat", (const void*)cb_syscall___xstat},
    {"__xstat64", (const void*)cb_syscall___xstat64},
    {"fstat", (const void*)cb_syscall_fstat},
    {"__fxstat", (const void*)cb_syscall___fxstat},
    {"__fxstat64", (const void*)cb_syscall___fxstat64},
    {"lstat", (const void*)cb_syscall_lstat},
    {"__lxstat", (const void*)cb_syscall___lxstat},
    {"__lxstat64", (const void*)cb_syscall___lxstat64},

    {"poll", (const void*)cb_syscall_poll},
    {"ppoll", (const void*)cb_syscall_ppoll},

    {"lseek", (const void*)cb_syscall_lseek},
    {"lseek64", (const void*)cb_syscall_lseek64},

    {"mmap", (const void*)cb_syscall_mmap},
    {"mprotect", (const void*)cb_syscall_mprotect},
    {"mremap", (const void*)cb_syscall_mremap},
    {"msync", (const void*)cb_syscall_msync},

    {"sigaction", (const void*)cb_syscall_sigaction},

    {"ioctl", (const void*)cb_syscall_ioctl},

    {"pipe", (const void*)cb_syscall_pipe},
    {"pipe2", (const void*)cb_syscall_pipe2},

    {"dup", (const void*)cb_syscall_dup},
    {"dup2", (const void*)cb_syscall_dup2},
    {"dup3", (const void*)cb_syscall_dup3},

    {"socket", (const void*)cb_syscall_socket},
    {"bind", (const void*)cb_syscall_bind},
    {"listen", (const void*)cb_syscall_listen},
    {"connect", (const void*)cb_syscall_connect},
    {"accept", (const void*)cb_syscall_accept},
    {"accept4", (const void*)cb_syscall_accept4},
    {"send", (const void*)cb_syscall_send},
    {"sendto", (const void*)cb_syscall_sendto},
    {"sendmsg", (const void*)cb_syscall_sendmsg},
    {"sendmmsg", (const void*)cb_syscall_sendmmsg},
    {"sendfile", (const void*)cb_syscall_sendfile},
    {"recv", (const void*)cb_syscall_recv},
    {"recvfrom", (const void*)cb_syscall_recvfrom},
    {"recvmsg", (const void*)cb_syscall_recvmsg},
    {"recvmmsg", (const void*)cb_syscall_recvmmsg},
    {"getsockname", (const void*)cb_syscall_getsockname},
    {"getpeername", (const void*)cb_syscall_getpeername},
    {"getsockopt", (const void*)cb_syscall_getsockopt},
    {"setsockopt", (const void*)cb_syscall_setsockopt},
    {"socketpair", (const void*)cb_syscall_socketpair},

    {"semget", (const void*)cb_syscall_semget},
    {"semop", (const void*)cb_syscall_semop},
    {"semtimedop", (const void*)cb_syscall_semtimedop},
    {"semctl", (const void*)cb_syscall_semctl},

    {"shmat", (const void*)cb_syscall_shmat},

    {"msgget", (const void*)cb_syscall_msgget},
    {"msgsnd", (const void*)cb_syscall_msgsnd},
    {"msgrcv", (const void*)cb_syscall_msgrcv},
    {"msgctl", (const void*)cb_syscall_msgctl},

};
// readv, preadv, preadv2 and writev ...
// epoll
// fseek
// syscall


#define CB_LIBC1(type, name, res, type1, arg1) \
    CB1(libc, type, name, res, type1, arg1)
#define CB_LIBC2(type, name, res, type1, arg1, type2, arg2) \
    CB2(libc, type, name, res, type1, arg1, type2, arg2)
#define CB_LIBC3(type, name, res, type1, arg1, type2, arg2, type3, arg3) \
    CB3(libc, type, name, res, type1, arg1, type2, arg2, type3, arg3)
#define CB_LIBC4(type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
    CB4(libc, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4)
#define CB_LIBC5(type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
    CB5(libc, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)
#define CB_LIBC6(type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
    CB6(libc, type, name, res, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6)


CB_LIBC1(void*, malloc, NULL, size_t, size)
CB_LIBC2(void*, calloc, NULL, size_t, nmemb, size_t, size)
CB_LIBC2(void*, realloc, NULL, void*, ptr, size_t, size)

CB_LIBC2(FILE*, fopen, NULL, const char*, path, const char*, mode)
CB_LIBC4(size_t, fread, 0, void*, ptr, size_t, size, size_t, nmemb, FILE*, stream)
CB_LIBC4(size_t, fwrite, 0, const void*, ptr, size_t, size, size_t, nmemb, FILE*, stream)
CB_LIBC1(int, fgetc, EOF, FILE*, stream)
CB_LIBC3(char*, fgets, NULL, char*, s, int, size, FILE*, stream)
CB_LIBC1(char*, strdup, NULL, const char*, s)
CB_LIBC2(const char*, strchr, NULL, const char*, s, int, c)


static const std::list<ns_elffuzz::hookProcInfo> s_libc_hooks_info = {
    {"malloc", (const void*)cb_libc_malloc},
    {"calloc", (const void*)cb_libc_calloc},
    {"realloc", (const void*)cb_libc_realloc},

    {"fopen", (const void*)cb_libc_fopen},
    {"fread", (const void*)cb_libc_fread},
    {"fwrite", (const void*)cb_libc_fwrite},
    {"fgetc", (const void*)cb_libc_fgetc},
    {"fgets", (const void*)cb_libc_fgets},
    {"strdup", (const void*)cb_libc_strdup},
    {"strchr", (const void*)cb_libc_strchr},
};
// ZZZ
// strtok
// strtok_r



//elffuzz_t* elffuzz_init(const char* so_name, const char* proc_name)
//{
//    LOG_D("ELFFUZZ : elffuzz_init : so_name = %s, proc_name = %s", so_name, proc_name);
//    if (!s_elffuzz) {
//        try {
//            s_elffuzz = new elffuzz_t();
//            s_elffuzz->obj = proc_name ?
//                        new ns_elffuzz::ElfFuzz(so_name, proc_name) :
//                        new ns_elffuzz::ElfFuzz(so_name);
//        } catch (const std::exception& e) {
//            LOG_E("%s", e.what());
//            elffuzz_done(s_elffuzz);
//        }
//    }
//    return s_elffuzz;
//}
elffuzz_t* elffuzz_init(void)
{
    LOG_D("ELFFUZZ : elffuzz_init");
    if (!s_elffuzz) {
        try {
            s_elffuzz = new elffuzz_t();
            s_elffuzz->obj = new ns_elffuzz::ElfFuzz();
        } catch (const std::exception& e) {
            LOG_E("%s", e.what());
            elffuzz_done(s_elffuzz);
        }
    }
    return s_elffuzz;
}
void elffuzz_done(elffuzz_t* obj)
{
    LOG_D("ELFFUZZ : elffuzz_done");
    if (obj) {
        if (obj->obj) {
            delete static_cast<ns_elffuzz::ElfFuzz*>(obj->obj);
            obj->obj = NULL;
        }
        delete obj;
        s_elffuzz = NULL;
    }
}

void elffuzz_set_hooks(elffuzz_t* obj, int hook_call_idx)
{
    LOG_D("ELFFUZZ : elffuzz_set_hooks : hook_call_idx = %d", hook_call_idx);
    if (obj && obj->obj) {
        set_syscall_hooks(obj);
        set_libc_hooks(obj);
        s_hooks_call_idx = hook_call_idx;
        s_hooks_call_cnt = 0;
    }
}
void elffuzz_del_hooks(elffuzz_t* obj)
{
    LOG_D("ELFFUZZ : elffuzz_del_syscall_hooks");
    if (obj && obj->obj) {
        del_libc_hooks(obj);
        del_syscall_hooks(obj);
        s_hooks_call_idx = -1;
    }
}

static void set_syscall_hooks(elffuzz_t* obj)
{
    if (obj && obj->obj) {
        if (ns_elffuzz::ElfFuzz::isHookInstalled(s_syscall_hooks_data)) {
            del_syscall_hooks(obj);
        }
        s_syscall_hooks_data = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setHooks(s_syscall_hooks_info);
    }
}
static void del_syscall_hooks(elffuzz_t* obj)
{
    if (obj && obj->obj) {
        (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->delHooks(s_syscall_hooks_data);
        s_syscall_hooks_data.clear();
    }
}
static void set_libc_hooks(elffuzz_t* obj)
{
    if (obj && obj->obj) {
        if (ns_elffuzz::ElfFuzz::isHookInstalled(s_libc_hooks_data)) {
            del_libc_hooks(obj);
        }
        s_libc_hooks_data = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setHooks(s_libc_hooks_info);
    }
}
static void del_libc_hooks(elffuzz_t* obj)
{
    if (obj && obj->obj) {
        (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->delHooks(s_libc_hooks_data);
        s_libc_hooks_data.clear();
    }
}
