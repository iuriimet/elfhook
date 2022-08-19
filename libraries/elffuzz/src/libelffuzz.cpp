#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>
#include <list>
#include <stdexcept>
#include <cassert>

#include <fcntl.h>
#include <unistd.h>

#include "elffuzz_def.h"
#include "elffuzz.h"
#include "libelffuzz.h"

#include "logger.h"


struct elffuzz
{
    void* obj;
};


static int cb_syscall_open(const char* pathname, int flags, mode_t mode = 0);
static int cb_syscall_close(int fd);
static ssize_t cb_syscall_read(int fd, void* buf, size_t count);
static ssize_t cb_syscall_write(int fd, const void* buf, size_t count);


static elffuzz_t* s_elffuzz = NULL;

static const std::list<ns_elffuzz::hookProcInfo> s_syscall_hooks_info = {
    {"open", (const void*)cb_syscall_open},
    {"close", (const void*)cb_syscall_close},
    {"read", (const void*)cb_syscall_read},
    {"write", (const void*)cb_syscall_write},
};
static std::list<ns_elffuzz::hookData> s_syscall_hooks_data = {};
static int s_syscall_hooks_call_idx = -1;
static int s_syscall_hooks_call_cnt = 0;


static bool syscall_hook_triggered()
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    return ((static_cast<ns_elffuzz::ElfFuzz*>(s_elffuzz->obj))->checkCallStack() &&
            (s_syscall_hooks_call_idx == s_syscall_hooks_call_cnt++));
}

static int cb_syscall_open(const char* pathname, int flags, mode_t mode)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_syscall_open: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? -1 : open(pathname, flags, mode);
}
static int cb_syscall_close(int fd)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_syscall_close: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? -1 : close(fd);
}
static ssize_t cb_syscall_read(int fd, void* buf, size_t count)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_syscall_read: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? -1 : read(fd, buf, count);
}
static ssize_t cb_syscall_write(int fd, const void* buf, size_t count)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_syscall_write: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? -1 : write(fd, buf, count);
}





/*
static long elffuzz_syscall_hook_cb(long number, ...)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : elffuzz_syscall_hook_cb: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hook_call_idx, s_syscall_hook_call_cnt);
    return ((static_cast<ns_elffuzz::ElfFuzz*>(s_elffuzz->obj))->checkCallStack() &&
            (s_syscall_hook_call_idx == s_syscall_hook_call_cnt++)) ? -1 : syscall(number);
}
*/


//struct syscall
//{
//    const char* name;
//    const void* hook_proc_add;
//    const void* orig_proc_addr;
//};

//enum
//{
//    SYSCALL_OPEN_IDX = 0,
//    SYSCALL_CLOSE_IDX,
//    SYSCALL_READ_IDX,
//    SYSCALL_WRITE_IDX,
//};


//typedef int (*fp_syscall_open_t)(const char*, int, mode_t);
//typedef int (*fp_syscall_close_t)(int);
//typedef ssize_t (*fp_syscall_read_t)(int, void*, size_t);
//typedef ssize_t (*fp_syscall_write_t)(int, const void*, size_t);


//static int elffuzz_syscall_open_hook(const char* pathname, int flags, mode_t mode = 0);
//static int elffuzz_syscall_close_hook(int fd);
//static ssize_t elffuzz_syscall_read_hook(int fd, void* buf, size_t count);
//static ssize_t elffuzz_syscall_write_hook(int fd, const void* buf, size_t count);


//static elffuzz_t* s_elffuzz = NULL;
//static syscall s_syscalls[] =
//{
//    {"open", (const void*)elffuzz_syscall_open_hook, NULL},
//    {"close", (const void*)elffuzz_syscall_close_hook, NULL},
//    {"read", (const void*)elffuzz_syscall_read_hook, NULL},
//    {"write", (const void*)elffuzz_syscall_write_hook, NULL},
//};
//static int s_syscall_hook_call_idx = -1;
//static int s_syscall_hook_call_cnt = 0;


//static bool syscall_hook_triggered()
//{
//    return ((static_cast<ns_elffuzz::ElfFuzz*>(s_elffuzz->obj))->checkCallStack() &&
//            (s_syscall_hook_call_idx == s_syscall_hook_call_cnt++));
//}

//static int elffuzz_syscall_open_hook(const char* pathname, int flags, mode_t mode)
//{
//    assert(s_elffuzz);
//    assert(s_elffuzz->obj);
//    assert(s_syscalls[SYSCALL_OPEN_IDX].orig_proc_addr);
//    LOG_D("ELFFUZZ : elffuzz_syscall_open_hook: orig_proc_addr - %p, syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
//          s_syscalls[SYSCALL_OPEN_IDX].orig_proc_addr, s_syscall_hook_call_idx, s_syscall_hook_call_cnt);
//    return syscall_hook_triggered() ? -1 : (((fp_syscall_open_t)s_syscalls[SYSCALL_OPEN_IDX].orig_proc_addr)(pathname, flags, mode));
//}
//static int elffuzz_syscall_close_hook(int fd)
//{
//    assert(s_elffuzz);
//    assert(s_elffuzz->obj);
//    assert(s_syscalls[SYSCALL_CLOSE_IDX].orig_proc_addr);
//    LOG_D("ELFFUZZ : elffuzz_syscall_close_hook: orig_proc_addr - %p, syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
//          s_syscalls[SYSCALL_CLOSE_IDX].orig_proc_addr, s_syscall_hook_call_idx, s_syscall_hook_call_cnt);
//    return syscall_hook_triggered() ? -1 : (((fp_syscall_close_t)s_syscalls[SYSCALL_CLOSE_IDX].orig_proc_addr)(fd));
//}
//static ssize_t elffuzz_syscall_read_hook(int fd, void* buf, size_t count)
//{
//    assert(s_elffuzz);
//    assert(s_elffuzz->obj);
//    assert(s_syscalls[SYSCALL_READ_IDX].orig_proc_addr);
//    LOG_D("ELFFUZZ : elffuzz_syscall_read_hook: orig_proc_addr - %p, syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
//          s_syscalls[SYSCALL_READ_IDX].orig_proc_addr, s_syscall_hook_call_idx, s_syscall_hook_call_cnt);
//    return syscall_hook_triggered() ? -1 : (((fp_syscall_read_t)s_syscalls[SYSCALL_READ_IDX].orig_proc_addr)(fd, buf, count));
//}
//static ssize_t elffuzz_syscall_write_hook(int fd, const void* buf, size_t count)
//{
//    assert(s_elffuzz);
//    assert(s_elffuzz->obj);
//    assert(s_syscalls[SYSCALL_WRITE_IDX].orig_proc_addr);
//    LOG_D("ELFFUZZ : elffuzz_syscall_write_hook: orig_proc_addr - %p, syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
//          s_syscalls[SYSCALL_WRITE_IDX].orig_proc_addr, s_syscall_hook_call_idx, s_syscall_hook_call_cnt);
//    return syscall_hook_triggered() ? -1 : (((fp_syscall_write_t)s_syscalls[SYSCALL_WRITE_IDX].orig_proc_addr)(fd, buf, count));
//}






elffuzz_t* elffuzz_init(const char* so_name, const char* proc_name)
{
    LOG_D("ELFFUZZ : elffuzz_init : so_name = %s, proc_name = %s", so_name, proc_name);
    if (!s_elffuzz) {
        try {
            s_elffuzz = new elffuzz_t();
            s_elffuzz->obj = new ns_elffuzz::ElfFuzz(so_name, proc_name);
        } catch (const std::exception& e) {
            LOG_E("%s", e.what());
            elffuzz_done(s_elffuzz);
            s_elffuzz = NULL;
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
    }
}

void elffuzz_set_syscall_hooks(elffuzz_t* obj, int hook_call_idx)
{
    LOG_D("ELFFUZZ : elffuzz_set_syscall_hooks : hook_call_idx = %d", hook_call_idx);
    if (obj && obj->obj) {
        if (ns_elffuzz::ElfFuzz::isHookInstalled(s_syscall_hooks_data)) {
            elffuzz_del_syscall_hooks(obj);
        }
        s_syscall_hooks_data = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setHooks(s_syscall_hooks_info);
        s_syscall_hooks_call_idx = hook_call_idx;
        s_syscall_hooks_call_cnt = 0;
    }
}
void elffuzz_del_syscall_hooks(elffuzz_t* obj)
{
    LOG_D("ELFFUZZ : elffuzz_del_syscall_hooks");
    if (obj && obj->obj) {
        (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->delHooks(s_syscall_hooks_data);
        s_syscall_hooks_data.clear();
        s_syscall_hooks_call_idx = -1;
    }
}









/*
bool elffuzz_set_syscall_hook(elffuzz_t* obj, int hook_call_idx)
{
    LOG_D("ELFFUZZ : elffuzz_set_syscall_hooks : hook_call_idx = %d", hook_call_idx);
    if (obj && obj->obj) {
        if ((static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setHook("syscall", (const void*)elffuzz_syscall_hook_cb)) {
            s_syscall_hook_call_idx = hook_call_idx;
            s_syscall_hook_call_cnt = 0;
            return true;
        }
    }
    return false;
}
void elffuzz_del_syscall_hook(elffuzz_t* obj)
{
    LOG_D("ELFFUZZ : elffuzz_del_syscall_hook");
    if (obj && obj->obj) (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->delHook();
    s_syscall_hook_call_idx = -1;
}
*/




//bool elffuzz_set_syscall_hooks(elffuzz_t* obj, int hook_call_idx)
//{
//    bool res = false;
//    LOG_D("ELFFUZZ : elffuzz_set_syscall_hooks : hook_call_idx = %d", hook_call_idx);
//    if (obj && obj->obj) {
//        for (syscall& it : s_syscalls) {
//            LOG_D("ELFFUZZ : elffuzz_set_syscall_hooks : name = %s", it.name);
//            if (!it.orig_proc_addr) {
//                if ((it.orig_proc_addr = (static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setHook(it.name, it.hook_proc_add))) {
//                    LOG_D("ELFFUZZ : elffuzz_set_syscall_hooks : name = %s : OK", it.name);
//                    res = true;
//                } else {
//                    LOG_D("ELFFUZZ : elffuzz_set_syscall_hooks : name = %s : ERR", it.name);
//                }
//            } else {
//                LOG_D("ELFFUZZ : elffuzz_set_syscall_hooks : name = %s : hook already installed", it.name);
//            }
//        }
//        if (res) {
//            s_syscall_hook_call_idx = hook_call_idx;
//            s_syscall_hook_call_cnt = 0;
//        }
//    }
//    return res;
//}
//void elffuzz_rem_syscall_hooks(elffuzz_t* obj)
//{
//    LOG_D("ELFFUZZ : elffuzz_rem_syscall_hooks");
//    if (obj && obj->obj) {
//        for (syscall& it : s_syscalls) {
//            if (it.orig_proc_addr) {
//                LOG_D("ELFFUZZ : elffuzz_rem_syscall_hooks : name = %s", it.name);
//                if ((static_cast<ns_elffuzz::ElfFuzz*>(obj->obj))->setHook(it.name, it.orig_proc_addr)) {
//                    LOG_D("ELFFUZZ : elffuzz_rem_syscall_hooks : name = %s : OK", it.name);
//                    it.orig_proc_addr = NULL;
//                } else {
//                    LOG_D("ELFFUZZ : elffuzz_rem_syscall_hooks : name = %s : ERR", it.name);
//                }
//            }
//        }
//        s_syscall_hook_call_idx = -1;
//    }
//}
