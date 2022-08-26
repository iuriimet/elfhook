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


// ZZZ
//static bool syscall_hook_triggered()
//{
//    assert(s_elffuzz);
//    assert(s_elffuzz->obj);
//    return ((static_cast<ns_elffuzz::ElfFuzz*>(s_elffuzz->obj))->checkCallStack() &&
//            (s_syscall_hooks_call_idx == s_syscall_hooks_call_cnt++));
//}
static bool syscall_hook_triggered()
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    return (s_syscall_hooks_call_idx == s_syscall_hooks_call_cnt++);
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


elffuzz_t* elffuzz_init(const char* so_name, const char* proc_name)
{
    LOG_D("ELFFUZZ : elffuzz_init : so_name = %s, proc_name = %s", so_name, proc_name);
    if (!s_elffuzz) {
        try {
            s_elffuzz = new elffuzz_t();
            s_elffuzz->obj = proc_name ?
                        new ns_elffuzz::ElfFuzz(so_name, proc_name) :
                        new ns_elffuzz::ElfFuzz(so_name);
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
