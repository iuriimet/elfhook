#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>
#include <list>
#include <stdexcept>
#include <cassert>

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "elffuzz_def.h"
#include "elffuzz.h"
#include "libelffuzz.h"

#include "logger.h"


struct elffuzz
{
    void* obj;
};

static bool syscall_hook_triggered();

static int cb_syscall_open(const char* pathname, int flags, mode_t mode = 0);
static int cb_syscall_close(int fd);
static ssize_t cb_syscall_read(int fd, void* buf, size_t count);
static ssize_t cb_syscall_write(int fd, const void* buf, size_t count);

static void* cb_malloc(size_t size);
static void* cb_calloc(size_t nmemb, size_t size);
static void* cb_realloc(void* ptr, size_t size);

static FILE* cb_fopen(const char* pathname, const char* mode);
static int cb_fclose(FILE* stream);
static size_t cb_fread(void* ptr, size_t size, size_t nmemb, FILE* stream);
static int cb_fgetc(FILE* stream);
static char* cb_fgets(char* s, int n, FILE* stream);

static char* cb_strdup(const char* s);
static const char* cb_strchr(const char* s, int c);


static elffuzz_t* s_elffuzz = NULL;

static const std::list<ns_elffuzz::hookProcInfo> s_syscall_hooks_info = {
    {"open", (const void*)cb_syscall_open},
    {"close", (const void*)cb_syscall_close},
    {"read", (const void*)cb_syscall_read},
    {"write", (const void*)cb_syscall_write},
    {"malloc", (const void*)cb_malloc},
    {"calloc", (const void*)cb_calloc},
    {"realloc", (const void*)cb_realloc},
    {"fopen", (const void*)cb_fopen},
    {"fclose", (const void*)cb_fclose},
    {"fread", (const void*)cb_fread},
    {"fgetc", (const void*)cb_fgetc},
    {"fgets", (const void*)cb_fgets},
    {"strdup", (const void*)cb_strdup},
    {"strchr", (const void*)cb_strchr},
};
// ZZZ
// strtok
// strtok_r

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

static void* cb_malloc(size_t size)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_malloc: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? NULL : malloc(size);
}
static void* cb_calloc(size_t nmemb, size_t size)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_calloc: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? NULL : calloc(nmemb, size);
}
static void* cb_realloc(void* ptr, size_t size)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_realloc: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? NULL : realloc(ptr, size);
}

static FILE* cb_fopen(const char* pathname, const char* mode)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_fopen: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? NULL : fopen(pathname, mode);
}
static int cb_fclose(FILE* stream)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_fclose: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? EOF : fclose(stream);
}
static size_t cb_fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_fread: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? 0 : fread(ptr, size, nmemb, stream);
}
static int cb_fgetc(FILE* stream)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_fgetc: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? EOF : fgetc(stream);
}
static char* cb_fgets(char* s, int n, FILE* stream)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_fgets: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? NULL : fgets(s, n, stream);
}

static char* cb_strdup(const char* s)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_strdup: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? NULL : strdup(s);
}
static const char* cb_strchr(const char* s, int c)
{
    assert(s_elffuzz);
    assert(s_elffuzz->obj);
    LOG_D("ELFFUZZ : cb_strchr: syscall_hook_call_idx - %d, syscall_hook_call_cnt - %d",
          s_syscall_hooks_call_idx, s_syscall_hooks_call_cnt);
    return syscall_hook_triggered() ? NULL : strchr(s, c);
}


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
