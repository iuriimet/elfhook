#ifndef __LOGGER_H__
#define __LOGGER_H__

#if defined(__ANDROID__)

#include <android/log.h>

static const char* TAG = "ELFHOOK";

#define LOG_D(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOG_I(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOG_W(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#elif defined(__TIZEN__)

#include <dlog.h>

#ifndef TAG
    #define TAG "ELFHOOK"
#endif

#define LOG_D(fmt, ...) dlog_print(DLOG_DEBUG, TAG, "[Debug] " fmt "\n", ##__VA_ARGS__)
#define LOG_I(fmt, ...) dlog_print(DLOG_INFO, TAG, "[Info] " fmt "\n", ##__VA_ARGS__)
#define LOG_W(fmt, ...) dlog_print(DLOG_WARN, TAG, "[Warning] " fmt "\n", ##__VA_ARGS__)
#define LOG_E(fmt, ...) dlog_print(DLOG_ERROR, TAG, "[Error] " fmt "\n", ##__VA_ARGS__)

#else

#include <stdio.h>
#include <string.h>

#define LOG_D(M, ...) \
        fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__); \
        fflush(stdout);
#define LOG_I(M, ...) \
        fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__);
#define LOG_W(M, ...) \
        fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__);
#define LOG_E(M, ...) \
        fprintf(stderr, "[%s:%d] " M " %s\n", strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__, strerror(errno));

#endif

#endif /* __LOGGER_H__ */
