#ifndef __LOGGER_H__
#define __LOGGER_H__

#ifdef __ANDROID__

#include <android/log.h>

static const char* TAG = "MediaRunner";

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG,__VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG,__VA_ARGS__)

#else

#include <stdio.h>
#include <string.h>

#define LOGE(M, ...) \
        fprintf(stderr, "[%s:%d] " M " %s\n", strrchr(__FILE__, '/') > 0 ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__, strerror(errno));
#define LOGW(M, ...) \
        fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') > 0 ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__);
#define LOGD(M, ...) \
        fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') > 0 ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__); \
        fflush(stdout);
#define LOGI(M, ...) \
        fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') > 0 ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__);

#endif

#endif /* __LOGGER_H__ */
