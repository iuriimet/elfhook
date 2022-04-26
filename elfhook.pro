DISTFILES += \
    CMakeLists.txt \
    LICENSE \
    README \
    build.sh \
    build_tizen.sh \
    elfhook.manifest \
    gbs/gbs_tizen6.5.conf \
    libraries/CMakeLists.txt \
    libraries/elffuzz/CMakeLists.txt \
    libraries/elfmem/CMakeLists.txt \
    libraries/test/CMakeLists.txt \
    packaging/elfhook.spec

HEADERS += \
    common/inc/logger.h \
    libraries/elffuzz/inc/elffuzz.h \
    libraries/elffuzz/inc/elffuzz_def.h \
    libraries/elffuzz/inc/libelffuzz.h \
    libraries/elfmem/inc/elfmem.h \
    libraries/elfmem/inc/elfmem_def.h \
    libraries/elfmem/inc/elfutils.h \
    libraries/elfmem/inc/libelfmem.h \
    libraries/test/libtest.h

SOURCES += \
    elfhook.cpp \
    libraries/elffuzz/src/elffuzz.cpp \
    libraries/elffuzz/src/libelffuzz.cpp \
    libraries/elfmem/src/elfmem.cpp \
    libraries/elfmem/src/elfutils.cpp \
    libraries/elfmem/src/libelfmem.cpp \
    libraries/test/libtest.cpp

INCLUDEPATH += \
    common/inc \
    libraries/elfmem/inc \
    libraries/elffuzz/inc
