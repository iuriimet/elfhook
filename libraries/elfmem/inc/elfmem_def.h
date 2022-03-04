#ifndef __ELFMEM_DEF_H__
#define __ELFMEM_DEF_H__

#include <stdlib.h>
#include <elf.h>

#ifdef __x86_64
    #define ELF_EHDR_T      Elf64_Ehdr
    #define ELF_SHDR_T      Elf64_Shdr
    #define ELF_PHDR_T      Elf64_Phdr
    #define ELF_DYN_T       Elf64_Dyn
    #define ELF_SYM_T       Elf64_Sym
    #define ELF_REL_T       Elf64_Rel
    #define ELF_RELA_T      Elf64_Rela
#ifndef ELF_ST_BIND
    #define ELF_ST_BIND(v)  ELF64_ST_BIND((v))
#endif
#ifndef ELF_ST_TYPE
    #define ELF_ST_TYPE(v)  ELF64_ST_TYPE((v))
#endif
#ifndef ELF_R_SYM
    #define ELF_R_SYM(v)    ELF64_R_SYM((v))
#endif
#ifndef ELF_R_TYPE
    #define ELF_R_TYPE(v)   ELF64_R_TYPE((v))
#endif
#else
    #define ELF_EHDR_T      Elf32_Ehdr
    #define ELF_SHDR_T      Elf32_Shdr
    #define ELF_PHDR_T      Elf32_Phdr
    #define ELF_DYN_T       Elf32_Dyn
    #define ELF_SYM_T       Elf32_Sym
    #define ELF_REL_T       Elf32_Rel
    #define ELF_RELA_T      Elf32_Rela
#ifndef ELF_ST_BIND
    #define ELF_ST_BIND(v)  ELF32_ST_BIND((v))
#endif
#ifndef ELF_ST_TYPE
    #define ELF_ST_TYPE(v)  ELF32_ST_TYPE((v))
#endif

#ifndef ELF_R_SYM
    #define ELF_R_SYM(v)    ELF32_R_SYM((v))
#endif
#ifndef ELF_R_TYPE
    #define ELF_R_TYPE(v)   ELF32_R_TYPE((v))
#endif
#endif

typedef enum
{
    MACHINE_UNKNOWN         = EM_NONE,                  /* No machine */
    MACHINE_M32             = EM_M32,                   /* AT&T WE 32100 */
    MACHINE_SPARC           = EM_SPARC,                 /* SUN SPARC */
    MACHINE_386             = EM_386,                   /* Intel 80386 */
    MACHINE_68K             = EM_68K,                   /* Motorola m68k family */
    MACHINE_88K             = EM_88K,                   /* Motorola m88k family */
    MACHINE_860             = EM_860,                   /* Intel 80860 */
    MACHINE_MIPS            = EM_MIPS,                  /* MIPS R3000 big-endian */
    MACHINE_S370            = EM_S370,                  /* IBM System/370 */
    MACHINE_MIPS_RS3_LE     = EM_MIPS_RS3_LE,           /* MIPS R3000 little-endian */

    MACHINE_PARISC          = EM_PARISC,                /* HPPA */
    MACHINE_VPP500          = EM_VPP500,                /* Fujitsu VPP500 */
    MACHINE_SPARC32PLUS     = EM_SPARC32PLUS,           /* Sun's "v8plus" */
    MACHINE_960             = EM_960,                   /* Intel 80960 */
    MACHINE_PPC             = EM_PPC,                   /* PowerPC */
    MACHINE_PPC64           = EM_PPC64,                 /* PowerPC 64-bit */
    MACHINE_S390            = EM_S390,                  /* IBM S390 */

    MACHINE_V800            = EM_V800,                  /* NEC V800 series */
    MACHINE_FR20            = EM_FR20,                  /* Fujitsu FR20 */
    MACHINE_RH32            = EM_RH32,                  /* TRW RH-32 */
    MACHINE_RCE             = EM_RCE,                   /* Motorola RCE */
    MACHINE_ARM             = EM_ARM,                   /* ARM */
    MACHINE_FAKE_ALPHA      = EM_FAKE_ALPHA,            /* Digital Alpha */
    MACHINE_SH              = EM_SH,                    /* Hitachi SH */
    MACHINE_SPARCV9         = EM_SPARCV9,               /* SPARC v9 64-bit */
    MACHINE_TRICORE         = EM_TRICORE,               /* Siemens Tricore */
    MACHINE_ARC             = EM_ARC,                   /* Argonaut RISC Core */
    MACHINE_H8_300          = EM_H8_300,                /* Hitachi H8/300 */
    MACHINE_H8_300H         = EM_H8_300H,               /* Hitachi H8/300H */
    MACHINE_H8S             = EM_H8S,                   /* Hitachi H8S */
    MACHINE_H8_500          = EM_H8_500,                /* Hitachi H8/500 */
    MACHINE_IA_64           = EM_IA_64,                 /* Intel Merced */
    MACHINE_MIPS_X          = EM_MIPS_X,                /* Stanford MIPS-X */
    MACHINE_COLDFIRE        = EM_COLDFIRE,              /* Motorola Coldfire */
    MACHINE_68HC12          = EM_68HC12,                /* Motorola M68HC12 */
    MACHINE_MMA             = EM_MMA,                   /* Fujitsu MMA Multimedia Accelerator*/
    MACHINE_PCP             = EM_PCP,                   /* Siemens PCP */
    MACHINE_NCPU            = EM_NCPU,                  /* Sony nCPU embeeded RISC */
    MACHINE_NDR1            = EM_NDR1,                  /* Denso NDR1 microprocessor */
    MACHINE_STARCORE        = EM_STARCORE,              /* Motorola Start*Core processor */
    MACHINE_ME16            = EM_ME16,                  /* Toyota ME16 processor */
    MACHINE_ST100           = EM_ST100,                 /* STMicroelectronic ST100 processor */
    MACHINE_TINYJ           = EM_TINYJ,                 /* Advanced Logic Corp. Tinyj emb.fam*/
    MACHINE_X86_64          = EM_X86_64,                /* AMD x86-64 architecture */
    MACHINE_PDSP            = EM_PDSP,                  /* Sony DSP Processor */

    MACHINE_FX66            = EM_FX66,                  /* Siemens FX66 microcontroller */
    MACHINE_ST9PLUS         = EM_ST9PLUS,               /* STMicroelectronics ST9+ 8/16 mc */
    MACHINE_ST7             = EM_ST7,                   /* STmicroelectronics ST7 8 bit mc */
    MACHINE_68HC16          = EM_68HC16,                /* Motorola MC68HC16 microcontroller */
    MACHINE_68HC11          = EM_68HC11,                /* Motorola MC68HC11 microcontroller */
    MACHINE_68HC08          = EM_68HC08,                /* Motorola MC68HC08 microcontroller */
    MACHINE_68HC05          = EM_68HC05,                /* Motorola MC68HC05 microcontroller */
    MACHINE_SVX             = EM_SVX,                   /* Silicon Graphics SVx */
    MACHINE_ST19            = EM_ST19,                  /* STMicroelectronics ST19 8 bit mc */
    MACHINE_VAX             = EM_VAX,                   /* Digital VAX */
    MACHINE_CRIS            = EM_CRIS,                  /* Axis Communications 32-bit embedded processor */
    MACHINE_JAVELIN         = EM_JAVELIN,               /* Infineon Technologies 32-bit embedded processor */
    MACHINE_FIREPATH        = EM_FIREPATH,              /* Element 14 64-bit DSP Processor */
    MACHINE_ZSP             = EM_ZSP,                   /* LSI Logic 16-bit DSP Processor */
    MACHINE_MMIX            = EM_MMIX,                  /* Donald Knuth's educational 64-bit processor */
    MACHINE_HUANY           = EM_HUANY,                 /* Harvard University machine-independent object files */
    MACHINE_PRISM           = EM_PRISM,                 /* SiTera Prism */
    MACHINE_AVR             = EM_AVR,                   /* Atmel AVR 8-bit microcontroller */
    MACHINE_FR30            = EM_FR30,                  /* Fujitsu FR30 */
    MACHINE_D10V            = EM_D10V,                  /* Mitsubishi D10V */
    MACHINE_D30V            = EM_D30V,                  /* Mitsubishi D30V */
    MACHINE_V850            = EM_V850,                  /* NEC v850 */
    MACHINE_M32R            = EM_M32R,                  /* Mitsubishi M32R */
    MACHINE_MN10300         = EM_MN10300,               /* Matsushita MN10300 */
    MACHINE_MN10200         = EM_MN10200,               /* Matsushita MN10200 */
    MACHINE_PJ              = EM_PJ,                    /* picoJava */
    MACHINE_OPENRISC        = EM_OPENRISC,              /* OpenRISC 32-bit embedded processor */
//    MACHINE_ARC_A5          = EM_ARC_A5,                /* ARC Cores Tangent-A5 */
    MACHINE_XTENSA          = EM_XTENSA,                /* Tensilica Xtensa Architecture */
    MACHINE_ALTERA_NIOS2    = EM_ALTERA_NIOS2,          /* Altera Nios II */
    MACHINE_AARCH64         = EM_AARCH64,               /* ARM AARCH64 */
    MACHINE_TILEPRO         = EM_TILEPRO,               /* Tilera TILEPro */
    MACHINE_MICROBLAZE      = EM_MICROBLAZE,            /* Xilinx MicroBlaze */
    MACHINE_TILEGX          = EM_TILEGX,                /* Tilera TILE-Gx */
} Machine;

typedef enum
{
    MACHINE_TYPE_UNKNOWN    = ELFCLASSNONE,
    MACHINE_TYPE_B32        = ELFCLASS32,               /* 32-bit objects */
    MACHINE_TYPE_B64        = ELFCLASS64,               /* 64-bit objects */
} MachineType;

typedef enum
{
    ENCODING_TYPE_UNKNOWN   = ELFDATANONE,
    ENCODING_TYPE_LSB       = ELFDATA2LSB,              /* 2's complement, little endian */
    ENCODING_TYPE_MSB       = ELFDATA2MSB,              /* 2's complement, big endian */
} EncodingType;

#define CHECK_SYM_ST_BIND(v)    ((v) != STB_HIPROC)
#define CHECK_SYM_ST_TYPE(v)    ((v) != STT_HIPROC)
#define CHECK_SYM_ATTR(attr)    (CHECK_SYM_ST_BIND(ELF_ST_BIND(attr)) && CHECK_SYM_ST_TYPE(ELF_ST_TYPE(attr)))

typedef struct
{
    const char* object;
    const char* symbol;
    uintptr_t address;
    off_t offset;
} CallStackItem;

#endif /* __ELFMEM_DEF_H__ */
