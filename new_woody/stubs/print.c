#include <stdint.h>

typedef void *HANDLE;
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    void *Reserved1[2];
    struct
    {
        void *Flink;
        void *Blink;
    } InMemoryOrderLinks;
    void *Reserved2[2];
    void *DllBase;
    void *Reserved3[2];
    struct
    {
        WORD Length;
        WORD MaximumLength;
        WORD *Buffer;
    } FullDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;
    BYTE padding[58];
    DWORD e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef HANDLE (*GetStdHandle_t)(DWORD nStdHandle);
typedef int (*WriteFile_t)(HANDLE hFile, const void *lpBuffer, DWORD nNumberOfBytesToWrite, DWORD *lpNumberOfBytesWritten, void *lpOverlapped);

int custom_strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

void print_woody(void *peb)
{

    void *ldr = *(void **)((BYTE *)peb + 0x18);
    void *list_head = (BYTE *)ldr + 0x20;
    void *entry1 = *(void **)list_head;
    void *entry2 = *(void **)entry1;
    void *entry3 = *(void **)entry2;

    LDR_DATA_TABLE_ENTRY *kernel32_entry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)entry3 - 0x10);
    BYTE *kernel32_base = (BYTE *)kernel32_entry->DllBase;

    IMAGE_DOS_HEADER *dos_hdr = (IMAGE_DOS_HEADER *)kernel32_base;

    DWORD export_dir_rva = *(DWORD *)(kernel32_base + dos_hdr->e_lfanew + 0x88);
    IMAGE_EXPORT_DIRECTORY *export_dir = (IMAGE_EXPORT_DIRECTORY *)(kernel32_base + export_dir_rva);

    DWORD *names_rva = (DWORD *)(kernel32_base + export_dir->AddressOfNames);
    DWORD *funcs_rva = (DWORD *)(kernel32_base + export_dir->AddressOfFunctions);
    WORD *ordinals_rva = (WORD *)(kernel32_base + export_dir->AddressOfNameOrdinals);

    char str_GetStdHandle[] = {'G', 'e', 't', 'S', 't', 'd', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    char str_WriteFile[] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0'};

    GetStdHandle_t pGetStdHandle = 0;
    WriteFile_t pWriteFile = 0;

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++)
    {
        char *func_name = (char *)(kernel32_base + names_rva[i]);
        WORD ordinal = ordinals_rva[i];

        if (custom_strcmp(func_name, str_GetStdHandle) == 0)
        {
            pGetStdHandle = (GetStdHandle_t)(kernel32_base + funcs_rva[ordinal]);
        }
        else if (custom_strcmp(func_name, str_WriteFile) == 0)
        {
            pWriteFile = (WriteFile_t)(kernel32_base + funcs_rva[ordinal]);
        }

        if (pGetStdHandle && pWriteFile)
            break;
    }

    if (pGetStdHandle && pWriteFile)
    {

        HANDLE hConsole = pGetStdHandle((DWORD)-11);

        char msg[] = {'.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', '\n', '\0'};
        DWORD bytes_written = 0;

        pWriteFile(hConsole, msg, 12, &bytes_written, 0);
    }
}