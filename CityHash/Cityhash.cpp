#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <Windows.h>

#define FIRST_HASH 0xcbf29ce484222325
#define SECOND_HASH 0x100000001b3
#define THIRD_HASH  0xff51afd7ed558ccd
#define HASH_OFFSET 33

#define FUNCTION_SUFFIX "_CH"
#define CHASH(STR)    ( simple_cityhash( (LPCSTR)STR ) )

// �򻯰�� CityHash
UINT32 simple_cityhash(LPCSTR cString) {
    int length = strlen(cString);
    uint64_t hash = FIRST_HASH;

    for (size_t i = 0; i < length; ++i) {
        hash ^= (uint64_t)cString[i];
        hash *= SECOND_HASH;
    }

    hash ^= hash >> HASH_OFFSET;
    hash *= THIRD_HASH;
    hash ^= hash >> HASH_OFFSET;

    return hash;
}

const char* GOBAL_FUNCTION[] = {
    "NtOpenSection",
    "NtMapViewOfSection",
    "NtProtectVirtualMemory",
    "NtUnmapViewOfSection",
    "NtAllocateVirtualMemory",
    "NtDelayExecution",
    "LoadLibraryA",
    "CreateThreadpoolTimer",
    "SetThreadpoolTimer",
    "WaitForSingleObject",
    "AddVectoredExceptionHandler",
    "RemoveVectoredExceptionHandler",
    NULL
};

const char* GOBAL_MODULE[] = {
    "kernel32.dll",
    "ntdll.dll",
    "win32u.dll",
    ".text",
    NULL
};

// �滻 '.' Ϊ ''
void format_module_name(const char* input, char* output) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0'; ++i) {
        if (input[i] != '.') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0'; // ȷ������ַ����� '\0' ����
}

// ͨ�ô�ӡ����
void print_hash_definitions(const char* suffix, const char* array[], int format_name) {
    char formatted_name[256]; // ���ڴ洢��ʽ���������
    char temp_name[256];      // ���ڴ洢��ʱ�ַ���
    for (size_t i = 0; array[i] != NULL; ++i) {
        // ���������ʽ��ģ����
        if (format_name) {
            format_module_name(array[i], temp_name); // ��ʽ��ģ����
        }
        else {
            strncpy_s(temp_name, sizeof(temp_name), array[i], _TRUNCATE); // ��ȫ�����ַ���
        }

        // ƴ�Ӻ�׺��ȷ����ȫ
        sprintf_s(formatted_name, sizeof(formatted_name), "%s%s", temp_name, suffix);

        // ��ӡ��ʽ���ĺ궨��
        printf("#define %-40s 0x%0.8X\n", formatted_name, CHASH(array[i]));
    }
    printf("\n");
}



int main() {
    // ��ӡ������ϣ����
    print_hash_definitions(FUNCTION_SUFFIX, GOBAL_FUNCTION, 0);

    

    // ��ӡģ���ϣ���壨��Ҫ��ʽ��ģ������
    print_hash_definitions(FUNCTION_SUFFIX, GOBAL_MODULE, 1);

    return 0;
}
