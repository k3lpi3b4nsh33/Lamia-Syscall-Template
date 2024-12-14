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

// 简化版的 CityHash
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

// 替换 '.' 为 ''
void format_module_name(const char* input, char* output) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0'; ++i) {
        if (input[i] != '.') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0'; // 确保输出字符串以 '\0' 结束
}

// 通用打印函数
void print_hash_definitions(const char* suffix, const char* array[], int format_name) {
    char formatted_name[256]; // 用于存储格式化后的名称
    char temp_name[256];      // 用于存储临时字符串
    for (size_t i = 0; array[i] != NULL; ++i) {
        // 根据需求格式化模块名
        if (format_name) {
            format_module_name(array[i], temp_name); // 格式化模块名
        }
        else {
            strncpy_s(temp_name, sizeof(temp_name), array[i], _TRUNCATE); // 安全复制字符串
        }

        // 拼接后缀，确保安全
        sprintf_s(formatted_name, sizeof(formatted_name), "%s%s", temp_name, suffix);

        // 打印格式化的宏定义
        printf("#define %-40s 0x%0.8X\n", formatted_name, CHASH(array[i]));
    }
    printf("\n");
}



int main() {
    // 打印函数哈希定义
    print_hash_definitions(FUNCTION_SUFFIX, GOBAL_FUNCTION, 0);

    

    // 打印模块哈希定义（需要格式化模块名）
    print_hash_definitions(FUNCTION_SUFFIX, GOBAL_MODULE, 1);

    return 0;
}
