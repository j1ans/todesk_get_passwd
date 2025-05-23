#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include "offset.h"


char MAGIC_VALUE[] = "WinSock 2.0";
PVOID BumpSearchProcessMemory(HANDLE hProcess);
void find_strings_in_memory(const uint8_t* address, size_t size, size_t min_len);

int main()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    LPPROCESSENTRY32 lpPE = 0;
    lpPE = (LPPROCESSENTRY32)VirtualAlloc(NULL, sizeof(PROCESSENTRY32), MEM_COMMIT, PAGE_READWRITE);
    lpPE->dwSize = sizeof(PROCESSENTRY32);
    DWORD PID[2] = {0,0};
    int i = 0;
    Process32First(hSnapshot, lpPE);
    while (Process32Next(hSnapshot, lpPE)) {
        if (wcsstr(lpPE->szExeFile, L"ToDesk")) {
            std::wcout << "[+]found " << lpPE->szExeFile << " - PID  " << lpPE->th32ProcessID << std::endl;
            PID[i] = lpPE->th32ProcessID;
            i++;
        }
    }

    for (int i = 0; i < 2; i++) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID[i]);
        PVOID MAGIC_ADDR = BumpSearchProcessMemory(hProcess);
        PVOID ReadMemoryAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        ReadProcessMemory(hProcess, MAGIC_ADDR, ReadMemoryAddr, 0x1000,NULL);
        find_strings_in_memory((uint8_t*)ReadMemoryAddr, 0x1000, 7);


    }
        




}


PVOID BumpSearchProcessMemory(HANDLE hProcess) {
    printf("[+] Searching Magic in process memory...\n");

    const char MAGIC[] = "WinSock 2.0";
    const int MAGIC_LEN = strlen(MAGIC);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = sysInfo.lpMinimumApplicationAddress;

    char buffer[4096];
    SIZE_T bytesRead;

    while (address < sysInfo.lpMaximumApplicationAddress) {
        if (!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
            LPVOID chunkStart = mbi.BaseAddress;
            SIZE_T chunkSize = mbi.RegionSize;

            while (chunkSize > 0) {
                SIZE_T readSize = min(sizeof(buffer), chunkSize);
                if (ReadProcessMemory(hProcess, chunkStart, buffer, readSize, &bytesRead)) {
                    for (int i = 0; i <= bytesRead - MAGIC_LEN; i++) {
                        if (memcmp(buffer + i, MAGIC, MAGIC_LEN) == 0) {
                            PVOID foundAddr = (PVOID)((DWORD_PTR)chunkStart + i);
                            printf("[+] Found at: 0x%p\n", foundAddr);
                            return foundAddr;
                        }
                    }
                }
                chunkStart = (LPVOID)((DWORD_PTR)chunkStart + readSize);
                chunkSize -= readSize;
            }
        }
        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    printf("[-] Not found\n");
    return NULL;
}

void find_strings_in_memory(const uint8_t* address, size_t size, size_t min_len) {
    int find_string_count = 0;
    if (address == NULL || size == 0) {
        printf("Invalid address or size\n");
        return;
    }

    size_t current_pos = 0;
    size_t string_start = 0;
    size_t string_length = 0;
    int in_string = 0;

    for (current_pos = 0; current_pos < size; current_pos++) {
        uint8_t c = address[current_pos];

        // 检查是否是可打印ASCII字符
        if (isprint(c) && c != '\0') {
            if (!in_string) {
                string_start = current_pos;
                in_string = 1;
            }
            string_length++;
        }
        else {
            if (in_string && string_length >= min_len) {
                find_string_count++;
                size_t dict_size = sizeof(dict) / sizeof(dict[0]);  // 计算数组元素个数

                for (size_t i = 0; i < dict_size; i++) {
                    if (find_string_count - 1 == dict[i].key) {
                        printf("[+]Found %s => \"",
                            dict[i].value);
                        // 安全打印字符串(确保不越界)
                        size_t end = string_start + string_length;
                        if (end > size) end = size;

                        for (size_t i = string_start; i < end; i++) {
                            putchar(address[i]);
                        }
                        printf("\"\n");
                        break;
                    }
                }
            }
            in_string = 0;
            string_length = 0;
        }
    }

    // 检查缓冲区末尾是否还有字符串
    if (in_string && string_length >= min_len) {
        printf("Found string at 0x%p (len=%zu): \"",
            (void*)(address + string_start), string_length);

        size_t end = string_start + string_length;
        if (end > size) end = size;

        for (size_t i = string_start; i < end; i++) {
            putchar(address[i]);
        }
        printf("\"\n");
    }
}