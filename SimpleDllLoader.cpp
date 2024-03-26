// SimpleDllLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#define NullCheck(var, varName) \
    if(var == NULL){ \
        printf("[!] " varName " failed : %d\n", GetLastError()); \
        return false; \
    }else{ \
        printf("[*] " varName " success : %d\n", GetLastError()); \
    } \


void printLogo() {
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    //1000 is an abitrary number
    wchar_t logo[1000] = L"";


    wcscat_s(logo,L"  ██████  ██▓ ███▄ ▄███▓ ██▓███   ██▓    ▓█████  ██▓     ▒█████   ▄▄▄      ▓█████▄ ▓█████  ██▀███  \n");
    wcscat_s(logo,L"▒██    ▒ ▓██▒▓██▒▀█▀ ██▒▓██░  ██▒▓██▒    ▓█   ▀ ▓██▒    ▒██▒  ██▒▒████▄    ▒██▀ ██▌▓█   ▀ ▓██ ▒ ██▒\n");
    wcscat_s(logo,L"░ ▓██▄   ▒██▒▓██    ▓██░▓██░ ██▓▒▒██░    ▒███   ▒██░    ▒██░  ██▒▒██  ▀█▄  ░██   █▌▒███   ▓██ ░▄█ ▒\n");
    wcscat_s(logo,L"  ▒   ██▒░██░▒██    ▒██ ▒██▄█▓▒ ▒▒██░    ▒▓█  ▄ ▒██░    ▒██   ██░░██▄▄▄▄██ ░▓█▄   ▌▒▓█  ▄ ▒██▀▀█▄  \n");
    wcscat_s(logo,L"▒██████▒▒░██░▒██▒   ░██▒▒██▒ ░  ░░██████▒░▒████▒░██████▒░ ████▓▒░ ▓█   ▓██▒░▒████▓ ░▒████▒░██▓ ▒██▒\n");
    wcscat_s(logo,L"▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ░  ░▒▓▒░ ░  ░░ ▒░▓  ░░░ ▒░ ░░ ▒░▓  ░░ ▒░▒░▒░  ▒▒   ▓▒█░ ▒▒▓  ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░\n");
    wcscat_s(logo,L"░ ░▒  ░ ░ ▒ ░░  ░      ░░▒ ░     ░ ░ ▒  ░ ░ ░  ░░ ░ ▒  ░  ░ ▒ ▒░   ▒   ▒▒ ░ ░ ▒  ▒  ░ ░  ░  ░▒ ░ ▒░\n");
    wcscat_s(logo,L"░  ░  ░   ▒ ░░      ░   ░░         ░ ░      ░     ░ ░   ░ ░ ░ ▒    ░   ▒    ░ ░  ░    ░     ░░   ░ \n");
    wcscat_s(logo,L"      ░   ░         ░                ░  ░   ░  ░    ░  ░    ░ ░        ░  ░   ░       ░  ░   ░     \n");
    wcscat_s(logo, L"\n");
    if (!WriteConsoleW(console, logo, 1000, NULL, NULL)) {
        printf("%d\n", GetLastError());
    }
    //reset cursor
    CONSOLE_SCREEN_BUFFER_INFO cbsi;
    int y;
    if (GetConsoleScreenBufferInfo(console, &cbsi))
    {
        y = cbsi.dwCursorPosition.Y;
    }
    else
    {
        printf("Error resetting console cursor: %d\n", GetLastError());
        return;
    }

    COORD pos = { 0,y };
    SetConsoleCursorPosition(console, pos);
    
}
void printUsage() {
    printf("[!] SimpleDllLoader.exe <method> <dll> <pid:optional>\n");
    printf("\t[+] method : self/remote for injection type\n");
    printf("\t[+] dll : path of dll to load\n");
    printf("\t[+] pid <optional> : pid of process for remote injection\n");
}

BOOL remoteInjection(IN char* DllPath,IN int pid) {

    DWORD dwSize = strlen(DllPath) * sizeof(CHAR);

    HANDLE hRemoteProcess;
    hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    NullCheck(hRemoteProcess, "OpenProcessHandle");
    
    HMODULE kernal32;
    kernal32 = GetModuleHandle(L"kernel32.dll");
    NullCheck(kernal32, "GetModulehandle");

    LPVOID pLoadLibrary;
    pLoadLibrary = GetProcAddress(kernal32, "LoadLibraryA");
    NullCheck(pLoadLibrary, "GetProcAddress")
    LPVOID pVirtualAlloc;
    pVirtualAlloc = VirtualAllocEx(hRemoteProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    NullCheck(pVirtualAlloc, "VirtualAllocEx");
    printf("\t[i] pAddress Allocated At : 0x%p Of Size : %d\n", pVirtualAlloc, dwSize);

    SIZE_T lpNumBytesWr;
    HANDLE hThread;

    if (!WriteProcessMemory(hRemoteProcess, pVirtualAlloc, DllPath, dwSize, &lpNumBytesWr) || lpNumBytesWr != dwSize) {
        printf("[!] WriteProcessMemory failed : %d\n", GetLastError());
        return false;
    }
    printf("\t[i] Successfully Written %d Bytes\n", lpNumBytesWr);

    hThread = CreateRemoteThread(hRemoteProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibrary, pVirtualAlloc, NULL, NULL);
    NullCheck(hThread, "CreateRemoteThread");
    CloseHandle(hThread);

    return true;
}

BOOL selfInjection(IN char *DllPath) {
    if (LoadLibraryA(DllPath) == NULL) {
        printf("[!] loadlibraryA failed\n");
        return false;
    }
    printf("[*] LoadLibraryA success\n");
    return true;
}

int main(int argc, char* argv[])
{
    printLogo();
    if (argc < 3) {
        printUsage();
    }
    char* method = argv[1];
    char* dll = argv[2];

    printf("[*] Dll : %s\n", dll);
    if (strcmp(method, "self") == 0) {
        printf("[*] Self injection\n");
        selfInjection(dll);
    }
    else if (strcmp(method, "remote")==0) {
        if (argc < 4) {
            printUsage();
            return 0;
        }
        printf("[*] remote injection\n");
        int pid = atoi(argv[3]);
        printf("[*] PID : %d\n",pid);
        remoteInjection(dll,pid);
    }

    getchar();
}

