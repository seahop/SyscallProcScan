#include <Windows.h>
#define WIN32_LEAN_AND_MEAN
#include <winternl.h>
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <process.h>
#include "defFunc.h"      //Function definitions
#include "NtStructs.h"    //NtQuerySystemInformation VirtuallAlloc Structs

#pragma comment(lib,"ntdll.lib") // Need to link with ntdll.lib import library. You can find the ntdll.lib from the Windows DDK.

#define STATUS_SUCCESS	   ((NTSTATUS)0x00000000L) // ntsubauth
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR) -1 )


char* getProcUser(DWORD dwProcessId) {
    char error_return[9] = "Error###";

    NTSTATUS status;
    HANDLE hToken = NULL;
    PVOID buffer = NULL;

    CLIENT_ID pid = { (HANDLE)dwProcessId, NULL };

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, 0, 0, 0, 0);
    HANDLE hProc = NULL;

    PTOKEN_USER ptu = NULL;
    DWORD dwSize = 0;
    LPTSTR StringSid = NULL;

    //Get handle to NtClose
    _NtClose NtClose = (_NtClose)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtClose");

    //Get handle to NtOpenProcess
    _NtOpenProcess pNtOpenProcess = (_NtOpenProcess)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtOpenProcess");

    if (!NT_SUCCESS(status = pNtOpenProcess(&hProc, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &pid)))
    {
        printf("\nError: Unable to query process list (%#lx)\nNote: This is likely a different user's process you are querying\n\n", status);
        NtClose(hToken);
        return error_return;
    }
    //Get handle to NtOpenProcessToken
    _NtOpenProcessToken pNtOpenProcessToken = (_NtOpenProcessToken)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");

    if (!NT_SUCCESS(status = pNtOpenProcessToken(hProc, TOKEN_QUERY, &hToken)))
    {
        printf("\nError: Unable to query process token (%#lx)\n", status);
        NtClose(hToken);
        return error_return;
    }

    TOKEN_STATISTICS ts;

    //Get handle to NtQueryInformationToken
    _NtQueryInformationToken pNtQueryInformationToken = (_NtQueryInformationToken)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtQueryInformationToken");

    if (!NT_SUCCESS(status = pNtQueryInformationToken(hToken, TokenOwner, &ts, sizeof(ts), &ts.DynamicCharged)))
    {
        printf("\nError: Unable to query token information (%#lx)\n", status);
        NtClose(hToken);
        return error_return;
    }

    PTOKEN_USER getSID = (PTOKEN_USER)&ts.TokenId;

    SID_NAME_USE SidType;
    char lpName[125];
    char lpDomain[125];
    std::string slash = "\\";
    DWORD dwSize2 = 256;

    _LdrLoadDll pLdrLoadDll = (_LdrLoadDll)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "LdrLoadDll");

    //Import ADVAPI32.DLL
    //HMODULE advapi32 = LoadLibrary(_T("ADVAPI32.dll"));
    HANDLE advapi32 = NULL;
    UNICODE_STRING dll;
    RtlInitUnicodeString(&dll, L"ADVAPI32.dll");
    pLdrLoadDll(NULL, NULL, &dll, &advapi32);
    _LookupAccountSidA pLookupAccountSid = (_LookupAccountSidA)hlpGetProcAddress(hlpGetModuleHandle(L"advapi32.dll"), "LookupAccountSidA");

    if (!pLookupAccountSid(NULL, getSID->User.Sid, lpName, &dwSize2, lpDomain, &dwSize2, &SidType))
    {
        DWORD dwResult = GetLastError();
        if (dwResult == ERROR_NONE_MAPPED)
        {
            strcpy_s(lpName, "NONE_MAPPED");
            strcpy_s(lpDomain, "NONE_MAPPED");
        }
        else
        {
            printf("LookupAccountSid Error %u\n", GetLastError());
            NtClose(hToken);
        }
    }
    else
    {
        printf("\nUser is  %s\\%s\n", lpDomain, lpName);
        NtClose(hToken);
        return lpName;
    }

    NtClose(hToken);
    return FALSE;
}

int compareProcess(wchar_t* proc, DWORD cPid) {
    NTSTATUS status;
    PVOID buffer = NULL;
    PSYSTEM_PROCESS_INFO spi;
    ULONG ReturnLength;
    PSIZE_T sz = (PSIZE_T)&ReturnLength;

    //Get handle to NtAllocateVirtualMemory
    LPNTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");

    //Get handle to NtQuerySystemInformation
    _NtQuerySystemInformation pNtQuerySystemInformation = (_NtQuerySystemInformation)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NT_SUCCESS(status = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLength)))
    {
        //buffer = VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
        status = pNtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status))
        {
            printf("NtAllocateVirtualMemory failed with %lx\n", status);
            return -1;
        }
        if (!buffer)
        {
            printf("\nError: Unable to allocate memory for process list (%d)\n", GetLastError());
            return -1;
        }

        //printf("\nProcess list allocated at address %#zx\n", buffer);
        spi = (PSYSTEM_PROCESS_INFO)buffer;

        //Get handle to NtFreeVirtualmemory
        LPNTFREEVIRTUALMEMORY     pNtFreeVirtualMemory = (LPNTFREEVIRTUALMEMORY)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtFreeVirtualMemory");
        if (!NT_SUCCESS(status = pNtQuerySystemInformation(SystemProcessInformation, spi, ReturnLength, NULL)))
        {
            printf("\nError: Unable to query process list (%#zx)\n", status);
            //VirtualFree(buffer, 0, MEM_RELEASE);
            pNtFreeVirtualMemory(NtCurrentProcess(), &buffer, sz, MEM_RELEASE);
            return -1;
        }

        while (spi->NextEntryOffset) // Loop over the list until we reach the last entry.
        {
            int check = 0;
            //printf("\nProcess: %ws | Process ID: %d\n", spi->ImageName.Buffer, spi->ProcessId); // Display process information.
            if (spi->ImageName.Buffer == NULL)
            {
                check++;
                if (check > 1) {
                    //VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
                    pNtFreeVirtualMemory(NtCurrentProcess(), &buffer, sz, MEM_RELEASE);
                    return 0;
                }

                spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
            }
            else
            {
                wchar_t* test = spi->ImageName.Buffer;
                if (wcscmp(test, proc) == 0)
                {
                    printf("Process: %ws matches Process: %ws | PID: %d\n", test, proc, spi->ProcessId);
                    DWORD dwProcessId = (DWORD)spi->ProcessId;

                    char* current_usr = getProcUser(cPid);
                    char* remote_usr = getProcUser(dwProcessId);
                    if (strcmp(remote_usr, current_usr) == 0 || current_usr == "SYSTEM")
                    {
                        printf("\nWe have a match, you are elevated, or you are running as SYSTEM!");
                        pNtFreeVirtualMemory(NtCurrentProcess(), &buffer, sz, MEM_RELEASE);
                        return 1;
                    }
                }
                spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
            }
        }
    }
}

int listProcceses() {
    NTSTATUS status;
    PVOID buffer = NULL;
    PSYSTEM_PROCESS_INFO spi;
    ULONG ReturnLength;
    PSIZE_T sz = (PSIZE_T)&ReturnLength;

    //Get handle to NtAllocateVirtualMemory
    LPNTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");

    //Get handle to NtQuerySystemInformation
    _NtQuerySystemInformation pNtQuerySystemInformation = (_NtQuerySystemInformation)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NT_SUCCESS(status = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLength)))
    {
        //buffer = VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
        status = pNtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status))
        {
            printf("NtAllocateVirtualMemory failed with %lx\n", status);
            return -1;
        }
        if (!buffer)
        {
            printf("\nError: Unable to allocate memory for process list (%d)\n", GetLastError());
            return -1;
        }

        //printf("\nProcess list allocated at address %#zx\n", buffer);
        spi = (PSYSTEM_PROCESS_INFO)buffer;

        //Get handle to NtFreeVirtualmemory
        LPNTFREEVIRTUALMEMORY     pNtFreeVirtualMemory = (LPNTFREEVIRTUALMEMORY)hlpGetProcAddress(hlpGetModuleHandle(L"ntdll.dll"), "NtFreeVirtualMemory");
        if (!NT_SUCCESS(status = pNtQuerySystemInformation(SystemProcessInformation, spi, ReturnLength, NULL)))
        {
            printf("\nError: Unable to query process list (%#zx)\n", status);
            //VirtualFree(buffer, 0, MEM_RELEASE);
            pNtFreeVirtualMemory(NtCurrentProcess(), &buffer, sz, MEM_RELEASE);
            return -1;
        }

        while (spi->NextEntryOffset) // Loop over the list until we reach the last entry.
        {
            int check = 0;
            //Skips over a PID of 0 as a first result
            if (spi->ImageName.Buffer == NULL)
            {
                check++;
                if (check > 1) {
                    //VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
                    pNtFreeVirtualMemory(NtCurrentProcess(), &buffer, sz, MEM_RELEASE);
                    return 0;
                }

                spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
            }

            //Print binary + PID
            printf("\nProcess: %ws | Process ID: %d\n", spi->ImageName.Buffer, spi->ProcessId); // Display process information.

            //Increment +1 on process list
            spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);  
        }
    }
}

/*
void Helper() {
    printf("------Sysacall List All Processes------\n");
    printf("      ex: SyscallProcScan.exe\n");
    printf("------Syscall Process List and Match-----\n");
    printf("      ex: SyscallProcScan.exe [process]");
    exit(0);
}
*/

int wmain(int argc, wchar_t* argv[])
{
    DWORD cPid = _getpid();

    if (argc == 1)
    {
        listProcceses();
    }
    if (argc == 2)
    {
        wchar_t* proc = argv[1];
        compareProcess(proc, cPid);
    }
}