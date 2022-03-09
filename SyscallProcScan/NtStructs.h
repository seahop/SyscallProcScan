#include <Windows.h>
#define WIN32_LEAN_AND_MEAN
#include <winternl.h>

typedef NTSTATUS(NTAPI* _NtClose)(
	HANDLE Handle
	);

//NtQuerySystemInformation struct
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	_UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

//NtVirtualAllocateMemory Structs
typedef NTSTATUS NTAPI NTALLOCATEVIRTUALMEMORY(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID* BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
);
typedef NTALLOCATEVIRTUALMEMORY FAR* LPNTALLOCATEVIRTUALMEMORY;
/*
NTSTATUS (NTAPI* NtAllocateVirtualMemory)(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID* BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
	);
*/
typedef NTSTATUS NTAPI NTFREEVIRTUALMEMORY(
	_In_       HANDLE ProcessHandle,
	_Inout_    PVOID* BaseAddress,
	_Inout_    PSIZE_T RegionSize,
	_In_       ULONG FreeType
);
typedef NTFREEVIRTUALMEMORY FAR* LPNTFREEVIRTUALMEMORY;

//LPNTCREATETRANSACTION		NtCreateTransaction;
LPNTALLOCATEVIRTUALMEMORY	pNtAllocateVirtualMemory;
//LPNTCREATESECTION			NtCreateSection;
//LPNTROLLBACKTRANSACTION		NtRollbackTransaction;
//LPNTCLOSE					NtClose;
//LPNTCREATEPROCESSEX			NtCreateProcessEx;
//LPNTQUERYINFORMATIONPROCESS	NtQueryInformationProcess;
//LPNTREADVIRTUALMEMORY		NtReadVirtualMemory;
//LPNTWRITEVIRTUALMEMORY		NtWriteVirtualMemory;
//LPNTCREATETHREADEX			NtCreateThreadEx;
LPNTFREEVIRTUALMEMORY		pNtFreeVirtualMemory;


//NtOpenProcess Requirement
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    };

//NtOpenProcess struct
typedef NTSTATUS(NTAPI* _NtOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes,
	CLIENT_ID *ClientID
	);

//NtToken Requirements
typedef NTSTATUS (NTAPI * _NtOpenProcessToken)(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle
);

//NtQueryInformationToken struct
typedef NTSTATUS (NTAPI * _NtQueryInformationToken)(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
	_In_ ULONG TokenInformationLength,
	_Out_ PULONG ReturnLength
);


//LookupAccountsid struct
typedef BOOL (WINAPI* _LookupAccountSidA)(
	LPCSTR        lpSystemName,
	PSID          Sid,
	LPSTR         Name,
	LPDWORD       cchName,
	LPSTR         ReferencedDomainName,
	LPDWORD       cchReferencedDomainName,
	PSID_NAME_USE peUse
	);

//LdrLoadDll struct 
typedef NTSTATUS (NTAPI * _LdrLoadDll)(
	IN PWCHAR               PathToFile OPTIONAL,
	IN ULONG                Flags OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle);
