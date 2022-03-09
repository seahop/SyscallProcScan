# SyscallProcessScan
Process scanner using syscalls. It will enumerate running processes, check the name against the argument you gave. Then it will attempt to get the SID from the remote process and compare the user/domain with the current running process. If it fails, it will keep moving on to attempt to find another match.
This will also perform a normal process listing of all processes it can enumerate (default, no args)

Example: SyscallProcScan.exe <--- lists all processes\n
Example: SyscallProcScan.exe lsass.exe <--- compares current user to process owner's user and attempts to gain a handle

Uses mapped functions and syscalls: GetProcAddress, GetModuelHandle, LdrLoadDll (LoadLibrary), NtOpenProcess, NtOpenProcessToken, NtQueryInformationToken, NtClose, LookupAccountSid, NtAllocateVirtualMemory, NtQuerySystemInformation, NtFreeVirtualMemory.
