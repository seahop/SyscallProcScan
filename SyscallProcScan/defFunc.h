#pragma once
#include <Windows.h>
#define WIN32_LEAN_AND_MEAN

int listProcceses();
HMODULE WINAPI hlpGetModuleHandle(LPCWSTR);
FARPROC WINAPI hlpGetProcAddress(HMODULE, const char*);
int compareProcess(wchar_t*, DWORD);
char* getProcUser(DWORD);