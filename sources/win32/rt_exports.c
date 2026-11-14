#include "runtime.h"

#define EXPORTS(X) \
    X(AcquireSRWLockExclusive) X(CloseHandle) X(CompareStringW) X(CreateDirectoryW) X(CreateFileW) \
    X(DecodePointer) X(DeleteCriticalSection) X(DeleteFileW) X(EncodePointer) X(EnterCriticalSection) \
    X(EnumSystemLocalesW) X(ExitProcess) X(FindClose) X(FindFirstFileExW) X(FindNextFileW) X(FlsAlloc) \
    X(FlsFree) X(FlsGetValue) X(FlsSetValue) X(FlushFileBuffers) X(FreeEnvironmentStringsW) X(FreeLibrary) \
    X(GetACP) X(GetCPInfo) X(GetCommandLineA) X(GetCommandLineW) X(GetConsoleCP) X(GetConsoleMode) \
    X(GetConsoleOutputCP) X(GetCurrentDirectoryW) X(GetCurrentProcess) X(GetCurrentProcessId) \
    X(GetCurrentThreadId) X(GetEnvironmentStringsW) X(GetEnvironmentVariableW) X(GetFileAttributesW) \
    X(GetFileSizeEx) X(GetFileType) X(GetLastError) X(GetLocaleInfoW) X(GetModuleFileNameW) \
    X(GetModuleHandleExW) X(GetModuleHandleW) X(GetOEMCP) X(GetProcAddress) X(GetProcessHeap) \
    X(GetStartupInfoW) X(GetStdHandle) X(GetStringTypeW) X(GetSystemTimeAsFileTime) \
    X(GetSystemTimePreciseAsFileTime) X(GetTickCount) X(GetTickCount64) X(GetUserDefaultLCID) X(HeapAlloc) \
    X(HeapFree) X(HeapReAlloc) X(HeapSize) X(InitializeCriticalSectionAndSpinCount) X(InitializeCriticalSectionEx) \
    X(InitializeSListHead) X(IsDebuggerPresent) X(IsProcessorFeaturePresent) X(IsValidCodePage) X(IsValidLocale) \
    X(LCMapStringEx) X(LCMapStringW) X(LeaveCriticalSection) X(LoadLibraryExW) X(MoveFileExW) \
    X(MultiByteToWideChar) X(QueryPerformanceCounter) X(QueryPerformanceFrequency) X(RaiseException) \
    X(ReadConsoleW) X(ReadFile) X(ReleaseSRWLockExclusive) X(RemoveDirectoryW) X(RtlCaptureContext) \
    X(RtlLookupFunctionEntry) X(RtlPcToFileHeader) X(RtlUnwind) X(RtlUnwindEx) X(RtlVirtualUnwind) \
    X(SetConsoleCtrlHandler) X(SetConsoleMode) X(SetCurrentDirectoryW) X(SetEndOfFile) \
    X(SetEnvironmentVariableW) X(SetFilePointerEx) X(SetLastError) X(SetStdHandle) \
    X(SetUnhandledExceptionFilter) X(Sleep) X(SleepConditionVariableSRW) X(TerminateProcess) X(TlsAlloc) \
    X(TlsFree) X(TlsGetValue) X(TlsSetValue) X(UnhandledExceptionFilter) X(VirtualAlloc) X(VirtualFree) \
    X(VirtualProtect) X(VirtualQuery) X(WakeAllConditionVariable) X(WideCharToMultiByte) X(WriteConsoleW) \
    X(WriteFile)

#define DECLARE(name) extern char name[];
#define ENTRY(name) {(uint64_t)#name, (uint64_t)name},
#define COUNT(name) +1

EXPORTS(DECLARE)
extern char runtime_entry[];
extern char __runtime_end[];

static const win32_export_t exports[] = {EXPORTS(ENTRY)};

__attribute__((section(".runtime_header"), used))
static const win32_runtime_header_t header = {
    WIN32_RUNTIME_MAGIC,
    0 EXPORTS(COUNT),
    (uint64_t)exports,
    (uint64_t)runtime_entry,
    (uint64_t)__runtime_end,
    0
};