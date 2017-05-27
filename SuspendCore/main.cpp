#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

#include "SuspendCore.h"


static auto g_dwSleepAddress = (DWORD)GetProcAddress(LoadLibraryA("kernel32"), "Sleep");
static void __declspec(naked) SleepStub()
{
	__asm {
		push 0xFFFFFFFF /* INFINITE */	/* 0x2 */
		nop
		nop
		nop
		nop
		nop								/* 0x5 */
	}
										/* 0x7 */
}


void SuspendCore::CSuspendCore::SuspendThread(DWORD dwThreadId)
{
	auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (!hThread || hThread == INVALID_HANDLE_VALUE) {
		printf("OpenThread fail! Error: %u\n", GetLastError());
		return;
	}
	printf("Thread handle(%p) successfully created!\n", hThread);

	auto dwOwnerProcessId = GetProcessIdOfThread(hThread);
	if (!dwOwnerProcessId) {
		printf("GetProcessIdOfThread fail! Error: %u\n", GetLastError());
		return;
	}
	printf("Thread: %u Owner process found! PID: %u\n", dwThreadId, dwOwnerProcessId);

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwOwnerProcessId);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
		printf("OpenProcess fail! Error: %u\n", GetLastError());
		return;
	}
	printf("Process handle(%p) successfully created!\n", hProcess);

	auto dwSuspendRet = ::SuspendThread(hThread);
	if (dwSuspendRet == (DWORD)-1) {
		printf("SuspendThread fail! Error: %u\n", GetLastError());
		return;
	}
	printf("Thread: %u successfully suspended!\n", dwThreadId);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(hThread, &ctx) == FALSE) {
		printf("GetThreadContext fail! Error: %u\n", GetLastError());
		ResumeThread(hThread);
		return;
	}
	printf("Thread context(%p) found! Eip: %p\n", ctx, ctx.Eip);

	DWORD dwOldProtect = 0;
	auto bProtectRet = VirtualProtect(SleepStub, 0x7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (bProtectRet == FALSE) {
		printf("VirtualProtect fail! Error: %u\n", GetLastError());
		ResumeThread(hThread);
		return;
	}
	printf("Stub protect adjust completed!\n");

	(*(BYTE*)((DWORD)SleepStub + 2)) = 0xE9; // Jump
	(*(DWORD*)((DWORD)SleepStub + 3)) = (g_dwSleepAddress - ctx.Eip - 0x7 /* stub size */); // Target addr
	printf("Stub successfully re-write completed!\n");

	SIZE_T writtenByteSize = 0;
	auto bWriteRet = WriteProcessMemory(hProcess, (LPVOID)(ctx.Eip), SleepStub, 0x7, &writtenByteSize);
	if (bWriteRet == FALSE) {
		printf("WriteProcessMemory fail! Error: %u\n", GetLastError());
		ResumeThread(hThread);
		return;
	}
	printf("Stub writed to: %p 0x7/0x%x bytes!\n", ctx.Eip, writtenByteSize);

	auto dwResumeRet = ::ResumeThread(hThread);
	if (dwResumeRet == (DWORD)-1) {
		printf("ResumeThread fail! Error: %u\n", GetLastError());
		return;
	}
	printf("Thread: %u successfully resumed!\n", dwThreadId);

	if (CloseHandle(hThread) == FALSE || CloseHandle(hProcess) == FALSE) {
		printf("CloseHandle fail! Error: %u\n", GetLastError());
		return;
	}
	printf("Handles cleared!\n");
}

