#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <assert.h>
#include <psapi.h>
#pragma comment( lib, "psapi.lib" )

#include "../SuspendCore/SuspendCore.h"
#ifdef _DEBUG
#pragma comment( lib, "../Debug/SuspendCore.lib" )
#else
#pragma comment( lib, "../Release/SuspendCore.lib" )
#endif
using namespace SuspendCore;
static CSuspendCore suspendCore;


typedef NTSTATUS(NTAPI* lpRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
lpRtlAdjustPrivilege RtlAdjustPrivilege = nullptr;

typedef NTSTATUS(WINAPI* lpNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
lpNtQueryInformationThread NtQueryInformationThread = nullptr;

std::vector <DWORD> vThreadIdList;


int main()
{
	HMODULE hNtdll = LoadLibraryA("ntdll");
	assert(hNtdll);

	RtlAdjustPrivilege = (lpRtlAdjustPrivilege)GetProcAddress(LoadLibraryA("ntdll"), "RtlAdjustPrivilege");
	assert(RtlAdjustPrivilege);

	NtQueryInformationThread = (lpNtQueryInformationThread)GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationThread");
	assert(NtQueryInformationThread);


	auto GetThreadStartAddress = [](HANDLE hThread) -> DWORD {
		DWORD dwCurrentThreadAddress = 0;
		NtQueryInformationThread(hThread, 0x9, &dwCurrentThreadAddress, sizeof(dwCurrentThreadAddress), NULL);
		return dwCurrentThreadAddress;
	};

	auto GetThreadOwner = [](HANDLE hProcess, DWORD dwStartAddress) -> std::string {
		char cFileName[2048] = { 0 };
		GetMappedFileNameA(hProcess, (LPVOID)dwStartAddress, cFileName, 2048);
		return cFileName;
	};


	BOOLEAN boAdjustPrivRet;
	RtlAdjustPrivilege(20, TRUE, FALSE, &boAdjustPrivRet);


	printf("Target Process: ");
	DWORD dwTargetPID = 0;
	std::cin >> dwTargetPID;
	auto hProcess = OpenProcess(SYNCHRONIZE, FALSE, dwTargetPID);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
		printf("Target process %u is not active!\n", dwTargetPID);
		return 0;
	}
	CloseHandle(hProcess);


	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPID);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
		printf("Target process: %u couldn't be opened!\n", dwTargetPID);
		return 0;
	}


	auto GetThreadList = [](DWORD dwProcessId) -> void {
		auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
		THREADENTRY32 ti = { 0 };
		ti.dwSize = sizeof(ti);

		if (Thread32First(hSnap, &ti))
		{
			do {
				if (dwProcessId == ti.th32OwnerProcessID)
					vThreadIdList.push_back(ti.th32ThreadID);
			} while (Thread32Next(hSnap, &ti));
		}
		CloseHandle(hSnap);
	};
	GetThreadList(dwTargetPID);


	for (const auto & dwThreadId : vThreadIdList)
	{
		printf("[*] Thread found! %u processing...\n", dwThreadId);

		auto hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
		if (!hThread || hThread == INVALID_HANDLE_VALUE) {
			printf("#Error: Thread: %u couldn't be opened!\n", dwThreadId);
			continue;
		}

		auto dwThreadAddress = GetThreadStartAddress(hThread);
		if (!dwThreadAddress) {
			printf("#Error: Thread: %u start address not found!\n", dwThreadId);
			continue;
		}

		auto szThreadOwner = GetThreadOwner(hProcess, dwThreadAddress);
		if (szThreadOwner.empty()) {
			printf("#Error: Thread: %u owner module not found!\n", dwThreadId);
			continue;
		}

		printf("\tThread: %p(%u) Adr: %p Owner: %s\n", hThread, dwThreadId, dwThreadAddress, szThreadOwner.c_str());
		CloseHandle(hThread);
	}
	vThreadIdList.clear();


	printf("\n\n- Target Thread ID: ");
	DWORD dwTargetTID = 0;
	std::cin >> dwTargetTID;

	suspendCore.SuspendThread(dwTargetTID);
	printf("Suspend work completed!\n");


	CloseHandle(hProcess);
	printf("\n\nCompleted!\n");
	Sleep(INFINITE);
	return 0;
}

