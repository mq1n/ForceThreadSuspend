#include <Windows.h>
#include <iostream>
#include <assert.h>

int main()
{
	printf("Test process started! PID: %u\n", GetCurrentProcessId());

	DWORD dwThreadId = 0;
	auto workerThread = [](LPVOID) -> DWORD {
		DWORD dwTick = 0;
		while (1) {
			printf("%u) I'm working!\n", ++dwTick);
			Sleep(5000);
		}
		return 0;
	};

	auto hThread = CreateThread(nullptr, 0, workerThread, nullptr, 0, &dwThreadId);
	assert(hThread);
	printf("Thread successfully created! TID: %u\n", dwThreadId);

	while (1) Sleep(1000);
	return 0;
}

