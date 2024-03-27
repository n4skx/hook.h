# hook.h
A very simple inline hooking library in c, for x32 and x64. This library is designed to be very simple to use.

### Example
```c++
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#include "Hook.h"

//
//  Prototypes
//

int WINAPI HookedSleep(DWORD dwMiliseconds);

int main(void)
{
	BYTE SavedBytes[1024] = { 0x00 };

	// Hook
	H_Hooks Hook = {
		(PVOID)GetProcAddress(LoadLibraryA("kernel32.dll"), "Sleep"),
		(PVOID)HookedSleep,
		&SavedBytes
	};

	if (!H_HookFunction(&Hook))
	{
		printf("[Error] Failed to install hook, err: %ld\n", GetLastError());

		return -1;
	}

	// Call
	Sleep(3);

	// Restore
	if (!H_RestoreHook(&Hook))
	{
		printf("[Error] Failed to restore hook, err: %ld\n", GetLastError());

		return -1;
	}

	// Call again
	Sleep(3);
}

int WINAPI HookedSleep(DWORD dwMiliseconds)
{
	printf("[INFO] HookedSleep called\n");

	return 0;
}
```
