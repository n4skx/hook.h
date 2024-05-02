#pragma once

#include <windows.h>
#include <winternl.h>

//
//  Typedefs
//

typedef struct
{
	PVOID FuncPtr;
	PVOID MyFuncPtr;
	PVOID SavedBytes;
	DWORD PatchSize;
} H_Hooks;

//
//  Functions
// 

BOOL H_HookFunction(
	_Inout_ H_Hooks* Hook
)
{
#ifdef _WIN64
	UCHAR Patch[] =
	{
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xe0
	};

	// Setup patch
	*(DWORD64*)&Patch[2] = (DWORD64)Hook->MyFuncPtr;
#else
	UCHAR Patch[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

	// Calc offset
	DWORD Source = (DWORD) Hook->FuncPtr + 5;
	DWORD Destine = (DWORD) Hook->MyFuncPtr;
	DWORD Offset = (DWORD)(Destine - Source);

	*(DWORD*)&Patch[1] = Offset;
#endif

	Hook->PatchSize = sizeof(Patch);

	// Change protection
	DWORD OldPotection = 0x00;

	if (!VirtualProtect(Hook->FuncPtr, Hook->PatchSize, PAGE_EXECUTE_READWRITE, &OldPotection))
	{
		return FALSE;
	}

	// Save
	if (Hook->SavedBytes)
	{
		if (!ReadProcessMemory((HANDLE)-1, Hook->FuncPtr, Hook->SavedBytes, Hook->PatchSize, NULL))
		{
			return FALSE;
		}
	}

	// Write hook
	if (!WriteProcessMemory((HANDLE)-1, Hook->FuncPtr, Patch, Hook->PatchSize, NULL))
	{
		return FALSE;
	}

	// Change protection
	if (!VirtualProtect(Hook->FuncPtr, sizeof(Patch), OldPotection, &OldPotection))
	{
		return FALSE;
	}

	return TRUE;
}

BOOL H_RestoreHook(
	_Inout_ H_Hooks* Hook
)
{
	// Change protection
	DWORD OldPotection = 0x00;

	if (!VirtualProtect((LPVOID)Hook->FuncPtr, Hook->PatchSize, PAGE_EXECUTE_READWRITE, &OldPotection))
	{
		return FALSE;
	}

	// Write saved bytes
	if (!WriteProcessMemory((HANDLE)-1, (LPVOID)Hook->FuncPtr, Hook->SavedBytes, Hook->PatchSize, NULL))
	{
		return FALSE;
	}

	// Change protection
	if (!VirtualProtect((LPVOID)Hook->FuncPtr, Hook->PatchSize, OldPotection, &OldPotection))
	{
		return FALSE;
	}

	return TRUE;
}
