#include "stdafx.h"
#include "libipfltr.h"

#pragma data_seg(".share")

UINT dll_attach_counter = 0;

#pragma data_seg(".data")

HANDLE DllMutex = INVALID_HANDLE_VALUE;
HANDLE hDriver = INVALID_HANDLE_VALUE;


BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpvReserved) {
	if (!lpvReserved)
		return(FALSE);

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:

		DisableThreadLibraryCalls(hInstDll);

		/*			 DllMutex=OpenMutex(SYNCHRONIZE,FALSE,MUTEX_NAME);
					 if(!DllMutex) {
						DllMutex=CreateMutex(NULL,FALSE,MUTEX_NAME);
						if(!DllMutex)
							return(FALSE);
					 }
		*/
		dll_attach_counter++;
		break;

	case DLL_PROCESS_DETACH:

		dll_attach_counter--;


		if (hDriver != INVALID_HANDLE_VALUE)
			CloseHandle(hDriver);
		/*
					 if(!dll_attach_counter) {
						CloseHandle(DllMutex);
					 }
		*/
		break;
	default:	return(FALSE);
	}
	return(TRUE);
}

