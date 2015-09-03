// DLLMagicHook.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"

// Built in Win API funcs
BOOL InitInstance();
void ExitInstance();

// Attach the DLL Process
BOOL DllProcessAttach(HINSTANCE hModule, 
           DWORD  Reason, 
           LPVOID lpReserved
		 )
{
	InitInstance();
	return TRUE;
}

// Detach the DLL Process
BOOL DllProcessDetach(HINSTANCE hModule, 
           DWORD  Reason, 
           LPVOID lpReserved
		 )
{
	ExitInstance();
	return TRUE;
}

BOOL InitInstance() 
{
	MessageBox(NULL, "Hello World from Inside Our Process", "Alert", MB_OK);
	return TRUE;
}

void ExitInstance()
{
}

BOOL APIENTRY DllMain( HINSTANCE hModule, 
                       DWORD  Reason, 
                       LPVOID lpReserved
					 )
{
	switch (Reason)
	{
		// Attached the DLL to the process
		case DLL_PROCESS_ATTACH:
			return DllProcessAttach(hModule, Reason, lpReserved);
		break;
		// Detached the DLL to the process
		case DLL_PROCESS_DETACH:
			return DllProcessDetach(hModule, Reason, lpReserved);
		break;
		case DLL_THREAD_ATTACH:
		break;
		case DLL_THREAD_DETACH:
		break;
	}
    return true;
}
