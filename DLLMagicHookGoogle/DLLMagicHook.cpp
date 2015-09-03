// DLLMagicHook.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"

// Built in Win API funcs
BOOL InitInstance();
void ExitInstance();

// Handle for Winsock 2
HMODULE handleWS2_32 = NULL;

// Function Data for an injection point
struct FuncData{
	DWORD BytesToCopy;
	void * AddressFunc;
	void * AddressBuffer;
	long Count;
	
	// Struct Constructor - NULL everything
	static FuncData opCall(){
		FuncData thisFunc;
		thisFunc.BytesToCopy = 0;
		thisFunc.AddressBuffer = 0;
		thisFunc.AddressFunc = 0;
		thisFunc.Count = 0;
		return thisFunc;
	}

	// Has this injection point been filled?
	bool isFilled(){
		return (bool)( BytesToCopy && AddressFunc && AddressBuffer );
	}
};

// We want to overload WSASend, WSARecv, Send, and Recv in Winsock2
FuncData WSARecvData;
FuncData RecvData;

// Forward Declaration of ASM overwrite functions
void functionHandlerWSARecv();
void functionHandlerRecv();

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

// Pack this union to 1-byte
#pragma pack(1)
	union
	{
		struct
		{
			BYTE Op;		// Opcode
			DWORD Address;	// Address for JMP
		};
		BYTE Buffer[10];	// Buffer of our Command
	} Command;
#pragma pack() // Pack normally again

// Images we want to replace in the HTML
static char * imgArray[] = { ".png", ".gif", ".jpg", ".bmp"};

// global replace for now
static char * replaceUrl = "http://cthulhu32.kraln.com/misc/avatar_laugh.png";
#define MAX_SIZE 128 // max size of a valid http image should be around 128

// Recieve function overload
static void newRecv(
  DWORD RetValue,
  DWORD RetAddress,
  SOCKET s,
  char FAR* buf,
  int len,
  int flags)
{
	// Does not apply in Firefox, our demo browser
}

// WSA Recieve function overload
static void newWSARecv(
	DWORD RetValue,
	DWORD RetAddress,
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	char * buf = lpBuffers[0].buf;
	while (buf < lpBuffers[0].buf + lpNumberOfBytesRecvd[0]) {
		if (strncmp(buf, "https", 5) == 0)
		{
			memcpy(buf, " http", sizeof(char) * 5);
			buf += 5;
		}
		buf++;
	}
}

// Used for unloading the hooks ASM JMP overwrites
int UnloadHookASM(FuncData & inFunc){
	DWORD prF;		// Page Read Flags for Function
	DWORD prB;		// Page Read Flags for Buffer
	DWORD bytes = 0;
	
	int res;
	
	// Virtually Lock the memory at the address function & the address buffer
	VirtualLock(inFunc.AddressFunc, inFunc.BytesToCopy);
	VirtualProtect(inFunc.AddressFunc, inFunc.BytesToCopy, PAGE_EXECUTE_READWRITE, &prF);
	VirtualLock(inFunc.AddressBuffer, inFunc.BytesToCopy);
	VirtualProtect(inFunc.AddressBuffer, inFunc.BytesToCopy, PAGE_EXECUTE_READWRITE, &prB);
	
	// Write the buffer (original 5/6 bytes) over the top of the address function, removing the hook JMP
	res = WriteProcessMemory(GetCurrentProcess(), inFunc.AddressFunc, inFunc.AddressBuffer, inFunc.BytesToCopy, &bytes);
	
	// Virtually Unlock the memory at the address function & the address buffer
	VirtualProtect(inFunc.AddressFunc, inFunc.BytesToCopy, prB , &prB);
	VirtualUnlock(inFunc.AddressFunc, inFunc.BytesToCopy);
	VirtualProtect(inFunc.AddressBuffer, inFunc.BytesToCopy, prF , &prF);
	VirtualUnlock(inFunc.AddressBuffer, inFunc.BytesToCopy);

	// Return our write process memory's return as its the only relevant int
	return res;
}

// Install the ASM Handler
int installHandlerASM(PROC* func, void* handlerFunction, int asmSetupSize){
	// Page Read Attributes
	DWORD prF;	// Function PageRead
	DWORD prB;	// Buffer PageRead
	DWORD bytes = 0;

	// Lock the WinSock2 Function, and protect from Read/Write
	VirtualLock(func, 6);
	VirtualProtect(func, 6, PAGE_EXECUTE_READWRITE, &prF);

	// Lock the Handler Function, and protect from Read/Write
	VirtualLock(handlerFunction, asmSetupSize+6+5);
	VirtualProtect(handlerFunction, asmSetupSize+6+5, PAGE_EXECUTE_READWRITE, &prB);

	// Res is used to process function call returns
	int res = 0;
	int nBytesToCopy = 0;

	// Clear our Command Buffer
	memset(Command.Buffer, 0x90, sizeof(Command.Buffer)); // DWORD Buffer[10]

	// Read in the first 6 bytes of the WinSock2 function into the Command Buffer
	res = ReadProcessMemory(GetCurrentProcess(), func, Command.Buffer, 6, &bytes);

	static BYTE Win2kXP[] = { 0x55, 0x8B, 0xEC, 0x51, 0x51 };
	static BYTE Win9xNT[] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10 };
	static BYTE WinVista[] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };
	
	// Use a pointer to bytes to copy here, because we only need to check the ws2_s2.dll 
	if(nBytesToCopy == 0){
		// Compare with Opcodes of Windows 2k/XP
		if(!memcmp(Command.Buffer, Win2kXP, sizeof(Win2kXP)))
			nBytesToCopy = sizeof(Win2kXP);
		// Compare with Opcodes of Windows 9x/NT
		else if(!memcmp(Command.Buffer, Win9xNT, sizeof(Win9xNT))) 
			nBytesToCopy = sizeof(Win9xNT);
		// Compare with Opcodes of Windows Vista
		else if(!memcmp(Command.Buffer, WinVista, sizeof(WinVista))) 
			nBytesToCopy = sizeof(WinVista);
		if ( nBytesToCopy == 0 ){
			// This is an unrecognized ws2_s2.dll, unlock and return 0
			// Protect and unlock handler function
			VirtualProtect(handlerFunction, asmSetupSize+6+5, prB , &prB);
			VirtualUnlock(handlerFunction, asmSetupSize+6+5);

			// Protect and unlock original WinSock2 function
			VirtualProtect(func, 6, prF, &prF);
			VirtualUnlock(func, 6);
			return 0;
		}
	}

	// Create a pointer to the handler function's NOP space
	PBYTE pData = ((PBYTE)handlerFunction + asmSetupSize);

	// Write the Command Buffer (2kXP,9xNT,Vista) to that NOP space to retain the original code
	res = WriteProcessMemory(GetCurrentProcess(), pData, Command.Buffer, nBytesToCopy, &bytes);

	// Clear out our command buffer, incase we had 6 bytes
	memset(Command.Buffer, 0x90, sizeof(Command.Buffer));

	// Set our JMP command
	Command.Op = 0xE9;

	// With an address to the end of the Func[] bytes we pulled out of the original Send
	Command.Address = ((DWORD)func + (nBytesToCopy)) - ((DWORD)handlerFunction + asmSetupSize+6+5); // 6 = nop buffer, 5 = jmp space

	// Set our pData pointer to the JMP space of our handler function
	pData = ((PBYTE)handlerFunction + asmSetupSize + 6); // 6 = nop buffer

	// Write our Command to the JMP space of our handler function (5 bytes)
	res = WriteProcessMemory(GetCurrentProcess(), pData, Command.Buffer, 5, &bytes);

	// Command is already set to JMP, so all we need is the address
	//  Set the address to the beginning of the function handler
	Command.Address = (DWORD)handlerFunction - ((DWORD)func + nBytesToCopy);

	// Special case, if the byte size is 6, we need to fill in a NOP to remove any excess 0x10 (interrupt!)
	if ( nBytesToCopy == 6)
		Command.Buffer[5] = 0x90;

	// Write our new JMP hook to the original function, we're done modifying the local dll asm here...
	res = WriteProcessMemory(GetCurrentProcess(), func, Command.Buffer, nBytesToCopy, &bytes);

	// Protect and unlock handler function
	VirtualProtect(handlerFunction, asmSetupSize+6+5, prB , &prB);
	VirtualUnlock(handlerFunction, asmSetupSize+6+5);

	// Protect and unlock original WinSock2 function
	VirtualProtect(func, 6, prF, &prF);
	VirtualUnlock(func, 6);

	return nBytesToCopy;
}

BOOL InitInstance() 
{
	// Hook WS2_32.dll to hook Winsock2
	handleWS2_32 = LoadLibrary("ws2_32.dll");
	if(!handleWS2_32) return false; // if we didn't hook, return a bad init instance

	ULONG ulSize;
	PIMAGE_SECTION_HEADER foundHeader;
	// Pointer to import table for looking module
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToDataEx(handleWS2_32, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ulSize, &foundHeader);

	if (pExport != NULL)
	{
		const DWORD * pNames = (const DWORD *) ((PBYTE) handleWS2_32 + pExport->AddressOfNames);
		const WORD  * pOrds  = (const WORD  *) ((PBYTE) handleWS2_32 + pExport->AddressOfNameOrdinals);
		const DWORD * pAddr  = (const DWORD *) ((PBYTE) handleWS2_32 + pExport->AddressOfFunctions);
		DWORD ord = 0;					 // Keep address

		int functionCnt = 0; // we only want 4

		// Technically X cannot reach pExport->NumberOfFunctions or else it will fail, so maybe adjust this?
		for(DWORD x = 0; x < pExport->NumberOfFunctions; x++)
		{
			char * functionname = (char*)((PBYTE) handleWS2_32 + pNames[x]);

			ord = pExport->Base + pOrds[x];
			if(strcmp(functionname, "recv") == 0)
			{
				DWORD * pRVA = (DWORD *) ((PBYTE) handleWS2_32 + pExport->AddressOfFunctions) + ord - pExport->Base;
				PROC* func = (PROC*)((PBYTE)handleWS2_32 +  *pRVA);
				int bytesCopied = installHandlerASM(func, (void*)functionHandlerRecv, (20+6));
				if(bytesCopied)
				{
					// Save our address function, the size of the function in Winsock2, and a pointer to the now used NOP space of the function handler
					RecvData.AddressFunc=func;
					RecvData.BytesToCopy=bytesCopied;
					RecvData.AddressBuffer=((PBYTE)functionHandlerRecv + 20+6);
				}
				functionCnt++;
			}
			else if(strcmp(functionname, "WSARecv") == 0)
			{
				DWORD * pRVA = (DWORD *) ((PBYTE) handleWS2_32 + pExport->AddressOfFunctions) + ord - pExport->Base;
				PROC* func = (PROC*)((PBYTE)handleWS2_32 +  *pRVA);
				int bytesCopied = installHandlerASM(func, (void*)functionHandlerWSARecv, (35+6));
				if(bytesCopied)
				{
					// Save our address function, the size of the function in Winsock2, and a pointer to the now used NOP space of the function handler
					WSARecvData.AddressFunc=func;
					WSARecvData.BytesToCopy=bytesCopied;
					WSARecvData.AddressBuffer=((PBYTE)functionHandlerWSARecv + 35+6);
				}
				functionCnt++;
			}
			if ( functionCnt == 2 ){
				break;
			}
		}
	}

	return TRUE;
}

void ExitInstance()
{
	// LA - Every browser either uses a regular function, or a WSA function, so we can check for one or the other
	if(RecvData.isFilled())			// Recv
	{
		UnloadHookASM(RecvData);
	}
	if(WSARecvData.isFilled())		// WSARecv
	{
		UnloadHookASM(WSARecvData);
	}

	// Free Winsock 32 and set to NULL
	FreeLibrary(handleWS2_32);
	handleWS2_32 = NULL;
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

// This is our WSAReceive handler
static __declspec(naked) void functionHandlerWSARecv()
{
	__asm
	{
		; 35 bytes
		mov	eax, [esp+28]		; 28 = 7 variables * 2 bytes per mov * 2 bytes per push
		push eax				; SOCKET S
		mov	eax, [esp+28]
		push eax				; LPWSABUF lpBuffers
		mov	eax, [esp+28]
		push eax				; DWORD dwBufferCount
		mov	eax, [esp+28]
		push eax				; LPDWORD lpNumberOfBytesRecvd
		mov	eax, [esp+28]
		push eax				; LPDWORD lpFlags
		mov	eax, [esp+28]
		push eax				; LPWSAOVERLAPPED lpOverlapped
		mov	eax, [esp+28]
		push eax				; LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletion Routine
		mov eax, offset addr	; Place newWSARecv on top of execution stack
		push eax
		nop						; NOP space , 6 bytes used to retain original data
		nop						;    - buffer -
		nop						;    - buffer -
		nop						;    - buffer -
		nop						;    - buffer -
		nop						;    - buffer -
		nop						;  5 bytes, JMP space, overwritten in the original function
		nop
		nop
		nop
		nop
addr:
		push eax				; Save the original execution stack
		call newWSARecv			; Execute newWSARecv Function
		pop eax					; Pop off the original execution stack
		retn	28				; Return back 28 bytes
	}
}

// This is our Receive handler
static __declspec(naked) void functionHandlerRecv()
{
	__asm
	{
		; 20 bytes
		mov	eax, [esp+16]		; 16 = 4 variables * 2 bytes per mov * 2 bytes per push
		push eax				; SOCKET S
		mov	eax, [esp+16]
		push eax				; char FAR *buf
		mov	eax, [esp+16]
		push eax				; int len
		mov	eax, [esp+16]
		push eax				; int flags
		mov eax, offset addr	; 6 bytes, Place newRecv on top of execution stack
		push eax
		nop						; NOP space , 6 bytes used to retain original data
		nop						;    - buffer -
		nop						;    - buffer -
		nop						;    - buffer -
		nop						;    - buffer -
		nop						;    - buffer -
		nop						; 5 bytes of JMP Space, overwritten in the original function
		nop
		nop
		nop
		nop
addr:
		push eax				; Save the original execution stack
		call newRecv			; Execute newRecv Function
		pop eax					; Pop off the original execution stack
		retn	16				; Return back 16 bytes
	}
}
