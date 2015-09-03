// DLLMagic.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

#define MAX_LOADSTRING 100
#define MAXWAIT 10000
#define REFRESH_FPS 5				// 5 ticks per second for the auto-refresh

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];								// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];								// The title bar text
char name[1000];

typedef struct {
	DWORD pid;			// process ID
	HWND hWnd;			// process HWnd
	DWORD libModule;	// loaded Library Hwnd
	DWORD listIdx;		// which index am I on the windows list?
	bool hasInjected;	// have we already injected here?
	char name[128];		// Name of the Window
} Target;

std::vector<Target*> targetList;

bool autoRefreshing = false;

char dllFileName[MAX_PATH] = "";

static HWND hWnd, hwndList, hTool, hStatus;//, hwndFireButton, hwndRefreshButton, hwndFreeButton, hwndHookAllButton, hwndCheckrefresh;

// Foward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

bool insertDll(Target*);
bool removeDll(Target*);

int CALLBACK enumCallback(HWND hwnd, LPARAM lParam)
{
	int isChildEnumeration = lParam;

	//CString caption;
	TCHAR windowTitle[2049];
	memset(windowTitle, 0, sizeof(windowTitle));
	TCHAR className[MAX_PATH];
	TCHAR titleName[MAX_PATH];
	if(!IsWindow(hwnd)) // don't check hwnd's without a title
		return TRUE;

	//Check for a window class that sounds like a supported browser
	int nPathLength = GetClassName(hwnd, className, MAX_PATH);
	int nTitleLength = GetWindowText(hwnd, titleName, MAX_PATH);

	if (nPathLength == 0)
		return TRUE; //No class name.  No Match

	//static char * appList[] = {"IEFrame", "MozillaUIWindowClass", "Chrome_ContainerWin_0"};
	static char * appList[] = { "TabWindowClass", "MozillaWindowClass", "Chrome_ContainerWin_0" };
	static char * officialName[] = {"Internet Explorer", "Mozilla Firefox", "Google Chrome"};

	// Get our OS
	OSVERSIONINFO	vi;
	memset(&vi, 0, sizeof vi);
	vi.dwOSVersionInfoSize = sizeof vi;
	GetVersionEx(&vi);

	for(int i = 0; i < 3; i++){
		if (!strcmp(className, appList[i]) && nTitleLength > 0){
			// do some hooking magic
			char message[256];
			DWORD pid;
			DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
			
			Target * newTarget = new Target; 
			newTarget->pid = pid;
			newTarget->hWnd = hwnd;
			newTarget->libModule = 0x0;
			newTarget->listIdx = 0;
			strncpy(newTarget->name,appList[i],128);

			if ( strlen(dllFileName) == 0 ){
				newTarget->hasInjected = false;
				sprintf(message, "%s (%x)", officialName[i], hwnd);
			}
			else{

				// Lets check to see if we've already hooked this guy with our current DLL
				HMODULE hLocKernel32 = GetModuleHandle("Kernel32");
				FARPROC hLocGetModuleLibrary = GetProcAddress(hLocKernel32, "GetModuleHandleA");

				//Adjust token privileges to open system processes
				HANDLE hToken;
				TOKEN_PRIVILEGES tkp;
				if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
				{
					LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
					tkp.PrivilegeCount = 1;
					tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
					AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL);
				}

				//Open the process with all access
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, newTarget->pid);

				DWORD dllSize = (DWORD)strlen(dllFileName);
				LPVOID hRemoteMem = VirtualAllocEx(hProc, NULL, dllSize, MEM_COMMIT, PAGE_READWRITE);
 
				//Write the path to the Dll File in the location just created
				DWORD numBytesWritten;
				WriteProcessMemory(hProc, hRemoteMem, (void*)dllFileName, dllSize, &numBytesWritten);
				
				HANDLE hRemoteThread;

				// We are looking a a Windows XP machine or lower
				//Create a remote thread that starts begins at the LoadLibrary function and is passed are memory pointer
				hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)hLocGetModuleLibrary, hRemoteMem, 0, NULL);

				//Wait for the thread to finish
				bool res = false;
				if (hRemoteThread){
					res = (DWORD)WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;
				}

				DWORD hTmp = 0;	// handle if it exists
				GetExitCodeThread( hRemoteThread, &hTmp);
				
				if ( hTmp == NULL ){
					newTarget->hasInjected = false;
					sprintf(message, "%s (%x)", officialName[i], hwnd);
				
				}
				else{
					newTarget->hasInjected = true;
					newTarget->libModule = hTmp;
					sprintf(message, "%s (%x) (*injected*)", officialName[i], hwnd);
				}

				CloseHandle( hRemoteThread );

				//Free the memory created on the other process
				VirtualFreeEx(hProc, hRemoteMem, dllSize, MEM_RELEASE);

				//Release the handle to the other process
				CloseHandle(hProc);

			}

			targetList.insert(targetList.begin(), newTarget);
			SendMessage(hwndList, LB_INSERTSTRING, 0, (LPARAM)message);

			break;
		}
	}

	return TRUE;
}

void refreshList()
{
	while ( SendMessage(hwndList, LB_GETCOUNT, 0, 0) > 0 ){
		SendMessage(hwndList, LB_DELETESTRING, (WPARAM)0, 0);
	}
	while ( !targetList.empty() ){
		delete targetList[0];
		targetList.erase(targetList.begin());
	}
	
	// Check All windows
	EnumWindows(enumCallback, 0);
}

bool insertDll(Target * curTarget)
{
	// Get our OS
	OSVERSIONINFO	vi;
	memset(&vi, 0, sizeof vi);
	vi.dwOSVersionInfoSize = sizeof vi;
	GetVersionEx(&vi);

    //Find the address of the LoadLibrary api, luckily for us, it is loaded in the same address for every process
    HMODULE hLocKernel32 = GetModuleHandle("Kernel32");
    FARPROC hLocLoadLibrary = GetProcAddress(hLocKernel32, "LoadLibraryA");
	FARPROC hLocGetModuleLibrary = GetProcAddress(hLocKernel32, "GetModuleHandleA");

    //Adjust token privileges to open system processes
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL);
    }
 
    //Open the process with all access
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, curTarget->pid);
 
	DWORD dllSize = (DWORD)strlen(dllFileName);
    LPVOID hRemoteMem = VirtualAllocEx(hProc, NULL, dllSize, MEM_COMMIT, PAGE_READWRITE);
 
    //Write the path to the Dll File in the location just created
    DWORD numBytesWritten;
    WriteProcessMemory(hProc, hRemoteMem, (void*)dllFileName, dllSize, &numBytesWritten);
 
	HANDLE hRemoteThread;

	//Create a remote thread that starts begins at the LoadLibrary function and is passed are memory pointer
	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)hLocGetModuleLibrary, hRemoteMem, 0, NULL);


	bool res = false;
	if (hRemoteThread)
		res = (DWORD)WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;

	DWORD hLibModule = 0; // base of loaded module if it exists
	GetExitCodeThread( hRemoteThread, &hLibModule);

	// Has it already been loaded?
	if ( hLibModule ){
		VirtualFreeEx(hProc, hRemoteMem, dllSize, MEM_RELEASE);
		CloseHandle( hRemoteThread );
		CloseHandle( hProc );
		curTarget->libModule = hLibModule;
		curTarget->hasInjected = true;
		return false;
	}
	else{
		CloseHandle( hRemoteThread );
	}
	
	//Create a remote thread that starts begins at the LoadLibrary function and is passed are memory pointer
	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)hLocLoadLibrary, hRemoteMem, 0, NULL);

    //Wait for the thread to finish
    res = false;
    if (hRemoteThread)
        res = (DWORD)WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;
 
	hLibModule = 0;	// base adress of loaded module (==HMODULE);
	GetExitCodeThread( hRemoteThread, &hLibModule);

	CloseHandle( hRemoteThread );

    //Free the memory created on the other process
    VirtualFreeEx(hProc, hRemoteMem, dllSize, MEM_RELEASE);

	curTarget->libModule = hLibModule;

    //Release the handle to the other process
    CloseHandle(hProc);

	curTarget->hasInjected = true;

    return res;
}

bool removeDll(Target * curTarget)
{
    HMODULE hLocKernel32 = GetModuleHandle("Kernel32");
    FARPROC hLocFreeLibrary = GetProcAddress(hLocKernel32, "FreeLibrary");

    //Adjust token privileges to open system processes
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL);
    }

    //Open the process with all access
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, curTarget->pid);

    //Create a remote thread that starts begins at the LoadLibrary function and is passed are memory pointer
    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)hLocFreeLibrary, (void*)curTarget->libModule, 0, NULL);

    //Wait for the thread to finish
    bool res = false;
    if (hRemoteThread)
        res = (DWORD)WaitForSingleObject(hRemoteThread, MAXWAIT) != WAIT_TIMEOUT;
 
    //Release the handle to the other process
    CloseHandle(hProc);
 
	curTarget->hasInjected = false;

    return res;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_DLLMAGIC, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow)) 
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, (LPCTSTR)IDC_DLLMAGIC);

	// 50ms here, lower value gives higher speed
	//SetTimer((HWND)hWnd,1,REFRESH_FPS,NULL); // 30 fps updates

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0)) 
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) 
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage is only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX); 

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, (LPCTSTR)IDI_DLLMAGIC);
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= (LPCSTR)IDC_DLLMAGIC;
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDI_SMALL);

	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HANDLE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	InitCommonControls();

   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindowEx(WS_EX_APPWINDOW, szWindowClass, szTitle, WS_MINIMIZEBOX | WS_SYSMENU,
      CW_USEDEFAULT, CW_USEDEFAULT, 450, 320, NULL, NULL, hInstance, NULL);
	TBADDBITMAP tbBitmaps;
	tbBitmaps.hInst = hInst; // current instance
	tbBitmaps.nID = IDR_TOOLBAR1; // ID of the bitmap resource

    hTool = CreateWindowEx(0, TOOLBARCLASSNAME,NULL, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
        hWnd, (HMENU)IDC_MAINTOOL, tbBitmaps.hInst, NULL);

	SendMessage(hTool, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);

    if (SendMessage(hTool, TB_ADDBITMAP, 5, (LPARAM) &tbBitmaps) == -1)  
        return FALSE;

	TBBUTTON tbButtons[] = {
	   { 0, IDM_LOADDLL, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0L, 0},
	   { 0, 0, TBSTATE_ENABLED, TBSTYLE_SEP, 0L, -1},
	   { 1, IDM_INJECTDLL, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0L, 0},
	   { 2, IDM_REMOVEDLL, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0L, 0},
	   { 3, IDM_REFRESH, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0L, 0},
	   { 4, IDM_HOOKALL, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0L, 0}
	};

    // Add the buttons to the toolbar.
    SendMessage(hTool, TB_ADDBUTTONS, sizeof(tbButtons)/sizeof(TBBUTTON), (LPARAM) &tbButtons);

   hwndList = CreateWindowEx(WS_EX_CLIENTEDGE, "Listbox", NULL, LBS_NOINTEGRALHEIGHT | LBS_MULTIPLESEL | WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP,
	   0, 28, 445, 220, hWnd, (HMENU) IDC_LIST, hInst, NULL);

	hStatus = CreateWindowEx(0, STATUSCLASSNAME, NULL, WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP, 0, 0, 0, 0,
		hWnd, (HMENU)IDC_MAINSTATUS, hInst, NULL);

	SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)"No DLL Loaded...");

   // Refresh the Browser List
   EnumWindows(enumCallback, 0);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, unsigned, WORD, LONG)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent, i;
	PAINTSTRUCT ps;
	HDC hdc;
	TCHAR szHello[MAX_LOADSTRING];
	LoadString(hInst, IDS_HELLO, szHello, MAX_LOADSTRING);

	OPENFILENAME ofn;
	char szFileName[MAX_PATH] = "";

	HMENU hMenu;
	DWORD fdwMenu;

	switch (message) 
	{
		case WM_COMMAND:
			wmId    = LOWORD(wParam); 
			wmEvent = HIWORD(wParam); 
			// Parse the menu selections:
			switch (wmId)
			{
				case IDC_LIST:
					//if (wmEvent == LBN_SELCHANGE){
					//	int selId = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
					//	SendMessage(hwndList, LB_GETTEXT, selId, (LPARAM)listboxBuf);
						// grab the message in the list buf, then set our current PID accordingly
					//}
					break;
				case IDM_LOADDLL:
				case IDM_OPENDLL:
					ZeroMemory(&ofn, sizeof(ofn));
					ofn.lStructSize = sizeof(ofn);
					ofn.hwndOwner = hWnd;
					ofn.lpstrFilter = "Dll Files (*.dll)\0*.dll\0";
					ofn.lpstrFile = szFileName;
					ofn.nMaxFile = MAX_PATH;
					ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
					ofn.lpstrDefExt = "dll";
					if (GetOpenFileName(&ofn))
					{
						strcpy(dllFileName, ofn.lpstrFile);
						SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)dllFileName);
					}
				break;
				case IDM_INJECTDLL:
				case ID_ACTIONS_INJECTDLL:
					// kaboom
					if ( strlen(dllFileName) > 0 ){
						DWORD listCnt = SendMessage(hwndList, LB_GETCOUNT, 0, 0);
						for(unsigned int idx=0; idx < listCnt; idx++){
							if ( SendMessage(hwndList, LB_GETSEL, (WPARAM)idx, 0) > 0 ){
								insertDll(targetList[idx]);
							}
						}
						refreshList();
					}
					else{
						MessageBox(NULL, "Error, No DLL Loaded.", "Error", MB_OK);
					}
				break;
				case IDM_REMOVEDLL:
				case ID_ACTIONS_REMOVEDLL:
					if ( SendMessage(hwndList, LB_GETCOUNT, 0, 0) > 0 ){
						DWORD listCnt = SendMessage(hwndList, LB_GETCOUNT, 0, 0);
						for(unsigned int idx=0; idx < listCnt; idx++){
							if ( SendMessage(hwndList, LB_GETSEL, (WPARAM)idx, 0) > 0 ){
								removeDll(targetList[idx]);
							}
						}
						refreshList();
					}
					else{
						MessageBox(NULL, "No Window Selected.", "Error", MB_OK);
					}
					break;
				break;
				case IDM_REFRESH:
				case ID_ACTIONS_REFRESH:
					refreshList();
				break;
				case IDM_HOOKALL:
				case ID_ACTIONS_HOOKALL:
					if ( strlen(dllFileName) > 0 ){
						for(i = 0; i < SendMessage(hwndList, LB_GETCOUNT, 0, 0); i++)
							insertDll(targetList[i]);
						refreshList();
					}
					else{
						MessageBox(NULL, "Error, No DLL Loaded.", "Error", MB_OK);
					}
				break;
				case ID_ACTIONS_AUTOREFRESH:
					//SendMessage(hWnd, TB_CHECKBUTTON, (WPARAM)ID_ACTIONS_AUTOREFRESH, true);
					hMenu = GetMenu(hWnd);
					fdwMenu = GetMenuState(hMenu, (UINT) ID_ACTIONS_AUTOREFRESH, MF_BYCOMMAND);
					if ( fdwMenu & MF_CHECKED ){

						CheckMenuItem(GetMenu(hWnd), ID_ACTIONS_AUTOREFRESH, MF_BYCOMMAND | MF_UNCHECKED);
						autoRefreshing = false;
					}
					else{
						CheckMenuItem(GetMenu(hWnd), ID_ACTIONS_AUTOREFRESH, MF_BYCOMMAND | MF_CHECKED);
						autoRefreshing = true;
					}
				break;
/*
				case AUTOREFRESH_CHECK:
					if (SendMessage(hwndCheckrefresh,BM_GETCHECK,0,0)==BST_UNCHECKED) {
						autoRefreshing = false;	
					}
					else {
						autoRefreshing = true;
					}
					break;
*/
				case IDM_ABOUT:
				   DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hWnd, (DLGPROC)About);
				   break;
				case IDM_EXIT:
				   DestroyWindow(hWnd);
				   break;
				default:
				   return DefWindowProc(hWnd, message, wParam, lParam);
			}
			break;
		case WM_TIMER:
			//if ( autoRefreshing == true ){
			//	autoRefresh();
			//}
			break;
		case WM_PAINT:
			hdc = BeginPaint(hWnd, &ps);
			// TODO: Add any drawing code here...
			RECT rt;
			GetClientRect(hWnd, &rt);
			DrawText(hdc, szHello, strlen(szHello), &rt, DT_CENTER);
			EndPaint(hWnd, &ps);
			break;
		case WM_DESTROY:
			//KillTimer((HWND)hWnd,1);
			PostQuitMessage(0);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
   }
   return 0;
}

// Mesage handler for about box.
LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_INITDIALOG:
				return TRUE;

		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) 
			{
				EndDialog(hDlg, LOWORD(wParam));
				return TRUE;
			}
			break;
	}
    return FALSE;
}
