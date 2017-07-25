#include "SysCaller.h"

BOOL startup(LPCTSTR lpApplicationName, wchar_t * CommandLine)
{
	// additional information
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	BOOL bResult;

	// set the size of the structures
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// start the program up
	bResult = CreateProcess(lpApplicationName,   // the path
		CommandLine,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi           // Pointer to PROCESS_INFORMATION structure
	);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return bResult;
}