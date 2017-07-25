#ifndef _PERSISTENCE_H_
	#define _PERSISTENCE_H_

#include <windows.h>

BOOL RegisterMyProgramForStartup(PCWSTR pszAppName, PCWSTR pathToExe, PCWSTR args);
BOOL RegisterProgram(PCWSTR pszAppName, wchar_t szPathToExe[MAX_PATH]);

BOOL IsMyProgramRegisteredForStartup(PCWSTR pszAppName);

#endif