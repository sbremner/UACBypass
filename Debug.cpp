/*
	Printing messages to the console
*/

#include "Debug.h"

#include <stdio.h>
#include <tchar.h>
#include <io.h>
#include <fcntl.h>

char GetDebugLevelCh(DebugLevel level)
{
	switch (level)
	{
	case DebugLevel::Action:
		return '+';
	case DebugLevel::Notice:
		return '*';
	case DebugLevel::Error:
		return '!';
	default:
		return '-';
	}
}

void PrintT(DebugLevel level, char * str)
{
	if (level == DebugLevel::Raw)
	{
		printf("%s\n", str);
	}
	else
	{
		printf("[%c] :: %s\n", GetDebugLevelCh(level), str);
	}
}

void PrintW(DebugLevel level, wchar_t * str)
{
	if (level == DebugLevel::Raw)
	{
		wprintf(L"%s\n", str);
	}
	else
	{
		wprintf(L"[%c] :: %s\n", GetDebugLevelCh(level), str);
	}
}