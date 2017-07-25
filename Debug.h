#ifndef _DEBUG_H_
	#define _DEBUG_H_

typedef enum DebugLevel {
	Action,
	Notice,
	Raw,
	Error
} DebugLevel;


char GetDebugLevelCh(DebugLevel level);


void PrintT(DebugLevel level, char * str);
void PrintW(DebugLevel level, wchar_t * str);

#endif