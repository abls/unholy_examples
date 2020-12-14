#include <cstdio>
#include <Windows.h>

#pragma region Cdecl Return Tests

int __cdecl hacked_cdecl(char* message, int arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_cdecl %s %d\n", message, arg);
	return arg + 1;
}

__int64 __cdecl hacked_cdeclRtn64(char* message, __int64 arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_cdeclRtn64 %s %lld\n", message, arg);
	return arg + 2;
}

float __cdecl hacked_cdeclRtnFlt(char* message, float arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_cdeclRtnFlt %s %f\n", message, arg);
	return arg + 3;
}

double __cdecl hacked_cdeclRtnDbl(char* message, double arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_cdeclRtnDbl %s %lf\n", message, arg);
	return arg + 4;
}

#pragma endregion

#pragma region Stdcall Return Tests

int __stdcall hacked_stdcall(char* message, int arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_stdcall %s %d\n", message, arg);
	return arg + 1;
}

__int64 __stdcall hacked_stdcallRtn64(char* message, __int64 arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_stdcallRtn64 %s %lld\n", message, arg);
	return arg + 2;
}

float __stdcall hacked_stdcallRtnFlt(char* message, float arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_stdcallRtnFlt %s %f\n", message, arg);
	return arg + 3;
}

double __stdcall hacked_stdcallRtnDbl(char* message, double arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_stdcallRtnDbl %s %lf\n", message, arg);
	return arg + 4;
}

#pragma endregion

#pragma region Fastcall Return Tests

int __fastcall hacked_fastcall(char* message, int arg, int other_arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_fastcall %s %d [%d]\n", message, arg, other_arg);
	return arg + 1;
}

__int64 __fastcall hacked_fastcallRtn64(char* message, __int64 arg, int other_arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_fastcallRtn64 %s %lld [%d]\n", message, arg, other_arg);
	return arg + 2;
}

float __fastcall hacked_fastcallRtnFlt(char* message, float arg, int other_arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_fastcallRtnFlt %s %f [%d]\n", message, arg, other_arg);
	return arg + 3;
}

double __fastcall hacked_fastcallRtnDbl(char* message, double arg, int other_arg) {
	if (message == 0) {
		throw 666;
	}

	printf("hacked_fastcallRtnDbl %s %lf [%d]\n", message, arg, other_arg);
	return arg + 4;
}

#pragma endregion

#pragma region Callback Tests

int __cdecl caller_cdecl(void* func_addr) {
	printf("caller_cdecl\n");
	int retval = ((int(__cdecl*)(double))func_addr)(777);
	printf("callback_cdecl rtnval: %d\n", retval);
	return retval + 2;
}

int __stdcall caller_stdcall(void* func_addr) {
	printf("caller_stdcall\n");
	int retval = ((int(__stdcall*)(double))func_addr)(777);
	printf("callback_stdcall rtnval: %d\n", retval);
	return retval + 2;
}

int __fastcall caller_fastcall(void* func_addr) {
	printf("caller_fastcall\n");
	int retval = ((int(__fastcall*)(double))func_addr)(777);
	printf("callback_fastcall rtnval: %d\n", retval);
	return retval + 2;
}

#pragma endregion

void __cdecl hello() {
	printf("hello!!!\n");
}

int main() {
	hello();
	while (1) { Sleep(100); };
	return 0;
}

// Link-time code generation and whole program optimization have been
// disabled in this project's settings. This is to ensure that the
// compiler doesn't convert any calling conventions to be "faster"...
//   (it had been compiling some of the cdecls as fastcall)
//
// Programs you use bridges with DO NOT require these options to be
// set, since you would be determining the calling convention of
// target functions during reverse engineering, AFTER the program
// has been compiled. These options are only set this way to ensure
// that the demo environment is consistent.