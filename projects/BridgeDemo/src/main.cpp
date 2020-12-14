#include <stdio.h>
#include <stdint.h>
#include <Windows.h>

#include "unholy/win32memory.hpp"
#include "unholy/win32bridges.hpp"

#define MOD_NAME "DemoTarget.exe"

// --- BEGIN OFFSETS
// These are offsets from the base address of the target module
// You need to do some reverse engineering yourself to get these,
// after you compile the target executable...
// (just search strings)
//

#define OFF_HELLO 0x17D0

#define OFF_HACKED_CDECL        0x1540
#define OFF_HACKED_CDECL_RTN64  0x1580
#define OFF_HACKED_CDECL_RTNFLT 0x15D0
#define OFF_HACKED_CDECL_RTNDBL 0x1B70

#define OFF_HACKED_STDCALL        0x1700
#define OFF_HACKED_STDCALL_RTN64  0x1740
#define OFF_HACKED_STDCALL_RTNFLT 0x17E0
#define OFF_HACKED_STDCALL_RTNDBL 0x1790

#define OFF_HACKED_FASTCALL        0x1620
#define OFF_HACKED_FASTCALL_RTN64  0x1660
#define OFF_HACKED_FASTCALL_RTNFLT 0x27B0
#define OFF_HACKED_FASTCALL_RTNDBL 0x16B0

#define OFF_CALLER_CDECL 0x1420
#define OFF_CALLER_STDCALL 0x14B0
#define OFF_CALLER_FASTCALL 0x1470

//
// --- END OFFSETS

// Typedefs of remote functions
//

typedef void(__cdecl* hello_t)();

typedef int(__cdecl* hacked_cdecl_t)(char* message, int arg);
typedef __int64(__cdecl* hacked_cdeclRtn64_t)(char* message, __int64 arg);
typedef float(__cdecl* hacked_cdeclRtnFlt_t)(char* message, float arg);
typedef double(__cdecl* hacked_cdeclRtnDbl_t)(char* message, double arg);

typedef int(__stdcall* hacked_stdcall_t)(char* message, int arg);
typedef __int64(__stdcall* hacked_stdcallRtn64_t)(char* message, __int64 arg);
typedef float(__stdcall* hacked_stdcallRtnFlt_t)(char* message, float arg);
typedef double(__stdcall* hacked_stdcallRtnDbl_t)(char* message, double arg);

typedef int(__fastcall* hacked_fastcall_t)(char* message, int arg, int other_arg);
typedef __int64(__fastcall* hacked_fastcallRtn64_t)(char* message, __int64 arg, int other_arg);
typedef float(__fastcall* hacked_fastcallRtnFlt_t)(char* message, float arg, int other_arg);
typedef double(__fastcall* hacked_fastcallRtnDbl_t)(char* message, double arg, int other_arg);

typedef int(__cdecl* caller_cdecl_t)(void* func_addr);
typedef int(__stdcall* caller_stdcall_t)(void* func_addr);
typedef int(__fastcall* caller_fastcall_t)(void* func_addr);

// Callbacks to be called from the remote process
//

int __cdecl callback_cdecl(HANDLE rmt_handle, double n) {
	printf("arg passed to cdecl callback: %lf\n", n);
	return 888;
}

int __stdcall callback_stdcall(HANDLE rmt_handle, double n) {
	printf("arg passed to stdcall callback: %lf\n", n);
	return 888;
}

int __fastcall callback_fastcall(HANDLE rmt_handle, double n) {
	printf("arg passed to fastcall callback: %lf\n", n);
	return 888;
}

int main() {
	printf("About to begin demo...\n\n");

	uint32_t rmt_pid = MemRmt::getPid(MOD_NAME);
	HANDLE rmt_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, rmt_pid);
	uint32_t img_base_addr = MemRmt::getModBase(rmt_pid, MOD_NAME);
	char* message = MemRmt::allocWriteString(rmt_handle, "hiii how are you???");

	/////////////////
	// CDECL DEMOS //
	/////////////////

	hacked_cdecl_t hacked_cdecl = Bridges::createBridgeRmt<hacked_cdecl_t>(rmt_handle, img_base_addr + OFF_HACKED_CDECL, TFUNC_CDECL, BRIDGE_ARGS(char*, int));
	int hacked_cdecl_rtnval = hacked_cdecl(message, 666);
	printf("hacked_cdecl_rtnval: %d\n", hacked_cdecl_rtnval);

	try {
		hacked_cdecl_rtnval = hacked_cdecl(0, 666);
	} catch (...) {
		hacked_cdecl_rtnval = 123;
		printf("CAUGHT hacked_cdecl_rtnval: %d\n", hacked_cdecl_rtnval);
	}

	hacked_cdeclRtn64_t hacked_cdeclRtn64 = Bridges::createBridgeRmt<hacked_cdeclRtn64_t>(rmt_handle, img_base_addr + OFF_HACKED_CDECL_RTN64, TFUNC_CDECL_RTN64, BRIDGE_ARGS(char*, __int64));
	__int64 hacked_cdeclRtn64_rtnval = hacked_cdeclRtn64(message, 666);
	printf("hacked_cdeclRtn64_rtnval: %lld\n", hacked_cdeclRtn64_rtnval);

	hacked_cdeclRtnFlt_t hacked_cdeclRtnFlt = Bridges::createBridgeRmt<hacked_cdeclRtnFlt_t>(rmt_handle, img_base_addr + OFF_HACKED_CDECL_RTNFLT, TFUNC_CDECL_RTNFLT, BRIDGE_ARGS(char*, float));
	float hacked_cdeclRtnFlt_rtnval = hacked_cdeclRtnFlt(message, 666);
	printf("hacked_cdeclRtnFlt_rtnval: %f\n", hacked_cdeclRtnFlt_rtnval);

	hacked_cdeclRtnDbl_t hacked_cdeclRtnDbl = Bridges::createBridgeRmt<hacked_cdeclRtnDbl_t>(rmt_handle, img_base_addr + OFF_HACKED_CDECL_RTNDBL, TFUNC_CDECL_RTNDBL, BRIDGE_ARGS(char*, double));
	double hacked_cdeclRtnDbl_rtnval = hacked_cdeclRtnDbl(message, 666);
	printf("hacked_cdeclRtnDbl_rtnval: %lf\n", hacked_cdeclRtnDbl_rtnval);

	try {
		hacked_cdecl_rtnval = hacked_cdecl(0, 666);
	} catch (...) {
		hacked_cdecl_rtnval = 123;
		printf("CAUGHT hacked_cdecl_rtnval: %d\n", hacked_cdecl_rtnval);
	}

	try {
		hacked_cdeclRtn64_rtnval = hacked_cdeclRtn64(0, 666);
	} catch (...) {
		hacked_cdeclRtn64_rtnval = 123;
		printf("CAUGHT hacked_cdeclRtn64_rtnval: %lld\n", hacked_cdeclRtn64_rtnval);
	}

	try {
		hacked_cdeclRtnFlt_rtnval = hacked_cdeclRtnFlt(0, 666);
	} catch (...) {
		hacked_cdeclRtnFlt_rtnval = 123;
		printf("CAUGHT hacked_cdeclRtnFlt_rtnval: %f\n", hacked_cdeclRtnFlt_rtnval);
	}

	try {
		hacked_cdeclRtnDbl_rtnval = hacked_cdeclRtnDbl(0, 666);
	} catch (...) {
		hacked_cdeclRtnDbl_rtnval = 123;
		printf("CAUGHT hacked_cdeclRtnDbl_rtnval: %lf\n", hacked_cdeclRtnDbl_rtnval);
	}

	///////////////////
	// STDCALL DEMOS //
	///////////////////

	hacked_stdcall_t hacked_stdcall = Bridges::createBridgeRmt<hacked_stdcall_t>(rmt_handle, img_base_addr + OFF_HACKED_STDCALL, TFUNC_STDCALL, BRIDGE_ARGS(char*, int));
	int hacked_stdcall_rtnval = hacked_stdcall(message, 666);
	printf("hacked_stdcall_rtnval: %d\n", hacked_stdcall_rtnval);

	hacked_stdcallRtn64_t hacked_stdcallRtn64 = Bridges::createBridgeRmt<hacked_stdcallRtn64_t>(rmt_handle, img_base_addr + OFF_HACKED_STDCALL_RTN64, TFUNC_STDCALL_RTN64, BRIDGE_ARGS(char*, __int64));
	__int64 hacked_stdcallRtn64_rtnval = hacked_stdcallRtn64(message, 666);
	printf("hacked_stdcallRtn64_rtnval: %lld\n", hacked_stdcallRtn64_rtnval);

	hacked_stdcallRtnFlt_t hacked_stdcallRtnFlt = Bridges::createBridgeRmt<hacked_stdcallRtnFlt_t>(rmt_handle, img_base_addr + OFF_HACKED_STDCALL_RTNFLT, TFUNC_STDCALL_RTNFLT, BRIDGE_ARGS(char*, float));
	float hacked_stdcallRtnFlt_rtnval = hacked_stdcallRtnFlt(message, 666);
	printf("hacked_stdcallRtnFlt_rtnval: %f\n", hacked_stdcallRtnFlt_rtnval);

	hacked_stdcallRtnDbl_t hacked_stdcallRtnDbl = Bridges::createBridgeRmt<hacked_stdcallRtnDbl_t>(rmt_handle, img_base_addr + OFF_HACKED_STDCALL_RTNDBL, TFUNC_STDCALL_RTNDBL, BRIDGE_ARGS(char*, double));
	double hacked_stdcallRtnDbl_rtnval = hacked_stdcallRtnDbl(message, 666);
	printf("hacked_stdcallRtnDbl_rtnval: %lf\n", hacked_stdcallRtnDbl_rtnval);

	try {
		hacked_stdcall_rtnval = hacked_stdcall(0, 666);
	} catch (...) {
		hacked_stdcall_rtnval = 123;
		printf("CAUGHT hacked_stdcall_rtnval: %d\n", hacked_stdcall_rtnval);
	}

	try {
		hacked_stdcallRtn64_rtnval = hacked_stdcallRtn64(0, 666);
	} catch (...) {
		hacked_stdcallRtn64_rtnval = 123;
		printf("CAUGHT hacked_stdcallRtn64_rtnval: %lld\n", hacked_stdcallRtn64_rtnval);
	}

	try {
		hacked_stdcallRtnFlt_rtnval = hacked_stdcallRtnFlt(0, 666);
	} catch (...) {
		hacked_stdcallRtnFlt_rtnval = 123;
		printf("CAUGHT hacked_stdcallRtnFlt_rtnval: %f\n", hacked_stdcallRtnFlt_rtnval);
	}

	try {
		hacked_stdcallRtnDbl_rtnval = hacked_stdcallRtnDbl(0, 666);
	} catch (...) {
		hacked_stdcallRtnDbl_rtnval = 123;
		printf("CAUGHT hacked_stdcallRtnDbl_rtnval: %lf\n", hacked_stdcallRtnDbl_rtnval);
	}

	////////////////////
	// FASTCALL DEMOS //
	////////////////////

	hacked_fastcall_t hacked_fastcall = Bridges::createBridgeRmt<hacked_fastcall_t>(rmt_handle, img_base_addr + OFF_HACKED_FASTCALL, TFUNC_FASTCALL, BRIDGE_ARGS(char*, int, int));
	int hacked_fastcall_rtnval = hacked_fastcall(message, 666, 520420);
	printf("hacked_fastcall_rtnval: %d\n", hacked_fastcall_rtnval);

	hacked_fastcallRtn64_t hacked_fastcallRtn64 = Bridges::createBridgeRmt<hacked_fastcallRtn64_t>(rmt_handle, img_base_addr + OFF_HACKED_FASTCALL_RTN64, TFUNC_FASTCALL_RTN64, BRIDGE_ARGS(char*, __int64, int));
	__int64 hacked_fastcallRtn64_rtnval = hacked_fastcallRtn64(message, 666, 520420);
	printf("hacked_fastcallRtn64_rtnval: %lld\n", hacked_fastcallRtn64_rtnval);

	hacked_fastcallRtnFlt_t hacked_fastcallRtnFlt = Bridges::createBridgeRmt<hacked_fastcallRtnFlt_t>(rmt_handle, img_base_addr + OFF_HACKED_FASTCALL_RTNFLT, TFUNC_FASTCALL_RTNFLT, BRIDGE_ARGS(char*, float, int));
	float hacked_fastcallRtnFlt_rtnval = hacked_fastcallRtnFlt(message, 666, 520420);
	printf("hacked_fastcallRtnFlt_rtnval: %f\n", hacked_fastcallRtnFlt_rtnval);

	hacked_fastcallRtnDbl_t hacked_fastcallRtnDbl = Bridges::createBridgeRmt<hacked_fastcallRtnDbl_t>(rmt_handle, img_base_addr + OFF_HACKED_FASTCALL_RTNDBL, TFUNC_FASTCALL_RTNDBL, BRIDGE_ARGS(char*, double, int));
	double hacked_fastcallRtnDbl_rtnval = hacked_fastcallRtnDbl(message, 666, 520420);
	printf("hacked_fastcallRtnDbl_rtnval: %lf\n", hacked_fastcallRtnDbl_rtnval);

	try {
		hacked_fastcall_rtnval = hacked_fastcall(0, 666, 520420);
	} catch (...) {
		hacked_fastcall_rtnval = 123;
		printf("CAUGHT hacked_fastcall_rtnval: %d\n", hacked_fastcall_rtnval);
	}

	try {
		hacked_fastcallRtn64_rtnval = hacked_fastcallRtn64(0, 666, 520420);
	} catch (...) {
		hacked_fastcallRtn64_rtnval = 123;
		printf("CAUGHT hacked_fastcallRtn64_rtnval: %lld\n", hacked_fastcallRtn64_rtnval);
	}

	try {
		hacked_fastcallRtnFlt_rtnval = hacked_fastcallRtnFlt(0, 666, 520420);
	} catch (...) {
		hacked_fastcallRtnFlt_rtnval = 123;
		printf("CAUGHT hacked_fastcallRtnFlt_rtnval: %f\n", hacked_fastcallRtnFlt_rtnval);
	}

	try {
		hacked_fastcallRtnDbl_rtnval = hacked_fastcallRtnDbl(0, 666, 520420);
	} catch (...) {
		hacked_fastcallRtnDbl_rtnval = 123;
		printf("CAUGHT hacked_fastcallRtnDbl_rtnval: %lf\n", hacked_fastcallRtnDbl_rtnval);
	}

	////////////////////
	// CALLBACK DEMOS //
	////////////////////

	/*caller_cdecl_t caller_cdecl = Bridges::createBridgeRmt<caller_cdecl_t>(rmt_handle, img_base_addr + OFF_CALLER_CDECL, TFUNC_CDECL, BRIDGE_ARGS(void*));
	void* rmt_callback_cdecl = Bridges::createBridgeLocal(rmt_handle, callback_cdecl, TFUNC_CDECL, BRIDGE_ARGS(double));
	int caller_cdecl_rtnval = caller_cdecl(rmt_callback_cdecl);
	printf("caller_cdecl_rtnval: %d\n", caller_cdecl_rtnval);

	caller_stdcall_t caller_stdcall = Bridges::createBridgeRmt<caller_stdcall_t>(rmt_handle, img_base_addr + OFF_CALLER_STDCALL, TFUNC_STDCALL, BRIDGE_ARGS(void*));
	void* rmt_callback_stdcall = Bridges::createBridgeLocal(rmt_handle, callback_stdcall, TFUNC_STDCALL, BRIDGE_ARGS(double));
	int caller_stdcall_rtnval = caller_stdcall(rmt_callback_stdcall);
	printf("caller_stdcall_rtnval: %d\n", caller_stdcall_rtnval);

	caller_fastcall_t caller_fastcall = Bridges::createBridgeRmt<caller_fastcall_t>(rmt_handle, img_base_addr + OFF_CALLER_FASTCALL, TFUNC_FASTCALL, BRIDGE_ARGS(void*));
	void* rmt_callback_fastcall = Bridges::createBridgeLocal(rmt_handle, callback_fastcall, TFUNC_FASTCALL, BRIDGE_ARGS(double));
	int caller_fastcall_rtnval = caller_fastcall(rmt_callback_fastcall);
	printf("caller_fastcall_rtnval: %d\n", caller_fastcall_rtnval);*/

	printf("\nDemo complete!\n");
	Sleep(INFINITE);
}