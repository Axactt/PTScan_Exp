#include<Windows.h>
#include<iostream>
#include"SigScan_RIP.h"

// This is the thread function created be CreateThread function from DllMain
DWORD APIENTRY MyThreadFunc(HMODULE hinstDLL)  // PVOID parameter replaced by HMODULE parameter
{
	//Allocate a console to check the output, loading and unloading
	AllocConsole();
	FILE* f;
	freopen_s( &f, "CONOUT$", "w", stdout );
	//Craete an instance of MemoryScanner class, passing the name of the module you want to scan as the parameter
	//Note each time you have to find a pattern , CREATE NEW INSTANCE OF Memoryscanner CLass to work it properly
	{
		MemoryScanner mScan { "learngamehacking1.exe" }; // get this from crackme-folder
		//Call the findpattern function and get the address
		byte bytePattern[] = "\x4C\x8D\x05\x71\x32\x00\x00\xBA\x01\x00\x00\x00\x48\x8D\x4C\x24\x20\xE8\x00\x00\x00\x00";
		char byteMask[] = "xxxxxxxxxxxxxxxxxx????";

		ptrdiff_t addressFound = mScan.FindPattern( bytePattern, byteMask ).GetAddress();
		// this prints the address found at the end of signature scan bytes
		std::cout << " The address of signature found is: " << std::hex << addressFound << '\n';

		// we need to test the absolute address finding code now which will find the address from rip relative offset
		int whole_inst_size = 7; // size of the whole  instruction where rip relative offset is present
		int ofst_firstInstByt_firstAddrByt = 3; // this is offset diffrence of byte numbers between first instruction byte and first byte of relative offset
		// Find out the absolute address which is prsent as RIP relative address

		ptrdiff_t  absAddrs { mScan.GetAbsoluteAddress( whole_inst_size, ofst_firstInstByt_firstAddrByt ) };

		// Print out the absolute address of memory/data reference which is present as relative int32 offset

		std::cout << " The absolute address of rip relative address is: " << std::hex << absAddrs << '\n';
	}

	FreeLibraryAndExitThread( hinstDLL, 0 );
	
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		::DisableThreadLibraryCalls( hinstDLL );
		CreateThread( nullptr, 0, (LPTHREAD_START_ROUTINE) MyThreadFunc, hinstDLL, 0, nullptr );
		break;

		case DLL_PROCESS_DETACH: // unloads the dll 

		break;

	}

	return TRUE;
}