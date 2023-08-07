#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <windows.h>
#include "Tlhelp32.h"
#include <wchar.h>
#include <debugapi.h>
#include "protextion/xorstr.hpp"
#include "protextion/protectmain.h"
#include "protextion/anti_debugger.h"
#include <random>
#include <Shlwapi.h>
#include <cstdlib>
#include <ctime>
#include <Urlmon.h>
#include <ShlObj.h>
#include <lm.h>
#include "Auth/auth.hpp"
#include "BE/be_service.hpp"
#include "BE/installer.hpp"
#include "BE/game_launcher.hpp"
#include "Auth/skStr.h"
#include "Auth/utils.hpp"
#include <Psapi.h>
#include "krnel.h"
#include "mapper.h"
#include "cleaner.h"

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "urlmon.lib")


std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

using namespace KeyAuth;
std::string name = XorStr("MExploitUI");
std::string ownerid = XorStr("r7sn2M1IOH");
std::string secret = XorStr("8c327a7aa478571f8b5efb6c37d2cd6353c186ac63c20cf3ba99d3f6fb567a36");
std::string version = XorStr("1.0");
std::string url = XorStr("https://keyauth.win/api/1.2/");


std::string GenerateRandomName()
{
	const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+|{}:>?";
	const int length = 40;
	std::string randomName;
	randomName.reserve(length);
	std::srand(static_cast<unsigned int>(std::time(nullptr)));
	for (int i = 0; i < length; ++i)
	{
		randomName += charset[std::rand() % charset.length()];
	}
	return randomName;
}

namespace Utilities
{
	bool ReadFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer);
	bool CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size);
}

bool Utilities::ReadFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer)
{
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	return true;
}

bool Utilities::CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size)
{
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size))
	{
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

void DeleteFolderRecursive(const std::wstring& folderPath) {
	WIN32_FIND_DATAW findData;
	HANDLE findHandle;
	std::wstring searchPath = folderPath + L"\\*";

	findHandle = FindFirstFileW(searchPath.c_str(), &findData);
	if (findHandle == INVALID_HANDLE_VALUE) {
		// Failed to find any file or folder
		return;
	}

	do {
		if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
			std::wstring filePath = folderPath + L"\\" + findData.cFileName;
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				// Recursive call to delete subfolders
				DeleteFolderRecursive(filePath);
			}
			else {
				// Delete files
				DeleteFileW(filePath.c_str());
			}
		}
	} while (FindNextFileW(findHandle, &findData));

	FindClose(findHandle);
	RemoveDirectoryW(folderPath.c_str());
}

void createDirectory(const std::string& directoryPath) {
	// Check if the directory already exists
	if (std::filesystem::exists(directoryPath)) {

	}
	else {
		// Create the directory
		if (std::filesystem::create_directory(directoryPath)) {

		}
		else
		{

		}
	}
}

bool isConsoleVisible = true;

// Function to show or hide the console window
void ToggleConsoleVisibility()
{
	HWND hwndConsole = GetConsoleWindow();
	if (isConsoleVisible)
		ShowWindow(hwndConsole, SW_HIDE);
	else
		ShowWindow(hwndConsole, SW_SHOW);
	isConsoleVisible = !isConsoleVisible;
}

void timerLoop(int interval)
{
	while (true) {
		// Get the current time
		auto start = std::chrono::steady_clock::now();
		std::string randomName = GenerateRandomName();
		std::string fixedString = "";
		std::string consoleTitle = randomName + fixedString;
		SetConsoleTitle(consoleTitle.c_str());
		auto end = std::chrono::steady_clock::now();
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		std::this_thread::sleep_for(std::chrono::milliseconds(interval - elapsed));
	}
}
bool WriteToProcessMemory(HANDLE processHandle, DWORD addressToWrite, const BYTE* buffer, SIZE_T size) {
	return WriteProcessMemory(processHandle, (LPVOID)addressToWrite, buffer, size, NULL) != 0;
}

std::string LOGO = XorStr(R"(
         __   __  _______  __   __  _______  ______    __   __    _______  __   __  _______  ___      _______  ___   _______ 
        |  |_|  ||       ||  |_|  ||       ||    _ |  |  | |  |  |       ||  |_|  ||       ||   |    |       ||   | |       |
        |       ||    ___||       ||   _   ||   | ||  |  |_|  |  |    ___||       ||    _  ||   |    |   _   ||   | |_     _|
        |       ||   |___ |       ||  | |  ||   |_||_ |       |  |   |___ |       ||   |_| ||   |    |  | |  ||   |   |   |  
        |       ||    ___||       ||  |_|  ||    __  ||_     _|  |    ___| |     | |    ___||   |___ |  |_|  ||   |   |   |  
        | ||_|| ||   |___ | ||_|| ||       ||   |  | |  |   |    |   |___ |   _   ||   |    |       ||       ||   |   |   |  
        |_|   |_||_______||_|   |_||_______||___|  |_|  |___|    |_______||__| |__||___|    |_______||_______||___|   |___|  
)");

std::string LINE = XorStr(R"(-------------------------------------------------------------------------------------------------------------------------------------)");
api KeyAuthApp(name, ownerid, secret, version, url);




void kill_process1()
{
	system(XorStr("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1").c_str());
	system(XorStr("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq HTTPDebuggerSvc*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq HTTPDebuggerUI*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq KsDumperClient*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq FolderChangesView*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq ProcessHacker*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq KsDumperClient*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq procmon*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq idaq*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq idaq64*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq Bearmer*\" /IM * /F /T >nul 2>&1").c_str());
}

void blue_screen1()
{
	system(XorStr("taskkill.exe /f /im svchost.exe").c_str());
}

void find_exe_title()
{
	while (true) {
		if (FindWindowA(NULL, skCrypt("KsDumperClient.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("HTTPDebuggerUI.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("HTTPDebuggerSvc.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("FolderChangesView.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("ProcessHacker.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("procmon.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("idaq.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("idaq64.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("Wireshark.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("Fiddler.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("Xenos64.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("Cheat Engine.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("HTTP Debugger Windows Service (32 bit).exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("KsDumper.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("x64dbg.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("ProcessHacker.exe")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("IDA: Quick start")))
		{
			blue_screen1();
		}

		if (FindWindowA(NULL, skCrypt("Memory Viewer")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("Process List")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("KsDumper")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("HTTP Debugger")))
		{
			blue_screen1();
		}
		if (FindWindowA(NULL, skCrypt("OllyDbg")))
		{
			blue_screen1();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(3900));

	}
}
void bsod()
{
	system(XorStr("taskkill.exe /f /im svchost.exe").c_str());
}
void DetectDebuggerThread1()
{
	while (true)
	{
		if (FindWindowA(NULL, skCrypt("Resource Monitor"))) { Beep(200, 200); system("taskkill /F /T /IM perfmon.exe"); exit(-1); }
		if (FindWindowA(NULL, skCrypt("The Wireshark Network Analyzer"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Progress Telerik Fiddler Web Debugger"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Fiddler"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("HTTP Debugger"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("x64dbg"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("dnSpy"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("FolderChangesView"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("BinaryNinja"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("HxD"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.2"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.1"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.0"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 6.9"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.3"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.4"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.5"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Cheat Engine 7.6"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Ida"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Ida Pro"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Ida Freeware"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("HTTP Debugger Pro"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Process Hacker"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("Process Hacker 2"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("OllyDbg"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("The Wireshark Network Analyzer")))
		{
			bsod();
		}
		if (FindWindowA(NULL, skCrypt("Progress Telerik Fiddler Web Debugger")))
		{
			bsod();
		}
		if (FindWindowA(NULL, skCrypt("x64dbg"))) { bsod(); }
		if (FindWindowA(NULL, skCrypt("KsDumper"))) { bsod(); }
	}
}
void tasky11()
{
	system(XorStr("net stop FACEIT >nul 2>&1").c_str());
	system(XorStr(("net stop ESEADriver2 >nul 2>&1")).c_str());
	system(XorStr(("sc stop HTTPDebuggerPro >nul 2>&1")).c_str());
	system(XorStr(("sc stop KProcessHacker3 >nul 2>&1")).c_str());
	system(XorStr(("sc stop KProcessHacker2 >nul 2>&1")).c_str());
	system(XorStr(("sc stop KProcessHacker1 >nul 2>&1")).c_str());
	system(XorStr(("sc stop wireshark >nul 2>&1")).c_str());
	system(XorStr(("sc stop npf >nul 2>&1")).c_str());
	system(skCrypt("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(skCrypt("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq rawshark*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq charles*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker3 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker2 >nul 2>&1"));
	system(skCrypt("sc stop KProcessHacker1 >nul 2>&1"));
	system(skCrypt("sc stop wireshark >nul 2>&1"));
	system(skCrypt("sc stop npf >nul 2>&1"));
}


void mainprotect()
{
	std::thread(hidethread).detach();
	std::thread(remotepresent).detach();
	std::thread(contextthread).detach();
	std::thread(debugstring).detach();
	std::thread(kill_process1).detach();
	std::thread(find_exe_title).detach();
	std::thread(tasky11).detach();
	std::thread(DetectDebuggerThread1).detach();
}




bool IsProcessRunning(const wchar_t* processName) {
	DWORD processes[1024], bytesNeeded;
	if (!EnumProcesses(processes, sizeof(processes), &bytesNeeded)) {
		return false;
	}

	// Calculate the number of processes
	DWORD numProcesses = bytesNeeded / sizeof(DWORD);

	// Get a handle to the current process
	HANDLE hCurrentProcess = GetCurrentProcess();

	for (DWORD i = 0; i < numProcesses; ++i) {
		// Skip the current process
		if (processes[i] == GetProcessId(hCurrentProcess)) {
			continue;
		}

		// Get a handle to the process
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
		if (hProcess) {
			wchar_t szProcessName[MAX_PATH] = L"";
			if (GetModuleBaseNameW(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(wchar_t))) {
				if (_wcsicmp(szProcessName, processName) == 0) {
					CloseHandle(hProcess);
					return true;
				}
			}
			CloseHandle(hProcess);
		}
	}

	return false;
}

void WaitForProcessStart(const wchar_t* processName) {
	while (!IsProcessRunning(processName)) {
		// Adjust the sleep duration according to your needs
		Sleep(1000); // Wait for 1 second before checking again
	}
}


bool ReadProcessMemoryValue(HANDLE processHandle, DWORD address, BYTE& value) {
	SIZE_T bytesRead;
	if (ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(address), &value, sizeof(value), &bytesRead)) {
		return (bytesRead == sizeof(value));
	}
	return false;
}



DWORD GetProcessIdByName(const std::wstring& processName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Error creating snapshot: " << GetLastError() << std::endl;
		return 0;
	}

	PROCESSENTRY32W pe; // Use PROCESSENTRY32W for wide-character strings
	pe.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(hSnapshot, &pe)) { // Use Process32FirstW for wide-character strings
		do {
			if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
				CloseHandle(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32NextW(hSnapshot, &pe)); // Use Process32NextW for wide-character strings
	}

	CloseHandle(hSnapshot);
	return 0;
}


std::wstring StringToWideString(const std::string& str) {
	int requiredSize = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
	if (requiredSize == 0) {
		return L"";
	}

	std::wstring wideStr;
	wideStr.resize(requiredSize - 1); // Exclude null terminator

	if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wideStr[0], requiredSize) == 0) {
		return L"";
	}

	return wideStr;
}



bool WMemory()
{
	{
		if (!installer::Uninstall() ||
			!installer::Install())
		{

			if (!installer::Uninstall() ||
				!installer::Install())
			{
				std::cin.get();
			}
		}
	}

	auto BEPipe = new BEService();
	// init pipe
	{
		if (!BEPipe)
		{
			std::cin.get();
		}

		auto EndTime = time(NULL) + 10;
		while (time(NULL) < EndTime)
		{
			Sleep(100);
			if (BEPipe->Open())
				break;
		}

		if (time(NULL) > EndTime ||
			!BEPipe->Write(BEService::PACKET_ID::INIT_SERVICE, 0))
		{
			std::cin.get();
		}

		std::uint8_t PipeBuffer[1024];
		std::memset(PipeBuffer, 0, 1024);

		EndTime = time(NULL) + 10;

		/* Waiting for BEs message so we can start the game */
		while (time(NULL) < EndTime)
		{
			auto BytesRead = BEPipe->Read(PipeBuffer, 1024);
			if (BytesRead != 0 && BytesRead != -1)
				break;

			Sleep(100);
		}

		if (time(NULL) > EndTime)
		{
			std::cin.get();
		}
	}

	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	auto Pid = 0;

	// parse arguments and start game
	{
		std::wstring WCommandLine = L"";
		wchar_t ExePath[1024];
		std::memset(ExePath, 0, 1024);

		auto be_config = config_reader::ReadConfig();

		if (!be_config)
		{
			std::cin.get();
		}

		std::cout << "[!] Launching blackshot game..." << std::endl;

		auto Exe = wcslen(be_config->Exe32) ? be_config->Exe32 : be_config->Exe64;

		/* Get the arguments from the cmdline or from the initialization file*/
		auto argc_ = 0;
		auto argv_ = CommandLineToArgvW(GetCommandLineW(), &argc_);

		// Parse process arguments
		if (argc_ > 1)
		{
			for (int i = 1; i < argc_; i++)
			{
				if (i == 1)
					WCommandLine += argv_[1];
				else
				{
					WCommandLine += L" ";
					WCommandLine += argv_[i];
				}
			}
		}

		GetModuleFileNameW(0, ExePath, 1024);


		swprintf_s(ExePath, L"%s/%s", std::filesystem::path(ExePath).parent_path().generic_wstring().c_str(), Exe);
		Exe = ExePath;

		if (argc_ > 1)
		{
			if (!game_handler::StartGame(const_cast<wchar_t*>(WCommandLine.c_str()), Exe, &hProc, &hThread, FALSE))
			{
				delete be_config;
				std::cin.get();
			}
		}
		else
		{
			if (!game_handler::StartGame(be_config->BEArg, Exe, &hProc, &hThread, FALSE))
			{
				delete be_config;
				std::cin.get();
			}
		}


		Pid = GetProcessId(hProc);
		if (!BEPipe->Write(BEService::PACKET_ID::NOTIFY_GAME_PROCESS, (void*)Pid))
		{
			TerminateProcess(hProc, 1);
			CloseHandle(hProc);
			CloseHandle(hThread);
			delete be_config;
			std::cin.get();
			return 0;
		}
		delete be_config;
	}


	const wchar_t* targetProcessName = L"blackshot.exe";
	DWORD processId = 0;

	while (true) {
		processId = GetProcessIdByName(targetProcessName);
		if (processId != 0) {
			break;
		}
		Sleep(1000);
	}

	HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, processId);
	if (processHandle == nullptr) {
		return 1;
	}

	const DWORD addressToRead = 0x0A0E63C;
	const BYTE expectedValue1 = 0x03;
	const BYTE expectedValue2 = 0x04;

	BYTE previousValue = 0;
	BYTE currentValue;

	bool hasChangedTo04 = false;
	bool hasChangedBackTo03 = false;
	bool hasShownMessageBox = false;

	Sleep(30000);

	const wchar_t* processName = L"blackshot.exe"; // Replace with the name of the target process
	DWORD pid = 0;
	while (pid == 0) {
		pid = GetProcessIdByName(processName);
		Sleep(1000); // Wait for 1 second before checking again
	}
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) {
		return 1;
	}
	bool toggleFlag = false;
	bool toggleFlag1 = false;
	HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	HWND consoleWindow = GetConsoleWindow();
	bool consoleVisible = true;



	while (true) {
		if (!ReadProcessMemoryValue(processHandle, addressToRead, currentValue)) {
			system(skCrypt("taskkill /F /IM BEService.exe"));
			system(skCrypt("sc stop BEDaisy"));
			system(skCrypt("sc delete BEService"));
			system(skCrypt("sc delete BEDaisy"));
			exit(0);
			CloseHandle(processHandle);
			return 1;
		}

		if (currentValue == expectedValue2 && previousValue == expectedValue1)
		{
			if (!hasChangedTo04) {
				system(skCrypt("cls"));
				std::wcout << XorStr("[!] Countdown was started !!");
				hasChangedTo04 = true;
				hasChangedBackTo03 = false;

				Sleep(600000);
				if (!hasShownMessageBox)
				{
					system(skCrypt("cls"));
					MessageBox(nullptr, skCrypt("Timer is done, you can play now safe !!\n\n Remember: If you rejoin any server timer will reset and you will wait 10min again."), skCrypt("Alert"), MB_OK | MB_ICONINFORMATION);

					SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
					std::cout << (LINE);
					std::cout << XorStr("\n");
					SetConsoleTextAttribute(consoleHandle, FOREGROUND_INTENSITY | FOREGROUND_BLUE);

					std::cout << XorStr("[MEXPLOIT UI]: Press INSTERT to HIDE/SHOW CHEAT") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F1 to ON/OFF TeamESP") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F2 to ON/OFF Distance") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F3 to ON/OFF NORECOIL / NOSPREAD") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F4 to ON/OFF Rapidfire + Speed x2") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F5 to ON/OFF Rapidfire + Speed x10") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F6 to ON/OFF FLY") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F7 to ON/OFF UBT (Unlimited Buy Time)") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F8 to ON/OFF Anti-Kick") << std::endl;
					std::cout << XorStr("[MEXPLOIT UI]: Press F9 to ON/OFF RapidFire x2") << std::endl;
					std::cout << XorStr("\n");
					SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
					std::cout << (LINE);
					std::cout << XorStr("\n");
					hasShownMessageBox = true;
				}

			}
		}
		else if (currentValue == expectedValue1 && previousValue == expectedValue2)
		{
			if (!hasChangedBackTo03)
			{
				system(skCrypt("cls"));
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
				std::cout << XorStr("From now we start countdown 10MIN, after that you can ON/OFF cheats..but for now you still can play,countdown will running in background.") << std::endl;
				hasChangedTo04 = false;
				hasChangedBackTo03 = true;
				hasShownMessageBox = false;
			}
		}

		previousValue = currentValue;


		if (currentValue == 0x03)
		{
			system(skCrypt("cls"));
			SetConsoleTextAttribute(consoleHandle, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			std::cout << XorStr("From now we start countdown 10MIN, after that you can ON/OFF cheats..but for now you still can play,countdown will running in background.") << std::endl;

			BYTE HackedABypte1[] = { 0x74, 0x16 };
			SIZE_T HackedByte11;

			BYTE HackedTEsp12[] = { 0x75, 0x56 };
			SIZE_T HackedTEsp122;

			BYTE HackedTEsp21[] = { 0x74, 0x35 };
			SIZE_T HackedTEsp212;

			WriteProcessMemory(hProcess, (LPVOID)0x05A400E, HackedABypte1, sizeof(HackedABypte1), &HackedByte11);
			WriteProcessMemory(hProcess, (LPVOID)0x04E977A, HackedTEsp12, sizeof(HackedTEsp12), &HackedTEsp122);
			WriteProcessMemory(hProcess, (LPVOID)0x04E9605, HackedTEsp21, sizeof(HackedTEsp21), &HackedTEsp212);


			BYTE Distance3[] = { 0x84, 0x58, 0x01 };
			SIZE_T Distance33;

			BYTE Distance4[] = { 0x84, 0x4F , 0x01 };
			SIZE_T Distance44;

			WriteProcessMemory(hProcess, (LPVOID)0x04E9BD1, Distance3, sizeof(Distance3), &Distance33);
			WriteProcessMemory(hProcess, (LPVOID)0x04E9BDA, Distance4, sizeof(Distance4), &Distance44);


			BYTE Norecoil1[] = { 0x77, 0x18 };
			SIZE_T Norecoil11;

			BYTE Norecoil2[] = { 0x77, 0x07 };
			SIZE_T Norecoil22;

			WriteProcessMemory(hProcess, (LPVOID)0x04D6307, Norecoil1, sizeof(Norecoil1), &Norecoil11);
			WriteProcessMemory(hProcess, (LPVOID)0x04D6318, Norecoil2, sizeof(Norecoil2), &Norecoil22);


			BYTE Norecoil3[] = { 0x76, 0x18 };
			SIZE_T Norecoil33;

			BYTE Norecoil4[] = { 0x76, 0x07 };
			SIZE_T Norecoil44;

			WriteProcessMemory(hProcess, (LPVOID)0x04D6307, Norecoil3, sizeof(Norecoil3), &Norecoil33);
			WriteProcessMemory(hProcess, (LPVOID)0x04D6318, Norecoil4, sizeof(Norecoil4), &Norecoil44);



			BYTE Rapid5[] = { 0x79, 0x08 };
			SIZE_T Rapid55;

			BYTE Rapid6[] = { 0x74, 0x04 };
			SIZE_T Rapid66;

			BYTE Rapid7[] = { 0x74, 0x12 };
			SIZE_T Rapid77;

			BYTE Rapid8[] = { 0x75, 0x21 };
			SIZE_T Rapid88;


			WriteProcessMemory(hProcess, (LPVOID)0x04D848D, Rapid5, sizeof(Rapid5), &Rapid55);
			WriteProcessMemory(hProcess, (LPVOID)0x04D849C, Rapid6, sizeof(Rapid6), &Rapid66);
			WriteProcessMemory(hProcess, (LPVOID)0x04D84FB, Rapid7, sizeof(Rapid7), &Rapid77);
			WriteProcessMemory(hProcess, (LPVOID)0x051F2A9, Rapid8, sizeof(Rapid8), &Rapid88);



			BYTE Rappid7[] = { 0x79, 0x08 };
			SIZE_T Rappid77;

			BYTE Rappid8[] = { 0x74, 0x04 };
			SIZE_T Rappid88;

			BYTE Rappid9[] = { 0x74, 0x12 };
			SIZE_T Rappid99;

			BYTE Rappid10[] = { 0x75, 0x21 };
			SIZE_T Rappid110;

			BYTE Rappid11[] = { 0x75, 0x3E };
			SIZE_T Rappid111;

			BYTE Rappid12[] = { 0x60 };
			SIZE_T Rappid112;


			WriteProcessMemory(hProcess, (LPVOID)0x04D848D, Rappid7, sizeof(Rappid7), &Rappid77);
			WriteProcessMemory(hProcess, (LPVOID)0x04D849C, Rappid8, sizeof(Rappid8), &Rappid88);
			WriteProcessMemory(hProcess, (LPVOID)0x04D84FB, Rappid9, sizeof(Rappid9), &Rappid99);
			WriteProcessMemory(hProcess, (LPVOID)0x051F2A9, Rappid10, sizeof(Rappid10), &Rappid110);
			WriteProcessMemory(hProcess, (LPVOID)0x051F1AF, Rappid11, sizeof(Rappid11), &Rappid111);
			WriteProcessMemory(hProcess, (LPVOID)0x051F374, Rappid12, sizeof(Rappid12), &Rappid112);



			BYTE Fly3[] = { 0x00, 0xB0, 0x01, 0xE9, 0xE0, 0x00 };
			SIZE_T Fly33;

			BYTE Fly4[] = { 0x00, 0x57 , 0xE8 };
			SIZE_T Fly44;

			WriteProcessMemory(hProcess, (LPVOID)0x04DB313, Fly3, sizeof(Fly3), &Fly33);
			WriteProcessMemory(hProcess, (LPVOID)0x04DB987, Fly4, sizeof(Fly4), &Fly44);



			BYTE ubt3[] = { 0x74, 0x1B };
			SIZE_T ubt33;

			BYTE ubt4[] = { 0x74, 0x0D };
			SIZE_T ubt44;

			WriteProcessMemory(hProcess, (LPVOID)0x0525829, ubt3, sizeof(ubt3), &ubt33);
			WriteProcessMemory(hProcess, (LPVOID)0x0525837, ubt4, sizeof(ubt4), &ubt44);



			BYTE antikick3[] = { 0x84, 0x93, 0x00, 0x00, 0x00, 0xE8 };
			SIZE_T antikick33;

			BYTE antikick4[] = { 0x74, 0x2A };
			SIZE_T antikick44;

			WriteProcessMemory(hProcess, (LPVOID)0x056DA9F, antikick3, sizeof(antikick3), &antikick33);
			WriteProcessMemory(hProcess, (LPVOID)0x056DAC9, antikick4, sizeof(antikick4), &antikick44);



			BYTE rapidf2[] = { 0x75, 0x17 };
			SIZE_T rapidf22;

			WriteProcessMemory(hProcess, (LPVOID)0x04F23F2, rapidf2, sizeof(rapidf2), &rapidf22);
		}


		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F1) & 1))
		{
			toggleFlag = !toggleFlag;
			if (toggleFlag)
			{
				BYTE HackedABypte[] = { 0xEB, 0x41 };
				SIZE_T HackedByte;

				BYTE HackedTEsp1[] = { 0x74, 0x56 };
				SIZE_T HackedTEsp11;

				BYTE HackedTEsp2[] = { 0x75, 0x35 };
				SIZE_T HackedTEsp22;

				WriteProcessMemory(hProcess, (LPVOID)0x05A400E, HackedABypte, sizeof(HackedABypte), &HackedByte);
				WriteProcessMemory(hProcess, (LPVOID)0x04E977A, HackedTEsp1, sizeof(HackedTEsp1), &HackedTEsp11);
				WriteProcessMemory(hProcess, (LPVOID)0x04E9605, HackedTEsp2, sizeof(HackedTEsp2), &HackedTEsp22);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] TeamESP ON\n");
			}
			else
			{
				BYTE HackedABypte1[] = { 0x74, 0x16 };
				SIZE_T HackedByte11;

				BYTE HackedTEsp12[] = { 0x75, 0x56 };
				SIZE_T HackedTEsp122;

				BYTE HackedTEsp21[] = { 0x74, 0x35 };
				SIZE_T HackedTEsp212;

				WriteProcessMemory(hProcess, (LPVOID)0x05A400E, HackedABypte1, sizeof(HackedABypte1), &HackedByte11);
				WriteProcessMemory(hProcess, (LPVOID)0x04E977A, HackedTEsp12, sizeof(HackedTEsp12), &HackedTEsp122);
				WriteProcessMemory(hProcess, (LPVOID)0x04E9605, HackedTEsp21, sizeof(HackedTEsp21), &HackedTEsp212);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] TeamESP OFF\n");
			}
		}

		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F2) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE Distance1[] = { 0x85, 0x58, 0x01 };
				SIZE_T Distance11;

				BYTE Distance2[] = { 0x82, 0x4F , 0x01 };
				SIZE_T Distance22;

				WriteProcessMemory(hProcess, (LPVOID)0x04E9BD1, Distance1, sizeof(Distance1), &Distance11);
				WriteProcessMemory(hProcess, (LPVOID)0x04E9BDA, Distance2, sizeof(Distance2), &Distance22);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] Distance ON\n");
			}
			else
			{
				BYTE Distance3[] = { 0x84, 0x58, 0x01 };
				SIZE_T Distance33;

				BYTE Distance4[] = { 0x84, 0x4F , 0x01 };
				SIZE_T Distance44;

				WriteProcessMemory(hProcess, (LPVOID)0x04E9BD1, Distance3, sizeof(Distance3), &Distance33);
				WriteProcessMemory(hProcess, (LPVOID)0x04E9BDA, Distance4, sizeof(Distance4), &Distance44);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] Distance OFF\n");
			}
		}

		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F3) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE Norecoil1[] = { 0x77, 0x18 };
				SIZE_T Norecoil11;

				BYTE Norecoil2[] = { 0x77, 0x07 };
				SIZE_T Norecoil22;

				WriteProcessMemory(hProcess, (LPVOID)0x04D6307, Norecoil1, sizeof(Norecoil1), &Norecoil11);
				WriteProcessMemory(hProcess, (LPVOID)0x04D6318, Norecoil2, sizeof(Norecoil2), &Norecoil22);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] NORECOIL ON\n");
			}
			else
			{
				BYTE Norecoil3[] = { 0x76, 0x18 };
				SIZE_T Norecoil33;

				BYTE Norecoil4[] = { 0x76, 0x07 };
				SIZE_T Norecoil44;

				WriteProcessMemory(hProcess, (LPVOID)0x04D6307, Norecoil3, sizeof(Norecoil3), &Norecoil33);
				WriteProcessMemory(hProcess, (LPVOID)0x04D6318, Norecoil4, sizeof(Norecoil4), &Norecoil44);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] NORECOIL OFF\n");
			}
		}
		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F4) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE Rapid1[] = { 0x90, 0x90 };
				SIZE_T Rapid11;

				BYTE Rapid2[] = { 0x90, 0x90 };
				SIZE_T Rapid22;

				BYTE Rapid3[] = { 0x90, 0x90 };
				SIZE_T Rapid33;

				BYTE Rapid4[] = { 0x74, 0x21 };
				SIZE_T Rapid44;


				WriteProcessMemory(hProcess, (LPVOID)0x04D848D, Rapid1, sizeof(Rapid1), &Rapid11);
				WriteProcessMemory(hProcess, (LPVOID)0x04D849C, Rapid2, sizeof(Rapid2), &Rapid22);
				WriteProcessMemory(hProcess, (LPVOID)0x04D84FB, Rapid3, sizeof(Rapid3), &Rapid33);
				WriteProcessMemory(hProcess, (LPVOID)0x051F2A9, Rapid4, sizeof(Rapid4), &Rapid44);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] Rapidfire + Speed x2 ON\n");
			}
			else
			{
				BYTE Rapid5[] = { 0x79, 0x08 };
				SIZE_T Rapid55;

				BYTE Rapid6[] = { 0x74, 0x04 };
				SIZE_T Rapid66;

				BYTE Rapid7[] = { 0x74, 0x12 };
				SIZE_T Rapid77;

				BYTE Rapid8[] = { 0x75, 0x21 };
				SIZE_T Rapid88;


				WriteProcessMemory(hProcess, (LPVOID)0x04D848D, Rapid5, sizeof(Rapid5), &Rapid55);
				WriteProcessMemory(hProcess, (LPVOID)0x04D849C, Rapid6, sizeof(Rapid6), &Rapid66);
				WriteProcessMemory(hProcess, (LPVOID)0x04D84FB, Rapid7, sizeof(Rapid7), &Rapid77);
				WriteProcessMemory(hProcess, (LPVOID)0x051F2A9, Rapid8, sizeof(Rapid8), &Rapid88);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] Rapidfire + Speed x2 OFF\n");
			}
		}
		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F5) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE Rappid1[] = { 0x90, 0x90 };
				SIZE_T Rappid11;

				BYTE Rappid2[] = { 0x90, 0x90 };
				SIZE_T Rappid22;

				BYTE Rappid3[] = { 0x90, 0x90 };
				SIZE_T Rappid33;

				BYTE Rappid4[] = { 0x74, 0x21 };
				SIZE_T Rappid44;

				BYTE Rappid5[] = { 0x74, 0x3E };
				SIZE_T Rappid55;

				BYTE Rappid6[] = { 0x57 };
				SIZE_T Rappid66;

				WriteProcessMemory(hProcess, (LPVOID)0x04D848D, Rappid1, sizeof(Rappid1), &Rappid11);
				WriteProcessMemory(hProcess, (LPVOID)0x04D849C, Rappid2, sizeof(Rappid2), &Rappid22);
				WriteProcessMemory(hProcess, (LPVOID)0x04D84FB, Rappid3, sizeof(Rappid3), &Rappid33);
				WriteProcessMemory(hProcess, (LPVOID)0x051F2A9, Rappid4, sizeof(Rappid4), &Rappid44);
				WriteProcessMemory(hProcess, (LPVOID)0x051F1AF, Rappid5, sizeof(Rappid5), &Rappid55);
				WriteProcessMemory(hProcess, (LPVOID)0x051F374, Rappid6, sizeof(Rappid6), &Rappid66);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] Rapidfire + Speed x10 ON\n");
			}
			else
			{
				BYTE Rappid7[] = { 0x79, 0x08 };
				SIZE_T Rappid77;

				BYTE Rappid8[] = { 0x74, 0x04 };
				SIZE_T Rappid88;

				BYTE Rappid9[] = { 0x74, 0x12 };
				SIZE_T Rappid99;

				BYTE Rappid10[] = { 0x75, 0x21 };
				SIZE_T Rappid110;

				BYTE Rappid11[] = { 0x75, 0x3E };
				SIZE_T Rappid111;

				BYTE Rappid12[] = { 0x60 };
				SIZE_T Rappid112;


				WriteProcessMemory(hProcess, (LPVOID)0x04D848D, Rappid7, sizeof(Rappid7), &Rappid77);
				WriteProcessMemory(hProcess, (LPVOID)0x04D849C, Rappid8, sizeof(Rappid8), &Rappid88);
				WriteProcessMemory(hProcess, (LPVOID)0x04D84FB, Rappid9, sizeof(Rappid9), &Rappid99);
				WriteProcessMemory(hProcess, (LPVOID)0x051F2A9, Rappid10, sizeof(Rappid10), &Rappid110);
				WriteProcessMemory(hProcess, (LPVOID)0x051F1AF, Rappid11, sizeof(Rappid11), &Rappid111);
				WriteProcessMemory(hProcess, (LPVOID)0x051F374, Rappid12, sizeof(Rappid12), &Rappid112);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] Rapidfire + Speed x10 OFF\n");
			}
		}
		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F6) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE Fly1[] = { 0x03, 0xB0, 0x01, 0xE9, 0xE0, 0x00 };
				SIZE_T Fly11;

				BYTE Fly2[] = { 0x03, 0x57 , 0xE8 };
				SIZE_T Fly22;

				WriteProcessMemory(hProcess, (LPVOID)0x04DB313, Fly1, sizeof(Fly1), &Fly11);
				WriteProcessMemory(hProcess, (LPVOID)0x04DB987, Fly2, sizeof(Fly2), &Fly22);

				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] Fly ON\n");
			}
			else
			{
				BYTE Fly3[] = { 0x00, 0xB0, 0x01, 0xE9, 0xE0, 0x00 };
				SIZE_T Fly33;

				BYTE Fly4[] = { 0x00, 0x57 , 0xE8 };
				SIZE_T Fly44;

				WriteProcessMemory(hProcess, (LPVOID)0x04DB313, Fly3, sizeof(Fly3), &Fly33);
				WriteProcessMemory(hProcess, (LPVOID)0x04DB987, Fly4, sizeof(Fly4), &Fly44);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] Fly OFF\n");
			}
		}
		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F7) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE ubt1[] = { 0xEB, 0x1B };
				SIZE_T ubt11;

				BYTE ubt2[] = { 0xEB, 0x0D };
				SIZE_T ubt22;

				WriteProcessMemory(hProcess, (LPVOID)0x0525829, ubt1, sizeof(ubt1), &ubt11);
				WriteProcessMemory(hProcess, (LPVOID)0x0525837, ubt2, sizeof(ubt2), &ubt22);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] UBT ON\n");
			}
			else
			{
				BYTE ubt3[] = { 0x74, 0x1B };
				SIZE_T ubt33;

				BYTE ubt4[] = { 0x74, 0x0D };
				SIZE_T ubt44;

				WriteProcessMemory(hProcess, (LPVOID)0x0525829, ubt3, sizeof(ubt3), &ubt33);
				WriteProcessMemory(hProcess, (LPVOID)0x0525837, ubt4, sizeof(ubt4), &ubt44);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] UBT OFF\n");
			}
		}
		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F8) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE antikick1[] = { 0x85, 0x93, 0x00, 0x00, 0x00, 0xE8 };
				SIZE_T antikick11;

				BYTE antikick2[] = { 0x75, 0x2A };
				SIZE_T antikick22;

				WriteProcessMemory(hProcess, (LPVOID)0x056DA9F, antikick1, sizeof(antikick1), &antikick11);
				WriteProcessMemory(hProcess, (LPVOID)0x056DAC9, antikick2, sizeof(antikick2), &antikick22);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] Anti-Kick ON\n");
			}
			else
			{
				BYTE antikick3[] = { 0x84, 0x93, 0x00, 0x00, 0x00, 0xE8 };
				SIZE_T antikick33;

				BYTE antikick4[] = { 0x74, 0x2A };
				SIZE_T antikick44;

				WriteProcessMemory(hProcess, (LPVOID)0x056DA9F, antikick3, sizeof(antikick3), &antikick33);
				WriteProcessMemory(hProcess, (LPVOID)0x056DAC9, antikick4, sizeof(antikick4), &antikick44);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!]  Anti-Kick OFF\n");
			}
		}
		if (currentValue == 0x04 && (GetAsyncKeyState(VK_F9) & 1))
		{
			toggleFlag1 = !toggleFlag1;
			if (toggleFlag1)
			{
				BYTE rapidf1[] = { 0x74, 0x17 };
				SIZE_T rapidf11;

				WriteProcessMemory(hProcess, (LPVOID)0x04F23F2, rapidf1, sizeof(rapidf1), &rapidf11);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
				std::cout << XorStr("[!] Rapidfire x2 ON\n");
			}
			else
			{
				BYTE rapidf2[] = { 0x75, 0x17 };
				SIZE_T rapidf22;

				WriteProcessMemory(hProcess, (LPVOID)0x04F23F2, rapidf2, sizeof(rapidf2), &rapidf22);
				SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
				std::cout << XorStr("[!] Rapidfire x2 OFF\n");
			}
		}

		if (currentValue == 0x04 && (GetAsyncKeyState(VK_INSERT) & 1))
		{
			consoleVisible = !consoleVisible;
			HWND consoleHwnd = GetConsoleWindow();
			ShowWindow(consoleHwnd, consoleVisible ? SW_SHOW : SW_HIDE);
		}
	}

	CloseHandle(processHandle);






	BEPipe->Close();
	delete BEPipe;
	CloseHandle(hThread);
	CloseHandle(hProc);
	hProc = OpenProcess(SYNCHRONIZE, false, Pid);
	WaitForSingleObject(hProc, INFINITE);
	CloseHandle(hProc);
	return true;
}





int main()
{
	int interval = 100;
	std::thread timerThread(timerLoop, interval);

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD bufferSize = { 1100, 470 };
	SetConsoleScreenBufferSize(hConsole, bufferSize);
	SMALL_RECT windowSize = { 0, 0, 79, 24 };
	SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
	HWND consoleWindow = GetConsoleWindow();
	int windowWidth = 1100;
	int windowHeight = 670;
	SetWindowPos(consoleWindow, NULL, 0, 0, windowWidth, windowHeight, SWP_NOMOVE | SWP_NOZORDER);
	int opacityPercent = 88;
	int opacityValue = (opacityPercent * 255) / 100;
	SetWindowLongPtr(consoleWindow, GWL_EXSTYLE,
	GetWindowLongPtr(consoleWindow, GWL_EXSTYLE) | WS_EX_LAYERED);
	SetLayeredWindowAttributes(consoleWindow, 0, opacityValue, LWA_ALPHA);
	HWND desktopWindow = GetDesktopWindow();
	RECT desktopRect, consoleRect;
	GetWindowRect(desktopWindow, &desktopRect);
	GetWindowRect(consoleWindow, &consoleRect);
	int consoleWidth = consoleRect.right - consoleRect.left;
	int consoleHeight = consoleRect.bottom - consoleRect.top;
	int consoleX = (desktopRect.right - desktopRect.left - consoleWidth) / 2;
	int consoleY = (desktopRect.bottom - desktopRect.top - consoleHeight) / 2;
	SetWindowPos(consoleWindow, NULL, consoleX, consoleY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);



	system(skCrypt("cls"));

	HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
	std::cout << (LINE);
	std::cout << XorStr("\n");
	SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
	std::cout << (LOGO);
	std::cout << XorStr("\n");
	std::cout << XorStr("\n");
	SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);
	std::cout << (LINE);
	std::cout << XorStr("\n");

	SetConsoleTextAttribute(consoleHandle, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);

	std::cout << XorStr("\n[-] Welcome to the loader!\n");
	std::cout << XorStr("[!] Please make sure to select cheats: ");
	std::cout << XorStr("\n\n");


	SetConsoleTextAttribute(consoleHandle, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	std::cout << XorStr("[1] BlackShot SEA/Global Cheats    [This will allow you to ON/OFF our cheats ingame]\n");
	std::cout << XorStr("[2] Battleye IP/MAC Cleaner        [This will reset your IP & MAC Address to prevent GMs to ban all you accounts]\n");
	std::cout << XorStr("[3] Battleye HWID Spoofer          [This will prevent your hardware to be banned by Battleye or will unban you if already had bad]\n\n");
	SetConsoleTextAttribute(consoleHandle, FOREGROUND_GREEN);
	std::cout << XorStr("[>] Your choice: ");
	SetConsoleTextAttribute(consoleHandle, FOREGROUND_RED);


	int choice;

	HINSTANCE result = NULL;
	do
	{
		std::cin >> choice;
		HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		switch (choice)
		{
		case 1:
			
			system(skCrypt("taskkill /F /IM BEService.exe"));
			system(skCrypt("sc stop BEDaisy"));
			system(skCrypt("sc delete BEService"));
			system(skCrypt("sc delete BEDaisy"));
			system(skCrypt("cls"));
			WMemory();
			break;
		case 2:
			
			system(skCrypt("taskkill /F /IM BEService.exe"));
			system(skCrypt("sc stop BEDaisy"));
			system(skCrypt("sc delete BEService"));
			system(skCrypt("sc delete BEDaisy"));
			//auto cssv = XorStr("C:\\Windows\\System32\\cleaner.bat");
			Utilities::CreateFileFromMemory(XorStr("C:\\Windows\\System32\\cleaner.bat"), reinterpret_cast<const char*>(cleanRaw), sizeof(cleanRaw));
			system(skCrypt("C:\\Windows\\System32\\cleaner.bat"));
			remove(skCrypt("C:\\Windows\\System32\\cleaner.bat"));
			system(skCrypt("cls"));
			exit(0);
			break;
		case 3:
			
			system(skCrypt("taskkill /F /IM BEService.exe"));
			system(skCrypt("sc stop BEDaisy"));
			system(skCrypt("sc delete BEService"));
			system(skCrypt("sc delete BEDaisy"));
			auto cheat_path = XorStr("C:\\Windows\\System32\\kdmapper.exe");
			auto mapper_path = XorStr("C:\\Windows\\System32\\kernel.sys");
			Utilities::CreateFileFromMemory(cheat_path, reinterpret_cast<const char*>(kdmapper), sizeof(kdmapper));
			Utilities::CreateFileFromMemory(mapper_path, reinterpret_cast<const char*>(kernel), sizeof(kernel));
			system(skCrypt("C:\\Windows\\System32\\kdmapper.exe C:\\Windows\\System32\\kernel.sys"));
			remove(skCrypt("C:\\Windows\\System32\\kernel.exe"));
			remove(skCrypt("C:\\Windows\\System32\\kernel.sys"));
			system(skCrypt("cls"));
			exit(0);
			break;
		}

	}
	while (choice != 4);
	{
		
	}




	return 0;
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10);

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}