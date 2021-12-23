#pragma once

#include <Windows.h>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <iterator>
#include <iphlpapi.h>
#include <psapi.h>
#include <Tlhelp32.h>
#include <WbemIdl.h>
#include <winternl.h>
#include <comdef.h>
#include <vector>
#include <filesystem>
#include <thread>

#include "Process.h"

bool HasEnding(std::string const &fullString, std::string const &ending) {
	if (fullString.length() >= ending.length()) {
		return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
	}
	else {
		return false;
	}
}

bool IsHabboProcess(int pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (hProcess == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Invalid process handle\n";
		return false;
	}

	if (hProcess) {
		TCHAR processPath[MAX_PATH];
		bool result = false;
		
		if (GetModuleFileNameEx(hProcess, 0, processPath, MAX_PATH)) {
			result = HasEnding(std::string(processPath), "habbo2020-global-prod.exe");
		}

		CloseHandle(hProcess);

		return result;
	}

	return false;
}

std::vector<int> GetProcessIds()
{
	std::vector<int> processIds;

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return processIds;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			processIds.push_back(aProcesses[i]);
		}
	}

	return processIds;
}

int main()
{
	auto pids = GetProcessIds();

	std::vector<std::thread> threads;

	for (auto pid : pids) {
		if (IsHabboProcess(pid)) {
			auto p = new Process(pid);
			threads.push_back(std::thread(std::bind(&Process::PrintChaChaPossibilities, p)));
		}
	}
    
	for (auto i = 0; i < threads.size(); i++)
		if (threads[i].joinable())
			threads[i].join();

	if (pids.empty())
		std::cerr << "No pids found\n";
}
