#include "Process.h"
#include "ctpl_stl.h"

#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <vector>

Process::Process() : Process(0)
{}

Process::Process(int pid)
	: mPid(pid),
	mHandle(nullptr)
{}

bool Process::Open()
{
	mHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, false, mPid);

	return true;
}

std::vector<MemoryChunk*> Process::GetChunks()
{
	return mChunks;
}

void Process::Close()
{
	CloseHandle(mHandle);
}

void Process::PrintChaChaPossibilities()
{
	SYSTEM_INFO sys_info;

	GetSystemInfo(&sys_info);

	Open();

	FindMaps(sys_info);

	CreateMapsForChaCha();

	Close();
}

void Process::CreateMapFromChunk(MemoryChunk *chunk)
{
	const auto dump = new BYTE[chunk->mSize + 1];

	memset(dump, 0, chunk->mSize + 1);

	if (!ReadProcessMemory(mHandle, chunk->mStart, dump, chunk->mSize, nullptr))
	{
		std::cerr << "Failed to read memory at: " << chunk->mStart << std::endl;
		return;
	}

	BYTE pattern[] = { 0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33, 0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B };
	const int patternLen = sizeof(pattern);

	for (size_t i = 0; i < (chunk->mSize - patternLen); ++i)
	{
		if (memcmp(pattern, &dump[i], patternLen) == 0) // pattern check
		{
			if (dump[(i + patternLen + 31)] == 0) // chacha key last bytes null because of filling
			{
				if (dump[(i + patternLen + 32 + 4)] + dump[(i + patternLen + 32 + 5)] + dump[(i + patternLen + 32 + 6)] + dump[(i + patternLen + 32 + 7)] == 0) // chacha key engine state check
				{
					std::cout << "keyBytes:";

					for (int j = 0; j < 32; j++) {
						printf("%02X", dump[(i + patternLen + j)]);
					}

					std::cout << ",ivBytes:";

					for (int j = 0; j < 8; j++) {
						printf("%02X", dump[(i + patternLen + 32 + 8 + j)]);
					}

					std::cout << std::endl;
				}
			}
		}
	}

	delete chunk;
}

void Process::CreateMapsForChaCha()
{
	ctpl::thread_pool p(5);

	for (auto chunk : mChunks) {
		p.push(std::bind(&Process::CreateMapFromChunk, this, chunk));
	}

	p.stop(true);
}



void Process::FindMaps(SYSTEM_INFO sys_info)
{

	auto addr = reinterpret_cast<uintptr_t>(sys_info.lpMinimumApplicationAddress);
	const auto end = reinterpret_cast<uintptr_t>(sys_info.lpMaximumApplicationAddress);

	MEMORY_BASIC_INFORMATION mbi;

	while (addr < end) {
		if (!VirtualQueryEx(mHandle, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
			std::cerr << "Failed to get memory maps\n";
			return;
		}

		if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_GUARD) == 0) && ((mbi.Protect & PAGE_NOACCESS) == 0)) {
			mChunks.push_back(new MemoryChunk(reinterpret_cast<LPVOID>(addr), mbi.RegionSize));
		}
		addr += mbi.RegionSize;
	}
}



Process::~Process()
{
	for (auto m : mChunks)
		delete m;
}
