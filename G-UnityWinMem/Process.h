#include <Windows.h>
#include <vector>

class MemoryChunk
{
public:
	MemoryChunk(LPVOID start, SIZE_T size);
	LPVOID mStart;
	SIZE_T mSize;
};

inline MemoryChunk::MemoryChunk(LPVOID start, SIZE_T size) :
	mStart(start),
	mSize(size)
{}


class Process
{
public:
	Process();
	Process(int pid);
	bool Open();
	void Close();
	void FindMaps(SYSTEM_INFO sys_info);
	void CreateMapsForChaCha();
	void CreateMapFromChunk(MemoryChunk *chunk);
	void PrintChaChaPossibilities();
	~Process();
	std::vector<MemoryChunk*> GetChunks();
private:
	int mPid;
	HANDLE mHandle;
	std::vector<MemoryChunk*> mChunks;
};
