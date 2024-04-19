#include "final.h"

DWORD findProcessByName(LPCWSTR targetName) {
	// Searches through the running process and compares their names to the one provided returning a HANDLE to that 
	// process if it is found or NULL if it is not

	DWORD processList[1024], bytesNeeded, numOfProcess;
	HANDLE curProcess;
	HMODULE moduleHolder;
	DWORD otherBytesNeeded;
	LPWSTR name = (LPWSTR)malloc(sizeof(wchar_t) * 1024);

	EnumProcesses(processList, sizeof(processList), &bytesNeeded);
	numOfProcess = bytesNeeded / sizeof(DWORD);

	for (DWORD i = 0; i < numOfProcess; i++) {
		curProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processList[i]);
		if (0 == curProcess)
			continue;

		if (EnumProcessModules(curProcess, &moduleHolder, sizeof(moduleHolder), &otherBytesNeeded)) {
			GetModuleBaseName(curProcess, moduleHolder, name, 1024);
		}

		if (wcscmp(name, targetName) == 0) {
			CloseHandle(curProcess);
			return processList[i];
		}

		CloseHandle(curProcess);
	}

	return NULL;
}

BYTE* convertStringToBytes(const char* chars) {
	BYTE bytes[32];
	for (int i = 0; i < 32; i++)
		bytes[i] = strtol(chars, nullptr, 16);
	return bytes;
}

int checkHash(BYTE* needsToCheck) {
	std::ifstream hashes_file("hashes", std::ios::binary);
	std::string curHash;
	int flag = 1;
	while (std::getline(hashes_file, curHash)) {
		for (int i = 0; i < 32; i++) {
			if ((char)curHash[i] != (char)needsToCheck[i]) {
				// printf("\n%x from hash does not equal %x from thread\n", hardcopy[i], needsToCheck[i]);
				flag = 0;
				break;
			}
		}
		if (flag) {
			printf("ALERT:Dangerous hash detected:");
			for (int i = 0; i < 32; i++) {
				printf("\\x%02x", needsToCheck[i]);
			}
			printf("\n");
			return 1;
		}
		flag = 1;
	}

	return 0;
}

int checkThread(DEBUG_EVENT event, DWORD pid) {
	HCRYPTPROV provider;
	HCRYPTHASH hash;
	BYTE result[33];
	char stringVersion[33];
	DWORD len = 33;
	MEMORY_BASIC_INFORMATION memInfo;
	BYTE* determineSize;
	SIZE_T sizeofThread = 0;
	DWORD read_write = 0x02, old = 0x0;
	BYTE* virusCheck;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	VirtualQueryEx(process, event.u.CreateThread.lpStartAddress, &memInfo, sizeof(memInfo));
	if (0x1000000 != memInfo.Type) {
		printf("WARNING:Found thread created without related disk image.\n");
	}
	VirtualProtectEx(process, event.u.CreateThread.lpStartAddress, memInfo.RegionSize, read_write, &old); // Ensure we will have read access

	if (memInfo.AllocationProtect == 0x40) {
		printf("WARNING:Found thread with suspicious access permisions: read, write, and execute.\n");
	}
	virusCheck = (BYTE*)malloc(sizeof(byte) * memInfo.RegionSize);
	if (NULL == virusCheck)
		return -1;

	ReadProcessMemory(process, memInfo.AllocationBase, virusCheck, memInfo.RegionSize, &sizeofThread);

	while (virusCheck[sizeofThread-1] == 0 && sizeofThread > 0) sizeofThread--;

	CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash);
	CryptHashData(hash, virusCheck, sizeofThread, 0); // 1 should be the length of bytes to hash
	CryptGetHashParam(hash, HP_HASHVAL, result, &len, 0);
	CryptDestroyHash(hash);
	CryptReleaseContext(provider, 0); 
	VirtualProtectEx(process, event.u.CreateThread.lpStartAddress, memInfo.RegionSize, old, &read_write); // Fix permissions
	CloseHandle(process);
	return checkHash(result);
}

void KillChildren(DWORD processPid) {
	DWORD otherBytesNeeded;
	LPWSTR name = (LPWSTR)malloc(sizeof(wchar_t) * 1024);
	HANDLE killMe;
	HANDLE snap32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap32 == INVALID_HANDLE_VALUE)
		printf("Bruh...\n");
	PROCESSENTRY32 curProcess = { 0 };
	curProcess.dwSize = sizeof(curProcess);
	if (Process32First(snap32, &curProcess)) {
		do {
			if (curProcess.th32ParentProcessID == processPid) {
				printf("Found child with pid: %d!\nKilling...\n", curProcess.th32ProcessID);
				killMe = OpenProcess(PROCESS_ALL_ACCESS, FALSE, curProcess.th32ProcessID);
				TerminateProcess(killMe, -1);
				printf("Killed child!\n");
				CloseHandle(killMe);
			}
		} while (Process32Next(snap32, &curProcess));
	}
}

int scanAllProcesses(void) {
	DWORD processList[1024], bytesNeeded, numOfProcess;
	HANDLE curProcess;
	HMODULE moduleHolder;
	DWORD otherBytesNeeded;
	DWORD processPid;
	DEBUG_EVENT debugEvent;
	HANDLE injectedProcess;

	LPWSTR name = (LPWSTR)malloc(sizeof(wchar_t) * 1024);

	EnumProcesses(processList, sizeof(processList), &bytesNeeded);
	numOfProcess = bytesNeeded / sizeof(DWORD);

	for (DWORD i = 0; i < numOfProcess; i++) {
		processPid = processList[i];
		if (!DebugActiveProcess(processPid)) {
			printf("Can't attach to the process with pid %d, try running at a higher privilege?\n", processPid);
			continue;
		}
		printf("Attached!\n");
		printf("Watching for new threads...\n");
		while (true) {
			if (!WaitForDebugEvent(&debugEvent, 500)) {
				DebugActiveProcessStop(processPid);
				break;
			}

			if (debugEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
				printf("New thread found with id: %d!\nChecking...\n", debugEvent.dwThreadId);
				if (checkThread(debugEvent, processPid) == 1) {
					printf("Malicious thread found in process %d with thread id %d!\n", processPid, debugEvent.dwThreadId);
					printf("Killing...\n");
					injectedProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processPid);
					KillChildren(processPid);
					TerminateThread(debugEvent.u.CreateThread.hThread, -1);
					TerminateProcess(injectedProcess, -1);
					CloseHandle(injectedProcess);
					printf("Killed!\nGoodbye!\n");
					continue;
				}
				printf("Clean!\n");
				ContinueDebugEvent(processPid, debugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
				printf("Watching for new threads...\n");
				continue;
			}
			else {
				ContinueDebugEvent(processPid, debugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
			}
		}
	}

	return 0;
}

int main() {
	LPCWSTR args = GetCommandLine();
	DWORD processPid;
	HANDLE injectedProcess;
	DEBUG_EVENT debugEvent;
	DWORD count = 0;


	while (NULL != *args && *args != L' ') args++; // Get past name of executable
	while (NULL != *args && *args == L' ') args++; // Get first executable name
	if (NULL == *args) {
		printf("Usage final.exe [ name of the exectuable | all ]\n");
		exit(-1);
	}

	printf("Searching for executable...\n");
	if (wcscmp(L"all", args))
		exit(scanAllProcesses());

	if (NULL == (processPid = findProcessByName(args))) {
		printf("Process not found...\nExiting\n");
		exit(-1);
	}
	printf("Found!\nAttaching to the process...\n");

	if (!DebugActiveProcess(processPid)) {
		printf("Can't attach to the process, try running at a higher privilege?\n");
		exit(-1);
	}
	printf("Attached!\n");
	printf("Watching for new threads...\n");
	while (true) {
		if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
			printf("Error waiting for thread... is the process dead?\n");
			exit(-2);
		}

		if (debugEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
			printf("New thread found with id: %d!\nChecking...\n", debugEvent.dwThreadId);
			if (checkThread(debugEvent, processPid) == 1) {
				printf("Malicious thread found in process %d with thread id %d!\n", processPid, debugEvent.dwThreadId);
				printf("Killing...\n");
				injectedProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processPid);
				KillChildren(processPid);
				TerminateThread(debugEvent.u.CreateThread.hThread, -1);
				TerminateProcess(injectedProcess, -1);
				CloseHandle(injectedProcess);
				printf("Killed!\nGoodbye!\n");
				exit(0);
			}
			printf("Clean!\n");
			ContinueDebugEvent(processPid, debugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
			printf("Watching for new threads...\n");
			continue;
		}
		else {
			ContinueDebugEvent(processPid, debugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
		}
	}
	return 0;
}