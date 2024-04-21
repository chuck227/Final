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
			free(name);
			CloseHandle(curProcess);
			return processList[i];
		}

		CloseHandle(curProcess);
	}
	free(name);
	return NULL;
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

int checkForBytes(BYTE* needsToCheck, DWORD length) {
	std::ifstream bytes_file("bytes", std::ios::binary);
	std::string curBins;
	int curPos;

	while (std::getline(bytes_file, curBins)) {
		for (curPos = 0; curPos < length - curBins.length(); curPos++) {
			if (strncmp(curBins.c_str(), reinterpret_cast<const char*>(needsToCheck + curPos), curBins.length()) == 0) {
				return 1;
			}
			//if("\xac\x1c\x25\xad", curPos()
		}
	}
	return 0;
}

int checkThread(DEBUG_EVENT event, DWORD pid, DWORD hashBased) {
	HCRYPTPROV provider;
	HCRYPTHASH hash;
	BYTE result[33];
	DWORD len = 33;
	MEMORY_BASIC_INFORMATION memInfo;
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
	if (NULL == virusCheck) {
		CloseHandle(process);
		return -1;
	}

	ReadProcessMemory(process, memInfo.AllocationBase, virusCheck, memInfo.RegionSize, &sizeofThread);

	while (virusCheck[sizeofThread-1] == 0 && sizeofThread > 0) sizeofThread--;

	if (hashBased) {
		CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
		CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash);
		CryptHashData(hash, virusCheck, (DWORD)sizeofThread, 0); // 1 should be the length of bytes to hash
		CryptGetHashParam(hash, HP_HASHVAL, result, &len, 0);
		CryptDestroyHash(hash);
		CryptReleaseContext(provider, 0);
		VirtualProtectEx(process, event.u.CreateThread.lpStartAddress, memInfo.RegionSize, old, &read_write); // Fix permissions
		CloseHandle(process);
		free(virusCheck);
		return checkHash(result);
	}
	else {
		CloseHandle(process);
		DWORD retVal = checkForBytes(virusCheck, sizeofThread);
		free(virusCheck);
		return retVal;
	}
}

void KillChildren(DWORD processPid) {
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
	free(name);
	CloseHandle(snap32);
}

int scanAllProcesses(DWORD checkHashes) {
	DWORD processList[1024], bytesNeeded, numOfProcess;
	DWORD processPid;
	HANDLE injectedProcess;
	DWORD myPid = GetCurrentProcessId();
	DEBUG_EVENT debugEvent;

	EnumProcesses(processList, sizeof(processList), &bytesNeeded);
	numOfProcess = bytesNeeded / sizeof(DWORD);


	for (DWORD i = 0; i < numOfProcess; i++) {
		processPid = processList[i];
		if(processPid == myPid)
			continue;
		if (!DebugActiveProcess(processPid)) {
			printf("Can't attach to the process with pid %d, try running at a higher privilege?\n", processPid);
			continue;
		}
		printf("Attached to %d!\n", processPid);
		printf("Watching for new threads...\n");
		while (true) {

			if (!WaitForDebugEvent(&debugEvent, 0)) {
				DebugActiveProcessStop(processPid);
				break;
			}

			if (debugEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
				printf("New thread found with id: %d!\nChecking...\n", debugEvent.dwThreadId);
				if (checkThread(debugEvent, processPid, checkHashes) == 1) {
					printf("Malicious thread found in process %d with thread id %d!\n", processPid, debugEvent.dwThreadId);
					printf("Killing...\n");
					injectedProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processPid);
					KillChildren(processPid);
					TerminateThread(debugEvent.u.CreateThread.hThread, -1);
					TerminateProcess(injectedProcess, -1);
					CloseHandle(injectedProcess);
					printf("Killed!\nGoodbye!\n");
					ContinueDebugEvent(processPid, debugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
					continue;
				}
				printf("Clean!\n");
				ContinueDebugEvent(processPid, debugEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
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
	wchar_t* filename = (wchar_t*)malloc(sizeof(WCHAR) * 1024);
	DWORD processPid;
	HANDLE injectedProcess;
	DEBUG_EVENT debugEvent;
	DWORD count = 0, length = 0;
	DWORD checkHashes = 1;
	ZeroMemory(filename, sizeof(WCHAR) * 1024);

	while (NULL != *args && *args != L' ') args++; // Get past name of executable
	while (NULL != *args && *args == L' ') args++; // Get first executable name
	if (NULL == *args || wcsncmp(L"/h", args, 2) == 0) {
		printf("Usage final.exe [/b] [ name of the exectuable | all ]\n");
		exit(-1);
	}
	while (NULL != *args && *args == L' ') args++;
	if (*args == L'/') {
		if (*(args + 1) == L'b')
			checkHashes = 0;
		else {
			printf("Usage final.exe [/b] [ name of the exectuable | all ]\n");
			exit(-1);
		}
		args += 2;
		while (NULL != *args && *args == L' ') args++;
	}

	if (wcsncmp(L"all", args, 3) == 0)
		exit(scanAllProcesses(checkHashes));
	printf("Searching for executable...\n");

	printf("%ls\n", args);
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
			if (checkThread(debugEvent, processPid, checkHashes) == 1) {
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