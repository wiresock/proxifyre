#pragma once


namespace process {
	std::unordered_map<DWORD, DWORD> processCache;
	std::chrono::time_point<std::chrono::steady_clock> lastCacheUpdate;
	const std::chrono::seconds cacheInterval(5); // 缓存间隔时间


	void UpdateProcessCache() {
		processCache.clear();
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			throw std::runtime_error("Failed to create snapshot.");
		}

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &pe32)) {
			do {
				processCache[pe32.th32ProcessID] = pe32.th32ParentProcessID;
			} while (Process32Next(hSnapshot, &pe32));
		}
		else {
			CloseHandle(hSnapshot);
			throw std::runtime_error("Failed to retrieve process information.");
		}

		CloseHandle(hSnapshot);
	}


	DWORD GetParentProcessId(DWORD pid) {
		auto now = std::chrono::steady_clock::now();

		// 检查是否需要更新缓存
		if (processCache.empty() || (now - lastCacheUpdate) > cacheInterval) {
			UpdateProcessCache();
			lastCacheUpdate = now;
		}

		auto it = processCache.find(pid);
		if (it != processCache.end()) {
			return it->second;
		}

		return 0; // 未找到父进程
	}



	TCHAR processPath[1024] = L"<unknown>";

	std::wstring GetProcessName(DWORD pid) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (hProcess == NULL) {
			std::wcerr << L"Failed to open process. Error: " << GetLastError() << std::endl;
			return L"Unknown";
		}

		DWORD size = sizeof(processPath) / sizeof(WCHAR);
		if (QueryFullProcessImageName(hProcess, 0, processPath, &size)) {
			CloseHandle(hProcess);
			std::wstring processName = processPath;
			size_t pos = processName.find_last_of(L"\\/");
			if (pos != std::wstring::npos) {
				return processName.substr(pos + 1);
			}
			return std::wstring(processName);
		}
		else {
			std::wcerr << L"Failed to get process image name. Error: " << GetLastError() << std::endl;
		}

		CloseHandle(hProcess);
		return L"Unknown";
	}


	std::vector<std::wstring> GetParentProcessNames(DWORD pid) {
		std::vector<std::wstring> parentProcessNames;
		try {
			DWORD parentPid = GetParentProcessId(pid);
			while (parentPid != 0) {
				std::wstring parentProcessName = GetProcessName(parentPid);
				if (parentProcessName == L"Explorer.EXE" || parentProcessName == L"Unknown") {
					break;
				}
				parentProcessNames.push_back(parentProcessName);
				parentPid = GetParentProcessId(parentPid);
			}
		}
		catch (const std::exception& ex) {
			std::cerr << "Error: " << ex.what() << std::endl;
		}
		return parentProcessNames;
	}
}