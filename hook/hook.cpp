#include "hook.h"
#include "MinHook.h"
#include <iostream>
#include <fstream>
#include <string>
#include <WinSock2.h>
#include <shellapi.h>
#include <shlwapi.h>
#pragma comment(lib, "libMinHook.x64.lib")
#pragma comment(lib, "shlwapi.lib")

struct UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
};
using PUNICODE_STRING = UNICODE_STRING*;

struct OBJECT_ATTRIBUTES {
	ULONG           Length = sizeof(OBJECT_ATTRIBUTES);
	HANDLE          RootDirectory = nullptr;
	PUNICODE_STRING ObjectName = nullptr;
	ULONG           Attributes = 0;
	PVOID           SecurityDescriptor = nullptr;
	PVOID           SecurityQualityOfService = nullptr;
};
using POBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES*;

constexpr DWORD DOMAIN_ALIAS_ADMINS = 0x00000220;
decltype(&send) pOriginSend = nullptr;
decltype(&recv) pOriginRecv = nullptr;
SendCallBack pSendCallBack = nullptr;
RecvCallBack pRecvCallBack = nullptr;
HANDLE hActCtx = INVALID_HANDLE_VALUE;
ULONG_PTR pActCtxCookie = 0;

void Log(const std::string& msg)
{
	std::ofstream file(GetLogFile(), std::ios::app);
	if (file.is_open())
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		std::print(file, "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}] {}\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
		file.close();
	}
}

void Log(const std::wstring& msg)
{
	Log(ToString(msg));
}

std::string ToString(const std::wstring& msg)
{
	if (msg.empty()) return "";

	int size = WideCharToMultiByte(CP_ACP, 0, msg.c_str(), static_cast<int>(msg.size()), nullptr, 0, nullptr, nullptr);
	if (size <= 0) return "";

	std::string target(size, 0);
	WideCharToMultiByte(CP_ACP, 0, msg.c_str(), static_cast<int>(msg.size()), &target[0], size, nullptr, nullptr);

	return target;
}

std::wstring GetBaseDir()
{
	static std::wstring path;
	if (path.empty())
	{
		HMODULE hModule;
		wchar_t szPath[MAX_PATH];
		GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCWSTR>(&GetBaseDir), &hModule);
		if (GetModuleFileNameW(hModule, szPath, MAX_PATH))
		{
			std::wstring dllPath(szPath);
			size_t pos = dllPath.find_last_of(L"\\/");
			if (pos != std::wstring::npos)
			{
				path = dllPath.substr(0, pos);
			}
		}
	}
	return path;
}

std::wstring GetLogFile()
{
	return GetBaseDir() + L"\\hook.log";
}

bool IsAdmin()
{
	bool res = false;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize))
		{
			res = elevation.TokenIsElevated;
		}
	}
	if (hToken) CloseHandle(hToken);
	return res;
} 

inline void InitAttribute(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a = 0, HANDLE r = nullptr, PVOID s = nullptr)
{
	p->Length = sizeof(OBJECT_ATTRIBUTES);
	p->RootDirectory = r;
	p->Attributes = a;
	p->ObjectName = n;
	p->SecurityDescriptor = s;
	p->SecurityQualityOfService = nullptr;
}

bool EnablePrivilege()
{
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return false;
	}

	struct
	{
		DWORD PrivilegeCount = 2;
		LUID_AND_ATTRIBUTES Privileges[2];
	} tp;

	if (!LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &tp.Privileges[0].Luid) ||
		!LookupPrivilegeValueW(nullptr, SE_RESTORE_NAME, &tp.Privileges[1].Luid))
	{
		CloseHandle(hToken);
		return false;
	}

	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL res = AdjustTokenPrivileges(hToken, FALSE, reinterpret_cast<PTOKEN_PRIVILEGES>(&tp), sizeof(tp), nullptr, nullptr);
	DWORD lastError = GetLastError();
	CloseHandle(hToken);

	if (!res || lastError == ERROR_NOT_ALL_ASSIGNED)
	{
		return false;
	}

	Log("获取特权成功");
	return true;
}

bool KernelModifyRegistry(const std::wstring& subKey, const std::wstring& flash)
{
	if (!EnablePrivilege())
	{
		Log("获取特权失败");
		return false;
	}

	std::wstring ntPath = L"\\Registry\\Machine\\" + subKey;
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtDll)
	{
		Log("加载内核失败");
		return false;
	}
	auto NtOpenKeyEx = reinterpret_cast<NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG)>(
		GetProcAddress(hNtDll, "NtOpenKeyEx")
	);
	auto NtSetValueKey = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG)>(
		GetProcAddress(hNtDll, "NtSetValueKey")
	);

	if (!NtOpenKeyEx || !NtSetValueKey)
	{
		Log("内核强写失败，导出函数失败");
		return false;
	}

	UNICODE_STRING usKeyPath;
	usKeyPath.Buffer = const_cast<wchar_t*>(ntPath.c_str());
	usKeyPath.Length = static_cast<USHORT>(ntPath.length() * sizeof(wchar_t));
	usKeyPath.MaximumLength = usKeyPath.Length + sizeof(wchar_t);

	OBJECT_ATTRIBUTES objAttr;
	InitAttribute(&objAttr, &usKeyPath, 0x00000040L, nullptr, nullptr);

	HANDLE hKey = nullptr;

	NTSTATUS res = NtOpenKeyEx(&hKey, KEY_WRITE, &objAttr, REG_OPTION_BACKUP_RESTORE);
	if (res != 0)
	{
		Log("内核强写失败，获取注册表失败");
		return false;
	}

	UNICODE_STRING usValueName = {0, 0, nullptr};
	DWORD dataSize = static_cast<DWORD>((flash.length() + 1) * sizeof(wchar_t));

	res = NtSetValueKey(
		hKey,
		&usValueName,
		0,
		REG_SZ,
		const_cast<BYTE*>(reinterpret_cast<const BYTE*>(flash.c_str())),
		dataSize
	);
	CloseHandle(hKey);
	if (res != 0)
	{
		Log("内核强写失败，写入注册表失败");
		return false;
	}

	Log("内核强写成功");
	Log(L"当前注册表值：" + flash);
	return true;
}

void ModifyRegistry()
{
	std::wstring subKey = L"SOFTWARE\\Classes\\TypeLib\\{D27CDB6B-AE6D-11CF-96B8-444553540000}\\1.0\\0\\win64";
	std::wstring flash = GetBaseDir() + L"\\Flash.ocx";
	HKEY hKey = nullptr;
	
	LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hKey);
	if (res == ERROR_SUCCESS && hKey != nullptr)
	{
		wchar_t value[MAX_PATH] = {0};
		DWORD size = sizeof(value);

		res = RegQueryValueExW(hKey, nullptr, nullptr, nullptr, reinterpret_cast<LPBYTE>(value), &size);
		RegCloseKey(hKey);

		if (res == ERROR_SUCCESS)
		{
			std::wstring registryValue(value);
			Log(L"当前注册表值：" + registryValue);

			if (PathFileExistsW(registryValue.c_str()))
			{
				Log("注册表所指文件有效，跳过写注册表");
				return;
			}
		}
	}

	if (IsAdmin())
	{
		hKey = nullptr;

		res = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_SET_VALUE, nullptr, &hKey, nullptr);
		if (res == ERROR_SUCCESS && hKey != nullptr)
		{
			DWORD dataSize = static_cast<DWORD>((flash.length() + 1) * sizeof(wchar_t));
			RegSetValueExW(hKey, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(flash.c_str()), dataSize);
			RegCloseKey(hKey);
			Log("管理员写注册表成功");
			Log(L"当前注册表值：" + flash);
		}
		else if (res == ERROR_ACCESS_DENIED)
		{
			Log("管理员写注册表失败，尝试内核强写");
			KernelModifyRegistry(subKey, flash);
		}
	}
	else
	{
		Log("权限不足，获取管理员权限");
		wchar_t path[MAX_PATH] = {0};
		GetModuleFileNameW(nullptr, path, MAX_PATH);
		std::wstring file(path);
		if (file.ends_with(L"pythonw.exe") || file.ends_with(L"python.exe"))
		{
			file = GetBaseDir() + L"\\.venv\\Scripts\\pythonw.exe";
		}

		LPCWSTR lpCmdArgs = PathGetArgsW(GetCommandLineW());
		std::wstring baseDir = GetBaseDir();
		HINSTANCE hRes = ShellExecuteW(nullptr, L"runas", file.c_str(), lpCmdArgs, baseDir.c_str(), SW_SHOWNORMAL);
		if (reinterpret_cast<ULONG_PTR>(hRes) > 32)
		{
			Log("获取管理员权限成功");
			ExitProcess(0);
		}
		Log("获取管理员权限失败");
	}
}

void LoadFlash()
{
	ModifyRegistry();

	std::wstring baseDir = GetBaseDir();
	std::wstring manifest = baseDir + L"\\manifest";
	ACTCTXW actctx = {0};
	actctx.cbSize = sizeof(ACTCTXW);
	actctx.dwFlags = ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID;
	actctx.lpSource = manifest.c_str();
	actctx.lpAssemblyDirectory = baseDir.c_str();

	hActCtx = CreateActCtxW(&actctx);
	if (hActCtx != INVALID_HANDLE_VALUE && hActCtx != nullptr)
	{
		if (ActivateActCtx(hActCtx, &pActCtxCookie))
		{
			Log("加载 Flash 成功");
		}
	}
}

void EnableHook()
{
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK)
	{
		Log("初始化 MinHook 失败");
	}
	Log("初始化 MinHook 成功");

	status = MH_CreateHookApi(L"ws2_32.dll", "send", reinterpret_cast<LPVOID>(MySend), reinterpret_cast<LPVOID*>(&pOriginSend));
	if (status != MH_OK)
	{
		Log("创建 Send Hook 失败");
	}
	Log("创建 Send Hook 成功");

	status = MH_CreateHookApi(L"ws2_32.dll", "recv", reinterpret_cast<LPVOID>(MyRecv), reinterpret_cast<LPVOID*>(&pOriginRecv));
	if (status != MH_OK)
	{
		Log("创建 Recv Hook 失败");
	}
	Log("创建 Recv Hook 成功");

	status = MH_EnableHook(MH_ALL_HOOKS);
	if (status != MH_OK)
	{
		Log("开启 Hook 失败");
	}
	Log("开启 Hook 成功");
}

void DisableHook()
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}

int WINAPI MySend(SOCKET s, char* buf, int len, int flags)
{
	return pSendCallBack(s, buf, len);
}

int WINAPI MyRecv(SOCKET s, char* buf, int len, int flags)
{
	int res = pOriginRecv(s, buf, len, flags);
	if (res > 0)
	{
		pRecvCallBack(s, buf, res);
	}
	return res;
}

int WINAPI Send(SOCKET s, char* buf, int len)
{
	return pOriginSend(s, buf, len, 0);
}

void SetSendCallBack(SendCallBack pCallBack)
{
	pSendCallBack = pCallBack;
}

void SetRecvCallBack(RecvCallBack pCallBack)
{
	pRecvCallBack = pCallBack;
}
