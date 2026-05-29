#include "pch.h"
#include "MinHook.h"
#include "WinSock2.h"
#include "hook.h"
#include <iostream>
#include <fstream>
#include <string>
#include <shellapi.h>
#include <shlwapi.h>  
#pragma comment(lib, "libMinHook.x64.lib")
#pragma comment(lib, "shlwapi.lib")
using namespace std;

decltype(&send) pOriginSend = nullptr;
decltype(&recv) pOriginRecv = nullptr;
SendCallBack pSendCallBack = nullptr;
RecvCallBack pRecvCallBack = nullptr;
HANDLE hActCtx = INVALID_HANDLE_VALUE;
ULONG_PTR pActCtxCookie = 0;
wstring baseDir;

void ClearLog()
{
#ifdef _DEBUG
	ofstream logFile("hook.log", ios::out);
#endif
}

void Log(const string& msg)
{
#ifdef _DEBUG
	ofstream logFile("hook.log", ios::app);
	if (logFile.is_open())
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		logFile << format("[{}-{}-{} {:02}:{:02}:{:02}] {}\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
		logFile.close();
	}
#endif
}

void Log(const wstring& msg)
{
#ifdef _DEBUG
	wofstream logFile("hook.log", ios::app);
	if (logFile.is_open())
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		logFile.imbue(locale(""));
		logFile << format(L"[{}-{}-{} {:02}:{:02}:{:02}] {}\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
		logFile.close();
	}
#endif
}

wstring GetBaseDir() {
	if (baseDir.empty())
	{
		HMODULE hModule;
		wchar_t szPath[MAX_PATH];
		GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCWSTR>(&GetBaseDir), &hModule);
		if (GetModuleFileNameW(hModule, szPath, MAX_PATH))
		{
			wstring dllPath(szPath);
			size_t pos = dllPath.find_last_of(L"\\/");
			if (pos != wstring::npos)
			{
				baseDir = dllPath.substr(0, pos);
			}
		}
	}
	return baseDir;
}

int WINAPI MySend(SOCKET s, PCHAR buf, int len, int flags)
{
	return pSendCallBack(s, buf, len);
}

int WINAPI MyRecv(SOCKET s, PCHAR buf, int len, int flags)
{
	int res = pOriginRecv(s, buf, len, flags);
	if (res > 0)
	{
		pRecvCallBack(s, buf, res);
	}
	return res;
}

int WINAPI Send(SOCKET s, PCHAR buf, int len)
{
	return pOriginSend(s, buf, len, 0);
}

void SetSendCallBack(SendCallBack pCallBack) {
	pSendCallBack = pCallBack;
}

void SetRecvCallBack(RecvCallBack pCallBack) {
	pRecvCallBack = pCallBack;
}

void CompleteRegistry()
{
	wstring subKey = L"SOFTWARE\\Classes\\TypeLib\\{D27CDB6B-AE6D-11CF-96B8-444553540000}\\1.0\\0\\win64";
	wstring flash = GetBaseDir() + L"\\Flash.ocx";

	HKEY hCheckKey = nullptr;
	LONG readRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hCheckKey);

	if (readRes == ERROR_SUCCESS && hCheckKey != nullptr) {
		wchar_t existingValue[MAX_PATH] = { 0 };
		DWORD valueSize = sizeof(existingValue);

		LONG queryRes = RegQueryValueExW(hCheckKey, nullptr, nullptr, nullptr, reinterpret_cast<LPBYTE>(existingValue), &valueSize);
		RegCloseKey(hCheckKey);

		if (queryRes == ERROR_SUCCESS) {
			wstring registryOcxPath(existingValue);

			if (PathFileExistsW(registryOcxPath.c_str())) {
				Log("系统存在 Flash，跳过注册表补全");
				return;
			}
		}
	}

	HKEY hWriteKey = nullptr;
	LONG writeRes = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_SET_VALUE, nullptr, &hWriteKey, nullptr);

	if (writeRes == ERROR_SUCCESS && hWriteKey != nullptr) {
		DWORD dataSize = (flash.length() + 1) * sizeof(wchar_t);
		RegSetValueExW(hWriteKey, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(flash.c_str()), dataSize);
		RegCloseKey(hWriteKey);
		Log("补全 Flash 注册表成功");
		return;
	}

	if (writeRes == ERROR_ACCESS_DENIED) {
		Log("权限不足，请求提权");

		wchar_t exePath[MAX_PATH] = { 0 };
		GetModuleFileNameW(nullptr, exePath, MAX_PATH);

		LPWSTR lpCmdLine = GetCommandLineW();

		HINSTANCE hRes = ShellExecuteW(nullptr, L"runas", exePath, lpCmdLine, nullptr, SW_SHOWNORMAL);
		if (reinterpret_cast<ULONG_PTR>(hRes) > 32)
		{
			Log("提权成功");
			ExitProcess(0);
		}
		Log("提权失败");
	}
}

void LoadFlash() {
	CompleteRegistry();

	wstring manifest = GetBaseDir() + L"\\manifest";
	ACTCTXW actctx = { 0 };
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

void UnloadFlash() {
	if (hActCtx != INVALID_HANDLE_VALUE && hActCtx != nullptr) {
		DeactivateActCtx(0, pActCtxCookie);
		ReleaseActCtx(hActCtx);
	}
}

void EnableHook()
{
	ClearLog();
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
	UnloadFlash();
}
