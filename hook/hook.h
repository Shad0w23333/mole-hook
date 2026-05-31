#pragma once
#include <string>
#include <WinSock2.h>
#define EXPORT extern "C" __declspec(dllexport)

// 函数声明
void Log(const std::string&);
void Log(const std::wstring&);
std::string ToString(const std::wstring&);
std::wstring GetBaseDir();
std::wstring GetLogFile();
bool IsAdmin();
bool GetPermission(const std::wstring&);
void ModifyRegistry();
void EnableHook();
void DisableHook();
int WINAPI MySend(SOCKET, char*, int, int);
int WINAPI MyRecv(SOCKET, char*, int, int);

// 函数指针类型
using SendCallBack = int (*)(SOCKET, char*, int);
using RecvCallBack = void (*)(SOCKET, char*, int);

// 函数导出
EXPORT void LoadFlash();
EXPORT int WINAPI Send(SOCKET, char*, int);
EXPORT void SetSendCallBack(SendCallBack);
EXPORT void SetRecvCallBack(RecvCallBack);