#include <WinSock2.h>
#define EXPORT extern "C" __declspec(dllexport)

// 函数声明
void EnableHook();
void DisableHook();

// 回调函数指针
typedef int (*SendCallBack)(SOCKET, PCHAR, INT);
typedef void (*RecvCallBack)(SOCKET, PCHAR, INT);

EXPORT void SetSendCallBack(SendCallBack);
EXPORT void SetRecvCallBack(RecvCallBack);
EXPORT int WINAPI Send(SOCKET, PCHAR, INT);
EXPORT void LoadFlash();