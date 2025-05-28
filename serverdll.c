
#include <windows.h>

extern void WINAPI _jmp_esp_gadget();

__declspec(dllexport) void WINAPI payload() {
    OutputDebugStringA("Server DLL here ;)\n");
}