// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "include/utils.h"
#pragma comment(lib, "include/libMinHook.x64.lib")

int brawlerWeaponID;
int rushWeaponID;
int beastWeaponID;
int legendWeaponID;
int thugWeaponID;
int breakerWeaponID;
int sluggerWeaponID;
int maddogWeaponID;
TCHAR moduleFileName[MAX_PATH];
std::string configPath = "weapons.ini";

enum StyleIDs : int {
    BRAWLER,
    RUSH,
    BEAST,
    LEGEND,
    THUG,
    BREAKER,
    SLUGGER,
    MADDOG
};

void getContents()
{
    brawlerWeaponID = GetPrivateProfileIntA("WEAPONS", "brawler", 0, configPath.c_str());
    rushWeaponID = GetPrivateProfileIntA("WEAPONS", "rush", 0, configPath.c_str());
    beastWeaponID = GetPrivateProfileIntA("WEAPONS", "beast", 0, configPath.c_str());
    legendWeaponID = GetPrivateProfileIntA("WEAPONS", "legend", 0, configPath.c_str());
    thugWeaponID = GetPrivateProfileIntA("WEAPONS", "thug", 0, configPath.c_str());
    breakerWeaponID = GetPrivateProfileIntA("WEAPONS", "breaker", 0, configPath.c_str());
    sluggerWeaponID = GetPrivateProfileIntA("WEAPONS", "slugger", 0, configPath.c_str());
    maddogWeaponID = GetPrivateProfileIntA("WEAPONS", "maddog", 0, configPath.c_str());
    std::cout << "brawlerWeaponID: " << brawlerWeaponID << std::endl;
    std::cout << "rushWeaponID: " << rushWeaponID << std::endl;
    std::cout << "beastWeaponID: " << beastWeaponID << std::endl;
    std::cout << "legendWeaponID: " << legendWeaponID << std::endl;
    std::cout << "thugWeaponID: " << thugWeaponID << std::endl;
    std::cout << "breakerWeaponID: " << breakerWeaponID << std::endl;
    std::cout << "sluggerWeaponID: " << sluggerWeaponID << std::endl;
    std::cout << "maddogWeaponID: " << maddogWeaponID << std::endl;

}

static int customStyle(StyleIDs styleID) {
    std::cout << "styleID: " << styleID << std::endl;
    switch (styleID) {
        case (StyleIDs::BRAWLER):
			return brawlerWeaponID;
        case (StyleIDs::RUSH):
            return rushWeaponID;
        case (StyleIDs::BEAST):
            return beastWeaponID;
        case (StyleIDs::LEGEND):
            return legendWeaponID;
        case (StyleIDs::THUG):
            return thugWeaponID;
        case (StyleIDs::BREAKER):
            return breakerWeaponID;
        case (StyleIDs::SLUGGER):
			return sluggerWeaponID;
        case (StyleIDs::MADDOG):
			return maddogWeaponID;
        default:
            return 0;
    }
}

DWORD APIENTRY InitHook(LPVOID lpParam)
{
    std::string::size_type pos = std::string((char*)moduleFileName).find_last_of("\\/");
    configPath = std::string((char*)moduleFileName).substr(0, pos).append("\\").append("weapons.ini");
    std::cout << "configPath: " << configPath << std::endl;
    getContents();
    BYTE patchCode[] = {
        0x48, 0x89, 0xc1, //mov rcx, rax
        0xE8, 0x90, 0x90, 0x90, 0x90, // fix call, nop nop nop nop
        0x48, 0x89, 0xc2 //mov rdx, rax

    };
    BYTE* ptr = (BYTE*)PatternScan(GetModuleHandle(NULL), "83 E8 02 0F 84 20 01 00 00 83 E8 04 74 72 FF C8 0F 85 21 01 00 00 48 8B 0D 11 24 E0 00");
    Trampoline* trampoline = Trampoline::MakeTrampoline(GetModuleHandle(nullptr));
    NopSize(ptr, 22);
    NopSize(ptr + 71, 5);
    patch(ptr, patchCode, 11);
    Memory::InjectHook(ptr+3, trampoline->Jump(customStyle));
	return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        GetModuleFileNameA(hModule, (LPSTR)moduleFileName, MAX_PATH);
        CloseHandle(CreateThread(0, 0, InitHook, 0, 0, NULL));
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

