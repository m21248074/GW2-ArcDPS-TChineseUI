#include "TabUI.h"
#include "GW2LangPatch.h" 
#include "VoicePatch.h"
#include "ChineseIme.h"

#include <stdexcept>
#include <string>
#include <imgui/imgui.h>
#include <arcdps_structs.h>

/* proto/globals */
arcdps_exports arc_exports{};
extern "C" __declspec(dllexport) void* get_init_addr(char* arcversionstr, void* imguicontext, void* id3dptr, HANDLE arcdll, void* mallocfn, void* freefn, uint32_t imguiversion);
extern "C" __declspec(dllexport) void* get_release_addr(uint32_t reason);
arcdps_exports* init_module();
void release_module();
void options_tab();
void imgui_callback(uint32_t not_charsel_or_loading, uint32_t hide_if_combat_or_ooc);

HMODULE g_hSelfModule;
HMODULE arc_dll;

// get exports
e3_func_ptr arc_log_file;
e3_func_ptr arc_log;

void ArcLog(const char* message) {
    if (arc_log_file) arc_log_file(const_cast<char*>(message));
}

arcdps_exports* init_module() {

    bool loading_successful = true;
    std::string error_message = "Unknown error";

    try {
        if (!GW2LangPatch::Initialize()) {
            throw std::runtime_error("GW2LangPatch initialization failed. Memory signatures not found.");
        }
    }
    catch (std::exception& e)
    {
        loading_successful = false;
        error_message = "Error starting up: ";
        error_message.append(e.what());
        ArcLog(error_message.c_str());
    }

    arc_exports.imguivers = IMGUI_VERSION_NUM;
    arc_exports.out_name = "TChinese UI";
    arc_exports.out_build = "1.0.0";

    if (loading_successful)
    {
        arc_exports.size = sizeof(arcdps_exports);
        arc_exports.sig = 0x54434849;
        arc_exports.options_end = options_tab;
        arc_exports.imgui = imgui_callback;
    }
    else
    {
        arc_exports.sig = 0;
        const std::string::size_type size = error_message.size();
        char* buffer = new char[size + 1]; //we need extra char for NUL
        memcpy(buffer, error_message.c_str(), size + 1);
        arc_exports.size = (uintptr_t)buffer;
    }

    return &arc_exports;
}

void release_module() {
    ChineseIme::Shutdown();
    VoicePatch::Shutdown();
    GW2LangPatch::Shutdown();
}

void options_tab()
{
    tabui.Draw();
}

void imgui_callback(uint32_t not_charsel_or_loading, uint32_t hide_if_combat_or_ooc) {
    GW2LangPatch::Update();
    VoicePatch::Update();
    ChineseIme::Update();
}

extern "C" __declspec(dllexport) void* get_init_addr(
    char* arcversionstr,
    void* imguicontext,
    void* id3dptr,
    HANDLE arcdll,
    void* mallocfn,
    void* freefn,
    uint32_t imguiversion)
{
    // set all arcdps stuff
    arc_dll = (HMODULE)arcdll;
    arc_log_file = (e3_func_ptr)GetProcAddress(arc_dll, "e3");
    arc_log = (e3_func_ptr)GetProcAddress(arc_dll, "e8");

    // set imgui context && allocation for arcdps dll space
    ImGui::SetCurrentContext(static_cast<ImGuiContext*>(imguicontext));
    ImGui::SetAllocatorFunctions((void* (*)(size_t, void*))mallocfn, (void (*)(void*, void*))freefn);

    return (void*)&init_module;
}

extern "C" __declspec(dllexport) void* get_release_addr(uint32_t reason) {
    return (void*)&release_module;
}

/* dll main -- winapi */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hSelfModule = hModule;
    }
    return TRUE;
}