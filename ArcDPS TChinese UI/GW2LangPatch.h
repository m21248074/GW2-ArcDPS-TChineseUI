#pragma once
#include <Windows.h>
#include <cstdint>

namespace GW2LangPatch {
    bool Initialize(); // for init_module
    void Shutdown(); // release_module

    // for ui
    bool IsChineseEnabled();
    void QueueLanguageToggle(bool enable);
    // 在遊戲執行緒上呼叫原生函式 function(arg0, arg1)；佇列忙碌或掛鉤無法安裝時回傳 false
    bool QueueNativeCall(uintptr_t function, uint32_t arg0, uint32_t arg1);
    bool IsNativeCallIdle();
    // 遊戲內語言設定：[0] = 文字語言、[1] = 配音語言
    uint32_t* GetLanguagePtr();

    bool IsTradModeEnabled();
    void SetTradMode(bool enable);

    void Update(); // for imgui_callback
}