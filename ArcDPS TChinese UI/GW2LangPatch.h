#pragma once
#include <Windows.h>
#include <cstdint>

namespace GW2LangPatch {
    bool Initialize(); // for init_module
    void Shutdown(); // release_module

    // for ui
    bool IsChineseEnabled();
    // 在遊戲執行緒上呼叫原生函式 function(arg0, arg1)；佇列忙碌或掛鉤無法安裝時回傳 false
    bool QueueNativeCall(uintptr_t function, uint32_t arg0, uint32_t arg1);
    bool IsNativeCallIdle();
    // 遊戲內語言設定：[0] = 文字語言、[1] = 配音語言
    uint32_t* GetLanguagePtr();

    // 簡體中文（文字語言）有兩種開啟方式：
    //   舊方式（預設）：只刷新介面文字，遊戲儲存的語言維持不變，字型不變；商城等網頁維持英文。
    //   新方式：完整切換遊戲語言，交易行、商城、魔法庫等網頁也會是中文（可繁體化），
    //           但遊戲字型會改成為中國版本設計的字型。
    bool IsFullLanguageAvailable();
    bool IsFullLanguageMode();
    // 「開啟內建簡體中文」（full = true，新方式）與「開啟內建簡體中文(舊)」（full = false）兩個按鈕共用。
    // 開啟時記下用哪一種方式，直接換掉另一種；關閉時方式維持不變，
    // 之後繁體模式自動開啟簡體中文時沿用最後用的方式（預設是舊方式）。
    void SetChinese(bool enable, bool full);
    // 簡體中文目前的狀態說明（例如新方式無法解鎖而改用舊方式）；沒有事要說時是空字串
    const char* LanguageStatusText();

    bool IsTradModeEnabled();
    void SetTradMode(bool enable);
    // 簡體轉繁體模式：勾選時自動開啟簡體中文（用目前選的方式），取消時只還原由它自動開啟的那一份；
    // 商城網頁繁體化跟著它（只有新方式才會載入）。
    void RequestTraditional(bool enable);

    void Update(); // for imgui_callback
}