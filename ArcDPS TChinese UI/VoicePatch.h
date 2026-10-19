#pragma once

// 中文語音（實驗功能）。
// 做法與「激战2中文切换」的手動模式相同：
//   1. 讀硬碟上的 Gw2-64.exe，用字串錨點與指令特徵定位語言限制與原生語言設定函式。
//   2. 使用者勾選時，才對執行中的遊戲套用「配音語言解鎖」補丁。
//   3. 透過遊戲執行緒呼叫原生 SetLanguage(5, LANGUAGE_USE_AUDIO) 切換配音。
namespace VoicePatch {
    void Update();                    // 每幀呼叫（imgui_callback）
    void Shutdown();                  // release_module：等待分析執行緒並還原補丁

    void RequestEnable(bool enable);  // UI 勾選
    bool IsEnabled();                 // 配音語言已確認為中文
    bool IsBusy();                    // 處理中，UI 應暫時停用
    bool IsAvailable();               // false = 本版遊戲無法適配
    const char* StatusText();         // UTF-8 狀態文字，可能為空字串
}
