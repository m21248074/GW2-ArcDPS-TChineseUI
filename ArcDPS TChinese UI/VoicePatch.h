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

    // 簡體中文（新方式）把遊戲儲存的語言設成中文「之前」，必須先解鎖文字語言：
    // 遊戲進入地圖時會斷言目前的文字語言是否被允許（LanguageIsPermitted(languageText, ...)），
    // 國際版客戶端預設不允許簡體中文，沒解鎖就會在進遊戲時崩潰。
    // 回傳 0 = 尚未完成（下一幀再呼叫）、1 = 已解鎖、-1 = 失敗（原因見 TextUnlockError）。
    int EnsureTextUnlocked();
    const char* TextUnlockError();
}
