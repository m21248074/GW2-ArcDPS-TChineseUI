#pragma once

// 中文輸入增強（實驗）。
// 讓遊戲內建的網頁介面（商城、交易行）與原生編輯框可以使用系統輸入法打中文。做法與「激战2中文切换」相同：
//   1. 腳本橋接：遊戲建立內建瀏覽器時，把啟動腳本換成「原腳本 + 輸入法橋接腳本」。
//   2. 組字通知：在原生編輯框的文字變更通知上，組字期間先延遲通知，結束後才放行。
//   3. 商城編輯框的聚焦模式調整（兩處常數）。
// 勾選時才安裝；取消勾選會還原。已開啟的商城需要關閉後重新開啟才會生效。
namespace ChineseIme {
    void Update();                    // 每幀呼叫（imgui_callback）
    void Shutdown();                  // release_module：等待分析執行緒並還原

    void RequestEnable(bool enable);  // UI 勾選
    bool IsEnabled();

    // 網頁介面（交易行、寶石商城、魔法庫、兌換所）簡體 → 繁體；搜尋時會把輸入轉回簡體。
    // 由「簡體轉繁體模式」決定（見 GW2LangPatch），與中文輸入增強各自獨立；
    // 只有簡體中文用完整方式開啟（網頁才會是中文）時才會被要求。切換後新開的網頁才會生效。
    void SetWebTraditional(bool enable);
    bool IsWebTraditionalActive();
    const char* WebStatusText();
    bool IsBusy();
    bool IsAvailable();               // false = 本版遊戲無法適配
    const char* StatusText();         // UTF-8 狀態文字，可能為空字串
}
