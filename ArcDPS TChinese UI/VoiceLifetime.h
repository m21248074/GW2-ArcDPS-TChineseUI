#pragma once

// 語音準備任務的退出清理。
// 遊戲在準備（下載）中文語音時會有一個背景下載任務；如果任務還在跑時遊戲就退出，
// 會因為任務物件被不正確地銷毀而當機。做法與「激战2中文切换」的 VoiceTaskLifetime 相同：
// 在遊戲的「資源關閉」與「退出前下載佇列檢查」兩處接上清理程式，先取消並等待任務結束再放行。
// 掛鉤與記憶體區塊會一直保留到遊戲結束；插件卸載後它們仍然有效。

#include <string>

#include "VoicePrepare.h"

namespace VoicePrepare {

    // 安裝（或辨識先前已安裝的）退出清理。成功時回傳「生命週期內容」的位址：
    //   [0] 任務物件、[8] 關閉旗標（0 運作中 / 1 清理中 / 2 完成 / 3 物件不符）、[12] 進行中的呼叫數。
    // 失敗時丟出 std::runtime_error，且不會改動遊戲。log 會附加診斷訊息（以換行分隔）。
    uint8_t* EnsureExitCleanup(const Locator& loc, std::string& log);
}
