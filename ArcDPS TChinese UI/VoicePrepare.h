#pragma once

// 官方中文語音準備流程。
// 切換配音語言之後，遊戲還需要「準備」中文語音資源（檢查已有檔案、補齊缺少的檔案並登記），
// 否則會沒有聲音。做法與「激战2中文切换」的手動模式相同：
//   1. 分析（背景執行緒）：從硬碟上的 exe 定位遊戲內部的語音清單、準備物件與任務工廠。
//   2. 執行（主執行緒）：在遊戲執行緒上呼叫遊戲自己的語音準備任務，之後輪詢進度。

#include <cstdint>
#include <string>

#include "VoiceImage.h"

namespace VoicePrepare {

    struct Locator {
        uint32_t root = 0;       // 語言清單根物件的指標位置
        uint32_t preparers = 0;  // 清單準備物件表
        uint32_t factory = 0;    // 官方下載任務工廠
        uint32_t query = 0;      // 本地資源查詢
        uint32_t vtable = 0;     // 準備物件虛表

        // 退出清理（語音任務還在跑時遊戲退出的保護）所需的位址
        uint32_t shutdownSite = 0;      // 資源關閉流程的尾跳入口（jmp shutdownTarget）
        uint32_t shutdownTarget = 0;
        uint32_t exitStatsSite = 0;     // 退出前下載佇列檢查的呼叫點（call exitStatsTarget）
        uint32_t exitStatsTarget = 0;
        uint32_t taskVtable = 0;
        uint32_t taskDestroy = 0;
        uint32_t taskCancel = 0;
        uint32_t taskState = 0;
        uint32_t workerSleep = 0;
        bool queueChainResolved = false; // 官方下載佇列的回收也定位成功時才為 true
        uint32_t queueRoot = 0;
        uint32_t queueLock = 0;
        uint32_t queueLockEnter = 0;
        uint32_t queueLockLeaveIat = 0;
        uint32_t queueMoveBatch = 0;
        uint32_t queueClear = 0;
        uint32_t queuePump = 0;
        uint8_t shutdownSiteBytes[5]{}; // 兩個入口在硬碟檔案裡的原始位元組
        uint8_t exitStatsSiteBytes[5]{};

        // 呼叫前要確認「記憶體中的函式開頭與硬碟檔案一致」的函式：
        // 任務工廠、本地查詢、虛表槽 11 與 21、任務銷毀/取消/狀態、下載執行緒休眠
        static constexpr int kEntryCount = 8;
        uint32_t entryRva[kEntryCount]{};
        uint8_t entryBytes[kEntryCount][32]{};
    };

    // 背景執行緒：定位所有需要的位址。失敗時 err 為原因（UTF-8）。
    bool Resolve(const VoiceImage::DiskImage& img, Locator& out, std::string& err);

    enum class Step { Waiting, Running, Done, Failed };

    struct Progress {
        Step step = Step::Waiting;
        std::string text; // UTF-8，供 UI 顯示
    };

    // 主執行緒：一次語音準備。建立後定期呼叫 Poll()，直到 Done 或 Failed。
    class Session {
    public:
        explicit Session(const Locator& locator);
        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;

        Progress Poll();
        std::string TakeLog(); // 取出累積的診斷訊息（以換行分隔）

    private:
        enum class Phase { Locate, Queue, Submitted, Finished };

        Progress PollImpl();
        void Log(const std::string& line);

        Locator loc_;
        Phase phase_ = Phase::Locate;
        uint8_t* image_ = nullptr;
        uint32_t manifest_ = 0;
        uint64_t preparer_ = 0;
        uint64_t rootObject_ = 0;
        uint8_t* context_ = nullptr; // 退出清理的生命週期內容（[0] 任務、[8] 關閉旗標、[12] 進行中呼叫數）
        uint8_t* block_ = nullptr;   // 呼叫桩與狀態區；提交後不釋放，遊戲可能仍在使用
        uint64_t startedTick_ = 0;
        int lastState_ = -1;
        std::string log_;
    };
}
