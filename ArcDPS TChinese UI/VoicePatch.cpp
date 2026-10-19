#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "VoicePatch.h"
#include "GW2LangPatch.h"
#include "VoiceImage.h"
#include "VoicePrepare.h"

#include <Windows.h>
#include <Zydis/Zydis.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

extern void ArcLog(const char* message);

namespace {
    using namespace VoiceImage;

    constexpr uint32_t kChineseLanguageId = 5;
    constexpr uint32_t kLanguageUseAudio = 1;   // SetLanguage(lang, use)：0 = 文字，1 = 配音
    constexpr uint32_t kAudioPermittedMask = 45; // 配音「允許語言」遮罩的原版值
    constexpr uint32_t kTextPermittedMask = 63;  // 文字「允許語言」遮罩的原版值
    constexpr size_t kEntryCheckBytes = 32;

    // ------------------------------------------------------------------
    // A. 原生語言設定函式 SetLanguage(lang, use)
    //    以字串 "(unsigned)use < LANGUAGE_USES" 反查，再用函式開頭的指令特徵確認唯一。
    // ------------------------------------------------------------------
    bool FindSetLanguage(const DiskImage& img, uint32_t& outRva, std::string& err) {
        const std::set<uint32_t> strs = FindAsciiZ(img, "(unsigned)use < LANGUAGE_USES");
        if (strs.empty()) {
            err = U8("找不到語言設定函式的錨點字串");
            return false;
        }
        if (img.excDirSize < 12 || img.excDirSize % 12 != 0 || !img.InRange(img.excDirRva, img.excDirSize)) {
            err = U8("例外目錄異常");
            return false;
        }

        const uint32_t execEnd = img.execStart + img.execSize;
        std::set<uint32_t> found;
        for (uint32_t l = img.execStart; l + 7 <= execEnd; ++l) {
            if (img.mem[l] != 0x48 || img.mem[l + 1] != 0x8D || img.mem[l + 2] != 0x0D) continue;
            const int64_t t = static_cast<int64_t>(l) + 7 + img.S32(l + 3);
            if (t < 0 || !strs.count(static_cast<uint32_t>(t))) continue;

            for (uint32_t e = 0; e < img.excDirSize; e += 12) {
                const uint32_t begin = img.U32(img.excDirRva + e);
                const uint32_t end = img.U32(img.excDirRva + e + 4);
                if (l < begin || l >= end || begin < img.execStart || end > execEnd || end - begin > 2048) continue;

                bool invalid = false;
                const std::vector<Insn> list = DecodeSeq(img, begin, end - begin, false, &invalid);
                if (invalid || list.empty()) continue;

                bool movsxdUse = false, movLang = false, cmpLang = false, cmpUse = false;
                int calls = 0;
                for (size_t i = 0; i < list.size(); ++i) {
                    const Insn& x = list[i];
                    if (i < 12) {
                        if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOVSXD && IsReg(x.op[0], ZYDIS_REGISTER_RDI) && IsReg(x.op[1], ZYDIS_REGISTER_EDX)) movsxdUse = true;
                        if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOV && IsReg(x.op[0], ZYDIS_REGISTER_EBX) && IsReg(x.op[1], ZYDIS_REGISTER_ECX)) movLang = true;
                    }
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_CMP) {
                        if (IsReg(x.op[0], ZYDIS_REGISTER_ECX) && IsImm(x.op[1], 6)) cmpLang = true;
                        if (IsReg(x.op[0], ZYDIS_REGISTER_EDI) && IsImm(x.op[1], 2)) cmpUse = true;
                    }
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_CALL) ++calls;
                }
                if (movsxdUse && movLang && cmpLang && cmpUse && calls >= 8) found.insert(begin);
            }
        }

        if (found.size() != 1) {
            err = U8("原生語言設定函式無法唯一確認，本版遊戲未適配");
            return false;
        }
        outRva = *found.begin();
        return true;
    }

    // ------------------------------------------------------------------
    // B. 配音語言解鎖計畫
    //    語言限制函式內有兩個「允許語言遮罩」（原版 45 / 63）與兩個「封鎖遮罩」。
    //    配音只需要：允許遮罩（45）維持，並把離它最近的那組封鎖遮罩歸零、
    //    同時把會寫入該遮罩的 mov 指令改成 NOP。
    // ------------------------------------------------------------------
    struct Patch {
        uint32_t rva = 0;
        std::vector<uint8_t> original;
        std::vector<uint8_t> replacement;
        bool isMask = false;
        int group = -1;
    };

    Patch MakeMask(uint32_t rva, uint32_t value, int group) {
        Patch p;
        p.rva = rva;
        p.replacement.resize(4);
        std::memcpy(p.replacement.data(), &value, 4);
        p.isMask = true;
        p.group = group;
        return p;
    }

    bool BuildAudioPlan(const DiskImage& img, std::vector<Patch>& out, std::string& err) {
        std::set<uint32_t> strs = FindAsciiZ(img, "LanguageIsPermitted(languageText, LANGUAGE_USE_TEXT)");
        for (uint32_t s : FindAsciiZ(img, "LanguageIsPermitted(languageAudio, LANGUAGE_USE_AUDIO)")) strs.insert(s);
        if (strs.empty()) {
            err = U8("找不到語言限制的錨點字串");
            return false;
        }

        auto isData = [&](uint32_t rva) {
            if (rva % 4 != 0) return false;
            for (const auto& r : img.dataRanges) {
                if (rva >= r.first && static_cast<uint64_t>(rva) + 4 <= r.second) return true;
            }
            return false;
        };

        struct Found {
            std::vector<uint32_t> tests;
            std::vector<uint32_t> loads;
        };
        std::map<uint32_t, Found> funcs;

        const uint32_t execEnd = img.execStart + img.execSize;
        for (uint32_t l = img.execStart; l + 7 <= execEnd; ++l) {
            if ((img.mem[l] != 0x48 && img.mem[l] != 0x4C) || img.mem[l + 1] != 0x8D || (img.mem[l + 2] & 0xC7) != 5) continue;
            const int64_t t = static_cast<int64_t>(l) + 7 + img.S32(l + 3);
            if (t < 0 || !strs.count(static_cast<uint32_t>(t))) continue;

            const int64_t lowest = std::max<int64_t>(img.execStart, static_cast<int64_t>(l) - 120);
            for (int64_t n = static_cast<int64_t>(l) - 5; n >= lowest; --n) {
                if (img.mem[static_cast<size_t>(n)] != 0xE8) continue;
                const int64_t target = n + 5 + img.S32(static_cast<uint64_t>(n) + 1);
                if (target < img.execStart || target > static_cast<int64_t>(execEnd) - 128) continue;

                const std::vector<Insn> list = DecodeSeq(img, static_cast<uint32_t>(target), 128, true);
                Found f;
                for (const Insn& x : list) {
                    uint32_t a = 0;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_TEST && RipTarget(x, x.op[0], a)) PushDistinct(f.tests, a);
                    if ((x.ins.mnemonic == ZYDIS_MNEMONIC_MOV || x.ins.mnemonic == ZYDIS_MNEMONIC_CMOVZ)
                        && IsReg(x.op[0], ZYDIS_REGISTER_EAX) && RipTarget(x, x.op[1], a)) PushDistinct(f.loads, a);
                }
                if (f.tests.size() != 2 || f.loads.size() != 2) continue;

                std::set<uint32_t> all(f.tests.begin(), f.tests.end());
                all.insert(f.loads.begin(), f.loads.end());
                if (all.size() != 4 || !std::all_of(all.begin(), all.end(), isData)) continue;
                if (img.U32(f.tests[0]) != kAudioPermittedMask || img.U32(f.tests[1]) != kTextPermittedMask) continue;

                funcs[static_cast<uint32_t>(target)] = std::move(f);
                break;
            }
        }

        if (funcs.size() != 1) {
            err = U8("語言限制結構無法唯一確認，本版遊戲未適配");
            return false;
        }
        const Found& f = funcs.begin()->second;

        // 兩組封鎖遮罩各自的 NOP 補丁（與原工具相同，兩組都必須找得到 1~4 處）
        std::vector<Patch> nops;
        for (int g = 0; g < 2; ++g) {
            int count = 0;
            for (uint32_t n = img.execStart; n + 10 <= execEnd; ++n) {
                const uint8_t b0 = img.mem[n];
                if ((b0 != 0x89 && b0 != 0xC7) || (img.mem[n + 1] & 0xC7) != 5) continue;

                Insn x;
                uint32_t a = 0;
                if (!DecodeOne(img, n, static_cast<uint64_t>(n) + 15, x)) continue;
                if (x.ins.mnemonic != ZYDIS_MNEMONIC_MOV || !RipTarget(x, x.op[0], a) || a != f.loads[g]) continue;
                if (x.op[0].size != 32 || x.ins.length < 6 || x.ins.length > 10) {
                    err = U8("封鎖遮罩的寫入指令形態未適配");
                    return false;
                }

                Patch p;
                p.rva = n;
                p.original.assign(img.mem.begin() + n, img.mem.begin() + n + x.ins.length);
                p.replacement.assign(x.ins.length, 0x90);
                p.group = g;
                nops.push_back(std::move(p));
                ++count;
            }
            if (count == 0 || count > 4) {
                err = U8("封鎖遮罩的寫入點數量不符，本版遊戲未適配");
                return false;
            }
        }

        // 重疊檢查
        for (size_t i = 0; i < nops.size(); ++i) {
            for (size_t j = i + 1; j < nops.size(); ++j) {
                if (nops[i].rva < nops[j].rva + nops[j].replacement.size() && nops[j].rva < nops[i].rva + nops[i].replacement.size()) {
                    err = U8("補丁位置重疊，未適配");
                    return false;
                }
            }
        }

        // 配音計畫 = 允許遮罩 + 離它最近的那組封鎖遮罩（歸零）與其 NOP
        const Patch audioMask = MakeMask(f.tests[0], kAudioPermittedMask, -1);
        const uint32_t d0 = f.loads[0] > audioMask.rva ? f.loads[0] - audioMask.rva : audioMask.rva - f.loads[0];
        const uint32_t d1 = f.loads[1] > audioMask.rva ? f.loads[1] - audioMask.rva : audioMask.rva - f.loads[1];
        const int blocked = (d1 < d0) ? 1 : 0;

        out.clear();
        out.push_back(audioMask);
        out.push_back(MakeMask(f.loads[blocked], 0, blocked));
        for (const Patch& p : nops) {
            if (p.group == blocked) out.push_back(p);
        }
        return true;
    }

    // ------------------------------------------------------------------
    // 套用 / 還原（遊戲記憶體）
    // ------------------------------------------------------------------
    bool IsReadable(const void* ptr, size_t size) {
        uintptr_t current = reinterpret_cast<uintptr_t>(ptr);
        const uintptr_t end = current + size;
        while (current < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
            const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd <= current) return false;
            current = regionEnd;
        }
        return true;
    }

    bool WriteGameMemory(void* target, const void* source, size_t size) {
        DWORD oldProtect = 0;
        if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
        std::memcpy(target, source, size);
        FlushInstructionCache(GetCurrentProcess(), target, size);
        DWORD restored = 0;
        return VirtualProtect(target, size, oldProtect, &restored) != 0;
    }

    struct Applied {
        uintptr_t address;
        std::vector<uint8_t> previous;
    };

    std::vector<Applied> g_applied;

    bool ApplyPlan(const std::vector<Patch>& plan, std::string& err) {
        uint8_t* base = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
        if (!base) {
            err = U8("無法取得遊戲模組");
            return false;
        }

        std::vector<std::vector<uint8_t>> current(plan.size());
        for (size_t i = 0; i < plan.size(); ++i) {
            const Patch& p = plan[i];
            const uint8_t* addr = base + p.rva;
            if (!IsReadable(addr, p.replacement.size())) {
                err = U8("無法讀取遊戲記憶體");
                return false;
            }
            current[i].assign(addr, addr + p.replacement.size());

            if (!p.isMask) {
                if (current[i] != p.original && current[i] != p.replacement) {
                    err = U8("語言限制程式碼已被其他工具修改，請重啟遊戲後再試");
                    return false;
                }
            }
            else {
                uint32_t v = 0;
                std::memcpy(&v, current[i].data(), 4);
                if ((v & 0xFFFFFFC0u) != 0) {
                    err = U8("語言遮罩的現值異常，未適配");
                    return false;
                }
            }
        }

        // 先改程式碼（NOP），最後才改遮罩
        std::vector<size_t> order(plan.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return plan[a].isMask < plan[b].isMask; });

        std::vector<size_t> written;
        auto rollback = [&]() {
            for (auto it = written.rbegin(); it != written.rend(); ++it) {
                WriteGameMemory(base + plan[*it].rva, current[*it].data(), current[*it].size());
            }
        };

        for (size_t idx : order) {
            if (current[idx] == plan[idx].replacement) continue;
            if (!WriteGameMemory(base + plan[idx].rva, plan[idx].replacement.data(), plan[idx].replacement.size())) {
                rollback();
                err = U8("寫入遊戲記憶體失敗");
                return false;
            }
            written.push_back(idx);
        }

        for (const Patch& p : plan) {
            if (std::memcmp(base + p.rva, p.replacement.data(), p.replacement.size()) != 0) {
                rollback();
                err = U8("補丁寫入後校驗失敗");
                return false;
            }
        }

        for (size_t idx : written) {
            g_applied.push_back({ reinterpret_cast<uintptr_t>(base + plan[idx].rva), current[idx] });
        }
        return true;
    }

    void RestoreApplied() {
        for (auto it = g_applied.rbegin(); it != g_applied.rend(); ++it) {
            if (IsReadable(reinterpret_cast<void*>(it->address), it->previous.size())) {
                WriteGameMemory(reinterpret_cast<void*>(it->address), it->previous.data(), it->previous.size());
            }
        }
        g_applied.clear();
    }

    // ------------------------------------------------------------------
    // 背景分析（只讀硬碟檔案，不碰遊戲狀態）
    // ------------------------------------------------------------------
    struct Analysis {
        uint32_t setLanguageRva = 0;
        std::vector<Patch> plan;
        VoicePrepare::Locator locator;
        bool prepareOk = false;
        std::string prepareError;
        std::string log;
    };

    std::atomic<int> g_analysisState{ 0 }; // 0 未開始、1 進行中、2 成功、3 失敗
    std::thread g_worker;
    Analysis g_analysis;
    std::string g_analysisError;

    void AnalysisMain() {
        Analysis result;
        std::string err;
        bool ok = false;
        try {
            DiskImage img;
            ok = LoadDiskImage(img, err) && FindSetLanguage(img, result.setLanguageRva, err);
            if (ok) {
                char line[128];
                std::snprintf(line, sizeof(line), "[Voice] SetLanguage RVA 0x%X\n", result.setLanguageRva);
                result.log += line;

                // 與原工具相同：記憶體中的函式開頭必須與硬碟檔案一致，避免被其他程式 hook
                const uint8_t* live = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr)) + result.setLanguageRva;
                if (!IsReadable(live, kEntryCheckBytes) || std::memcmp(live, &img.mem[result.setLanguageRva], kEntryCheckBytes) != 0) {
                    err = U8("原生語言設定函式與硬碟檔案不一致（可能已被其他工具修改）");
                    ok = false;
                }
            }
            if (ok) ok = BuildAudioPlan(img, result.plan, err);
            if (ok) {
                // 語音準備流程的定位失敗不影響配音切換，只是之後無法自動補齊資源
                result.prepareOk = VoicePrepare::Resolve(img, result.locator, result.prepareError);
                char line[160];
                if (result.prepareOk) {
                    std::snprintf(line, sizeof(line), "[Voice] prepare root=0x%X preparers=0x%X factory=0x%X query=0x%X vtable=0x%X\n",
                        result.locator.root, result.locator.preparers, result.locator.factory, result.locator.query, result.locator.vtable);
                }
                else {
                    std::snprintf(line, sizeof(line), "[Voice] prepare locator failed\n");
                }
                result.log += line;
                if (!result.prepareOk) result.log += "[Voice] " + result.prepareError + "\n";
            }
            if (ok) {
                for (const Patch& p : result.plan) {
                    char line[128];
                    std::snprintf(line, sizeof(line), "[Voice] %s RVA 0x%X group=%d\n", p.isMask ? "mask" : "nop ", p.rva, p.group);
                    result.log += line;
                }
            }
        }
        catch (...) {
            err = U8("分析時發生例外");
            ok = false;
        }

        if (ok) {
            g_analysis = std::move(result);
        }
        else {
            g_analysisError = err;
        }
        g_analysisState.store(ok ? 2 : 3, std::memory_order_release);
    }

    // ------------------------------------------------------------------
    // 主執行緒狀態機
    // ------------------------------------------------------------------
    enum class Phase { Idle, Analyzing, WaitingCall, Preparing };

    Phase g_phase = Phase::Idle;
    bool g_requested = false;
    bool g_wantEnable = false;
    bool g_enabled = false;
    bool g_unavailable = false;
    bool g_patched = false;
    bool g_logFlushed = false;
    uint32_t g_originalAudio = 0;
    uint32_t g_expectLanguage = 0;
    int g_waitFrames = 0;
    int g_retryFrames = 0;
    std::string g_status;
    std::unique_ptr<VoicePrepare::Session> g_session;
    uint64_t g_lastPoll = 0;
    uint64_t g_lastAssert = 0;

    void FlushAnalysisLog() {
        if (g_logFlushed) return;
        g_logFlushed = true;
        const std::string& log = g_analysis.log;
        size_t start = 0;
        while (start < log.size()) {
            size_t end = log.find('\n', start);
            if (end == std::string::npos) end = log.size();
            ArcLog(log.substr(start, end - start).c_str());
            start = end + 1;
        }
    }

    void FlushSessionLog() {
        if (!g_session) return;
        const std::string log = g_session->TakeLog();
        size_t start = 0;
        while (start < log.size()) {
            size_t end = log.find('\n', start);
            if (end == std::string::npos) end = log.size();
            if (end > start) ArcLog(log.substr(start, end - start).c_str());
            start = end + 1;
        }
    }

    // 遊戲在進入角色等時機會重新套用帳號裡儲存的配音設定（通常是英文），把我們設好的中文蓋掉。
    // 勾選期間若發現配音語言被改掉，就在遊戲執行緒上重新套用。
    void MaintainAudioLanguage() {
        if (!g_enabled || g_requested || g_phase == Phase::WaitingCall) return;

        const uint64_t now = GetTickCount64();
        if (now - g_lastAssert < 2000) return;

        const uint32_t* lang = GW2LangPatch::GetLanguagePtr();
        if (!lang || lang[1] == kChineseLanguageId) return;
        if (!GW2LangPatch::IsNativeCallIdle()) return;

        const uintptr_t function = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) + g_analysis.setLanguageRva;
        if (GW2LangPatch::QueueNativeCall(function, kChineseLanguageId, kLanguageUseAudio)) {
            g_lastAssert = now;
            char line[96];
            std::snprintf(line, sizeof(line), "[Voice] audio language was changed to %u by the game, re-applying", lang[1]);
            ArcLog(line);
        }
    }

    void Fail(const std::string& message) {
        g_status = message;
        g_requested = false;
        g_phase = Phase::Idle;
        g_waitFrames = 0;
        g_retryFrames = 0;
        ArcLog(("[Voice] " + message).c_str());
    }
} // anonymous namespace

namespace VoicePatch {

    void RequestEnable(bool enable) {
        if (g_unavailable || IsBusy()) return;
        if (!enable && !g_enabled) return;
        g_requested = true;
        g_wantEnable = enable;
        g_status.clear();
    }

    bool IsEnabled() { return g_enabled; }

    // 準備資源（可能等很久）期間仍可取消勾選，所以不算忙碌
    bool IsBusy() { return g_requested || g_phase == Phase::Analyzing || g_phase == Phase::WaitingCall; }

    bool IsAvailable() { return !g_unavailable; }

    const char* StatusText() { return g_status.c_str(); }

    void Update() {
        MaintainAudioLanguage();

        // 原生呼叫已送出，等遊戲執行緒執行完並確認語言
        if (g_phase == Phase::WaitingCall) {
            if (!GW2LangPatch::IsNativeCallIdle()) {
                if (++g_waitFrames > 1800) Fail(U8("遊戲未執行語言切換呼叫"));
                return;
            }
            const uint32_t* lang = GW2LangPatch::GetLanguagePtr();
            const uint32_t audio = lang ? lang[1] : 0xFFFFFFFFu;
            if (audio == g_expectLanguage) {
                g_enabled = (g_expectLanguage == kChineseLanguageId);
                g_phase = Phase::Idle;
                ArcLog(g_enabled ? "[Voice] audio language -> 5 (verified)" : "[Voice] audio language restored");
                if (!g_enabled) {
                    g_status = U8("已還原原本的配音語言");
                }
                else if (g_analysis.prepareOk) {
                    // 切換語言之後，再讓遊戲準備（檢查/補齊/登記）中文語音資源，否則會沒有聲音
                    g_session = std::make_unique<VoicePrepare::Session>(g_analysis.locator);
                    g_lastPoll = 0;
                    g_phase = Phase::Preparing;
                    g_status = U8("中文語音：準備資源中…");
                }
                else {
                    g_status = std::string(U8("已切換為中文配音，但無法自動準備語音資源：")) + g_analysis.prepareError;
                }
            }
            else if (++g_waitFrames > 120) {
                Fail(U8("呼叫已執行，但配音語言未改變（可能需要進入遊戲後再試）"));
            }
            return;
        }

        // 使用者在準備資源期間切換勾選：放棄追蹤目前的準備任務，照新的請求處理
        if (g_phase == Phase::Preparing && g_requested) {
            g_session.reset();
            g_phase = Phase::Idle;
        }

        if (g_phase == Phase::Preparing) {
            const uint64_t now = GetTickCount64();
            if (now - g_lastPoll < 1000) return;
            g_lastPoll = now;

            const VoicePrepare::Progress progress = g_session->Poll();
            FlushSessionLog();
            if (!progress.text.empty()) g_status = progress.text;
            if (progress.step == VoicePrepare::Step::Done || progress.step == VoicePrepare::Step::Failed) {
                ArcLog(("[Voice] " + g_status).c_str());
                g_session.reset();
                g_phase = Phase::Idle;
            }
            return;
        }

        if (!g_requested) return;

        // 第一次使用時才分析（背景執行緒）
        const int state = g_analysisState.load(std::memory_order_acquire);
        if (state == 0) {
            g_analysisState.store(1);
            g_worker = std::thread(AnalysisMain);
            g_phase = Phase::Analyzing;
            g_status = U8("分析遊戲程式中…");
            return;
        }
        if (state == 1) return;
        if (state == 3) {
            g_unavailable = true;
            Fail(std::string(U8("中文語音不可用：")) + g_analysisError);
            return;
        }
        g_phase = Phase::Idle;
        FlushAnalysisLog();

        const uint32_t* langPtr = GW2LangPatch::GetLanguagePtr();
        if (!langPtr) {
            Fail(U8("尚未取得語言設定位址"));
            return;
        }

        uint32_t targetLanguage = 0;
        if (g_wantEnable) {
            if (!g_patched) {
                std::string err;
                if (!ApplyPlan(g_analysis.plan, err)) {
                    Fail(std::string(U8("套用解鎖補丁失敗：")) + err);
                    return;
                }
                g_patched = true;
                ArcLog("[Voice] audio unlock patches applied");
            }
            if (!g_enabled) {
                g_originalAudio = langPtr[1] <= 5 ? langPtr[1] : 0; // 記錄原本的配音語言以便還原
            }
            targetLanguage = kChineseLanguageId;
        }
        else {
            targetLanguage = g_originalAudio;
        }

        const uintptr_t function = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) + g_analysis.setLanguageRva;
        if (!GW2LangPatch::QueueNativeCall(function, targetLanguage, kLanguageUseAudio)) {
            // 佇列忙碌時下一幀重試；持續失敗代表掛鉤無法安裝
            if (++g_retryFrames > 600) Fail(U8("無法在遊戲執行緒上呼叫語言設定函式"));
            return;
        }

        g_requested = false;
        g_retryFrames = 0;
        g_waitFrames = 0;
        g_expectLanguage = targetLanguage;
        g_phase = Phase::WaitingCall;
        g_status = U8("套用中…");
    }

    void Shutdown() {
        g_session.reset();
        if (g_worker.joinable()) g_worker.join();
        RestoreApplied();
        g_patched = false;
    }

} // namespace VoicePatch
