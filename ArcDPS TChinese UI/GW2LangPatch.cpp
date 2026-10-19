#include "GW2LangPatch.h"
#include "ChineseIme.h"
#include "VoicePatch.h"
#include <Psapi.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <Windows.h>
#include <unordered_map>
#include <algorithm>
#include <atomic>
#include <vector>
#include <fstream>

#include <MinHook.h>
#include <asmjit/asmjit.h>

using namespace asmjit;

extern HMODULE g_hSelfModule;
extern void ArcLog(const char* message);

namespace {
    // --- 內部狀態變數 ---
    constexpr const char* kValidateLanguageAnchor = "ValidateLanguage(language)";
    constexpr const char* kViewAdvanceTextAnchor = "ViewAdvanceText";
    constexpr uint32_t kChineseLanguageId = 5;

    bool g_initialized = false;
    // 簡體中文（文字語言）：要求的狀態與已套用的狀態分開記錄，差異由 PlanLanguageSteps 排成原生呼叫
    bool g_chineseWanted = false;  // 使用者或繁體模式要求開啟
    bool g_fullWanted = false;     // 要求用完整的 SetLanguage（新方式）
    bool g_tradWanted = false;     // 繁體模式
    bool g_autoByTrad = false;     // 簡體中文是被繁體模式自動帶開的（取消繁體模式時才需要還原）
    bool g_applyDirty = false;     // 要求的狀態有變動，需要重新比對
    int g_appliedMode = 0;         // 已套用：0 未啟用、1 舊方式、2 新方式
    struct LangStep {
        uintptr_t function;
        uint32_t language;
        bool unlock = false;           // true = 不是原生呼叫，而是「解鎖文字語言」的閘門
    };
    std::vector<LangStep> g_langSteps; // 待執行的步驟（依序）
    int g_modeBeforePlan = 0;          // 排程前已套用的模式（解鎖失敗時要退回）
    std::string g_langStatus;
    bool g_waitingForDeferredCall = false;

    uint32_t g_originalLanguage = 0;
    uint32_t* g_originalLanguagePtr = nullptr;

    using LanguageSetterFn = void(__fastcall*)(uint32_t languageId);
    LanguageSetterFn g_languageSetter = nullptr;

    // 完整的 SetLanguage(lang, use)。g_languageSetter 只是它內部的「語言已變更」處理函式，
    // 呼叫它會刷新介面，但不會更新遊戲儲存的語言變數；網頁介面（交易行、商城、魔法庫、兌換所）
    // 組網址時讀的是那個變數，所以要用完整的 SetLanguage 才會跟著變成中文。
    uintptr_t g_fullSetter = 0;

    uint8_t* g_viewAdvanceTextHookPoint = nullptr;
    uint8_t* g_viewAdvanceTextOriginalCallTarget = nullptr;

    // --- Deferred Hook 結構與變數 ---
    struct PendingCallBuffer {
        uintptr_t Function;
        uint64_t Arg0;
        uint64_t CompletedCount;
        uint64_t Arg1; // 第二個參數（edx）；語言設定函式的 use：0 = 文字、1 = 配音
    };

    PendingCallBuffer g_pendingCall{};
    void* g_callerCodeCave = nullptr;
    std::array<uint8_t, 5> g_callerHookBackup{};
    bool g_callerHookInstalled = false;

    struct CodeBuffer {
        std::array<uint8_t, 512> Bytes{};
        size_t Size = 0;
    };

    struct ReplaceRule {
        std::wstring inStr;
        std::wstring outStr;
    };

    std::unordered_map<wchar_t, std::vector<ReplaceRule>> g_rules;

    constexpr const char* kCParserAnchor = "CParser::Validate(sourceBuffer.Ptr(), sourceBuffer.Term(), true ) == sourceBuffer.Term()";

    bool g_tradModeEnabled = false;

    uint8_t* g_textConverterHookPoint = nullptr;

    // MinHook 產生的原程式跳板指標
    void* g_textConverterOriginal = nullptr;

    // AsmJit 動態生成的掛鉤函數
    void* g_textConverterDetour = nullptr;
    JitRuntime* g_jitRuntime; // AsmJit 執行期記憶體管理

    // --- 記憶體輔助與除錯輸出 ---
    void DebugLog(const char* message) {
        OutputDebugStringA((std::string("[GW2LangPatch] ") + message + "\n").c_str());
    }

    void AppendU8(CodeBuffer& code, uint8_t value) {
        if (code.Size < code.Bytes.size()) code.Bytes[code.Size++] = value;
    }

    void AppendU32(CodeBuffer& code, uint32_t value) {
        for (int i = 0; i < 4; ++i) AppendU8(code, static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }

    void AppendU64(CodeBuffer& code, uint64_t value) {
        for (int i = 0; i < 8; ++i) AppendU8(code, static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }

    bool WriteProtectedMemory(void* target, const void* source, size_t size) {
        DWORD oldProtect = 0;
        if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
        std::memcpy(target, source, size);
        FlushInstructionCache(GetCurrentProcess(), target, size);
        DWORD restoredProtect = 0;
        return VirtualProtect(target, size, oldProtect, &restoredProtect) != 0;
    }

    bool BuildRel32Jump(uint8_t* source, uint8_t* target, std::array<uint8_t, 5>* out) {
        intptr_t delta = target - (source + 5);
        if (delta < INT32_MIN || delta > INT32_MAX) return false;
        (*out)[0] = 0xE9;
        int32_t rel = static_cast<int32_t>(delta);
        std::memcpy(out->data() + 1, &rel, sizeof(rel));
        return true;
    }

    bool AppendRel32Jump(CodeBuffer& code, uint8_t* codeBase, uint8_t* target) {
        uint8_t* source = codeBase + code.Size;
        intptr_t delta = target - (source + 5);
        if (delta < INT32_MIN || delta > INT32_MAX) return false;
        AppendU8(code, 0xE9);
        AppendU32(code, static_cast<uint32_t>(static_cast<int32_t>(delta)));
        return true;
    }

    void* AllocNearMemory(uint8_t* target, size_t size) {
        SYSTEM_INFO sysInfo{};
        GetSystemInfo(&sysInfo);
        uintptr_t granularity = sysInfo.dwAllocationGranularity;
        uintptr_t targetAddress = reinterpret_cast<uintptr_t>(target);
        uintptr_t minAddress = targetAddress > 0x7FFF0000ULL ? targetAddress - 0x7FFF0000ULL : granularity;
        uintptr_t maxAddress = targetAddress + 0x7FFF0000ULL;

        minAddress &= ~(granularity - 1);
        maxAddress &= ~(granularity - 1);

        for (uintptr_t address = minAddress; address < maxAddress; address += granularity) {
            void* result = VirtualAlloc(reinterpret_cast<void*>(address), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (result) return result;
        }
        return nullptr;
    }

    bool GetMainModuleRange(uint8_t** base, size_t* size) {
        HMODULE module = GetModuleHandleW(nullptr);
        if (!module) return false;
        MODULEINFO info{};
        if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info))) return false;
        *base = static_cast<uint8_t*>(info.lpBaseOfDll);
        *size = static_cast<size_t>(info.SizeOfImage);
        return *base != nullptr && *size > 0;
    }

    bool IsReadableProtect(DWORD protect) {
        if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS)) return false;
        switch (protect & 0xFF) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY: return true;
        default: return false;
        }
    }

    bool IsExecutableProtect(DWORD protect) {
        if ((protect & PAGE_GUARD) || (protect & PAGE_NOACCESS)) return false;
        switch (protect & 0xFF) {
        case PAGE_EXECUTE: case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY: return true;
        default: return false;
        }
    }

    bool IsMemoryRangeUsable(void* ptr, size_t size, bool executable) {
        if (!ptr || size == 0) return false;
        uintptr_t current = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t end = current + size;
        if (end < current) return false;

        while (current < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi))) return false;
            if (mbi.State != MEM_COMMIT) return false;
            bool usable = executable ? IsExecutableProtect(mbi.Protect) : IsReadableProtect(mbi.Protect);
            if (!usable) return false;
            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd <= current) return false;
            current = regionEnd;
        }
        return true;
    }

    bool IsReadableAddress(void* ptr, size_t size) { return IsMemoryRangeUsable(ptr, size, false); }
    bool IsExecutableAddress(void* ptr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) return false;
        return mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect);
    }
    bool IsInRange(uint8_t* ptr, uint8_t* base, size_t size) {
        uintptr_t start = reinterpret_cast<uintptr_t>(base);
        return reinterpret_cast<uintptr_t>(ptr) >= start && reinterpret_cast<uintptr_t>(ptr) < start + size;
    }

    uint8_t* FindBytes(uint8_t* base, size_t size, const uint8_t* pattern, size_t patternSize) {
        for (size_t i = 0; i <= size - patternSize; ++i) {
            if (std::memcmp(base + i, pattern, patternSize) == 0) return base + i;
        }
        return nullptr;
    }

    uint8_t* FindBytesInMemory(uint8_t* base, size_t size, const uint8_t* pattern, size_t patternSize, bool executable) {
        uintptr_t moduleStart = reinterpret_cast<uintptr_t>(base);
        uintptr_t moduleEnd = moduleStart + size;
        uintptr_t current = moduleStart;
        while (current < moduleEnd) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi))) break;
            uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd = regionStart + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT && (executable ? IsExecutableProtect(mbi.Protect) : IsReadableProtect(mbi.Protect))) {
                uintptr_t scanStart = regionStart > moduleStart ? regionStart : moduleStart;
                uintptr_t scanEnd = regionEnd < moduleEnd ? regionEnd : moduleEnd;
                if (scanEnd > scanStart && scanEnd - scanStart >= patternSize) {
                    uint8_t* found = FindBytes(reinterpret_cast<uint8_t*>(scanStart), static_cast<size_t>(scanEnd - scanStart), pattern, patternSize);
                    if (found) return found;
                }
            }
            current = regionEnd;
        }
        return nullptr;
    }

    uint8_t* FindAsciiLiteral(uint8_t* base, size_t size, const char* text) {
        return FindBytesInMemory(base, size, reinterpret_cast<const uint8_t*>(text), std::strlen(text), false);
    }

    uint8_t* FollowRel32(uint8_t* displacementAddress) {
        if (!IsReadableAddress(displacementAddress, sizeof(int32_t))) return nullptr;
        int32_t displacement = 0;
        std::memcpy(&displacement, displacementAddress, sizeof(displacement));
        return displacementAddress + sizeof(displacement) + displacement;
    }

    uint8_t* FindLeaRipRefTo(uint8_t* base, size_t size, uint8_t* target) {
        uintptr_t moduleStart = reinterpret_cast<uintptr_t>(base);
        uintptr_t moduleEnd = moduleStart + size;
        uintptr_t current = moduleStart;
        while (current < moduleEnd) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi))) break;
            uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd = regionStart + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect)) {
                uintptr_t scanStart = regionStart > moduleStart ? regionStart : moduleStart;
                uintptr_t scanEnd = regionEnd < moduleEnd ? regionEnd : moduleEnd;
                if (scanEnd > scanStart && scanEnd - scanStart >= 7) {
                    for (uintptr_t cursor = scanStart; cursor <= scanEnd - 7; ++cursor) {
                        uint8_t* instr = reinterpret_cast<uint8_t*>(cursor);
                        if (instr[0] == 0x48 && instr[1] == 0x8D && instr[2] == 0x0D) {
                            if (FollowRel32(instr + 3) == target) return instr + 3;
                        }
                    }
                }
            }
            current = regionEnd;
        }
        return nullptr;
    }

    std::vector<uint8_t*> FindLeaRipRefsTo(uint8_t* base, size_t size, uint8_t* target) {
        std::vector<uint8_t*> refs;
        uintptr_t moduleStart = reinterpret_cast<uintptr_t>(base);
        uintptr_t moduleEnd = moduleStart + size;
        uintptr_t current = moduleStart;
        while (current < moduleEnd) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<void*>(current), &mbi, sizeof(mbi))) break;
            uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd = regionStart + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect)) {
                uintptr_t scanStart = regionStart > moduleStart ? regionStart : moduleStart;
                uintptr_t scanEnd = regionEnd < moduleEnd ? regionEnd : moduleEnd;
                if (scanEnd > scanStart && scanEnd - scanStart >= 7) {
                    for (uintptr_t cursor = scanStart; cursor <= scanEnd - 7; ++cursor) {
                        uint8_t* instr = reinterpret_cast<uint8_t*>(cursor);
                        if (instr[0] == 0x48 && instr[1] == 0x8D && instr[2] == 0x0D && FollowRel32(instr + 3) == target) {
                            refs.push_back(instr);
                        }
                    }
                }
            }
            current = regionEnd;
        }
        return refs;
    }

    // 以字串 "(unsigned)use < LANGUAGE_USES" 反查引用它的函式，只接受開頭符合 SetLanguage 的那一個：
    //   mov [rsp+8],rbx; push rdi; sub rsp,20h; movsxd rdi,edx; mov ebx,ecx; cmp ecx,6
    uintptr_t FindFullSetLanguage(uint8_t* base, size_t size) {
        static const uint8_t kPrologue[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x63, 0xFA, 0x8B, 0xD9, 0x83, 0xF9, 0x06 };
        uint8_t* anchor = FindAsciiLiteral(base, size, "(unsigned)use < LANGUAGE_USES");
        if (!anchor) return 0;

        std::vector<uintptr_t> candidates;
        for (uint8_t* ref : FindLeaRipRefsTo(base, size, anchor)) {
            DWORD64 imageBase = 0;
            PRUNTIME_FUNCTION entry = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(ref), &imageBase, nullptr);
            if (!entry) continue;
            uint8_t* start = reinterpret_cast<uint8_t*>(imageBase + entry->BeginAddress);
            if (!IsReadableAddress(start, sizeof(kPrologue)) || std::memcmp(start, kPrologue, sizeof(kPrologue)) != 0) continue;
            if (std::find(candidates.begin(), candidates.end(), reinterpret_cast<uintptr_t>(start)) == candidates.end()) {
                candidates.push_back(reinterpret_cast<uintptr_t>(start));
            }
        }
        return candidates.size() == 1 ? candidates[0] : 0;
    }

    // --- 核心 Hook 邏輯 ---
    bool InstallDeferredCallerHook() {
        if (!g_languageSetter || !g_viewAdvanceTextHookPoint || !g_viewAdvanceTextOriginalCallTarget) return false;
        if (g_callerHookInstalled) return true;

        std::memcpy(g_callerHookBackup.data(), g_viewAdvanceTextHookPoint, g_callerHookBackup.size());
        uint8_t* jumpBack = g_viewAdvanceTextHookPoint + g_callerHookBackup.size();
        g_callerCodeCave = AllocNearMemory(g_viewAdvanceTextHookPoint, 512);
        if (!g_callerCodeCave) return false;

        CodeBuffer code{};
        // 保存現場
        AppendU8(code, 0x9C); // pushfq
        AppendU8(code, 0x50); // push rax
        AppendU8(code, 0x53); // push rbx
        AppendU8(code, 0x51); // push rcx
        AppendU8(code, 0x52); // push rdx
        AppendU8(code, 0x41); AppendU8(code, 0x50); // push r8
        AppendU8(code, 0x41); AppendU8(code, 0x51); // push r9
        AppendU8(code, 0x41); AppendU8(code, 0x52); // push r10
        AppendU8(code, 0x41); AppendU8(code, 0x53); // push r11
        AppendU8(code, 0x48); AppendU8(code, 0x83); AppendU8(code, 0xEC); AppendU8(code, 0x28); // sub rsp, 0x28

        // 檢查佇列並呼叫
        AppendU8(code, 0x48); AppendU8(code, 0xBB); AppendU64(code, reinterpret_cast<uint64_t>(&g_pendingCall));
        AppendU8(code, 0x48); AppendU8(code, 0x8B); AppendU8(code, 0x03); // mov rax, [rbx]
        AppendU8(code, 0x48); AppendU8(code, 0x85); AppendU8(code, 0xC0); // test rax, rax

        size_t jeOffset = code.Size;
        AppendU8(code, 0x0F); AppendU8(code, 0x84); AppendU32(code, 0); // je skip

        AppendU8(code, 0x8B); AppendU8(code, 0x4B); AppendU8(code, 0x08); // mov ecx, [rbx+8]
        AppendU8(code, 0x8B); AppendU8(code, 0x53); AppendU8(code, 0x18); // mov edx, [rbx+0x18]
        AppendU8(code, 0xFF); AppendU8(code, 0xD0); // call rax
        AppendU8(code, 0x48); AppendU8(code, 0xFF); AppendU8(code, 0x43); AppendU8(code, 0x10); // inc qword [rbx+0x10]
        AppendU8(code, 0x48); AppendU8(code, 0xC7); AppendU8(code, 0x03); AppendU32(code, 0); // mov qword [rbx], 0

        size_t skipOffset = code.Size;
        int32_t jeRel = static_cast<int32_t>(skipOffset - (jeOffset + 6));
        std::memcpy(code.Bytes.data() + jeOffset + 2, &jeRel, sizeof(jeRel));

        // 還原現場
        AppendU8(code, 0x48); AppendU8(code, 0x83); AppendU8(code, 0xC4); AppendU8(code, 0x28); // add rsp, 0x28
        AppendU8(code, 0x41); AppendU8(code, 0x5B); // pop r11
        AppendU8(code, 0x41); AppendU8(code, 0x5A); // pop r10
        AppendU8(code, 0x41); AppendU8(code, 0x59); // pop r9
        AppendU8(code, 0x41); AppendU8(code, 0x58); // pop r8
        AppendU8(code, 0x5A); // pop rdx
        AppendU8(code, 0x59); // pop rcx
        AppendU8(code, 0x5B); // pop rbx
        AppendU8(code, 0x58); // pop rax
        AppendU8(code, 0x9D); // popfq

        // 執行原跳轉
        AppendU8(code, 0x48); AppendU8(code, 0xB8); AppendU64(code, reinterpret_cast<uint64_t>(g_viewAdvanceTextOriginalCallTarget));
        AppendU8(code, 0xFF); AppendU8(code, 0xD0); // call rax
        if (!AppendRel32Jump(code, static_cast<uint8_t*>(g_callerCodeCave), jumpBack)) {
            VirtualFree(g_callerCodeCave, 0, MEM_RELEASE);
            g_callerCodeCave = nullptr;
            return false;
        }

        std::memcpy(g_callerCodeCave, code.Bytes.data(), code.Size);
        FlushInstructionCache(GetCurrentProcess(), g_callerCodeCave, code.Size);

        std::array<uint8_t, 5> hookJump{};
        if (!BuildRel32Jump(g_viewAdvanceTextHookPoint, static_cast<uint8_t*>(g_callerCodeCave), &hookJump)) return false;
        if (!WriteProtectedMemory(g_viewAdvanceTextHookPoint, hookJump.data(), hookJump.size())) return false;

        g_callerHookInstalled = true;
        return true;
    }

    // 排入一個語言呼叫：舊方式是「語言已變更」處理函式，新方式是完整的 SetLanguage(語言, 0)
    bool QueueLanguageCall(uintptr_t function, uint32_t languageId) {
        if (!g_callerHookInstalled && !InstallDeferredCallerHook()) {
            DebugLog("Failed to install deferred caller hook.");
            return false;
        }
        g_pendingCall.Arg0 = languageId;
        g_pendingCall.Arg1 = 0;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        g_pendingCall.Function = function; // 最後寫入，遊戲執行緒以此判斷有無待處理呼叫
        g_waitingForDeferredCall = true;
        return true;
    }

    // 比對「要求的狀態」與「已套用的狀態」，排出需要的呼叫：
    //   未啟用 → 舊方式：處理函式(5)            未啟用 → 新方式：SetLanguage(5)
    //   舊方式 → 未啟用：處理函式(原本)          新方式 → 未啟用：SetLanguage(原本)
    //   舊方式 → 新方式：SetLanguage(5)         新方式 → 舊方式：SetLanguage(原本)，再處理函式(5)
    void PlanLanguageSteps() {
        const bool useFull = g_fullWanted && g_fullSetter != 0;
        const int wanted = g_chineseWanted ? (useFull ? 2 : 1) : 0;
        if (wanted == g_appliedMode) return;

        const uintptr_t handler = reinterpret_cast<uintptr_t>(g_languageSetter);
        g_langSteps.clear();
        g_modeBeforePlan = g_appliedMode;
        if (wanted == 1) {
            if (g_appliedMode == 2) g_langSteps.push_back({ g_fullSetter, g_originalLanguage });
            g_langSteps.push_back({ handler, kChineseLanguageId });
        }
        else if (wanted == 2) {
            // 儲存的語言設成簡體之前，必須先解鎖文字語言，否則進遊戲（載入地圖）時會斷言失敗而崩潰
            g_langSteps.push_back({ 0, 0, true });
            g_langSteps.push_back({ g_fullSetter, kChineseLanguageId });
        }
        else {
            g_langSteps.push_back({ g_appliedMode == 2 ? g_fullSetter : handler, g_originalLanguage });
        }
        g_appliedMode = wanted;
    }

    // 商城網頁繁體化：繁體模式開著、簡體中文開著、而且是新方式（網頁才會是中文）才需要；
    // 舊方式下網頁是英文，不載入轉換腳本。
    void RefreshWeb() {
        ChineseIme::SetWebTraditional(g_tradWanted && g_chineseWanted && g_fullWanted && g_fullSetter != 0);
    }

    extern "C" void __fastcall CppTextConverterHook(wchar_t* srcText) {
        if (!g_tradModeEnabled || !srcText) return;

        std::wstring buffer;
        buffer.reserve(4096);
        size_t len = wcslen(srcText);

        for (size_t i = 0; i < len; ) {
            if (i > 8192) break;

            wchar_t c = srcText[i];
            bool matched = false;

            // 只針對中文字元進行查表
            if (c >= 19968 && c <= 40959) {
                auto it = g_rules.find(c);
                if (it != g_rules.end()) {
                    // 逐一比對 (優先匹配長詞彙)
                    for (const auto& rule : it->second) {
                        size_t matchLen = rule.inStr.length();

                        if (i + matchLen <= len && wcsncmp(&srcText[i], rule.inStr.c_str(), matchLen) == 0) {
                            buffer.append(rule.outStr); // 寫入修復字型的特殊標籤
                            i += matchLen; // 跳過已替換的長度
                            matched = true;
                            break;
                        }
                    }
                }
            }

            // 如果沒匹配到，保留原字元
            if (!matched) {
                buffer.push_back(c);
                i++;
            }
        }

        // 將修復過後的字串覆寫回遊戲記憶體
        wmemcpy(srcText, buffer.c_str(), buffer.length());
        srcText[buffer.length()] = L'\0';
    }

    // 使用 AsmJit 動態生成跳板
    void BuildAsmJitDetour() {
        CodeHolder code;
        code.init(g_jitRuntime->environment());
        x86::Assembler a(&code);

        // 保存所有暫存器
        a.pushfq();
        a.push(x86::rax);
        a.push(x86::rcx);
        a.push(x86::rdx);
        a.push(x86::rbx);
        a.push(x86::rbp);
        a.push(x86::rsi);
        a.push(x86::rdi);
        a.push(x86::r8);
        a.push(x86::r9);
        a.push(x86::r10);
        a.push(x86::r11);

        // 堆疊 16-byte 對齊
        a.mov(x86::rbp, x86::rsp);
        a.and_(x86::rsp, -16);
        a.sub(x86::rsp, 32); // Shadow space

        // 準備參數並呼叫 C++
        a.mov(x86::rcx, x86::rax); // RAX 是字串指標，傳給第一個參數 RCX
        a.mov(x86::rax, (uint64_t)&CppTextConverterHook);
        a.call(x86::rax);

        // 還原堆疊
        a.mov(x86::rsp, x86::rbp);

        // 還原暫存器
        a.pop(x86::r11);
        a.pop(x86::r10);
        a.pop(x86::r9);
        a.pop(x86::r8);
        a.pop(x86::rdi);
        a.pop(x86::rsi);
        a.pop(x86::rbp);
        a.pop(x86::rbx);
        a.pop(x86::rdx);
        a.pop(x86::rcx);
        a.pop(x86::rax);
        a.popfq();

        a.push(x86::rax);                                    // 把剛還原好的原始 RAX 備份到堆疊頂端
        a.mov(x86::rax, (uint64_t)&g_textConverterOriginal); // 借用 RAX 讀取指標位址
        a.mov(x86::rax, x86::ptr(x86::rax));                 // 取出 Trampoline 跳板位址

        a.xchg(x86::ptr(x86::rsp), x86::rax);

        a.ret();

        // 將生成的組語寫入執行期記憶體
        g_jitRuntime->add(&g_textConverterDetour, &code);
    }

    // 讀取 RC 資源並轉為 wstring
    std::wstring LoadJsonResource(int resourceId, const char* resourceType) {
        HRSRC hRes = FindResourceA(g_hSelfModule, MAKEINTRESOURCEA(resourceId), resourceType);
        if (!hRes) return L"";

        HGLOBAL hMem = LoadResource(g_hSelfModule, hRes);
        if (!hMem) return L"";

        DWORD size = SizeofResource(g_hSelfModule, hRes);
        const char* data = static_cast<const char*>(LockResource(hMem));

        if (size == 0 || !data) return L"";

        // 將 UTF-8 的 JSON 轉換為 UTF-16 (wstring)
        int wlen = MultiByteToWideChar(CP_UTF8, 0, data, size, NULL, 0);
        std::wstring wstr(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, data, size, &wstr[0], wlen);

        return wstr;
    }

    void ParseAndAddRules(const std::wstring& json, const char* filename) {
        if (json.empty()) {
            char err[128];
            std::snprintf(err, sizeof(err), "Failed to load or parse %s", filename);
            ArcLog(err);
            return;
        }

        size_t pos = 0;
        int ruleCount = 0;
        while ((pos = json.find(L"\"i\"", pos)) != std::wstring::npos) {
            size_t startI = json.find(L"\"", pos + 3);
            if (startI == std::wstring::npos) break;
            startI++;
            size_t endI = json.find(L"\"", startI);
            if (endI == std::wstring::npos) break;
            std::wstring iStr = json.substr(startI, endI - startI);

            size_t oPos = json.find(L"\"o\"", endI);
            if (oPos == std::wstring::npos) break;
            size_t startO = json.find(L"\"", oPos + 3);
            if (startO == std::wstring::npos) break;
            startO++;
            size_t endO = json.find(L"\"", startO);
            if (endO == std::wstring::npos) break;
            std::wstring oStr = json.substr(startO, endO - startO);

            if (!iStr.empty()) {
                g_rules[iStr[0]].push_back({ iStr, oStr });
                ruleCount++;
            }
            pos = endO + 1;
        }

        char logMsg[128];
        std::snprintf(logMsg, sizeof(logMsg), "Loaded %d rules from %s", ruleCount, filename);
        ArcLog(logMsg);
    }

    void InitDictionary() {
        g_rules.clear();

        ParseAndAddRules(LoadJsonResource(101, "JSON"), "jianfan.json");
        ParseAndAddRules(LoadJsonResource(102, "JSON"), "add.json");

        // 貪婪匹配排序 (長度由長到短)
        for (auto& pair : g_rules) {
            std::sort(pair.second.begin(), pair.second.end(), [](const ReplaceRule& a, const ReplaceRule& b) {
                return a.inStr.length() > b.inStr.length();
                });
        }

        char logMsg[128];
        std::snprintf(logMsg, sizeof(logMsg), "RC Dictionary ready. Keys: %zu", g_rules.size());
        DebugLog(logMsg);
    }
} // anonymous namespace

namespace GW2LangPatch {

    bool Initialize() {
        uint8_t* base = nullptr;
        size_t size = 0;
        if (!GetMainModuleRange(&base, &size)) return false;

        InitDictionary();

        if (!g_jitRuntime) {
            g_jitRuntime = new JitRuntime();
        }

        // 初始化 MinHook
        if (MH_Initialize() != MH_OK) {
            DebugLog("MinHook initialization failed!");
            return false;
        }

        // 1. 解析 Language Setter
        uint8_t* anchor = FindAsciiLiteral(base, size, kValidateLanguageAnchor);
        if (!anchor) return false;
        uint8_t* parentBlock = FindLeaRipRefTo(base, size, anchor);
        if (!parentBlock) return false;

        uint8_t* originLangPtrAddress = parentBlock + 0x0B;
        uint8_t* setterTargetAddress = parentBlock + 0x24;
        uint8_t* originLangPtr = FollowRel32(originLangPtrAddress);
        uint8_t* setterTarget = FollowRel32(setterTargetAddress);

        if (!originLangPtr || !setterTarget || !IsExecutableAddress(setterTarget)) return false;

        g_originalLanguagePtr = reinterpret_cast<uint32_t*>(originLangPtr);
        g_originalLanguage = *g_originalLanguagePtr;
        g_languageSetter = reinterpret_cast<LanguageSetterFn>(setterTarget);

        g_fullSetter = FindFullSetLanguage(base, size);
        {
            char message[128];
            if (g_fullSetter) {
                std::snprintf(message, sizeof(message), "[Lang] full SetLanguage RVA 0x%llX (web UI language follows text language)",
                    static_cast<unsigned long long>(g_fullSetter - reinterpret_cast<uintptr_t>(base)));
            }
            else {
                std::snprintf(message, sizeof(message), "[Lang] full SetLanguage not found; text switch only refreshes the UI");
            }
            ArcLog(message);
        }

        // 2. 解析 Caller Hook Diagnostics
        uint8_t* hookAnchor = FindAsciiLiteral(base, size, kViewAdvanceTextAnchor);
        if (!hookAnchor) return false;
        uint8_t* hookRef = FindLeaRipRefTo(base, size, hookAnchor);
        if (!hookRef) return false;

        uint8_t* hookPoint = hookRef - 0x08;
        if (hookPoint[0] != 0xE8) return false; // 必須是 Call 指令

        g_viewAdvanceTextOriginalCallTarget = FollowRel32(hookPoint + 1);
        g_viewAdvanceTextHookPoint = hookPoint;

        uint8_t* textAnchor = FindAsciiLiteral(base, size, kCParserAnchor);
        if (textAnchor) {
            uint8_t* textRef = FindLeaRipRefTo(base, size, textAnchor);
            if (textRef) {
                // 往後找 300 bytes 尋找 48 8B E8
                for (int offset = 0; offset < 300; ++offset) {
                    if (textRef[offset] == 0x48 && textRef[offset + 1] == 0x8B && textRef[offset + 2] == 0xE8) {
                        g_textConverterHookPoint = textRef + offset;

                        char logMsg[128];
                        std::snprintf(logMsg, sizeof(logMsg), "Found Hook Point at offset: %d", offset);
                        DebugLog(logMsg);

                        // 動態生成 AsmJit 跳板
                        BuildAsmJitDetour();

                        // 建立 MinHook
                        if (MH_CreateHook(g_textConverterHookPoint, g_textConverterDetour, &g_textConverterOriginal) != MH_OK) {
                            DebugLog("MH_CreateHook failed for Text Converter!");
                        }
                        break;
                    }
                }
            }
        }

        g_initialized = true;
        DebugLog("Initialization complete.");
        return true;
    }

    void Shutdown() {
        if (!g_initialized) return;

        if (g_callerHookInstalled && g_viewAdvanceTextHookPoint) {
            WriteProtectedMemory(g_viewAdvanceTextHookPoint, g_callerHookBackup.data(), g_callerHookBackup.size());
        }
        g_callerHookInstalled = false;
        g_pendingCall = {};

        if (g_callerCodeCave) {
            VirtualFree(g_callerCodeCave, 0, MEM_RELEASE);
            g_callerCodeCave = nullptr;
        }

        if (g_jitRuntime) {
            delete g_jitRuntime;
            g_jitRuntime = nullptr;
        }

        g_initialized = false;
    }

    bool IsChineseEnabled() {
        return g_chineseWanted;
    }

    const char* LanguageStatusText() {
        return g_langStatus.c_str();
    }

    bool IsFullLanguageAvailable() {
        return g_fullSetter != 0;
    }

    bool IsFullLanguageMode() {
        return g_fullWanted && g_fullSetter != 0;
    }

    void SetChinese(bool enable, bool full) {
        if (!g_initialized) return;
        g_chineseWanted = enable;
        if (enable) g_fullWanted = full; // 已開啟時改按另一個按鈕＝立刻換成另一種方式
        g_autoByTrad = false;            // 使用者手動操作後，簡體中文不再算是繁體模式自動開的
        g_applyDirty = true;
        RefreshWeb();
    }

    bool QueueNativeCall(uintptr_t function, uint32_t arg0, uint32_t arg1) {
        if (!g_initialized || !function) return false;
        if (g_pendingCall.Function != 0) return false;
        if (!g_callerHookInstalled && !InstallDeferredCallerHook()) return false;

        g_pendingCall.Arg0 = arg0;
        g_pendingCall.Arg1 = arg1;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        g_pendingCall.Function = function; // 最後寫入，遊戲執行緒以此判斷有無待處理呼叫
        return true;
    }

    bool IsNativeCallIdle() {
        return *reinterpret_cast<volatile uintptr_t*>(&g_pendingCall.Function) == 0;
    }

    uint32_t* GetLanguagePtr() {
        return g_originalLanguagePtr;
    }

    bool IsTradModeEnabled() {
        return g_tradModeEnabled;
    }

    void SetTradMode(bool enable) {
        if (!g_initialized || !g_textConverterHookPoint) return;

        if (enable && !g_tradModeEnabled) {
            if (MH_EnableHook(g_textConverterHookPoint) == MH_OK) {
                g_tradModeEnabled = true;
            }
        }
        else if (!enable && g_tradModeEnabled) {
            if (MH_DisableHook(g_textConverterHookPoint) == MH_OK) {
                g_tradModeEnabled = false;
            }
        }
    }

    void RequestTraditional(bool enable) {
        if (!g_initialized) return;
        g_tradWanted = enable;
        if (enable) {
            if (!g_chineseWanted) {
                g_chineseWanted = true;
                g_autoByTrad = true;
                g_applyDirty = true;
            }
            SetTradMode(true);
        }
        else {
            SetTradMode(false);
            if (g_autoByTrad) {
                g_chineseWanted = false;
                g_autoByTrad = false;
                g_applyDirty = true;
            }
        }
        RefreshWeb();
    }

    void Update() {
        if (!g_initialized) return;

        // 檢查延遲調用是否完成
        if (g_waitingForDeferredCall && g_pendingCall.Function == 0) {
            g_waitingForDeferredCall = false;
        }

        // 要求的狀態有變動：排出需要執行的原生呼叫
        if (g_applyDirty) {
            g_applyDirty = false;
            PlanLanguageSteps();
        }

        // 依序執行；佇列被其他原生呼叫（例如中文語音）佔用時，等下一幀
        if (!g_langSteps.empty()) {
            const LangStep step = g_langSteps.front();
            if (step.unlock) {
                const int unlocked = VoicePatch::EnsureTextUnlocked();
                if (unlocked > 0) {
                    g_langSteps.erase(g_langSteps.begin());
                    g_langStatus.clear();
                }
                else if (unlocked < 0) {
                    // 解鎖失敗就不能用新方式：改回舊方式，並說明原因
                    g_langSteps.clear();
                    g_appliedMode = g_modeBeforePlan;
                    g_fullWanted = false;
                    g_langStatus = std::string(reinterpret_cast<const char*>(u8"無法解鎖簡體中文，已改用舊方式：")) + VoicePatch::TextUnlockError();
                    ArcLog(("[Lang] " + g_langStatus).c_str());
                    g_applyDirty = true;
                    RefreshWeb();
                }
                else {
                    g_langStatus = reinterpret_cast<const char*>(u8"準備簡體中文（解鎖語言限制）…");
                }
            }
            else if (g_pendingCall.Function == 0) {
                g_langSteps.erase(g_langSteps.begin());
                if (!QueueLanguageCall(step.function, step.language)) g_langSteps.clear(); // 掛鉤無法安裝：放棄
            }
        }
    }

} // namespace GW2LangPatch