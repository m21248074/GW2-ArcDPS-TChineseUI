#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ChineseIme.h"
#include "VoiceImage.h"
#include "resource.h"

#include <Windows.h>
#include <Zydis/Zydis.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

extern HMODULE g_hSelfModule;
extern void ArcLog(const char* message);

using namespace VoiceImage;

namespace {
    // ------------------------------------------------------------------
    // 常數（與原工具相同，掛鉤區塊的格式因此可以互相辨識）
    // ------------------------------------------------------------------
    constexpr uint32_t kMarkerOffset = 2048;        // "GWIMECT2"
    constexpr uint32_t kCtorOffset = 2064;          // 原本的瀏覽器建構函式位址
    constexpr uint32_t kCallSiteOffset = 2072;      // 被接管的呼叫點位址
    constexpr uint32_t kCallBytesOffset = 2096;     // 呼叫點原本的 5 位元組
    constexpr uint32_t kOriginalTextOffset = 65536; // 官方腳本（用來比對）
    constexpr uint32_t kStatsOffset = 65280;        // 計數器：建立數、替換數、原樣透傳數
    constexpr uint32_t kCompMarkerOffset = 512;     // "GWIMECM1"
    constexpr uint32_t kCompBytesOffset = 528;
    constexpr uint32_t kCompSiteOffset = 544;
    constexpr uint32_t kCompCounterOffset = 4096;
    const char kBridgeMarker[8] = { 'G', 'W', 'I', 'M', 'E', 'C', 'T', '2' };
    const char kCompMarker[8] = { 'G', 'W', 'I', 'M', 'E', 'C', 'M', '1' };

    // 商城編輯框的聚焦：shr eax,N; and eax,1; mov dword [rsp+28h], 5 → 5 改成 3
    const uint8_t kFocusTemplate[19] = { 72, 141, 76, 36, 32, 193, 232, 0, 131, 224, 1, 199, 68, 36, 40, 5, 0, 0, 0 };
    constexpr int kFocusWildcard = 7;
    constexpr int kFocusC7Offset = 11;
    constexpr uint8_t kFocusShrIme = 4;
    const uint8_t kCompositionSiteSig[15] = { 65, 139, 77, 12, 69, 51, 201, 69, 51, 192, 186, 3, 0, 0, 0 };
    const uint8_t kNotifyPrologue[16] = { 72, 137, 92, 36, 8, 72, 137, 108, 36, 16, 72, 137, 116, 36, 24, 87 };

    [[noreturn]] void Throw(const std::string& message) {
        throw std::runtime_error(message);
    }

    // ------------------------------------------------------------------
    // 分析（背景執行緒，只讀硬碟檔案）
    // ------------------------------------------------------------------
    struct Plan {
        uint32_t callSite = 0;   // 瀏覽器建構的 call (E8)
        uint32_t constructor = 0;
        uint8_t callBytes[5]{};
        uint8_t preBytes[15]{};  // callSite 之前的 15 位元組
        uint8_t ctorHead[16]{};
        uint32_t focusSites[2]{}; // mov dword [rsp+28h], 5 的位址
        uint32_t compSite = 0;    // 原生編輯框的通知 call (E8)
        uint8_t compBytes[5]{};
        uint32_t notifyTarget = 0;
        std::string log;
    };

    // .pdata（RUNTIME_FUNCTION）二分搜尋；不處理鏈結項目（與原工具相同）
    int64_t PdataStart(const DiskImage& img, uint32_t rva) {
        int64_t lo = 0, hi = static_cast<int64_t>(img.excDirSize / 12) - 1;
        while (lo <= hi) {
            const int64_t mid = (lo + hi) / 2;
            const uint32_t begin = img.U32(img.excDirRva + static_cast<uint64_t>(mid) * 12);
            const uint32_t end = img.U32(img.excDirRva + static_cast<uint64_t>(mid) * 12 + 4);
            if (rva < begin) hi = mid - 1;
            else if (rva >= end) lo = mid + 1;
            else return begin;
        }
        return -1;
    }

    // 可執行區段內所有 lea r64,[rip+x]（x = target）的位址
    std::vector<uint32_t> FindLeaRefs(const DiskImage& img, uint32_t target) {
        std::vector<uint32_t> refs;
        for (uint32_t i = 0; static_cast<uint64_t>(i) + 7 < img.execSize; ++i) {
            const uint32_t rva = img.execStart + i;
            const uint8_t b0 = img.mem[rva];
            if ((b0 == 0x48 || b0 == 0x4C) && img.mem[rva + 1] == 0x8D && (img.mem[rva + 2] & 0xC7) == 5
                && static_cast<int64_t>(rva) + 7 + img.S32(rva + 3) == target) {
                refs.push_back(rva);
            }
        }
        return refs;
    }

    bool MatchesWithWildcard(const DiskImage& img, uint32_t at, const uint8_t* pattern, size_t size, int wildcard) {
        for (size_t i = 0; i < size; ++i) {
            if (static_cast<int>(i) != wildcard && img.mem[at + i] != pattern[i]) return false;
        }
        return true;
    }

    // 在可執行區段內找 pattern（wildcard = -1 表示沒有萬用位元組）
    std::vector<uint32_t> FindInText(const DiskImage& img, const uint8_t* pattern, size_t size, int wildcard) {
        std::vector<uint32_t> found;
        for (uint32_t i = 0; static_cast<uint64_t>(i) + size <= img.execSize; ++i) {
            const uint32_t rva = img.execStart + i;
            if (img.mem[rva] == pattern[0] && MatchesWithWildcard(img, rva, pattern, size, wildcard)) found.push_back(rva);
        }
        return found;
    }

    // 整個映像中不在可執行區段內的字串（不含結尾 NUL），必須唯一
    uint32_t FindUniqueString(const DiskImage& img, const char* text) {
        const std::vector<uint8_t> pattern(text, text + std::strlen(text));
        std::set<uint32_t> hits;
        for (uint32_t rva : FindBytes(img, pattern)) {
            if (rva >= img.execStart && rva < img.execStart + img.execSize) continue;
            hits.insert(rva);
        }
        if (hits.empty()) Throw(std::string(U8("錨點字串未找到（")) + text + U8("），未適配。"));
        if (hits.size() != 1) Throw(std::string(U8("錨點字串不唯一（")) + text + U8("），未適配。"));
        return *hits.begin();
    }

    // 瀏覽器建構的呼叫點：由 AwCefBrowser 的析構函式 → vtable → 建構函式 → 唯一符合參數約定的 call
    void ResolveBrowserConstructorCall(const DiskImage& img, Plan& plan) {
        const uint32_t target = FindUniqueString(img, "m_modules == nullptr");
        const std::vector<uint32_t> refs = FindLeaRefs(img, target);
        if (refs.size() != 1) Throw(U8("AwCefBrowser 斷言引用異常，未適配。"));
        const int64_t dtor = PdataStart(img, refs[0]);
        if (dtor < 0) Throw(U8("AwCefBrowser 析構函式邊界定位失敗，未適配。"));

        // 析構函式開頭 128 位元組內第一個指向 .rdata 的 lea → vtable
        uint32_t rdataStart = 0, rdataSize = 0;
        for (const Section& s : img.sections) {
            if (s.name == ".rdata") {
                rdataStart = s.va;
                rdataSize = std::min(s.vsize, s.rawSize);
            }
        }
        if (rdataStart == 0) Throw(U8(".rdata 區段定位失敗，未適配。"));
        int64_t vtable = -1;
        for (uint32_t i = static_cast<uint32_t>(dtor) - img.execStart;
            i < static_cast<uint32_t>(dtor) - img.execStart + 128 && static_cast<uint64_t>(i) + 7 <= img.execSize; ++i) {
            const uint32_t rva = img.execStart + i;
            const uint8_t b0 = img.mem[rva];
            if ((b0 == 0x48 || b0 == 0x4C) && img.mem[rva + 1] == 0x8D && (img.mem[rva + 2] & 0xC7) == 5) {
                const int64_t t = static_cast<int64_t>(rva) + 7 + img.S32(rva + 3);
                if (t >= rdataStart && t < static_cast<int64_t>(rdataStart) + rdataSize) { vtable = t; break; }
            }
        }
        if (vtable < 0) Throw(U8("AwCefBrowser vtable 定位失敗，未適配。"));

        // 引用 vtable 的函式中，除了析構函式外唯一的一個就是建構函式
        std::set<uint32_t> constructors;
        for (uint32_t r : FindLeaRefs(img, static_cast<uint32_t>(vtable))) {
            const int64_t start = PdataStart(img, r);
            if (start >= 0 && start != dtor) constructors.insert(static_cast<uint32_t>(start));
        }
        if (constructors.size() != 1) Throw(U8("瀏覽器建構函式定位不唯一。"));
        const uint32_t ctor = *constructors.begin();

        // 呼叫建構函式、且呼叫前 4 條指令符合 mov rcx,rsi / mov rdx,rdi / mov r8,rax / mov r9d,1 的呼叫點
        std::vector<uint32_t> sites;
        for (uint32_t i = 0; static_cast<uint64_t>(i) + 5 <= img.execSize; ++i) {
            const uint32_t site = img.execStart + i;
            if (img.mem[site] != 0xE8 || static_cast<int64_t>(site) + 5 + img.S32(site + 1) != ctor) continue;
            const int64_t start = PdataStart(img, site);
            if (start < 0 || site - start > 4096) continue;

            const std::vector<Insn> list = DecodeSeq(img, static_cast<uint32_t>(start), site + 5 - static_cast<uint32_t>(start), false);
            if (list.size() < 5) continue;
            const Insn& last = list.back();
            uint32_t branch = 0;
            if (last.rva != site || last.ins.mnemonic != ZYDIS_MNEMONIC_CALL || !BranchTarget(last, branch) || branch != ctor) continue;

            bool rcx = false, rdx = false, r8 = false, r9 = false;
            for (size_t k = list.size() - 5; k < list.size() - 1; ++k) {
                const Insn& x = list[k];
                if (x.ins.mnemonic != ZYDIS_MNEMONIC_MOV) continue;
                if (IsReg(x.op[0], ZYDIS_REGISTER_RCX) && IsReg(x.op[1], ZYDIS_REGISTER_RSI)) rcx = true;
                if (IsReg(x.op[0], ZYDIS_REGISTER_RDX) && IsReg(x.op[1], ZYDIS_REGISTER_RDI)) rdx = true;
                if (IsReg(x.op[0], ZYDIS_REGISTER_R8) && IsReg(x.op[1], ZYDIS_REGISTER_RAX)) r8 = true;
                if (IsReg(x.op[0], ZYDIS_REGISTER_R9D) && IsImm(x.op[1], 1)) r9 = true;
            }
            if (rcx && rdx && r8 && r9) sites.push_back(site);
        }
        if (sites.size() != 1) Throw(U8("瀏覽器建構呼叫關係或參數約定未適配。"));

        plan.callSite = sites[0];
        plan.constructor = ctor;
        std::memcpy(plan.callBytes, &img.mem[plan.callSite], 5);
        std::memcpy(plan.preBytes, &img.mem[plan.callSite - 15], 15);
        std::memcpy(plan.ctorHead, &img.mem[plan.constructor], 16);
    }

    void Analyze(const DiskImage& img, Plan& plan) {
        ResolveBrowserConstructorCall(img, plan);

        // 商城編輯框聚焦的兩處常數
        std::vector<uint32_t> focus;
        for (uint32_t rva : FindInText(img, kFocusTemplate, sizeof(kFocusTemplate), kFocusWildcard)) {
            if (img.mem[rva + kFocusWildcard] == kFocusShrIme) focus.push_back(rva + kFocusC7Offset);
        }
        if (focus.size() != 2) Throw(U8("聚焦指令定位異常，未適配。"));
        for (int i = 0; i < 2; ++i) {
            const uint8_t* p = &img.mem[focus[i]];
            if (p[0] != 0xC7 || p[1] != 0x44 || p[2] != 0x24 || p[3] != 0x28 || p[4] != 5 || p[5] != 0 || p[6] != 0 || p[7] != 0) {
                Throw(U8("聚焦指令未適配。"));
            }
            plan.focusSites[i] = focus[i];
        }

        // 原生編輯框的通知呼叫點
        const std::vector<uint32_t> sig = FindInText(img, kCompositionSiteSig, sizeof(kCompositionSiteSig), -1);
        if (sig.size() != 1) Throw(U8("合成通知呼叫點定位異常，未適配。"));
        const uint32_t site = sig[0] + sizeof(kCompositionSiteSig);
        if (site + 5 > img.execStart + img.execSize || img.mem[site] != 0xE8) Throw(U8("合成通知呼叫點形態未適配。"));
        const int64_t notify = static_cast<int64_t>(site) + 5 + img.S32(site + 1);
        if (notify < 0 || !img.InRange(static_cast<uint64_t>(notify), sizeof(kNotifyPrologue))
            || std::memcmp(&img.mem[static_cast<size_t>(notify)], kNotifyPrologue, sizeof(kNotifyPrologue)) != 0) {
            Throw(U8("合成通知目標自校驗失敗，未適配。"));
        }
        plan.compSite = site;
        plan.notifyTarget = static_cast<uint32_t>(notify);
        std::memcpy(plan.compBytes, &img.mem[site], 5);
    }

    // ------------------------------------------------------------------
    // 機器碼（與原工具逐位元組相同）
    // ------------------------------------------------------------------
    void Append32(std::vector<uint8_t>& v, uint32_t value) {
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }

    void Append64(std::vector<uint8_t>& v, uint64_t value) {
        for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }

    void AppendBytes(std::vector<uint8_t>& v, std::initializer_list<uint8_t> bytes) {
        v.insert(v.end(), bytes.begin(), bytes.end());
    }

    // 建構瀏覽器前：r8 若是官方腳本就換成「官方腳本 + 橋接腳本」，再跳到原本的建構函式
    std::vector<uint8_t> BootstrapThunk(uint64_t originalBytes, uint64_t replacementString, int originalChars, uint64_t constructor, uint64_t stats) {
        std::vector<uint8_t> c;
        AppendBytes(c, { 0x51, 0x56, 0x57 });
        auto countAt = [&](uint64_t address) {
            AppendBytes(c, { 0x49, 0xBA });
            Append64(c, address);
            AppendBytes(c, { 0xF0, 0x41, 0xFF, 0x02 });
        };
        countAt(stats);
        AppendBytes(c, { 0x4D, 0x85, 0xC0, 0x74 });
        const size_t at1 = c.size(); c.push_back(0);
        AppendBytes(c, { 0x41, 0x81, 0x78, 0x08 });
        Append32(c, static_cast<uint32_t>(originalChars));
        c.push_back(0x75);
        const size_t at2 = c.size(); c.push_back(0);
        AppendBytes(c, { 0x49, 0x8B, 0x30, 0x48, 0x85, 0xF6, 0x74 });
        const size_t at3 = c.size(); c.push_back(0);
        AppendBytes(c, { 0x48, 0xBF });
        Append64(c, originalBytes);
        c.push_back(0xB9);
        Append32(c, static_cast<uint32_t>(originalChars * 2));
        AppendBytes(c, { 0xFC, 0xF3, 0xA6, 0x75 });
        const size_t at4 = c.size(); c.push_back(0);
        countAt(stats + 4);
        AppendBytes(c, { 0x49, 0xB8 });
        Append64(c, replacementString);
        c.push_back(0xEB);
        const size_t at5 = c.size(); c.push_back(0);
        const size_t passthrough = c.size();
        countAt(stats + 8);
        const size_t call = c.size();
        for (size_t at : { at1, at2, at3, at4 }) c[at] = static_cast<uint8_t>(static_cast<int8_t>(passthrough - at - 1));
        c[at5] = static_cast<uint8_t>(static_cast<int8_t>(call - at5 - 1));
        AppendBytes(c, { 0x5F, 0x5E, 0x59, 0xFF, 0x25, 0, 0, 0, 0 });
        Append64(c, constructor);
        return c;
    }

    // 通知呼叫：旗標 bit 2（組字中）設定時吞掉通知並計數，否則放行給原本的通知函式
    std::vector<uint8_t> CompositionThunk(uint64_t address, uint64_t counter, uint64_t notify) {
        std::vector<uint8_t> c;
        AppendBytes(c, { 0x41, 0xF6, 0x45, 0x08, 0x04, 0x74, 0x0A });
        AppendBytes(c, { 0xF0, 0xFF, 0x05 });
        Append32(c, static_cast<uint32_t>(counter - address - c.size() - 4));
        AppendBytes(c, { 0x31, 0xC0, 0xC3 });
        AppendBytes(c, { 0xF0, 0xFF, 0x05 });
        Append32(c, static_cast<uint32_t>(counter + 4 - address - c.size() - 4));
        AppendBytes(c, { 0xFF, 0x25, 0, 0, 0, 0 });
        Append64(c, notify);
        return c;
    }

    // ------------------------------------------------------------------
    // 執行期（主執行緒，對遊戲記憶體直接讀寫）
    // ------------------------------------------------------------------
    bool IsReadable(const void* ptr, size_t size) {
        uintptr_t current = reinterpret_cast<uintptr_t>(ptr);
        const uintptr_t end = current + size;
        if (end < current) return false;
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

    std::vector<uint8_t> ReadBytes(uint64_t address, size_t size) {
        if (address == 0 || !IsReadable(reinterpret_cast<const void*>(address), size)) Throw(U8("無法讀取遊戲記憶體"));
        const uint8_t* p = reinterpret_cast<const uint8_t*>(address);
        return std::vector<uint8_t>(p, p + size);
    }

    bool SameBytes(uint64_t address, const void* expected, size_t size) {
        if (!IsReadable(reinterpret_cast<const void*>(address), size)) return false;
        return std::memcmp(reinterpret_cast<const void*>(address), expected, size) == 0;
    }

    void WriteGameMemory(uint64_t address, const void* source, size_t size) {
        void* target = reinterpret_cast<void*>(address);
        DWORD oldProtect = 0;
        if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect)) Throw(U8("無法調整遊戲記憶體保護"));
        std::memcpy(target, source, size);
        FlushInstructionCache(GetCurrentProcess(), target, size);
        DWORD restored = 0;
        VirtualProtect(target, size, oldProtect, &restored);
    }

    uint8_t* AllocNear(uint64_t anchorAddress, size_t size) {
        const uint64_t anchor = anchorAddress & ~0xFFFFull;
        for (uint64_t distance = 65536; distance < 1879048192ull; distance += 65536) {
            const uint64_t candidates[2] = { anchor + distance, anchor - distance };
            for (uint64_t candidate : candidates) {
                if (candidate < 65536) continue;
                void* p = VirtualAlloc(reinterpret_cast<void*>(candidate), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (p) return static_cast<uint8_t*>(p);
            }
        }
        return nullptr;
    }

    // RCDATA（UTF-8 文字）→ wstring
    std::wstring LoadTextResource(int id, LPCWSTR type = MAKEINTRESOURCEW(10) /* RT_RCDATA */) {
        HRSRC res = FindResourceW(g_hSelfModule, MAKEINTRESOURCEW(id), type);
        if (!res) return std::wstring();
        HGLOBAL mem = LoadResource(g_hSelfModule, res);
        const DWORD size = SizeofResource(g_hSelfModule, res);
        const char* data = mem ? static_cast<const char*>(LockResource(mem)) : nullptr;
        if (!data || size == 0) return std::wstring();
        const int length = MultiByteToWideChar(CP_UTF8, 0, data, static_cast<int>(size), nullptr, 0);
        std::wstring text(static_cast<size_t>(length), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, data, static_cast<int>(size), &text[0], length);
        if (!text.empty() && text[0] == 0xFEFF) text.erase(0, 1);
        return text;
    }

    // ------------------------------------------------------------------
    // 腳本內容：三個版本，掛鉤區塊裡各有一份呼叫桩，呼叫點指向其中一個
    //   A = 官方腳本 + 輸入法橋接                （只開中文輸入增強）
    //   B = 官方腳本 + 網頁簡轉繁 + 輸入法橋接    （兩者都開）
    //   C = 官方腳本 + 網頁簡轉繁                （只開網頁繁體化）
    // 網頁簡轉繁一定要排在橋接腳本前面，否則交易行與商城的轉換不會啟動。
    // ------------------------------------------------------------------
    enum class Entry { None = -1, A = 0, B = 1, C = 2 };
    constexpr uint32_t kThunkOffset[3] = { 0, 256, 512 }; // 每份呼叫桩 < 256 位元組

    struct Payload {
        std::vector<uint8_t> original;  // UTF-16LE，含結尾 NUL
        std::vector<uint8_t> text[3];   // A、B、C；缺少轉換腳本資源時 B、C 為空
        uint32_t textOffset[3]{};
        uint32_t descriptorOffset = 0;  // 三個描述結構，各 32 位元組
        uint32_t allocationSize = 0;
    };

    // 偵察用探針；目前不附加（需要時改成 true 並重新建置）
    constexpr bool kIncludeProbe = false;

    // 網頁簡轉繁腳本：函式本體 + 字典（與遊戲內相同的 jianfan.json、add.json）+ 繁轉簡字表
    std::wstring BuildConverterScript() {
        const std::wstring function = LoadTextResource(IDR_IME_S2T);
        const std::wstring t2s = LoadTextResource(IDR_IME_T2S);
        const std::wstring dict1 = LoadTextResource(IDR_JSON1, L"JSON");
        const std::wstring dict2 = LoadTextResource(IDR_JSON2, L"JSON");
        if (function.empty() || t2s.empty() || dict1.empty() || dict2.empty()) return std::wstring();
        return L"(" + function + L")(" + dict1 + L".concat(" + dict2 + L"), " + t2s + L");";
    }

    std::vector<uint8_t> Utf16Bytes(const std::wstring& text) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(text.c_str());
        return std::vector<uint8_t>(p, p + (text.size() + 1) * sizeof(wchar_t)); // 含結尾 NUL
    }

    Payload CreatePayload() {
        const std::wstring original = LoadTextResource(IDR_IME_ORIGINAL);
        const std::wstring bridge = LoadTextResource(IDR_IME_BRIDGE);
        if (original.empty() || bridge.empty()) Throw(U8("缺少輸入法腳本資源"));

        const std::wstring probe = kIncludeProbe ? LoadTextResource(IDR_IME_PROBE) : std::wstring();
        const std::wstring tail = probe.empty() ? std::wstring() : L"\n;" + probe;
        const std::wstring converter = BuildConverterScript();

        Payload p;
        p.original = Utf16Bytes(original);
        p.text[0] = Utf16Bytes(original + L"\n;" + bridge + tail);
        if (!converter.empty()) {
            p.text[1] = Utf16Bytes(original + L"\n;" + converter + L"\n;" + bridge + tail);
            p.text[2] = Utf16Bytes(original + L"\n;" + converter + tail);
        }

        uint32_t cursor = kOriginalTextOffset + static_cast<uint32_t>(p.original.size());
        for (int i = 0; i < 3; ++i) {
            cursor = (cursor + 4095) & ~4095u;
            p.textOffset[i] = cursor;
            cursor += static_cast<uint32_t>(p.text[i].size());
        }
        p.descriptorOffset = (cursor + 4095) & ~4095u;
        p.allocationSize = (p.descriptorOffset + 96 + 65535) & ~65535u;
        return p;
    }

    // 已安裝的狀態（用來還原與讀取計數器）
    struct Installed {
        uint8_t* cave = nullptr;        // 瀏覽器建構橋的掛鉤區塊（保留到遊戲結束）
        bool hasWeb = false;            // 區塊裡有 B、C（網頁簡轉繁）
        Entry entry = Entry::None;      // 呼叫點目前指向哪一份呼叫桩
        bool callPatched = false;
        uint8_t* compCave = nullptr;
        bool compPatched = false;
        bool focusPatched[2]{};
    };

    Installed g_installed;

    // 建立掛鉤區塊（或沿用先前外掛實例留下的同格式區塊）
    void EnsureCave(const Plan& plan, std::string& log) {
        if (g_installed.cave) return;

        const uint64_t image = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        const uint64_t site = image + plan.callSite;
        const uint64_t ctor = image + plan.constructor;
        const Payload payload = CreatePayload();
        const int originalChars = static_cast<int>(payload.original.size() / 2);

        const std::vector<uint8_t> live = ReadBytes(site, 5);
        if (std::memcmp(live.data(), plan.callBytes, 5) != 0) {
            // 已經被接管：只有格式完全相同的才沿用（例如外掛重新載入）
            bool recognized = false;
            if (live[0] == 0xE8) {
                int32_t rel = 0;
                std::memcpy(&rel, live.data() + 1, 4);
                const uint64_t target = site + 5 + static_cast<int64_t>(rel);
                for (int s = 0; s < 3 && !recognized; ++s) {
                    const uint64_t cave = target - kThunkOffset[s];
                    try {
                        bool ok = SameBytes(cave + kMarkerOffset, kBridgeMarker, 8)
                            && *reinterpret_cast<const uint64_t*>(cave + kCtorOffset) == ctor
                            && *reinterpret_cast<const uint64_t*>(cave + kCallSiteOffset) == site
                            && SameBytes(cave + kCallBytesOffset, plan.callBytes, 5);
                        if (ok) {
                            const std::vector<uint8_t> thunk = BootstrapThunk(cave + kOriginalTextOffset, cave + payload.descriptorOffset, originalChars, ctor, cave + kStatsOffset);
                            ok = SameBytes(cave, thunk.data(), thunk.size())
                                && SameBytes(cave + kOriginalTextOffset, payload.original.data(), payload.original.size())
                                && SameBytes(cave + payload.textOffset[0], payload.text[0].data(), payload.text[0].size());
                        }
                        if (ok) {
                            recognized = true;
                            g_installed.cave = reinterpret_cast<uint8_t*>(cave);
                            g_installed.entry = static_cast<Entry>(s);
                        }
                    }
                    catch (const std::exception&) {
                        recognized = false;
                    }
                }
            }
            if (!recognized) Throw(U8("瀏覽器建構呼叫已被其他補丁修改，未覆蓋；請重啟遊戲再試。"));
            g_installed.callPatched = true;
            g_installed.hasWeb = !payload.text[1].empty();
            log += "[IME] script bridge already installed\n";
            return;
        }

        if (!SameBytes(site - 15, plan.preBytes, 15) || !SameBytes(ctor, plan.ctorHead, 16)) {
            Throw(U8("瀏覽器建構參數或入口現場與解析結果不一致，未安裝。"));
        }

        uint8_t* cave = AllocNear(site, payload.allocationSize);
        if (!cave) Throw(U8("瀏覽器呼叫點附近沒有可用記憶體。"));
        const uint64_t base = reinterpret_cast<uint64_t>(cave);
        for (int s = 0; s < 3; ++s) {
            if (payload.text[s].empty()) continue;
            const std::vector<uint8_t> thunk = BootstrapThunk(base + kOriginalTextOffset, base + payload.descriptorOffset + 32u * s, originalChars, ctor, base + kStatsOffset);
            if (thunk.size() >= 256) {
                VirtualFree(cave, 0, MEM_RELEASE);
                Throw(U8("呼叫桩過大"));
            }
            std::memcpy(cave + kThunkOffset[s], thunk.data(), thunk.size());
            std::memcpy(cave + payload.textOffset[s], payload.text[s].data(), payload.text[s].size());
            const uint64_t address = base + payload.textOffset[s];
            const int32_t chars = static_cast<int32_t>(payload.text[s].size() / 2);
            std::memcpy(cave + payload.descriptorOffset + 32u * s, &address, 8);
            std::memcpy(cave + payload.descriptorOffset + 32u * s + 8, &chars, 4);
            std::memcpy(cave + payload.descriptorOffset + 32u * s + 20, &chars, 4);
        }
        std::memcpy(cave + kMarkerOffset, kBridgeMarker, 8);
        std::memcpy(cave + kCtorOffset, &ctor, 8);
        std::memcpy(cave + kCallSiteOffset, &site, 8);
        std::memcpy(cave + kCallBytesOffset, plan.callBytes, 5);
        std::memcpy(cave + kOriginalTextOffset, payload.original.data(), payload.original.size());
        DWORD old = 0;
        if (!VirtualProtect(cave, 4096, PAGE_EXECUTE_READ, &old)) {
            VirtualFree(cave, 0, MEM_RELEASE);
            Throw(U8("無法準備瀏覽器建構參數橋。"));
        }
        FlushInstructionCache(GetCurrentProcess(), cave, 4096);
        g_installed.cave = cave;
        g_installed.hasWeb = !payload.text[1].empty();
    }

    // 讓呼叫點指向 want 對應的呼叫桩；Entry::None 表示還原成原本的呼叫
    void SetEntry(const Plan& plan, Entry want, std::string& log) {
        const uint64_t image = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        const uint64_t site = image + plan.callSite;

        if (want == Entry::None) {
            if (g_installed.callPatched) {
                WriteGameMemory(site, plan.callBytes, 5);
                g_installed.callPatched = false;
            }
            g_installed.entry = Entry::None;
            return;
        }

        EnsureCave(plan, log);
        if (want != Entry::A && !g_installed.hasWeb) Throw(U8("缺少網頁簡轉繁腳本資源"));

        const uint64_t entry = reinterpret_cast<uint64_t>(g_installed.cave) + kThunkOffset[static_cast<int>(want)];
        const int64_t delta = static_cast<int64_t>(entry) - static_cast<int64_t>(site) - 5;
        if (delta < INT32_MIN || delta > INT32_MAX) Throw(U8("瀏覽器呼叫點距離過遠，無法接入。"));
        uint8_t call[5] = { 0xE8, 0, 0, 0, 0 };
        const int32_t rel = static_cast<int32_t>(delta);
        std::memcpy(call + 1, &rel, 4);
        if (!g_installed.callPatched && !SameBytes(site, plan.callBytes, 5)) Throw(U8("呼叫點狀態已改變，停止安裝。"));
        WriteGameMemory(site, call, 5);
        if (!SameBytes(site, call, 5)) Throw(U8("呼叫點讀回校驗失敗。"));
        g_installed.callPatched = true;
        g_installed.entry = want;
        log += want == Entry::A ? "[IME] script bridge: input method only\n"
            : want == Entry::B ? "[IME] script bridge: input method + page Simplified->Traditional\n"
            : "[IME] script bridge: page Simplified->Traditional only\n";
    }

    void InstallComposition(const Plan& plan, std::string& log);

    // 商城編輯框聚焦（5 → 3）與原生編輯框的組字通知補丁；都屬於「中文輸入增強」
    void InstallImePatches(const Plan& plan, std::string& log) {
        const uint64_t image = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        int patchedNow = 0, patchedBefore = 0;
        for (int i = 0; i < 2; ++i) {
            const uint64_t address = image + plan.focusSites[i];
            const std::vector<uint8_t> live = ReadBytes(address, 8);
            const uint8_t original[8] = { 0xC7, 0x44, 0x24, 0x28, 5, 0, 0, 0 };
            uint8_t patched[8];
            std::memcpy(patched, original, 8);
            patched[4] = 3;
            if (std::memcmp(live.data(), patched, 8) == 0) { ++patchedBefore; continue; }
            if (std::memcmp(live.data(), original, 8) != 0) Throw(U8("聚焦指令已被其他程式修改。"));
            const uint8_t three = 3;
            WriteGameMemory(address + 4, &three, 1);
            g_installed.focusPatched[i] = true;
            ++patchedNow;
        }
        char line[160];
        std::snprintf(line, sizeof(line), "[IME] focus tweak: %d new, %d already\n", patchedNow, patchedBefore);
        log += line;
        InstallComposition(plan, log);
    }

    void InstallComposition(const Plan& plan, std::string& log) {
        const uint64_t image = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        const uint64_t site = image + plan.compSite;
        const uint64_t notify = image + plan.notifyTarget;

        const std::vector<uint8_t> live = ReadBytes(site, 5);
        if (std::memcmp(live.data(), plan.compBytes, 5) != 0) {
            bool recognized = false;
            if (live[0] == 0xE8) {
                int32_t rel = 0;
                std::memcpy(&rel, live.data() + 1, 4);
                const uint64_t cave = site + 5 + static_cast<int64_t>(rel);
                try {
                    recognized = SameBytes(cave + kCompMarkerOffset, kCompMarker, 8)
                        && *reinterpret_cast<const uint64_t*>(cave + kCompSiteOffset) == site
                        && SameBytes(cave + kCompBytesOffset, plan.compBytes, 5);
                }
                catch (const std::exception&) {
                    recognized = false;
                }
                if (recognized) {
                    g_installed.compCave = reinterpret_cast<uint8_t*>(cave);
                    log += "[IME] composition patch already installed\n";
                    return;
                }
            }
            Throw(U8("合成通知呼叫點被其他程式修改，未覆蓋。"));
        }

        uint8_t* cave = g_installed.compCave;
        if (!cave) {
            cave = AllocNear(site, 8192);
            if (!cave) Throw(U8("通知呼叫點附近沒有可用記憶體。"));
            const uint64_t base = reinterpret_cast<uint64_t>(cave);
            const std::vector<uint8_t> thunk = CompositionThunk(base, base + kCompCounterOffset, notify);
            std::memcpy(cave, thunk.data(), thunk.size());
            std::memcpy(cave + kCompMarkerOffset, kCompMarker, 8);
            std::memcpy(cave + kCompBytesOffset, plan.compBytes, 5);
            std::memcpy(cave + kCompSiteOffset, &site, 8);
            DWORD old = 0;
            if (!VirtualProtect(cave, 4096, PAGE_EXECUTE_READ, &old)) {
                VirtualFree(cave, 0, MEM_RELEASE);
                Throw(U8("無法準備通知橋。"));
            }
            FlushInstructionCache(GetCurrentProcess(), cave, 4096);
            g_installed.compCave = cave;
        }

        const int64_t delta = static_cast<int64_t>(reinterpret_cast<uint64_t>(cave)) - static_cast<int64_t>(site) - 5;
        if (delta < INT32_MIN || delta > INT32_MAX) Throw(U8("通知呼叫點距離過遠，無法接入。"));
        uint8_t call[5] = { 0xE8, 0, 0, 0, 0 };
        const int32_t rel = static_cast<int32_t>(delta);
        std::memcpy(call + 1, &rel, 4);
        if (!SameBytes(site, plan.compBytes, 5)) Throw(U8("通知呼叫點狀態已改變。"));
        WriteGameMemory(site, call, 5);
        if (!SameBytes(site, call, 5)) Throw(U8("合成通知讀回校驗失敗。"));
        g_installed.compPatched = true;
        log += "[IME] composition patch installed\n";
    }

    // 還原我們改過的位置；掛鉤區塊保留（遊戲執行緒可能仍在其中）
    void RevertImePatches(const Plan& plan) {
        const uint64_t image = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        if (g_installed.compPatched) {
            WriteGameMemory(image + plan.compSite, plan.compBytes, 5);
            g_installed.compPatched = false;
        }
        for (int i = 0; i < 2; ++i) {
            if (!g_installed.focusPatched[i]) continue;
            const uint8_t five = 5;
            WriteGameMemory(image + plan.focusSites[i] + 4, &five, 1);
            g_installed.focusPatched[i] = false;
        }
    }

    // ------------------------------------------------------------------
    // 背景分析與主執行緒狀態機
    // ------------------------------------------------------------------
    std::atomic<int> g_analysisState{ 0 }; // 0 未開始、1 進行中、2 成功、3 失敗
    std::thread g_worker;
    Plan g_plan;
    std::string g_analysisError;

    void AnalysisMain() {
        Plan plan;
        std::string err;
        bool ok = false;
        try {
            DiskImage img;
            if (LoadDiskImage(img, err)) {
                Analyze(img, plan);
                char line[200];
                std::snprintf(line, sizeof(line), "[IME] browser ctor call RVA 0x%X (ctor 0x%X), focus 0x%X/0x%X, composition RVA 0x%X (notify 0x%X)",
                    plan.callSite, plan.constructor, plan.focusSites[0], plan.focusSites[1], plan.compSite, plan.notifyTarget);
                plan.log = line;
                ok = true;
            }
        }
        catch (const std::exception& e) {
            err = e.what();
        }
        catch (...) {
            err = U8("分析時發生例外");
        }
        if (ok) g_plan = plan;
        else g_analysisError = err;
        g_analysisState.store(ok ? 2 : 3, std::memory_order_release);
    }

    bool g_imeWanted = false;     // 使用者要求的中文輸入增強
    bool g_imeActive = false;     // 輸入法補丁已安裝
    bool g_webWanted = false;     // 要求的網頁繁體化（由繁體模式決定）
    bool g_webActive = false;     // 呼叫點目前載入了網頁簡轉繁
    bool g_unavailable = false;
    bool g_logFlushed = false;
    uint32_t g_statsShown[3] = { 0xFFFFFFFFu, 0, 0 };
    uint64_t g_lastStats = 0;
    std::string g_status;         // 中文輸入增強的狀態
    std::string g_webStatus;      // 網頁繁體化的狀態

    void Log(const std::string& text) {
        size_t start = 0;
        while (start < text.size()) {
            size_t end = text.find('\n', start);
            if (end == std::string::npos) end = text.size();
            if (end > start) ArcLog(text.substr(start, end - start).c_str());
            start = end + 1;
        }
    }

    void UpdateStatsStatus() {
        if (!g_imeActive || !g_installed.cave) return;
        const uint64_t now = GetTickCount64();
        if (now - g_lastStats < 2000) return;
        g_lastStats = now;

        const uint8_t* p = g_installed.cave + kStatsOffset;
        if (!IsReadable(p, 12)) return;
        uint32_t stats[3];
        std::memcpy(stats, p, 12);
        if (std::memcmp(stats, g_statsShown, 12) == 0) return;
        std::memcpy(g_statsShown, stats, 12);

        char line[160];
        if (stats[0] == 0) {
            g_status = U8("已安裝；請關閉後重新開啟商城／交易行");
        }
        else if (stats[1] == 0) {
            g_status = U8("已建立瀏覽器，但官方腳本未匹配，輸入增強未生效");
        }
        else {
            std::snprintf(line, sizeof(line), U8("已生效：瀏覽器建立 %u 次，腳本替換 %u 次"), stats[0], stats[1]);
            g_status = line;
        }
        std::snprintf(line, sizeof(line), "[IME] browsers created %u (script replaced %u, passthrough %u)", stats[0], stats[1], stats[2]);
        ArcLog(line);
    }

    // 全部或全無：任何一步失敗就把已改的都還原
    void FailAll(const std::string& message) {
        try { RevertImePatches(g_plan); } catch (...) {}
        try { std::string ignored; SetEntry(g_plan, Entry::None, ignored); } catch (...) {}
        const bool hadWeb = g_webWanted || g_webActive;
        const bool hadIme = g_imeWanted || g_imeActive;
        g_imeWanted = g_imeActive = g_webWanted = g_webActive = false;
        if (hadIme) g_status = message;
        if (hadWeb) g_webStatus = message;
        Log("[IME] " + message);
    }

    // 讓實際狀態追上「要求的狀態」：需要時才分析遊戲程式，只有被要求的功能才會載入對應的腳本
    void Reconcile() {
        const bool want = g_imeWanted || g_webWanted;
        const bool have = g_imeActive || g_webActive;
        if (!want && !have) return;

        if (want) {
            const int state = g_analysisState.load(std::memory_order_acquire);
            if (state == 0) {
                g_analysisState.store(1);
                g_worker = std::thread(AnalysisMain);
                if (g_imeWanted) g_status = U8("分析遊戲程式中…");
                if (g_webWanted) g_webStatus = U8("分析遊戲程式中…");
                return;
            }
            if (state == 1) return;
            if (state == 3) {
                g_unavailable = true;
                const std::string message = std::string(U8("不可用：")) + g_analysisError;
                if (g_imeWanted) g_status = message;
                if (g_webWanted) g_webStatus = message;
                g_imeWanted = g_webWanted = false;
                Log("[IME] " + message);
                return;
            }
            if (!g_logFlushed) {
                g_logFlushed = true;
                Log(g_plan.log);
            }
        }

        std::string log;
        try {
            if (g_imeWanted && !g_imeActive) {
                InstallImePatches(g_plan, log);
                g_imeActive = true;
                g_statsShown[0] = 0xFFFFFFFFu;
                g_lastStats = 0;
                g_status = U8("已安裝；請關閉後重新開啟商城／交易行");
            }
            else if (!g_imeWanted && g_imeActive) {
                RevertImePatches(g_plan);
                g_imeActive = false;
                g_status = U8("已還原（已開啟的商城需重新開啟）");
                log += "[IME] input method patches reverted\n";
            }

            Entry entry = Entry::None;
            if (g_imeWanted && g_webWanted) entry = Entry::B;
            else if (g_imeWanted) entry = Entry::A;
            else if (g_webWanted) entry = Entry::C;
            if (entry != g_installed.entry) SetEntry(g_plan, entry, log);

            const bool web = (entry == Entry::B || entry == Entry::C);
            if (web && !g_webActive) g_webStatus = U8("已啟用；請關閉後重新開啟商城／交易行");
            if (!web && g_webActive) g_webStatus = U8("已還原（已開啟的商城需重新開啟）");
            g_webActive = web;
        }
        catch (const std::exception& e) {
            Log(log);
            FailAll(std::string(U8("安裝失敗：")) + e.what());
            return;
        }
        Log(log);
    }
}

namespace ChineseIme {

    // ---- 中文輸入增強 ----
    void RequestEnable(bool enable) {
        if (enable == g_imeWanted) return;
        if (enable && g_unavailable) return;
        g_imeWanted = enable;
        if (enable) g_status.clear();
    }

    bool IsEnabled() { return g_imeWanted; }

    bool IsBusy() {
        return g_imeWanted != g_imeActive || g_analysisState.load(std::memory_order_acquire) == 1;
    }

    bool IsAvailable() { return !g_unavailable; }

    const char* StatusText() { return g_status.c_str(); }

    // ---- 網頁繁體化（由簡體轉繁體模式決定；只有網頁真的是中文時才需要） ----
    void SetWebTraditional(bool enable) {
        if (enable == g_webWanted) return;
        if (enable && g_unavailable) return;
        g_webWanted = enable;
        g_webStatus.clear();
    }

    bool IsWebTraditionalActive() { return g_webActive; }

    const char* WebStatusText() { return g_webStatus.c_str(); }

    void Update() {
        UpdateStatsStatus();
        Reconcile();
    }

    void Shutdown() {
        if (g_worker.joinable()) g_worker.join();
        try { if (g_imeActive) RevertImePatches(g_plan); } catch (...) {}
        try {
            if (g_installed.callPatched) {
                std::string ignored;
                SetEntry(g_plan, Entry::None, ignored);
            }
        }
        catch (...) {}
        g_imeActive = g_webActive = false;
    }
}
