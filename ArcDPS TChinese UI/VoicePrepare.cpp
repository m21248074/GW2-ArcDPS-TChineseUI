#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "VoicePrepare.h"
#include "GW2LangPatch.h"
#include "VoiceLifetime.h"

#include <Windows.h>
#include <asmjit/asmjit.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

using namespace VoiceImage;

namespace {
    constexpr uint32_t kStatusOffset = 384;  // 呼叫桩回報狀態：0 尚未執行、1 已啟動、<0 錯誤
    constexpr uint32_t kRequestOffset = 512; // 傳給任務工廠的請求結構
    constexpr uint32_t kManifestOffset = 576;
    constexpr size_t kBlockSize = 4096;
    constexpr size_t kMaxThunkSize = kStatusOffset;
    constexpr uint64_t kWaitGameLimitMs = 10ull * 60 * 1000;

    [[noreturn]] void Throw(const std::string& message) {
        throw std::runtime_error(message);
    }

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

    std::vector<uint8_t> ReadMem(uint64_t address, size_t size) {
        if (address == 0 || !IsReadable(reinterpret_cast<void*>(address), size)) {
            Throw(U8("中文語音：無法讀取遊戲的語音資源狀態"));
        }
        const uint8_t* p = reinterpret_cast<const uint8_t*>(address);
        return std::vector<uint8_t>(p, p + size);
    }

    template <typename T>
    T ReadAs(const std::vector<uint8_t>& bytes, size_t offset) {
        T v{};
        std::memcpy(&v, bytes.data() + offset, sizeof(T));
        return v;
    }

    uint64_t ReadU64(uint64_t address) { return ReadAs<uint64_t>(ReadMem(address, 8), 0); }

    // ------------------------------------------------------------------
    // 定位器（Zydis 版的 VoiceRuntimeLocator，只含啟動準備流程所需的部分）
    // ------------------------------------------------------------------
    class Resolver {
    public:
        explicit Resolver(const DiskImage& img) : img_(img) { BuildFunctionTable(); }

        void Run(VoicePrepare::Locator& out) {
            // 語言清單根物件
            const uint32_t selector = Unique(References("!foundEnglishLanguageManifest", false), U8("語言清單選擇器"));
            std::set<uint32_t> wrappers;
            for (uint32_t f : Callers(selector)) {
                if (Function(f).second - f < 40) wrappers.insert(f);
            }
            const uint32_t wrapper = Unique(wrappers, U8("語言清單包裝入口"));
            std::set<uint32_t> roots;
            for (const Insn& i : Code(wrapper)) {
                uint32_t t = 0;
                if (i.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(i, i.op[1], t)) roots.insert(t);
            }
            out.root = Unique(roots, U8("清單根物件")) + 8;

            // 清單準備物件表
            std::set<uint32_t> tables;
            for (uint32_t f : References("preparer", false)) {
                const std::vector<Insn>& code = Code(f);
                std::set<uint32_t> movTargets;
                for (const Insn& i : code) {
                    uint32_t t = 0;
                    if (i.ins.mnemonic != ZYDIS_MNEMONIC_MOV) continue;
                    if (RipTarget(i, i.op[0], t) || RipTarget(i, i.op[1], t)) movTargets.insert(t);
                }
                for (const Insn& i : code) {
                    uint32_t t = 0;
                    if (i.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(i, i.op[1], t) && movTargets.count(t + 8)) tables.insert(t);
                }
            }
            out.preparers = Unique(tables, U8("清單準備物件表"));

            // 官方下載任務工廠
            const uint32_t constructor = Unique(References("PatchArchiveThread", true), U8("官方下載執行緒建構入口"));
            out.factory = Unique(Callers(constructor), U8("官方下載任務工廠"));
            bool sizeHint = false;
            for (const Insn& i : Code(out.factory)) {
                if (i.ins.mnemonic == ZYDIS_MNEMONIC_MOV && IsReg(i.op[0], ZYDIS_REGISTER_EDX) && IsImm(i.op[1], 256)) sizeHint = true;
            }
            if (!sizeHint) Throw(U8("官方語音下載接口結構發生變化（任務工廠特徵不符），未調用該接口"));

            // 準備物件虛表（槽 14 指向「清單下載入口」）
            const uint32_t mount = Unique(References("state == MOUNT_STATE_INITIALIZED_NEEDS_PATCHING || state == MOUNT_STATE_PATCHED", false), U8("清單下載入口"));
            std::set<uint32_t> vtables;
            for (const Section& s : img_.sections) {
                if (s.name != ".rdata") continue;
                for (uint32_t off = 0; static_cast<uint64_t>(off) + 8 <= s.rawSize; off += 8) {
                    if (img_.U64(static_cast<uint64_t>(s.va) + off) == img_.imageBase + mount && s.va + off >= 112) {
                        vtables.insert(s.va + off - 112);
                    }
                }
            }
            out.vtable = Unique(vtables, U8("清單準備物件虛表"));
            const uint32_t getter11 = RequireGetter(out.vtable, 11);
            const uint32_t getter21 = RequireGetter(out.vtable, 21);

            // 本地資源查詢
            std::set<uint32_t> queries;
            for (uint32_t f : References("!stream", false)) {
                for (const Insn& i : Code(f)) {
                    uint32_t t = 0;
                    if (i.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(i, i.op[1], t) && StringEndsWith(t, "MultiArchiveLocal.cpp")) {
                        queries.insert(f);
                        break;
                    }
                }
            }
            out.query = Unique(queries, U8("本地資源查詢入口"));

            ResolveLifetime(out, constructor);

            // 呼叫前要確認未被其他程式 hook 的函式開頭
            const uint32_t entries[VoicePrepare::Locator::kEntryCount] = {
                out.factory, out.query, getter11, getter21, out.taskDestroy, out.taskCancel, out.taskState, out.workerSleep };
            for (int i = 0; i < VoicePrepare::Locator::kEntryCount; ++i) {
                if (!img_.InRange(entries[i], 32)) Throw(U8("官方語音接口位置異常"));
                out.entryRva[i] = entries[i];
                std::memcpy(out.entryBytes[i], &img_.mem[entries[i]], 32);
            }
            for (uint32_t rva : { out.shutdownSite, out.exitStatsSite }) {
                if (!img_.InRange(rva, 5)) Throw(U8("語音退出入口位置異常"));
            }
            std::memcpy(out.shutdownSiteBytes, &img_.mem[out.shutdownSite], 5);
            std::memcpy(out.exitStatsSiteBytes, &img_.mem[out.exitStatsSite], 5);
        }

    private:
        using Range = std::pair<uint32_t, uint32_t>;

        // 下載任務的生命週期與退出流程（對應原工具 VoiceRuntimeLocator.ResolveLifetime）
        void ResolveLifetime(VoicePrepare::Locator& out, uint32_t constructor) {
            // 官方下載佇列統計入口：「    -in-flight」所在函式中，mov ecx,17 之後的第一個 call
            std::set<uint32_t> statsTargets;
            for (uint32_t item : References("    -in-flight", true)) {
                const std::vector<Insn>& code = Code(item);
                for (size_t i = 0; i < code.size(); ++i) {
                    if (!(code[i].ins.mnemonic == ZYDIS_MNEMONIC_MOV && IsReg(code[i].op[0], ZYDIS_REGISTER_ECX) && IsImm(code[i].op[1], 17))) continue;
                    for (size_t j = i + 1; j < code.size(); ++j) {
                        if (code[j].ins.mnemonic != ZYDIS_MNEMONIC_CALL) continue;
                        uint32_t t = 0;
                        if (BranchTarget(code[j], t)) statsTargets.insert(t);
                        break;
                    }
                }
            }
            out.exitStatsTarget = Unique(statsTargets, U8("官方下載佇列統計入口"));

            // 退出前下載佇列檢查的呼叫點
            std::set<uint32_t> statsSites;
            for (uint32_t f : Callers(out.exitStatsTarget)) {
                if (Function(f).second - f >= 160) continue;
                const std::vector<Insn>& src = Code(f);
                bool hasSixteen = false, hasSix = false, hasJbe = false;
                int calls = 0;
                for (const Insn& x : src) {
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOV && IsReg(x.op[0], ZYDIS_REGISTER_ECX) && IsImm(x.op[1], 16)) hasSixteen = true;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOV && IsReg(x.op[0], ZYDIS_REGISTER_R8D) && IsImm(x.op[1], 6)) hasSix = true;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_CALL) ++calls;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_JBE) hasJbe = true;
                }
                if (!(hasSixteen && hasSix && calls == 4 && hasJbe)) continue;
                for (const Insn& x : src) {
                    uint32_t t = 0;
                    if (IsCallRel(x, t) && x.ins.length == 5 && t == out.exitStatsTarget) statsSites.insert(x.rva);
                }
            }
            out.exitStatsSite = Unique(statsSites, U8("退出前下載佇列檢查呼叫點"));

            // 官方下載佇列的回收（選用；定位失敗時退回只取消任務的版本）
            try {
                ResolveQueuedRequests(out);
                out.queueChainResolved = true;
            }
            catch (const std::runtime_error&) {
                out.queuePump = out.queueRoot = out.queueLock = out.queueLockEnter = 0;
                out.queueLockLeaveIat = out.queueMoveBatch = out.queueClear = 0;
                out.queueChainResolved = false;
            }

            // 資源關閉流程
            std::set<uint32_t> reclaimers;
            for (uint32_t f : References("m_count == 0", false)) {
                bool storesRoot = false, storesPreparers = false;
                for (const Insn& x : Code(f)) {
                    uint32_t t = 0;
                    if (x.ins.mnemonic != ZYDIS_MNEMONIC_MOV || !RipTarget(x, x.op[0], t)) continue;
                    if (t == out.root) storesRoot = true;
                    if (t == out.preparers + 8) storesPreparers = true;
                }
                if (storesRoot && storesPreparers) reclaimers.insert(f);
            }
            const uint32_t reclaimer = Unique(reclaimers, U8("根清單回收入口"));
            out.shutdownTarget = Unique(Callers(reclaimer), U8("資源關閉流程"));

            std::set<uint32_t> tails;
            for (uint32_t f : Callers(out.shutdownTarget)) {
                std::vector<const Insn*> body;
                for (const Insn& x : Code(f)) {
                    if (x.ins.mnemonic != ZYDIS_MNEMONIC_NOP) body.push_back(&x);
                }
                uint32_t t = 0;
                if (body.size() == 1 && body[0]->ins.mnemonic == ZYDIS_MNEMONIC_JMP && body[0]->ins.length == 5
                    && BranchTarget(*body[0], t) && t == out.shutdownTarget) {
                    tails.insert(f);
                }
            }
            out.shutdownSite = Unique(tails, U8("資源關閉尾跳入口"));

            // 下載任務物件：虛表與取消/銷毀/狀態函式
            std::set<uint32_t> taskVtables;
            for (const Insn& x : Code(out.factory)) {
                uint32_t t = 0;
                if (x.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(x, x.op[1], t) && InRdata(t)) taskVtables.insert(t);
            }
            out.taskVtable = Unique(taskVtables, U8("下載任務虛表"));
            auto vtableEntry = [&](int slot) {
                const uint64_t p = img_.U64(static_cast<uint64_t>(out.taskVtable) + static_cast<uint64_t>(slot) * 8);
                if (p < img_.imageBase || p - img_.imageBase > 0xFFFFFFFFull) Throw(U8("官方語音下載接口結構發生變化（下載任務虛表），未調用該接口"));
                return static_cast<uint32_t>(p - img_.imageBase);
            };
            out.taskDestroy = vtableEntry(0);
            out.taskCancel = vtableEntry(2);
            out.taskState = vtableEntry(3);

            const char* changed = U8("官方語音下載接口結構發生變化（下載任務），未調用該接口");
            for (int64_t offset : { 104, 112, 144 }) {
                bool found = false;
                for (const Insn& x : Code(out.taskDestroy)) {
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOV && HasMem(x, ZYDIS_REGISTER_RCX, offset, 1, 1)) { found = true; break; }
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOV && x.op[1].type == ZYDIS_OPERAND_TYPE_MEMORY && x.op[1].mem.disp.has_displacement && x.op[1].mem.disp.value == offset) { found = true; break; }
                }
                if (!found) Throw(changed);
            }
            {
                bool readsState = false, anyCall = false;
                for (const Insn& x : Code(out.taskState)) {
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOV && IsReg(x.op[0], ZYDIS_REGISTER_EAX) && HasMem(x, ZYDIS_REGISTER_RCX, 164, 1, 1)) readsState = true;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_CALL) anyCall = true;
                }
                if (!readsState || anyCall) Throw(changed);
            }
            {
                bool addsOffset = false, setsOne = false;
                for (const Insn& x : Code(out.taskCancel)) {
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_ADD && IsReg(x.op[0], ZYDIS_REGISTER_RCX) && IsImm(x.op[1], 160)) addsOffset = true;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_MOV && IsReg(x.op[0], ZYDIS_REGISTER_EDX) && IsImm(x.op[1], 1)) setsOne = true;
                }
                if (!addsOffset || !setsOne) Throw(changed);
            }

            // 下載任務的工作執行緒 → 其中「mov ecx,1; call」就是休眠函式
            std::set<uint32_t> workers;
            for (const Insn& x : Code(constructor)) {
                uint32_t a = 0;
                if (!(x.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(x, x.op[1], a) && IsFunctionStart(a))) continue;
                bool has160 = false, has164 = false;
                for (const Insn& y : Code(a)) {
                    if (HasDisp(y, 160)) has160 = true;
                    if (HasDisp(y, 164)) has164 = true;
                }
                if (has160 && has164) workers.insert(a);
            }
            const std::vector<Insn>& body = Code(Unique(workers, U8("下載任務工作執行緒")));
            std::set<uint32_t> sleeps;
            for (size_t n = 1; n < body.size(); ++n) {
                uint32_t t = 0;
                if (IsCallRel(body[n], t) && body[n - 1].ins.mnemonic == ZYDIS_MNEMONIC_MOV
                    && IsReg(body[n - 1].op[0], ZYDIS_REGISTER_ECX) && IsImm(body[n - 1].op[1], 1)) {
                    sleeps.insert(t);
                }
            }
            out.workerSleep = Unique(sleeps, U8("下載執行緒休眠入口"));
        }

        // 官方下載佇列：任務退出時把本任務排隊中的請求移出並回收（對應 ResolveQueuedRequests）
        void ResolveQueuedRequests(VoicePrepare::Locator& out) {
            const uint32_t completion = Unique(References("Falling back to full file-download for 0x%08x:0x%08x", true), U8("下載請求完成處理"));
            const uint32_t tick = Unique(Callers(completion), U8("下載佇列更新入口"));

            std::set<uint32_t> pumps;
            for (uint32_t f : Callers(tick)) {
                if (Function(f).second - f >= 160) continue;
                int calls = 0;
                for (const Insn& x : Code(f)) {
                    uint32_t t = 0;
                    if (IsCallRel(x, t) && t == tick) ++calls;
                }
                if (calls == 1) pumps.insert(f);
            }
            out.queuePump = Unique(pumps, U8("下載佇列帶鎖更新包裝"));
            if (out.queuePump == tick) Throw(U8("下載佇列結構不符"));
            const std::vector<Insn>& source = Code(out.queuePump);

            std::map<uint32_t, int> leaCounts;
            for (const Insn& x : Code(out.exitStatsTarget)) {
                uint32_t t = 0;
                if (x.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(x, x.op[1], t)) ++leaCounts[t];
            }
            std::set<uint32_t> roots;
            for (const auto& kv : leaCounts) {
                if (kv.second >= 2) roots.insert(kv.first);
            }
            out.queueRoot = Unique(roots, U8("下載佇列統計根"));

            bool usesRoot = false, scalesBy328 = false;
            for (const Insn& x : source) {
                uint32_t t = 0;
                if (x.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(x, x.op[1], t) && t == out.queueRoot) usesRoot = true;
                if (x.ins.mnemonic == ZYDIS_MNEMONIC_IMUL && IsImm(x.op[2], 328)) scalesBy328 = true;
            }
            if (!usesRoot || !scalesBy328) Throw(U8("下載佇列結構不符"));

            std::set<uint32_t> locks;
            for (const Insn& x : source) {
                uint32_t t = 0;
                if (x.ins.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(x, x.op[1], t) && t != out.queueRoot) locks.insert(t);
            }
            out.queueLock = Unique(locks, U8("下載佇列鎖"));

            bool foundEnter = false;
            for (const Insn& x : source) {
                uint32_t t = 0;
                if (IsCallRel(x, t)) { out.queueLockEnter = t; foundEnter = true; break; }
            }
            if (!foundEnter) Throw(U8("下載佇列結構不符"));
            bool statsEnters = false;
            for (const Insn& x : Code(out.exitStatsTarget)) {
                uint32_t t = 0;
                if (IsCallRel(x, t) && t == out.queueLockEnter) statsEnters = true;
            }
            if (!statsEnters) Throw(U8("下載佇列結構不符"));

            // 解鎖函式：優先取 call [rip+x] 的 IAT 位置；沒有的話，從 jmp [rip+x] 轉接函式推得
            std::set<uint32_t> leaveIats;
            for (const Insn& x : source) {
                uint32_t t = 0;
                if (x.ins.mnemonic == ZYDIS_MNEMONIC_CALL && RipTarget(x, x.op[0], t)) leaveIats.insert(t);
            }
            if (leaveIats.empty()) {
                std::set<uint32_t> callTargets;
                for (const Insn& x : source) {
                    uint32_t t = 0;
                    if (IsCallRel(x, t) && t != out.queueLockEnter && t != tick) callTargets.insert(t);
                }
                for (uint32_t t : callTargets) {
                    if (!img_.InRange(t, 8)) continue;
                    if (img_.mem[t] == 0xFF && img_.mem[t + 1] == 0x25) {
                        leaveIats.insert(static_cast<uint32_t>(static_cast<int64_t>(t) + 6 + img_.S32(t + 2)));
                    }
                    else if ((img_.mem[t] == 0x48 || img_.mem[t] == 0x4C) && img_.mem[t + 1] == 0xFF && img_.mem[t + 2] == 0x25) {
                        leaveIats.insert(static_cast<uint32_t>(static_cast<int64_t>(t) + 7 + img_.S32(t + 3)));
                    }
                }
            }
            out.queueLockLeaveIat = Unique(leaveIats, U8("下載佇列解鎖匯入"));

            auto decOffsets = [&](uint32_t f, std::initializer_list<int64_t> offsets) {
                try {
                    const std::vector<Insn>& code = Code(f);
                    for (int64_t o : offsets) {
                        bool found = false;
                        for (const Insn& x : code) {
                            if (x.ins.mnemonic == ZYDIS_MNEMONIC_DEC && HasDisp(x, o)) { found = true; break; }
                        }
                        if (!found) return false;
                    }
                    return true;
                }
                catch (const std::runtime_error&) {
                    return false;
                }
            };

            const uint32_t batchRegister = Unique(References("m_batches.IndexOf(batch) == MAX_UNSIGNED", false), U8("下載批次登記入口"));
            std::set<uint32_t> moves;
            for (const Insn& x : Code(batchRegister)) {
                uint32_t t = 0;
                if (IsCallRel(x, t) && decOffsets(t, { 216, 272 })) moves.insert(t);
            }
            out.queueMoveBatch = Unique(moves, U8("原生批次請求移交"));

            std::set<uint32_t> closers;
            for (uint32_t f : Callers(tick)) {
                if (Function(f).second - f > 160) closers.insert(f);
            }
            const uint32_t closer = Unique(closers, U8("下載佇列關閉入口"));
            std::map<uint32_t, int> callCounts;
            for (const Insn& x : Code(closer)) {
                uint32_t t = 0;
                if (IsCallRel(x, t)) ++callCounts[t];
            }
            std::set<uint32_t> clears;
            for (const auto& kv : callCounts) {
                if (kv.second == 6 && decOffsets(kv.first, { 72, 216, 296, 308 })) clears.insert(kv.first);
            }
            out.queueClear = Unique(clears, U8("原生私有請求佇列回收"));
        }

        const DiskImage& img_;
        std::vector<Range> functions_;
        std::map<uint32_t, std::vector<Insn>> decoded_;

        // .pdata 的 RUNTIME_FUNCTION；鏈結項目併入其父函式
        void BuildFunctionTable() {
            std::map<uint32_t, uint32_t> table;
            if (img_.excDirSize < 12 || !img_.InRange(img_.excDirRva, img_.excDirSize)) Throw(U8("例外目錄異常"));
            for (uint32_t e = 0; static_cast<uint64_t>(e) + 12 <= img_.excDirSize; e += 12) {
                const uint32_t begin = img_.U32(img_.excDirRva + e);
                const uint32_t end = img_.U32(img_.excDirRva + e + 4);
                uint32_t unwind = img_.U32(img_.excDirRva + e + 8);
                if (begin == 0 || end <= begin) continue;

                uint32_t key = begin;
                bool ok = true;
                for (int k = 0; k < 32; ++k) {
                    if (!img_.InRange(unwind, 4)) { ok = false; break; }
                    if ((img_.mem[unwind] & 0x20) == 0) break; // 不是鏈結項目
                    const uint32_t next = unwind + 4 + ((img_.mem[unwind + 2] + 1u) & ~1u) * 2;
                    if (!img_.InRange(next, 12)) { ok = false; break; }
                    key = img_.U32(next);
                    unwind = img_.U32(next + 8);
                    if (k == 31) Throw(U8("官方語音下載接口結構發生變化（unwind 鏈結過長），未調用該接口"));
                }
                if (!ok) continue;
                uint32_t& slot = table[key];
                slot = std::max(slot, end);
            }
            functions_.assign(table.begin(), table.end());
        }

        const Section* SectionAt(uint32_t rva) const {
            for (const Section& s : img_.sections) {
                if (rva >= s.va && rva < s.va + s.rawSize) return &s;
            }
            return nullptr;
        }

        bool TryFunction(uint32_t rva, Range& out) {
            auto it = std::upper_bound(functions_.begin(), functions_.end(), rva, [](uint32_t v, const Range& r) { return v < r.first; });
            if (it != functions_.begin()) {
                --it;
                if (rva >= it->first && rva < it->second) {
                    out = *it;
                    return true;
                }
            }

            // 沒有 .pdata 項目的小型葉函式：從前一個 16 位元組邊界往回找，並解碼到 ret / jmp
            for (const Section& s : img_.sections) {
                if (s.name != ".text" || rva < s.va || rva >= s.va + s.rawSize) continue;
                const int64_t start = static_cast<int64_t>(rva & ~15u);
                for (int64_t candidate = start; candidate >= std::max<int64_t>(s.va, start - 32); candidate -= 16) {
                    if (candidate <= s.va) continue;
                    const uint8_t before = img_.mem[static_cast<size_t>(candidate) - 1];
                    if (before != 0xCC && before != 0xC3) continue;

                    const uint64_t limit = std::min<uint64_t>(static_cast<uint64_t>(candidate) + 256, static_cast<uint64_t>(s.va) + s.rawSize);
                    uint32_t ip = static_cast<uint32_t>(candidate);
                    while (ip < limit) {
                        Insn x;
                        if (!DecodeOne(img_, ip, limit, x)) break;
                        if (x.ins.mnemonic == ZYDIS_MNEMONIC_INT3 || x.ins.mnemonic == ZYDIS_MNEMONIC_CALL) break;
                        const uint32_t next = ip + x.ins.length;
                        const bool directJmp = x.ins.mnemonic == ZYDIS_MNEMONIC_JMP && x.op[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
                        if (x.ins.mnemonic == ZYDIS_MNEMONIC_RET || directJmp) {
                            if (rva < static_cast<uint32_t>(candidate) || rva >= next) break;
                            out = { static_cast<uint32_t>(candidate), next };
                            return true;
                        }
                        ip = next;
                    }
                }
            }
            return false;
        }

        Range Function(uint32_t rva) {
            Range r;
            if (!TryFunction(rva, r)) {
                char buf[160];
                std::snprintf(buf, sizeof(buf), U8("官方語音下載接口結構發生變化（找不到函式邊界 0x%X），未調用該接口"), rva);
                Throw(buf);
            }
            return r;
        }

        const std::vector<Insn>& Code(uint32_t start) {
            auto it = decoded_.find(start);
            if (it != decoded_.end()) return it->second;
            const Range r = Function(start);
            return decoded_[start] = DecodeSeq(img_, r.first, r.second - r.first, false);
        }

        // 找出所有 lea r64,[rip+x]，其中 x 屬於 targets，並對每個命中呼叫 fn(lea 的 RVA)
        template <typename Fn>
        void ForEachLea(const std::set<uint32_t>& targets, Fn fn) {
            for (const Section& s : img_.sections) {
                if (s.name != ".text") continue;
                for (uint32_t rva = s.va; static_cast<uint64_t>(rva) + 7 <= static_cast<uint64_t>(s.va) + s.rawSize; ++rva) {
                    const uint8_t b0 = img_.mem[rva];
                    if ((b0 != 0x48 && b0 != 0x4C) || img_.mem[rva + 1] != 0x8D || (img_.mem[rva + 2] & 0xC7) != 5) continue;
                    const int64_t t = static_cast<int64_t>(rva) + 7 + img_.S32(rva + 3);
                    if (t >= 0 && targets.count(static_cast<uint32_t>(t))) fn(rva);
                }
            }
        }

        // 引用某字串（位於 .text / .pdata 以外的區段）的函式起點
        std::set<uint32_t> References(const char* text, bool wide) {
            const std::set<uint32_t> found = wide ? FindWideZ(img_, text) : FindAsciiZ(img_, text);
            std::set<uint32_t> hits;
            for (uint32_t h : found) {
                const Section* s = SectionAt(h);
                if (s && s->name != ".text" && s->name != ".pdata") hits.insert(h);
            }

            std::set<uint32_t> result;
            ForEachLea(hits, [&](uint32_t rva) {
                Range r;
                if (!TryFunction(rva, r)) return;
                for (const Insn& i : Code(r.first)) {
                    if (i.rva == rva && i.ins.mnemonic == ZYDIS_MNEMONIC_LEA) {
                        result.insert(r.first);
                        break;
                    }
                }
            });
            return result;
        }

        // 以 call / jmp rel32 呼叫 target 的函式起點
        std::set<uint32_t> Callers(uint32_t target) {
            std::set<uint32_t> result;
            for (const Section& s : img_.sections) {
                if (s.name != ".text") continue;
                for (uint32_t rva = s.va; static_cast<uint64_t>(rva) + 5 <= static_cast<uint64_t>(s.va) + s.rawSize; ++rva) {
                    const uint8_t b = img_.mem[rva];
                    if (b != 0xE8 && b != 0xE9) continue;
                    if (static_cast<int64_t>(rva) + 5 + img_.S32(rva + 1) != target) continue;

                    Range r;
                    if (!TryFunction(rva, r)) continue;
                    for (const Insn& i : Code(r.first)) {
                        if (i.rva == rva && (i.ins.mnemonic == ZYDIS_MNEMONIC_CALL || i.ins.mnemonic == ZYDIS_MNEMONIC_JMP)) {
                            result.insert(r.first);
                            break;
                        }
                    }
                }
            }
            return result;
        }

        bool StringEndsWith(uint32_t rva, const char* suffix) const {
            if (!img_.InRange(rva, 1)) return false;
            size_t end = rva;
            while (end < img_.mem.size() && img_.mem[end] != 0 && end - rva < 512) ++end;
            if (end >= img_.mem.size() || img_.mem[end] != 0) return false;
            const size_t len = std::strlen(suffix);
            return end - rva >= len && std::memcmp(&img_.mem[end - len], suffix, len) == 0;
        }

        static uint32_t Unique(const std::set<uint32_t>& values, const char* label) {
            if (values.size() != 1) {
                char buf[256];
                std::snprintf(buf, sizeof(buf), U8("%s候選 %zu 個，未啟動語音準備"), label, values.size());
                Throw(buf);
            }
            return *values.begin();
        }

        // 任一可見的記憶體運算元的位移等於 disp（不限基底暫存器）
        static bool HasDisp(const Insn& x, int64_t disp) {
            for (int k = 0; k < x.ins.operand_count_visible && k < ZYDIS_MAX_OPERAND_COUNT; ++k) {
                const ZydisDecodedOperand& o = x.op[k];
                if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.disp.has_displacement && o.mem.disp.value == disp) return true;
            }
            return false;
        }

        static bool IsCallRel(const Insn& x, uint32_t& target) {
            return x.ins.mnemonic == ZYDIS_MNEMONIC_CALL && BranchTarget(x, target);
        }

        bool IsFunctionStart(uint32_t rva) const {
            auto it = std::lower_bound(functions_.begin(), functions_.end(), rva, [](const Range& r, uint32_t v) { return r.first < v; });
            return it != functions_.end() && it->first == rva;
        }

        bool InRdata(uint32_t rva) const {
            for (const Section& s : img_.sections) {
                if (s.name == ".rdata" && rva >= s.va && rva < s.va + s.rawSize) return true;
            }
            return false;
        }

        static bool HasMem(const Insn& x, ZydisRegister base, int64_t disp, int firstOperand = 0, int lastOperand = 1) {
            for (int k = firstOperand; k <= lastOperand && k < ZYDIS_MAX_OPERAND_COUNT; ++k) {
                const ZydisDecodedOperand& o = x.op[k];
                if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.base != base) continue;
                const int64_t actual = o.mem.disp.has_displacement ? o.mem.disp.value : 0; // [rdx] 沒有位移欄位
                if (actual == disp) return true;
            }
            return false;
        }

        // 驗證虛表槽 slot 是一個短小的 getter；回傳該函式的 RVA
        uint32_t RequireGetter(uint32_t vtable, int slot) {
            const uint64_t ptr = img_.U64(static_cast<uint64_t>(vtable) + static_cast<uint64_t>(slot) * 8);
            char tag[160];
            if (ptr < img_.imageBase || ptr - img_.imageBase > 0xFFFFFFFFull) {
                std::snprintf(tag, sizeof(tag), U8("官方語音下載接口結構發生變化（虛表槽 %d 的指標無效），未調用該接口"), slot);
                Throw(tag);
            }
            const uint32_t rva = static_cast<uint32_t>(ptr - img_.imageBase);

            std::vector<Insn> list;
            uint32_t ip = rva;
            while (ip < static_cast<uint64_t>(rva) + 64) {
                Insn x;
                if (!DecodeOne(img_, ip, static_cast<uint64_t>(rva) + 64, x) || x.ins.mnemonic == ZYDIS_MNEMONIC_CALL) {
                    std::snprintf(tag, sizeof(tag), U8("官方語音下載接口結構發生變化（虛表槽 %d 的函式含 call 或無法解碼），未調用該接口"), slot);
                    Throw(tag);
                }
                list.push_back(x);
                ip += x.ins.length;
                if (x.ins.mnemonic == ZYDIS_MNEMONIC_RET) break;
            }
            if (list.empty() || list.back().ins.mnemonic != ZYDIS_MNEMONIC_RET) {
                std::snprintf(tag, sizeof(tag), U8("官方語音下載接口結構發生變化（虛表槽 %d 的函式不是短小 getter），未調用該接口"), slot);
                Throw(tag);
            }

            bool ok = false;
            if (slot == 11) {
                std::vector<const Insn*> body;
                for (const Insn& x : list) {
                    if (x.ins.mnemonic != ZYDIS_MNEMONIC_NOP && x.ins.mnemonic != ZYDIS_MNEMONIC_RET) body.push_back(&x);
                }
                const int64_t loads[3] = { 208, 220, 228 };
                const int64_t stores[3] = { 0, 8, 12 };
                ok = body.size() == 6;
                for (int k = 0; ok && k < 3; ++k) {
                    const Insn& load = *body[k * 2];
                    const Insn& store = *body[k * 2 + 1];
                    ok = load.ins.mnemonic == ZYDIS_MNEMONIC_MOV && HasMem(load, ZYDIS_REGISTER_RCX, loads[k], 1, 1)
                        && store.ins.mnemonic == ZYDIS_MNEMONIC_MOV && HasMem(store, ZYDIS_REGISTER_RDX, stores[k], 0, 0)
                        && load.op[0].type == ZYDIS_OPERAND_TYPE_REGISTER && store.op[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                        && load.op[0].reg.value == store.op[1].reg.value;
                }
            }
            else {
                bool field = false, cmp4 = false, setcc = false;
                for (const Insn& x : list) {
                    if (HasMem(x, ZYDIS_REGISTER_RCX, 200, 0, 1)) field = true;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_CMP && IsImm(x.op[1], 4)) cmp4 = true;
                    if (x.ins.mnemonic == ZYDIS_MNEMONIC_SETNB || x.ins.mnemonic == ZYDIS_MNEMONIC_SETNL) setcc = true;
                }
                ok = field && cmp4 && setcc;
            }
            if (!ok) {
                // 附上實際的指令，方便遊戲更新後判斷形態改了什麼
                std::string detail;
                for (const Insn& x : list) {
                    char one[96];
                    std::snprintf(one, sizeof(one), " [%s", ZydisMnemonicGetString(x.ins.mnemonic));
                    detail += one;
                    for (int k = 0; k < x.ins.operand_count_visible && k < 3; ++k) {
                        const ZydisDecodedOperand& o = x.op[k];
                        if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                            std::snprintf(one, sizeof(one), " mem(%s%+lld)", ZydisRegisterGetString(o.mem.base), static_cast<long long>(o.mem.disp.value));
                            detail += one;
                        }
                        else if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                            detail += std::string(" ") + ZydisRegisterGetString(o.reg.value);
                        }
                        else if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            std::snprintf(one, sizeof(one), " imm(%lld)", static_cast<long long>(o.imm.value.s));
                            detail += one;
                        }
                    }
                    detail += "]";
                }
                std::snprintf(tag, sizeof(tag), U8("官方語音下載接口結構發生變化（虛表槽 %d 的 getter 指令不符），未調用該接口"), slot);
                Throw(std::string(tag) + detail);
            }
            return rva;
        }
    };

    // ------------------------------------------------------------------
    // 呼叫桩：在遊戲執行緒上啟動官方語音準備任務（與原工具 BuildStartThunk 相同）
    //   狀態寫入 block+384：1 = 已啟動或已就緒、-2 = 缺少清單中繼資料、-3 = 物件狀態已變。
    // ------------------------------------------------------------------
    std::vector<uint8_t> BuildStartThunk(uint64_t address, uint64_t factory, uint64_t query, uint32_t manifest,
        uint64_t preparer, uint64_t vtable, uint64_t rootSlot, uint64_t root, uint64_t lifetime) {
        using namespace asmjit;

        CodeHolder code;
        code.init(Environment::host(), address);
        x86::Assembler a(&code);

        Label failState = a.newLabel();   // -3
        Label failMeta = a.newLabel();    // -2
        Label finish = a.newLabel();
        Label started = a.newLabel();
        Label begin = a.newLabel();

        a.push(x86::rbx);
        a.push(x86::rsi);
        a.sub(x86::rsp, 40);
        a.mov(x86::rbx, address + kStatusOffset);
        a.mov(x86::rsi, preparer);
        a.mov(x86::rax, lifetime);
        a.lock().inc(x86::dword_ptr(x86::rax, 12));
        a.cmp(x86::dword_ptr(x86::rax, 8), 0);
        a.jne(failState);
        a.mov(x86::rax, rootSlot);
        a.mov(x86::rcx, root);
        a.cmp(x86::qword_ptr(x86::rax), x86::rcx);
        a.jne(failState);
        a.mov(x86::rax, vtable);
        a.cmp(x86::qword_ptr(x86::rsi), x86::rax);
        a.jne(failState);
        a.mov(x86::rax, lifetime);
        a.cmp(x86::qword_ptr(x86::rax), 0);
        a.jne(started);
        a.cmp(x86::dword_ptr(x86::rsi, 200), 5);
        a.je(started);
        a.cmp(x86::dword_ptr(x86::rsi, 200), 4);
        a.je(begin);
        a.cmp(x86::dword_ptr(x86::rsi, 200), 1);
        a.jne(failState);
        a.cmp(x86::dword_ptr(x86::rsi, 8), 1);
        a.jne(failState);
        a.bind(begin);
        a.cmp(x86::dword_ptr(x86::rsi, 188), 0);
        a.jne(started);
        a.mov(x86::ecx, manifest);
        a.xor_(x86::edx, x86::edx);
        a.xor_(x86::r8d, x86::r8d);
        a.lea(x86::r9, x86::ptr(x86::rbx, 24));
        a.lea(x86::rax, x86::ptr(x86::rbx, 20));
        a.mov(x86::qword_ptr(x86::rsp, 32), x86::rax);
        a.mov(x86::rax, query);
        a.call(x86::rax);
        a.test(x86::eax, x86::eax);
        a.je(failMeta);
        a.cmp(x86::dword_ptr(x86::rbx, 20), 1);
        a.jne(failMeta);
        a.mov(x86::rcx, address + kRequestOffset);
        a.mov(x86::rdx, x86::rcx);
        a.mov(x86::rax, factory);
        a.call(x86::rax);
        a.test(x86::rax, x86::rax);
        a.je(failState);
        a.mov(x86::qword_ptr(x86::rbx, 8), x86::rax);
        a.mov(x86::rdx, lifetime);
        a.mov(x86::qword_ptr(x86::rdx), x86::rax);
        a.bind(started);
        a.mov(x86::dword_ptr(x86::rbx), 1);
        a.jmp(finish);
        a.bind(failMeta);
        a.mov(x86::dword_ptr(x86::rbx), -2);
        a.jmp(finish);
        a.bind(failState);
        a.mov(x86::dword_ptr(x86::rbx), -3);
        a.bind(finish);
        a.mov(x86::rax, lifetime);
        a.lock().dec(x86::dword_ptr(x86::rax, 12));
        a.add(x86::rsp, 40);
        a.pop(x86::rsi);
        a.pop(x86::rbx);
        a.ret();

        code.flatten();
        code.resolveUnresolvedLinks();
        const CodeBuffer& buffer = code.textSection()->buffer();
        if (buffer.size() == 0 || buffer.size() > kMaxThunkSize) Throw(U8("中文語音：呼叫桩大小異常"));
        return std::vector<uint8_t>(buffer.data(), buffer.data() + buffer.size());
    }
}

namespace VoicePrepare {

    bool Resolve(const DiskImage& img, Locator& out, std::string& err) {
        try {
            Resolver resolver(img);
            resolver.Run(out);
            return true;
        }
        catch (const std::exception& e) {
            err = e.what();
        }
        catch (...) {
            err = U8("語音準備定位時發生例外");
        }
        return false;
    }

    Session::Session(const Locator& locator) : loc_(locator) {
        image_ = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    }

    void Session::Log(const std::string& line) {
        log_ += "[Voice] " + line + "\n";
    }

    std::string Session::TakeLog() {
        std::string out;
        out.swap(log_);
        return out;
    }

    Progress Session::Poll() {
        try {
            return PollImpl();
        }
        catch (const std::exception& e) {
            phase_ = Phase::Finished;
            Log(e.what());
            return { Step::Failed, e.what() };
        }
    }

    Progress Session::PollImpl() {
        const uint64_t image = reinterpret_cast<uint64_t>(image_);
        const uint64_t rootSlot = image + loc_.root;
        const uint64_t vtable = image + loc_.vtable;

        if (phase_ == Phase::Finished) return { Step::Done, std::string() };

        if (phase_ == Phase::Locate) {
            // 官方清單要進入角色後才會載入
            const uint64_t root = ReadU64(rootSlot);
            if (root == 0) return { Step::Waiting, U8("中文語音：進入角色後才能準備語音資源…") };

            const std::vector<uint8_t> header = ReadMem(root, 16);
            const int32_t count = ReadAs<int32_t>(header, 4);
            const uint64_t rowsPtr = ReadAs<uint64_t>(header, 8);
            if (count <= 0 || count > 4096 || rowsPtr == 0) Throw(U8("中文語音：官方清單根結構不符"));
            const std::vector<uint8_t> rows = ReadMem(rowsPtr, static_cast<size_t>(count) * 24);

            // 找名稱為 ChineseSimplified 的語言清單
            std::vector<uint32_t> manifests;
            for (size_t i = 0; i < rows.size(); i += 24) {
                if ((ReadAs<uint32_t>(rows, i + 12) & 8) == 0) continue;
                const uint64_t namePtr = ReadAs<uint64_t>(rows, i + 16);
                if (namePtr == 0) continue;

                std::string name;
                bool terminated = false;
                for (int j = 0; j < 64; ++j) {
                    const std::vector<uint8_t> ch = ReadMem(namePtr + static_cast<uint64_t>(j) * 2, 2);
                    const uint16_t c = ReadAs<uint16_t>(ch, 0);
                    if (c == 0) { terminated = true; break; }
                    name.push_back(c < 128 ? static_cast<char>(c) : '?');
                }
                if (!terminated) Throw(U8("中文語音：官方語言清單名稱未結尾"));
                if (_stricmp(name.c_str(), "ChineseSimplified") == 0) manifests.push_back(ReadAs<uint32_t>(rows, i));
            }
            if (manifests.size() != 1) {
                char buf[256];
                std::snprintf(buf, sizeof(buf), U8("中文語音：簡體中文官方清單候選 %zu 個，未執行準備"), manifests.size());
                Throw(buf);
            }
            manifest_ = manifests[0];

            // 找該清單的準備物件
            const std::vector<uint8_t> table = ReadMem(image + loc_.preparers, 16);
            const int32_t capacity = ReadAs<int32_t>(table, 0);
            const int32_t used = ReadAs<int32_t>(table, 4);
            const uint64_t tablePtr = ReadAs<uint64_t>(table, 8);
            if (capacity <= 0 || capacity > 8192 || used < 1 || used > capacity || tablePtr == 0) {
                Throw(U8("中文語音：官方清單準備物件表尚未就緒"));
            }
            const std::vector<uint8_t> entries = ReadMem(tablePtr, static_cast<size_t>(capacity) * 24);
            std::vector<uint64_t> preparers;
            for (size_t i = 0; i < entries.size(); i += 24) {
                if (ReadAs<uint32_t>(entries, i + 16) != 0 && ReadAs<uint32_t>(entries, i) == manifest_) {
                    preparers.push_back(ReadAs<uint64_t>(entries, i + 8));
                }
            }
            if (preparers.size() != 1 || preparers[0] == 0) Throw(U8("中文語音：找不到簡體中文的官方準備物件"));
            preparer_ = preparers[0];
            if (ReadU64(preparer_) != vtable) Throw(U8("中文語音：準備物件虛表不符"));

            // 呼叫的函式必須與硬碟檔案一致，確保沒有被其他程式 hook
            for (int i = 0; i < Locator::kEntryCount; ++i) {
                const std::vector<uint8_t> live = ReadMem(image + loc_.entryRva[i], 32);
                if (std::memcmp(live.data(), loc_.entryBytes[i], 32) != 0) {
                    Throw(U8("中文語音：官方語音接口已被其他程式改變，未呼叫準備流程"));
                }
            }

            // 清單在這段期間沒有切換
            if (ReadU64(rootSlot) != root || ReadMem(image + loc_.preparers, 16) != table) {
                Throw(U8("中文語音：官方清單正在切換，請稍後重試"));
            }
            rootObject_ = root;

            // 先接上退出清理，之後即使遊戲在下載途中退出也能先取消並等待任務結束
            if (!context_) {
                std::string installLog;
                context_ = EnsureExitCleanup(loc_, installLog);
                for (size_t start = 0; start < installLog.size();) {
                    size_t end = installLog.find('\n', start);
                    if (end == std::string::npos) end = installLog.size();
                    if (end > start) log_ += installLog.substr(start, end - start) + "\n";
                    start = end + 1;
                }
            }

            // 呼叫桩與狀態區
            block_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, kBlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!block_) Throw(U8("中文語音：無法配置呼叫桩記憶體"));
            const uint64_t address = reinterpret_cast<uint64_t>(block_);

            std::vector<uint8_t> blob(kBlockSize, 0);
            const std::vector<uint8_t> thunk = BuildStartThunk(address, image + loc_.factory, image + loc_.query, manifest_,
                preparer_, vtable, rootSlot, rootObject_, reinterpret_cast<uint64_t>(context_));
            std::memcpy(blob.data(), thunk.data(), thunk.size());

            const uint16_t one16 = 1;
            const int32_t one = 1, sixtyFour = 64;
            const uint64_t manifestPtr = address + kManifestOffset;
            std::memcpy(&blob[kRequestOffset], &one16, 2);
            std::memcpy(&blob[kRequestOffset + 8], &manifestPtr, 8);
            std::memcpy(&blob[kRequestOffset + 16], &one, 4);
            std::memcpy(&blob[kRequestOffset + 20], &one, 4);
            std::memcpy(&blob[kRequestOffset + 24], &sixtyFour, 4);
            std::memcpy(&blob[kManifestOffset], &manifest_, 4);

            std::memcpy(block_, blob.data(), blob.size());
            FlushInstructionCache(GetCurrentProcess(), block_, blob.size());

            Log("preparer=" + std::to_string(preparer_) + " manifest=" + std::to_string(manifest_));
            phase_ = Phase::Queue;
        }

        if (phase_ == Phase::Queue) {
            if (!GW2LangPatch::QueueNativeCall(reinterpret_cast<uintptr_t>(block_), 0, 0)) {
                return { Step::Waiting, U8("中文語音：等待遊戲執行緒…") };
            }
            startedTick_ = GetTickCount64();
            phase_ = Phase::Submitted;
        }

        // Phase::Submitted
        if (*reinterpret_cast<volatile int32_t*>(context_ + 8) != 0 || ReadU64(rootSlot) == 0) {
            phase_ = Phase::Finished;
            return { Step::Failed, U8("中文語音：客戶端正在關閉資源，已結束進度監控") };
        }

        const int32_t status = ReadAs<int32_t>(ReadMem(reinterpret_cast<uint64_t>(block_) + kStatusOffset, 4), 0);
        if (status < 0) {
            phase_ = Phase::Finished;
            return { Step::Failed, status == -2
                ? U8("中文語音：客戶端缺少目前的中文清單中繼資料，請先用官方登入器或原工具下載一次中文語音")
                : U8("中文語音：語音準備物件狀態已變化，請進入角色後重試") };
        }
        if (status == 0) {
            if (GetTickCount64() - startedTick_ > kWaitGameLimitMs) {
                phase_ = Phase::Finished;
                return { Step::Failed, U8("中文語音：等待遊戲執行語音請求逾時") };
            }
            return { Step::Waiting, U8("中文語音：等待遊戲啟動官方任務…") };
        }

        if (ReadU64(rootSlot) != rootObject_ || ReadU64(preparer_) != vtable) {
            phase_ = Phase::Finished;
            return { Step::Failed, U8("中文語音：客戶端重新載入了官方清單，請重新勾選") };
        }

        const std::vector<uint8_t> data = ReadMem(preparer_ + 200, 40);
        const int32_t state = ReadAs<int32_t>(data, 0);
        const uint32_t done = ReadAs<uint32_t>(data, 20);
        const uint32_t total = ReadAs<uint32_t>(data, 28);
        if (state < 1 || state > 7 || total > 1000000 || done > total) Throw(U8("中文語音：語音進度結構不符"));

        if (state != lastState_) {
            lastState_ = state;
            Log("preparer state=" + std::to_string(state) + " " + std::to_string(done) + "/" + std::to_string(total));
        }

        if (state == 5) {
            phase_ = Phase::Finished;
            return { Step::Done, U8("中文語音：資源已就緒") };
        }
        if (state == 6 || state == 7) {
            phase_ = Phase::Finished;
            return { Step::Failed, U8("中文語音：下載失敗或已取消，請檢查網路後重試") };
        }
        if (state <= 3) return { Step::Running, U8("中文語音：正在檢查已有資源…") };

        char buf[256];
        if (total == 0) {
            std::snprintf(buf, sizeof(buf), "%s", U8("中文語音：正在補齊資源…"));
        }
        else {
            std::snprintf(buf, sizeof(buf), U8("中文語音補齊：%u / %u 個缺失檔案（%u%%）"), done, total,
                static_cast<uint32_t>(static_cast<uint64_t>(done) * 100 / total));
        }
        return { Step::Running, buf };
    }
}
