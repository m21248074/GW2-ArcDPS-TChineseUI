#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "VoiceLifetime.h"

#include <Windows.h>
#include <asmjit/asmjit.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

using namespace VoiceImage;

namespace {
    // 掛鉤區塊配置（偏移量與原工具相同）
    constexpr size_t kBlockSize = 8192;
    constexpr uint64_t kMarkerOffset = 768;
    constexpr uint64_t kContextOffset = 1024;
    constexpr uint64_t kEarlyOffset = 1280;        // 退出前下載佇列檢查的包裝
    constexpr uint64_t kEarlyCleanupOffset = 1536; // 同上包裝所用的清理
    constexpr uint64_t kReturnOffset = 2304;       // 單純的 ret，作為清理的接續位置
    constexpr uint64_t kQueuedOffset = 2560;       // 回收本任務排隊中的下載請求
    constexpr uint64_t kScratchOffset = 4096;
    constexpr char kMarker[8] = { 'G', 'W', 'V', 'O', 'I', 'C', 'L', '5' };

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

    std::vector<uint8_t> ReadBytes(uint64_t address, size_t size) {
        if (address == 0 || !IsReadable(reinterpret_cast<const void*>(address), size)) {
            Throw(U8("無法讀取遊戲的語音退出狀態"));
        }
        const uint8_t* p = reinterpret_cast<const uint8_t*>(address);
        return std::vector<uint8_t>(p, p + size);
    }

    bool Equal(uint64_t address, const std::vector<uint8_t>& expected) {
        if (!IsReadable(reinterpret_cast<const void*>(address), expected.size())) return false;
        return std::memcmp(reinterpret_cast<const void*>(address), expected.data(), expected.size()) == 0;
    }

    bool WriteGameMemory(uint64_t address, const void* source, size_t size) {
        void* target = reinterpret_cast<void*>(address);
        DWORD oldProtect = 0;
        if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
        std::memcpy(target, source, size);
        FlushInstructionCache(GetCurrentProcess(), target, size);
        DWORD restored = 0;
        return VirtualProtect(target, size, oldProtect, &restored) != 0;
    }

    int32_t ReadI32(const uint8_t* p) {
        int32_t v = 0;
        std::memcpy(&v, p, 4);
        return v;
    }

    std::vector<uint8_t> Finish(asmjit::CodeHolder& code, size_t limit, const char* tooLong) {
        code.flatten();
        code.resolveUnresolvedLinks();
        const asmjit::CodeBuffer& buffer = code.textSection()->buffer();
        if (buffer.size() == 0 || buffer.size() > limit) Throw(tooLong);
        return std::vector<uint8_t>(buffer.data(), buffer.data() + buffer.size());
    }

    // ------------------------------------------------------------------
    // 資源關閉流程的接管：取消並等待下載任務結束、銷毀它，之後才繼續原本的關閉流程
    // ------------------------------------------------------------------
    std::vector<uint8_t> BuildShutdownThunk(uint64_t address, uint64_t context, uint64_t continuation, uint64_t vtable,
        uint64_t cancel, uint64_t state, uint64_t destroy, uint64_t sleep, uint64_t queuedCleanup) {
        using namespace asmjit;

        CodeHolder code;
        code.init(Environment::host(), address);
        x86::Assembler a(&code);

        Label waitInflight = a.newLabel();    // 等進行中的呼叫歸零
        Label takeTask = a.newLabel();
        Label noTask = a.newLabel();
        Label waitState = a.newLabel();
        Label destroyTask = a.newLabel();
        Label mismatch = a.newLabel();
        Label finish = a.newLabel();

        a.push(x86::rbx);
        a.push(x86::rsi);
        a.sub(x86::rsp, 40);
        a.mov(x86::rbx, context);
        a.mov(x86::eax, 1);
        a.xchg(x86::dword_ptr(x86::rbx, 8), x86::eax);
        a.bind(waitInflight);
        a.cmp(x86::dword_ptr(x86::rbx, 12), 0);
        a.je(takeTask);
        a.mov(x86::ecx, 1);
        a.mov(x86::rax, sleep);
        a.call(x86::rax);
        a.jmp(waitInflight);
        a.bind(takeTask);
        a.xor_(x86::esi, x86::esi);
        a.xchg(x86::qword_ptr(x86::rbx), x86::rsi);
        a.test(x86::rsi, x86::rsi);
        a.je(noTask);
        a.mov(x86::rax, vtable);
        a.cmp(x86::qword_ptr(x86::rsi), x86::rax);
        a.jne(mismatch);
        if (queuedCleanup != 0) {
            a.mov(x86::rcx, x86::rsi);
            a.xor_(x86::edx, x86::edx);
            a.mov(x86::rax, queuedCleanup);
            a.call(x86::rax);
        }
        a.mov(x86::rcx, x86::rsi);
        a.mov(x86::rax, cancel);
        a.call(x86::rax);
        a.bind(waitState);
        a.mov(x86::rcx, x86::rsi);
        a.mov(x86::rax, state);
        a.call(x86::rax);
        a.cmp(x86::eax, 3);
        a.jae(destroyTask);
        a.mov(x86::ecx, 1);
        a.mov(x86::rax, sleep);
        a.call(x86::rax);
        a.jmp(waitState);
        a.bind(destroyTask);
        a.mov(x86::rcx, x86::rsi);
        a.mov(x86::edx, 1);
        a.mov(x86::rax, destroy);
        a.call(x86::rax);
        if (queuedCleanup != 0) {
            a.xor_(x86::ecx, x86::ecx);
            a.mov(x86::edx, 1);
            a.mov(x86::rax, queuedCleanup);
            a.call(x86::rax);
        }
        a.bind(noTask);
        a.mov(x86::dword_ptr(x86::rbx, 8), 2);
        a.jmp(finish);
        a.bind(mismatch);
        a.mov(x86::dword_ptr(x86::rbx, 8), 3);
        a.bind(finish);
        a.add(x86::rsp, 40);
        a.pop(x86::rsi);
        a.pop(x86::rbx);
        a.mov(x86::rax, continuation);
        a.jmp(x86::rax);

        return Finish(code, 768, U8("語音退出清理代碼過長"));
    }

    // ------------------------------------------------------------------
    // 退出前的下載佇列檢查：先做清理，再反覆呼叫原本的統計函式直到佇列清空
    // ------------------------------------------------------------------
    std::vector<uint8_t> BuildExitStatsThunk(uint64_t address, uint64_t cleanup, uint64_t stats, uint64_t context,
        uint64_t sleep, uint64_t pump) {
        using namespace asmjit;

        CodeHolder code;
        code.init(Environment::host(), address);
        x86::Assembler a(&code);

        Label setLimit = a.newLabel();
        Label afterCleanup = a.newLabel();
        Label loop = a.newLabel();
        Label notFirst = a.newLabel();
        Label done = a.newLabel();

        a.push(x86::rbx);
        a.push(x86::rsi);
        a.push(x86::rdi);
        a.push(x86::r12);
        a.push(x86::r13);
        a.push(x86::r14);
        a.sub(x86::rsp, 40);
        a.mov(x86::rbx, x86::rcx);
        a.mov(x86::rsi, x86::rdx);
        a.mov(x86::rdi, x86::r8);
        a.mov(x86::r12, x86::r9);
        a.mov(x86::r13, context);
        a.mov(x86::r14d, 128);
        a.cmp(x86::qword_ptr(x86::r13), 0);
        a.jne(setLimit);
        a.mov(x86::r14d, 1);
        a.bind(setLimit);
        a.mov(x86::rax, cleanup);
        a.call(x86::rax);
        a.cmp(x86::dword_ptr(x86::r13, 8), 2);
        a.je(afterCleanup);
        a.mov(x86::r14d, 1);
        a.bind(afterCleanup);
        a.mov(x86::dword_ptr(x86::rsp, 32), 0);
        a.bind(loop);
        a.cmp(x86::dword_ptr(x86::rsp, 32), x86::r14d);
        a.jae(done);
        if (pump != 0) {
            a.xor_(x86::ecx, x86::ecx);
            a.mov(x86::rax, pump);
            a.call(x86::rax);
        }
        a.mov(x86::rcx, x86::rbx);
        a.mov(x86::rdx, x86::rsi);
        a.mov(x86::r8, x86::rdi);
        a.mov(x86::r9, x86::r12);
        a.mov(x86::rax, stats);
        a.call(x86::rax);
        a.inc(x86::dword_ptr(x86::r13, 16));
        a.mov(x86::rdx, x86::qword_ptr(x86::rsi));
        a.cmp(x86::dword_ptr(x86::r13, 16), 1);
        a.jne(notFirst);
        a.mov(x86::qword_ptr(x86::r13, 24), x86::rdx);
        a.bind(notFirst);
        a.mov(x86::qword_ptr(x86::r13, 32), x86::rdx);
        a.cmp(x86::qword_ptr(x86::rsi), 0);
        a.je(done);
        a.mov(x86::ecx, 1);
        a.mov(x86::rax, sleep);
        a.call(x86::rax);
        a.jmp(loop);
        a.bind(done);
        a.add(x86::rsp, 40);
        a.pop(x86::r14);
        a.pop(x86::r13);
        a.pop(x86::r12);
        a.pop(x86::rdi);
        a.pop(x86::rsi);
        a.pop(x86::rbx);
        a.ret();

        return Finish(code, 256, U8("語音退出檢查橋代碼過長"));
    }

    // ------------------------------------------------------------------
    // 回收本任務排隊中的下載請求（mode 0 = 移出並暫存，mode 1 = 還原／回收）
    // ------------------------------------------------------------------
    std::vector<uint8_t> BuildQueuedCleanupThunk(uint64_t address, uint64_t scratch, uint64_t queues, uint64_t move,
        uint64_t clear, uint64_t queueLock, uint64_t enter, uint64_t leaveIat) {
        using namespace asmjit;

        CodeHolder code;
        code.init(Environment::host(), address);
        x86::Assembler a(&code);

        Label restore = a.newLabel();
        Label skipInit = a.newLabel();
        Label outer = a.newLabel();
        Label inner = a.newLabel();
        Label unlock = a.newLabel();
        Label finish = a.newLabel();

        a.push(x86::rbx);
        a.push(x86::rsi);
        a.push(x86::rdi);
        a.push(x86::r12);
        a.push(x86::r13);
        a.sub(x86::rsp, 48);
        a.mov(x86::rbx, x86::rcx);
        a.mov(x86::esi, x86::edx);
        a.mov(x86::rdi, scratch);
        a.test(x86::esi, x86::esi);
        a.jne(skipInit);
        a.xor_(x86::eax, x86::eax);
        for (int i = 0; i < 328; i += 8) {
            a.mov(x86::qword_ptr(x86::rdi, i), x86::rax);
        }
        a.lea(x86::rax, x86::ptr(x86::rdi, 64));
        a.mov(x86::qword_ptr(x86::rdi, 64), x86::rax);
        a.inc(x86::rax);
        a.mov(x86::qword_ptr(x86::rdi, 72), x86::rax);
        a.bind(skipInit);
        a.lea(x86::rcx, x86::ptr(x86::rsp, 32));
        a.mov(x86::rdx, queueLock);
        a.mov(x86::rax, enter);
        a.call(x86::rax);
        a.test(x86::esi, x86::esi);
        a.jne(restore);
        a.xor_(x86::esi, x86::esi);
        a.bind(outer);
        a.cmp(x86::esi, x86::dword_ptr(x86::rbx, 92));
        a.jae(unlock);
        a.mov(x86::rax, x86::qword_ptr(x86::rbx, 80));
        a.mov(x86::r12, x86::qword_ptr(x86::rax, x86::rsi, 3));
        a.xor_(x86::r13d, x86::r13d);
        a.bind(inner);
        a.imul(x86::rcx, x86::r13, 328);
        a.mov(x86::rax, queues);
        a.add(x86::rcx, x86::rax);
        a.mov(x86::rdx, x86::r12);
        a.lea(x86::r8, x86::ptr(x86::rdi, 56));
        a.mov(x86::rax, move);
        a.call(x86::rax);
        a.inc(x86::r13d);
        a.cmp(x86::r13d, 6);
        a.jb(inner);
        a.inc(x86::esi);
        a.jmp(outer);
        a.bind(restore);
        a.mov(x86::rcx, x86::rdi);
        a.mov(x86::rax, clear);
        a.call(x86::rax);
        a.bind(unlock);
        a.mov(x86::rcx, x86::qword_ptr(x86::rsp, 32));
        a.test(x86::rcx, x86::rcx);
        a.je(finish);
        a.mov(x86::rax, leaveIat);
        a.call(x86::qword_ptr(x86::rax));
        a.bind(finish);
        a.add(x86::rsp, 48);
        a.pop(x86::r13);
        a.pop(x86::r12);
        a.pop(x86::rdi);
        a.pop(x86::rsi);
        a.pop(x86::rbx);
        a.ret();

        return Finish(code, 1536, U8("語音排隊請求回收橋代碼過長"));
    }

    // 把 patchSite 的 5 位元組換成「opcode + rel32 → destination」
    void InstallJump(uint64_t patchSite, uint64_t destination, uint8_t opcode) {
        const int64_t delta = static_cast<int64_t>(destination) - static_cast<int64_t>(patchSite) - 5;
        if (delta < INT32_MIN || delta > INT32_MAX) Throw(U8("資源退出入口距離過遠，無法接入"));

        uint8_t bytes[5] = { opcode, 0, 0, 0, 0 };
        const int32_t rel = static_cast<int32_t>(delta);
        std::memcpy(bytes + 1, &rel, 4);
        if (!WriteGameMemory(patchSite, bytes, 5) || !Equal(patchSite, std::vector<uint8_t>(bytes, bytes + 5))) {
            Throw(U8("資源退出入口安裝失敗，請重啟遊戲"));
        }
    }
}

namespace VoicePrepare {

    uint8_t* EnsureExitCleanup(const Locator& loc, std::string& log) {
        const uint64_t image = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        const bool queued = loc.queueChainResolved;

        const uint64_t site = image + loc.shutdownSite;
        const uint64_t target = image + loc.shutdownTarget;
        const uint64_t statsSite = image + loc.exitStatsSite;
        const uint64_t stats = image + loc.exitStatsTarget;

        // 硬碟上的原始形態必須是 jmp target / call stats
        auto relTarget = [](uint64_t from, const uint8_t* bytes) {
            return static_cast<uint64_t>(static_cast<int64_t>(from) + 5 + ReadI32(bytes + 1));
        };
        if (loc.shutdownSiteBytes[0] != 0xE9 || relTarget(site, loc.shutdownSiteBytes) != target
            || loc.exitStatsSiteBytes[0] != 0xE8 || relTarget(statsSite, loc.exitStatsSiteBytes) != stats) {
            Throw(U8("語音退出呼叫關係不符，未啟動下載。"));
        }

        const std::vector<uint8_t> liveSite = ReadBytes(site, 5);
        const std::vector<uint8_t> liveStats = ReadBytes(statsSite, 5);
        if (liveSite[0] != 0xE9) Throw(U8("資源退出入口已被修改，未啟動下載。"));
        const uint64_t current = relTarget(site, liveSite.data());

        const uint64_t vtable = image + loc.taskVtable;
        const uint64_t cancel = image + loc.taskCancel;
        const uint64_t state = image + loc.taskState;
        const uint64_t destroy = image + loc.taskDestroy;
        const uint64_t sleep = image + loc.workerSleep;
        auto build = [&](uint64_t at) {
            return BuildShutdownThunk(at, at + kContextOffset, target, vtable, cancel, state, destroy, sleep, queued ? at + kQueuedOffset : 0);
        };
        auto buildEarly = [&](uint64_t at) {
            return BuildExitStatsThunk(at + kEarlyOffset, at + kEarlyCleanupOffset, stats, at + kContextOffset, sleep, queued ? image + loc.queuePump : 0);
        };
        auto buildEarlyCleanup = [&](uint64_t at) {
            return BuildShutdownThunk(at + kEarlyCleanupOffset, at + kContextOffset, at + kReturnOffset, vtable, cancel, state, destroy, sleep, queued ? at + kQueuedOffset : 0);
        };
        auto buildQueued = [&](uint64_t at) {
            return BuildQueuedCleanupThunk(at + kQueuedOffset, at + kScratchOffset, image + loc.queueRoot, image + loc.queueMoveBatch,
                image + loc.queueClear, image + loc.queueLock, image + loc.queueLockEnter, image + loc.queueLockLeaveIat);
        };

        // 已經接上了：如果完全是我們安裝的那一份，就沿用
        if (std::memcmp(liveSite.data(), loc.shutdownSiteBytes, 5) != 0) {
            bool recognized = false;
            try {
                recognized = Equal(current + kMarkerOffset, std::vector<uint8_t>(kMarker, kMarker + sizeof(kMarker)))
                    && Equal(current, build(current))
                    && liveStats[0] == 0xE8 && relTarget(statsSite, liveStats.data()) == current + kEarlyOffset
                    && Equal(current + kEarlyOffset, buildEarly(current))
                    && Equal(current + kEarlyCleanupOffset, buildEarlyCleanup(current))
                    && ReadBytes(current + kReturnOffset, 1)[0] == 0xC3
                    && (!queued || Equal(current + kQueuedOffset, buildQueued(current)))
                    && ReadI32(ReadBytes(current + kContextOffset + 8, 4).data()) == 0;
            }
            catch (const std::exception&) {
                recognized = false;
            }
            if (!recognized) Throw(U8("資源退出入口存在其他補丁或客戶端正在退出，請重啟遊戲後重試。"));
            return reinterpret_cast<uint8_t*>(current + kContextOffset);
        }
        if (std::memcmp(liveStats.data(), loc.exitStatsSiteBytes, 5) != 0) {
            Throw(U8("退出佇列檢查入口已被修改，請重啟遊戲後重試。"));
        }

        // 在入口附近配置區塊（rel32 要能到達）
        uint8_t* block = nullptr;
        const uint64_t anchor = site & ~0xFFFFull;
        for (uint64_t distance = 65536; distance < 1879048192ull && !block; distance += 65536) {
            const uint64_t candidates[2] = { anchor - distance, anchor + distance };
            for (uint64_t candidate : candidates) {
                if (candidate < 65536) continue;
                block = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(candidate), kBlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
                if (block) break;
            }
        }
        if (!block) Throw(U8("無法準備語音任務退出清理。"));

        bool published = false;
        try {
            const uint64_t base = reinterpret_cast<uint64_t>(block);
            std::vector<uint8_t> blob(kBlockSize, 0);
            auto put = [&](uint64_t offset, const std::vector<uint8_t>& bytes) {
                std::memcpy(blob.data() + offset, bytes.data(), bytes.size());
            };
            put(0, build(base));
            put(kMarkerOffset, std::vector<uint8_t>(kMarker, kMarker + sizeof(kMarker)));
            put(kEarlyOffset, buildEarly(base));
            put(kEarlyCleanupOffset, buildEarlyCleanup(base));
            blob[kReturnOffset] = 0xC3;
            if (queued) put(kQueuedOffset, buildQueued(base));

            std::memcpy(block, blob.data(), blob.size());
            FlushInstructionCache(GetCurrentProcess(), block, blob.size());

            // 寫入期間入口不能被別人改過
            if (!Equal(site, std::vector<uint8_t>(loc.shutdownSiteBytes, loc.shutdownSiteBytes + 5))
                || !Equal(statsSite, std::vector<uint8_t>(loc.exitStatsSiteBytes, loc.exitStatsSiteBytes + 5))) {
                Throw(U8("資源退出入口發生變化，未啟動下載。"));
            }

            published = true; // 一旦接上，區塊就必須永遠保留
            InstallJump(site, base, 0xE9);
            try {
                InstallJump(statsSite, base + kEarlyOffset, 0xE8);
            }
            catch (...) {
                WriteGameMemory(site, loc.shutdownSiteBytes, 5); // 兩處要一起生效，否則還原第一處
                throw;
            }

            log += queued
                ? "[Voice] exit cleanup installed (v4: queued requests recycled)\n"
                : "[Voice] exit cleanup installed (v3: task cancel + wait)\n";
            return block + kContextOffset;
        }
        catch (...) {
            if (!published) VirtualFree(block, 0, MEM_RELEASE);
            throw;
        }
    }
}
