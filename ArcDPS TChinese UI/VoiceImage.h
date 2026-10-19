#pragma once

// 讀取硬碟上的 Gw2-64.exe 並提供反組譯輔助，供中文語音的定位分析使用。
// 這裡的函式只讀檔案，不碰執行中的遊戲，可在背景執行緒呼叫。

#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <Zydis/Zydis.h>

#ifndef U8
#define U8(str) reinterpret_cast<const char*>(u8##str)
#endif

namespace VoiceImage {

    struct Section {
        std::string name;
        uint32_t va = 0;
        uint32_t vsize = 0;
        uint32_t rawSize = 0;
    };

    // 以 RVA 對應配置的映像（與執行中的位址一致）
    struct DiskImage {
        std::vector<uint8_t> mem;
        std::vector<Section> sections;
        uint64_t imageBase = 0;                                // PE 標頭中的偏好載入位址
        uint32_t execStart = 0;
        uint32_t execSize = 0;
        std::vector<std::pair<uint32_t, uint32_t>> dataRanges; // 可寫、非可執行的區段
        uint32_t excDirRva = 0;
        uint32_t excDirSize = 0;

        bool InRange(uint64_t off, uint64_t len) const {
            return off <= mem.size() && len <= mem.size() - off;
        }
        uint32_t U32(uint64_t off) const {
            uint32_t v = 0;
            if (InRange(off, 4)) std::memcpy(&v, &mem[static_cast<size_t>(off)], 4);
            return v;
        }
        uint64_t U64(uint64_t off) const {
            uint64_t v = 0;
            if (InRange(off, 8)) std::memcpy(&v, &mem[static_cast<size_t>(off)], 8);
            return v;
        }
        int32_t S32(uint64_t off) const { return static_cast<int32_t>(U32(off)); }
    };

    // 讀取目前行程（遊戲）的執行檔；或指定路徑的 PE 檔
    bool LoadDiskImage(DiskImage& img, std::string& err);
    bool LoadDiskImageFromFile(const wchar_t* path, DiskImage& img, std::string& err);

    // 在整個映像中搜尋位元組樣式 / 含結尾 NUL 的 ASCII 字串 / 含結尾 NUL 的 UTF-16 字串，回傳所有起點 RVA
    std::set<uint32_t> FindBytes(const DiskImage& img, const std::vector<uint8_t>& pattern);
    std::set<uint32_t> FindAsciiZ(const DiskImage& img, const char* text);
    std::set<uint32_t> FindWideZ(const DiskImage& img, const char* asciiText);

    struct Insn {
        ZydisDecodedInstruction ins{};
        ZydisDecodedOperand op[ZYDIS_MAX_OPERAND_COUNT]{};
        uint32_t rva = 0;
    };

    bool DecodeOne(const DiskImage& img, uint32_t rva, uint64_t limitRva, Insn& out);

    // 由 rva 起連續解碼 length 位元組；stopAtRet 時遇到 ret 即停。遇到無法解碼的指令會停止並回報。
    std::vector<Insn> DecodeSeq(const DiskImage& img, uint32_t rva, uint32_t length, bool stopAtRet, bool* sawInvalid = nullptr);

    bool IsReg(const ZydisDecodedOperand& o, ZydisRegister r);
    bool IsImm(const ZydisDecodedOperand& o, int64_t v);

    // [rip+disp] 形式的記憶體運算元 → 目標 RVA
    bool RipTarget(const Insn& x, const ZydisDecodedOperand& o, uint32_t& rva);

    // 相對 call / jmp 的目標 RVA
    bool BranchTarget(const Insn& x, uint32_t& rva);

    void PushDistinct(std::vector<uint32_t>& v, uint32_t value);
}
