#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "VoiceImage.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <iterator>

namespace VoiceImage {

    bool LoadDiskImage(DiskImage& img, std::string& err) {
        wchar_t path[MAX_PATH * 2]{};
        DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        if (n == 0 || n >= std::size(path)) {
            err = U8("無法取得遊戲執行檔路徑");
            return false;
        }
        return LoadDiskImageFromFile(path, img, err);
    }

    bool LoadDiskImageFromFile(const wchar_t* path, DiskImage& img, std::string& err) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in) {
            err = U8("無法讀取遊戲執行檔");
            return false;
        }
        const std::streamsize size = in.tellg();
        if (size < 1024) {
            err = U8("遊戲執行檔大小異常");
            return false;
        }
        std::vector<uint8_t> file(static_cast<size_t>(size));
        in.seekg(0);
        if (!in.read(reinterpret_cast<char*>(file.data()), size)) {
            err = U8("讀取遊戲執行檔失敗");
            return false;
        }

        auto u16 = [&](size_t o) -> uint32_t {
            uint16_t v = 0;
            if (o <= file.size() && file.size() - o >= 2) std::memcpy(&v, &file[o], 2);
            return v;
        };
        auto u32 = [&](size_t o) -> uint32_t {
            uint32_t v = 0;
            if (o <= file.size() && file.size() - o >= 4) std::memcpy(&v, &file[o], 4);
            return v;
        };
        auto u64 = [&](size_t o) -> uint64_t {
            uint64_t v = 0;
            if (o <= file.size() && file.size() - o >= 8) std::memcpy(&v, &file[o], 8);
            return v;
        };

        const uint32_t nt = u32(60);
        if (nt > file.size() - 264 || u32(nt) != 0x00004550 || u16(nt + 4) != 0x8664 || u16(nt + 24) != 0x20B) {
            err = U8("不是支援的 64 位元 PE 檔");
            return false;
        }
        const uint32_t imageSize = u32(nt + 80);
        if (imageSize < 4096 || imageSize > 268435456) {
            err = U8("映像大小異常");
            return false;
        }
        img.imageBase = u64(nt + 48);

        img.mem.assign(imageSize, 0);
        const uint32_t sections = u16(nt + 6);
        const uint32_t table = nt + 24 + u16(nt + 20);
        for (uint32_t i = 0; i < sections; ++i) {
            const size_t s = static_cast<size_t>(table) + static_cast<size_t>(i) * 40;
            if (s + 40 > file.size()) {
                err = U8("區段表異常");
                return false;
            }
            const uint32_t vsize = u32(s + 8);
            const uint32_t va = u32(s + 12);
            const uint32_t rawSize = u32(s + 16);
            const uint32_t rawPtr = u32(s + 20);
            const uint32_t flags = u32(s + 36);
            const uint64_t span = std::max(rawSize, vsize);
            if (va > imageSize || span > imageSize - va || rawPtr > file.size() || rawSize > file.size() - rawPtr) {
                err = U8("區段範圍異常");
                return false;
            }
            std::memcpy(&img.mem[va], &file[rawPtr], rawSize);

            Section sec;
            sec.name.assign(reinterpret_cast<const char*>(&file[s]), strnlen(reinterpret_cast<const char*>(&file[s]), 8));
            sec.va = va;
            sec.vsize = vsize;
            sec.rawSize = rawSize;
            img.sections.push_back(std::move(sec));

            if (flags & 0x20000000u) {
                if (img.execStart != 0) {
                    err = U8("出現多個可執行區段，未適配");
                    return false;
                }
                img.execStart = va;
                img.execSize = std::min(vsize, rawSize);
            }
            if ((flags & 0x80000000u) && !(flags & 0x20000000u)) {
                img.dataRanges.emplace_back(va, static_cast<uint32_t>(va + span));
            }
        }

        img.excDirRva = u32(nt + 24 + 112 + 24);
        img.excDirSize = u32(nt + 24 + 112 + 28);
        if (img.execStart == 0 || img.execSize < 4096) {
            err = U8("找不到可執行區段");
            return false;
        }
        return true;
    }

    std::set<uint32_t> FindBytes(const DiskImage& img, const std::vector<uint8_t>& pattern) {
        std::set<uint32_t> found;
        if (pattern.empty()) return found;
        std::boyer_moore_horspool_searcher searcher(pattern.begin(), pattern.end());
        auto it = img.mem.begin();
        while ((it = std::search(it, img.mem.end(), searcher)) != img.mem.end()) {
            found.insert(static_cast<uint32_t>(it - img.mem.begin()));
            ++it;
        }
        return found;
    }

    std::set<uint32_t> FindAsciiZ(const DiskImage& img, const char* text) {
        return FindBytes(img, std::vector<uint8_t>(text, text + std::strlen(text) + 1)); // 含結尾 NUL
    }

    std::set<uint32_t> FindWideZ(const DiskImage& img, const char* asciiText) {
        std::vector<uint8_t> pattern;
        for (const char* p = asciiText; *p; ++p) {
            pattern.push_back(static_cast<uint8_t>(*p));
            pattern.push_back(0);
        }
        pattern.push_back(0);
        pattern.push_back(0);
        return FindBytes(img, pattern);
    }

    namespace {
        const ZydisDecoder& Decoder() {
            static const ZydisDecoder decoder = [] {
                ZydisDecoder d;
                ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
                return d;
            }();
            return decoder;
        }
    }

    bool DecodeOne(const DiskImage& img, uint32_t rva, uint64_t limitRva, Insn& out) {
        if (rva >= limitRva || !img.InRange(rva, 1)) return false;
        size_t len = static_cast<size_t>(std::min<uint64_t>(limitRva - rva, img.mem.size() - rva));
        len = std::min<size_t>(len, 15);
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder(), &img.mem[rva], len, &out.ins, out.op))) return false;
        out.rva = rva;
        return true;
    }

    std::vector<Insn> DecodeSeq(const DiskImage& img, uint32_t rva, uint32_t length, bool stopAtRet, bool* sawInvalid) {
        std::vector<Insn> list;
        uint32_t ip = rva;
        const uint64_t end = static_cast<uint64_t>(rva) + length;
        while (ip < end) {
            Insn x;
            if (!DecodeOne(img, ip, end, x)) {
                if (sawInvalid) *sawInvalid = true;
                break;
            }
            list.push_back(x);
            ip += x.ins.length;
            if (stopAtRet && x.ins.mnemonic == ZYDIS_MNEMONIC_RET) break;
        }
        return list;
    }

    bool IsReg(const ZydisDecodedOperand& o, ZydisRegister r) {
        return o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.reg.value == r;
    }

    bool IsImm(const ZydisDecodedOperand& o, int64_t v) {
        return o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.value.s == v;
    }

    bool RipTarget(const Insn& x, const ZydisDecodedOperand& o, uint32_t& rva) {
        if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.base != ZYDIS_REGISTER_RIP) return false;
        ZyanU64 addr = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&x.ins, &o, x.rva, &addr)) || addr > 0xFFFFFFFFull) return false;
        rva = static_cast<uint32_t>(addr);
        return true;
    }

    bool BranchTarget(const Insn& x, uint32_t& rva) {
        if (x.ins.meta.branch_type == ZYDIS_BRANCH_TYPE_NONE) return false;
        const ZydisDecodedOperand& o = x.op[0];
        if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative) return false;
        ZyanU64 addr = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&x.ins, &o, x.rva, &addr)) || addr > 0xFFFFFFFFull) return false;
        rva = static_cast<uint32_t>(addr);
        return true;
    }

    void PushDistinct(std::vector<uint32_t>& v, uint32_t value) {
        if (std::find(v.begin(), v.end(), value) == v.end()) v.push_back(value);
    }
}
