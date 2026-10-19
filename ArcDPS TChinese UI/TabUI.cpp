#include "TabUI.h"
#include "GW2LangPatch.h"
#include "VoicePatch.h"
#include "ChineseIme.h"

#include <imgui/imgui.h>

#include <string>

#define IMGUI_UTF8(str) (const char*)u8##str

TabUI tabui;

void TabUI::Draw() {
    const bool chineseOn = GW2LangPatch::IsChineseEnabled();
    const bool fullMode = GW2LangPatch::IsFullLanguageMode();
    const bool fullAvailable = GW2LangPatch::IsFullLanguageAvailable();
    bool isTradMode = GW2LangPatch::IsTradModeEnabled();

    // 1. 開啟內建簡體中文：完整切換遊戲語言（商城等網頁也會是中文，字型會改變）
    bool isNew = chineseOn && fullMode;
    if (!fullAvailable) ImGui::BeginDisabled();
    if (ImGui::Checkbox(IMGUI_UTF8("開啟內建簡體中文"), &isNew)) {
        GW2LangPatch::SetChinese(isNew, true);
    }
    if (!fullAvailable) ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        // 每一段都要標 u8；IMGUI_UTF8 只會替第一段加上前綴
        ImGui::SetTooltip("%s", reinterpret_cast<const char*>(
            u8"完整切換遊戲語言。交易行、寶石商城、魔法庫、兌換所也會顯示中文，\n"
            u8"「簡體轉繁體模式」會一併轉換這些網頁。\n"
            u8"缺點：遊戲字型會改成為中國版本設計的字型。\n"
            u8"與「開啟內建簡體中文(舊)」擇一。"));
    }

    ImGui::SameLine();

    // 2. 簡體轉繁體模式：勾選時自動開啟簡體中文（沿用最後用的方式，預設是舊方式）
    if (ImGui::Checkbox(IMGUI_UTF8("簡體轉繁體模式"), &isTradMode)) {
        GW2LangPatch::RequestTraditional(isTradMode);
    }

    // 3. 中文語音
    bool isVoice = VoicePatch::IsEnabled();
    const bool voiceDisabled = VoicePatch::IsBusy() || !VoicePatch::IsAvailable();
    if (voiceDisabled) ImGui::BeginDisabled();
    if (ImGui::Checkbox(IMGUI_UTF8("中文語音（實驗）"), &isVoice)) {
        VoicePatch::RequestEnable(isVoice);
    }
    if (voiceDisabled) ImGui::EndDisabled();

    const char* voiceStatus = VoicePatch::StatusText();
    if (voiceStatus && voiceStatus[0]) {
        ImGui::SameLine();
        ImGui::TextUnformatted(voiceStatus);
    }

    // 4. 中文輸入增強
    bool isIme = ChineseIme::IsEnabled();
    const bool imeDisabled = ChineseIme::IsBusy() || !ChineseIme::IsAvailable();
    if (imeDisabled) ImGui::BeginDisabled();
    if (ImGui::Checkbox(IMGUI_UTF8("中文輸入增強"), &isIme)) {
        ChineseIme::RequestEnable(isIme);
    }
    if (imeDisabled) ImGui::EndDisabled();

    const char* imeStatus = ChineseIme::StatusText();
    if (imeStatus && imeStatus[0]) {
        ImGui::SameLine();
        ImGui::TextUnformatted(imeStatus);
    }

    // 5. 開啟內建簡體中文(舊)：只刷新介面文字，字型不變；商城等網頁維持英文
    bool isOld = chineseOn && !fullMode;
    if (ImGui::Checkbox(IMGUI_UTF8("開啟內建簡體中文(舊)"), &isOld)) {
        GW2LangPatch::SetChinese(isOld, false);
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s", reinterpret_cast<const char*>(
            u8"只刷新遊戲介面文字，遊戲字型不變。\n"
            u8"交易行、商城等網頁維持英文，「簡體轉繁體模式」不會轉換它們。\n"
            u8"與「開啟內建簡體中文」擇一。"));
    }

    // 簡體中文的狀態說明（例如新方式無法解鎖而改用舊方式）
    {
        const char* languageStatus = GW2LangPatch::LanguageStatusText();
        if (languageStatus && languageStatus[0]) ImGui::TextUnformatted(languageStatus);
    }

    // 商城網頁繁體化的狀態（跟著簡體轉繁體模式；舊方式下網頁是英文，不載入轉換腳本）
    {
        std::string webLine;
        const char* webStatus = ChineseIme::WebStatusText();
        if (isTradMode && !fullMode) {
            webLine = reinterpret_cast<const char*>(u8"商城網頁：維持英文（簡體中文使用舊方式）");
        }
        else if (webStatus && webStatus[0]) {
            webLine = reinterpret_cast<const char*>(u8"商城網頁繁體化：");
            webLine += webStatus;
        }
        if (!webLine.empty()) ImGui::TextUnformatted(webLine.c_str());
    }
}
