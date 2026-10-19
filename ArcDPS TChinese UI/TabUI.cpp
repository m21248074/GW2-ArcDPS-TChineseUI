#include "TabUI.h"
#include "GW2LangPatch.h"
#include "VoicePatch.h"

#include <imgui/imgui.h>

#define IMGUI_UTF8(str) (const char*)u8##str

TabUI tabui;

void TabUI::Draw() {
    bool isChinese = GW2LangPatch::IsChineseEnabled();
    bool isTradMode = GW2LangPatch::IsTradModeEnabled();
    
    if (ImGui::Checkbox(IMGUI_UTF8("開啟內建簡體中文"), &isChinese)) {
        GW2LangPatch::QueueLanguageToggle(isChinese);
    }

    ImGui::SameLine();

    if (ImGui::Checkbox(IMGUI_UTF8("簡體轉繁體模式"), &isTradMode)) {
        GW2LangPatch::SetTradMode(isTradMode);
    }

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
}