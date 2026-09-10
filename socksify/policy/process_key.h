#pragma once

#include <algorithm>
#include <cwctype>
#include <string>

namespace dip_policy {

// Canonical key for per-process destination policy storage and lookup.
// Strips path components and a trailing ".exe" extension, then lower-cases.
inline std::wstring normalize_process_key(const std::wstring& process_name_or_path) {
    const auto separator = process_name_or_path.find_last_of(L"\\/");
    std::wstring name = separator == std::wstring::npos
        ? process_name_or_path
        : process_name_or_path.substr(separator + 1);

    std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(static_cast<wint_t>(ch)));
    });

    static const std::wstring kExeExtension = L".exe";
    if (name.size() > kExeExtension.size() &&
        name.compare(name.size() - kExeExtension.size(), kExeExtension.size(), kExeExtension) == 0) {
        name.erase(name.size() - kExeExtension.size());
    }

    return name;
}

}  // namespace dip_policy
