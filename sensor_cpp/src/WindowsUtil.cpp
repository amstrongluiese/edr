#include "sensor/WindowsUtil.hpp"

#include <windows.h>

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

namespace edr::sensor {

std::string current_timestamp_utc() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);

    std::tm utc{};
    gmtime_s(&utc, &time);

    std::ostringstream value;
    value << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return value.str();
}

std::string generate_event_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static thread_local std::uniform_int_distribution<uint64_t> dist;

    const auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::ostringstream value;
    value << std::hex << now << "-" << dist(rng);
    return value.str();
}

std::string get_hostname() {
    char buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = sizeof(buffer);
    if (!GetComputerNameA(buffer, &size)) {
        return "unknown-host";
    }
    return buffer;
}

std::string wide_to_utf8(const wchar_t* value) {
    if (value == nullptr || value[0] == L'\0') {
        return "";
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return "";
    }

    std::string result(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), size, nullptr, nullptr);
    return result;
}

} // namespace edr::sensor
