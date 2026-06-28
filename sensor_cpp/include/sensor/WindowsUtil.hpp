#pragma once

#include <string>

namespace edr::sensor {

std::string current_timestamp_utc();
std::string generate_event_id();
std::string get_hostname();
std::string wide_to_utf8(const wchar_t* value);

} // namespace edr::sensor
