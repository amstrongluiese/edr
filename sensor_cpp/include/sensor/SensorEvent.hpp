#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <variant>

namespace edr::sensor {

using EventValue = std::variant<std::string, int64_t, uint64_t, bool>;

struct SensorEvent {
    std::string schema_version;
    std::string event_id;
    std::string event_type;
    std::string asset_id;
    std::string timestamp_utc;
    std::string source;
    std::map<std::string, EventValue> payload;
};

} // namespace edr::sensor
