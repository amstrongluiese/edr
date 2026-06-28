#include "sensor/JsonlEventWriter.hpp"

#include <sstream>
#include <type_traits>
#include <utility>

namespace edr::sensor {

namespace {

std::string escape_json(const std::string& value) {
    std::ostringstream escaped;
    for (const char ch : value) {
        switch (ch) {
            case '"':
                escaped << "\\\"";
                break;
            case '\\':
                escaped << "\\\\";
                break;
            case '\b':
                escaped << "\\b";
                break;
            case '\f':
                escaped << "\\f";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                const auto byte = static_cast<unsigned char>(ch);
                if (byte < 0x20) {
                    escaped << "\\u00";
                    constexpr char hex[] = "0123456789abcdef";
                    escaped << hex[(byte >> 4) & 0x0f] << hex[byte & 0x0f];
                } else {
                    escaped << ch;
                }
                break;
        }
    }
    return escaped.str();
}

void append_json_value(std::ostringstream& json, const EventValue& value) {
    std::visit(
        [&json](const auto& item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, std::string>) {
                json << '"' << escape_json(item) << '"';
            } else if constexpr (std::is_same_v<T, bool>) {
                json << (item ? "true" : "false");
            } else {
                json << item;
            }
        },
        value);
}

} // namespace

JsonlEventWriter::JsonlEventWriter(std::filesystem::path output_path)
    : output_path_(std::move(output_path)) {}

bool JsonlEventWriter::connect() {
    if (output_path_.has_parent_path()) {
        std::filesystem::create_directories(output_path_.parent_path());
    }

    stream_.open(output_path_, std::ios::app);
    return stream_.is_open();
}

bool JsonlEventWriter::publish(const SensorEvent& event) {
    if (!stream_.is_open()) {
        return false;
    }

    stream_ << to_json(event) << '\n';
    stream_.flush();
    return stream_.good();
}

void JsonlEventWriter::close() {
    if (stream_.is_open()) {
        stream_.close();
    }
}

std::string to_json(const SensorEvent& event) {
    std::ostringstream json;
    json << "{";
    json << "\"schema_version\":\"" << escape_json(event.schema_version) << "\",";
    json << "\"event_id\":\"" << escape_json(event.event_id) << "\",";
    json << "\"event_type\":\"" << escape_json(event.event_type) << "\",";
    json << "\"asset_id\":\"" << escape_json(event.asset_id) << "\",";
    json << "\"timestamp_utc\":\"" << escape_json(event.timestamp_utc) << "\",";
    json << "\"source\":\"" << escape_json(event.source) << "\",";
    json << "\"payload\":{";

    bool first = true;
    for (const auto& [key, value] : event.payload) {
        if (!first) {
            json << ",";
        }
        first = false;
        json << '"' << escape_json(key) << "\":";
        append_json_value(json, value);
    }

    json << "}}";
    return json.str();
}

} // namespace edr::sensor
