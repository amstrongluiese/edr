#pragma once

#include <filesystem>
#include <fstream>

#include "sensor/IEventTransport.hpp"

namespace edr::sensor {

class JsonlEventWriter final : public IEventTransport {
public:
    explicit JsonlEventWriter(std::filesystem::path output_path);

    bool connect() override;
    bool publish(const SensorEvent& event) override;
    void close() override;

private:
    std::filesystem::path output_path_;
    std::ofstream stream_;
};

std::string to_json(const SensorEvent& event);

} // namespace edr::sensor
