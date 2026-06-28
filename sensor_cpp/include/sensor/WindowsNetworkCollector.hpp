#pragma once

#include <set>
#include <string>

#include "sensor/ICollector.hpp"

namespace edr::sensor {

class WindowsNetworkCollector final : public ICollector {
public:
    explicit WindowsNetworkCollector(std::string asset_id);

    const char* name() const override;
    std::vector<SensorEvent> collect() override;

private:
    std::string asset_id_;
    std::set<std::string> known_connections_;
};

} // namespace edr::sensor
