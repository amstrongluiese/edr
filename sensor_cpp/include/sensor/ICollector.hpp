#pragma once

#include <vector>

#include "sensor/SensorEvent.hpp"

namespace edr::sensor {

class ICollector {
public:
    virtual ~ICollector() = default;

    virtual const char* name() const = 0;
    virtual std::vector<SensorEvent> collect() = 0;
};

} // namespace edr::sensor
