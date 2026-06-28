#pragma once

#include <string>

#include "sensor/SensorEvent.hpp"

namespace edr::sensor {

class INormalizer {
public:
    virtual ~INormalizer() = default;

    virtual SensorEvent normalize(const std::string& raw_event) = 0;
};

} // namespace edr::sensor
