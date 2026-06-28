#pragma once

#include "sensor/SensorEvent.hpp"

namespace edr::sensor {

class IEventTransport {
public:
    virtual ~IEventTransport() = default;

    virtual bool connect() = 0;
    virtual bool publish(const SensorEvent& event) = 0;
    virtual void close() = 0;
};

} // namespace edr::sensor
