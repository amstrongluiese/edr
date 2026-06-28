#pragma once

#include <map>
#include <string>

#include <windows.h>

#include "sensor/ICollector.hpp"

namespace edr::sensor {

struct ProcessSnapshotEntry {
    DWORD pid;
    DWORD parent_pid;
    std::string executable;
};

class WindowsProcessCollector final : public ICollector {
public:
    explicit WindowsProcessCollector(std::string asset_id);

    const char* name() const override;
    std::vector<SensorEvent> collect() override;

private:
    std::string asset_id_;
    bool initialized_ = false;
    std::map<DWORD, ProcessSnapshotEntry> known_processes_;
};

} // namespace edr::sensor
