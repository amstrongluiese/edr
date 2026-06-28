#include "sensor/WindowsProcessCollector.hpp"

#include <tlhelp32.h>

#include <utility>

#include "sensor/WindowsUtil.hpp"

namespace edr::sensor {

namespace {

std::map<DWORD, ProcessSnapshotEntry> read_process_snapshot() {
    std::map<DWORD, ProcessSnapshotEntry> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            processes[entry.th32ProcessID] = ProcessSnapshotEntry{
                entry.th32ProcessID,
                entry.th32ParentProcessID,
                wide_to_utf8(entry.szExeFile)
            };
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processes;
}

SensorEvent make_process_event(
    const std::string& asset_id,
    const char* source,
    const std::string& event_type,
    const ProcessSnapshotEntry& process) {
    SensorEvent event;
    event.schema_version = "1.0";
    event.event_id = generate_event_id();
    event.event_type = event_type;
    event.asset_id = asset_id;
    event.timestamp_utc = current_timestamp_utc();
    event.source = source;
    event.payload = {
        {"process_id", static_cast<uint64_t>(process.pid)},
        {"parent_process_id", static_cast<uint64_t>(process.parent_pid)},
        {"image_name", process.executable}
    };
    return event;
}

} // namespace

WindowsProcessCollector::WindowsProcessCollector(std::string asset_id)
    : asset_id_(std::move(asset_id)) {}

const char* WindowsProcessCollector::name() const {
    return "windows_process_collector";
}

std::vector<SensorEvent> WindowsProcessCollector::collect() {
    std::vector<SensorEvent> events;
    auto current_processes = read_process_snapshot();

    if (!initialized_) {
        initialized_ = true;
        known_processes_ = std::move(current_processes);
        return events;
    }

    for (const auto& [pid, process] : current_processes) {
        if (!known_processes_.contains(pid)) {
            events.push_back(make_process_event(asset_id_, name(), "process.created", process));
        }
    }

    for (const auto& [pid, process] : known_processes_) {
        if (!current_processes.contains(pid)) {
            events.push_back(make_process_event(asset_id_, name(), "process.terminated", process));
        }
    }

    known_processes_ = std::move(current_processes);
    return events;
}

} // namespace edr::sensor
