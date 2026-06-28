#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "sensor/ICollector.hpp"
#include "sensor/JsonlEventWriter.hpp"
#include "sensor/WindowsNetworkCollector.hpp"
#include "sensor/WindowsProcessCollector.hpp"
#include "sensor/WindowsUtil.hpp"

namespace {

volatile std::sig_atomic_t g_running = 1;

void handle_signal(int) {
    g_running = 0;
}

std::filesystem::path default_output_path() {
    return std::filesystem::path("output") / "sensor-events.jsonl";
}

} // namespace

int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::filesystem::path output_path = default_output_path();
    if (argc > 1) {
        output_path = argv[1];
    }

    const std::string asset_id = edr::sensor::get_hostname();

    edr::sensor::JsonlEventWriter writer(output_path);
    if (!writer.connect()) {
        std::cerr << "Failed to open JSONL output: " << output_path.string() << '\n';
        return 1;
    }

    std::vector<std::unique_ptr<edr::sensor::ICollector>> collectors;
    collectors.push_back(std::make_unique<edr::sensor::WindowsProcessCollector>(asset_id));
    collectors.push_back(std::make_unique<edr::sensor::WindowsNetworkCollector>(asset_id));

    std::cout << "Windows endpoint sensor writing JSONL to " << output_path.string() << '\n';
    std::cout << "Press Ctrl+C to stop." << '\n';

    while (g_running) {
        for (const auto& collector : collectors) {
            for (const auto& event : collector->collect()) {
                if (!writer.publish(event)) {
                    std::cerr << "Failed to write event: " << event.event_id << '\n';
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    writer.close();
    return 0;
}
