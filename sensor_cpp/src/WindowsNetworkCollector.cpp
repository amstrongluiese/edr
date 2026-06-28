#include "sensor/WindowsNetworkCollector.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <cstdint>
#include <memory>
#include <sstream>
#include <utility>

#include "sensor/WindowsUtil.hpp"

namespace edr::sensor {

namespace {

std::string ipv4_to_string(DWORD address) {
    in_addr addr{};
    addr.S_un.S_addr = address;

    char buffer[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) {
        return "";
    }
    return buffer;
}

bool ensure_winsock_started() {
    static const bool started = [] {
        WSADATA data{};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return started;
}

uint16_t port_from_dword(DWORD value) {
    return ntohs(static_cast<u_short>(value));
}

std::string connection_key(const MIB_TCPROW_OWNER_PID& row) {
    std::ostringstream key;
    key << row.dwOwningPid << "|"
        << row.dwLocalAddr << "|"
        << row.dwLocalPort << "|"
        << row.dwRemoteAddr << "|"
        << row.dwRemotePort << "|"
        << row.dwState;
    return key.str();
}

std::string tcp_state_name(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:
            return "CLOSED";
        case MIB_TCP_STATE_LISTEN:
            return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:
            return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:
            return "SYN_RECEIVED";
        case MIB_TCP_STATE_ESTAB:
            return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:
            return "FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2:
            return "FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:
            return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:
            return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:
            return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB:
            return "DELETE_TCB";
        default:
            return "UNKNOWN";
    }
}

} // namespace

WindowsNetworkCollector::WindowsNetworkCollector(std::string asset_id)
    : asset_id_(std::move(asset_id)) {}

const char* WindowsNetworkCollector::name() const {
    return "windows_network_collector";
}

std::vector<SensorEvent> WindowsNetworkCollector::collect() {
    std::vector<SensorEvent> events;
    if (!ensure_winsock_started()) {
        return events;
    }

    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return events;
    }

    auto buffer = std::make_unique<unsigned char[]>(size);
    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.get());
    result = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        return events;
    }

    std::set<std::string> current_connections;
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const auto& row = table->table[index];
        const auto key = connection_key(row);
        current_connections.insert(key);

        if (known_connections_.contains(key)) {
            continue;
        }

        SensorEvent event;
        event.schema_version = "1.0";
        event.event_id = generate_event_id();
        event.event_type = "network.connection_observed";
        event.asset_id = asset_id_;
        event.timestamp_utc = current_timestamp_utc();
        event.source = name();
        event.payload = {
            {"protocol", std::string("tcp")},
            {"process_id", static_cast<uint64_t>(row.dwOwningPid)},
            {"local_address", ipv4_to_string(row.dwLocalAddr)},
            {"local_port", static_cast<uint64_t>(port_from_dword(row.dwLocalPort))},
            {"remote_address", ipv4_to_string(row.dwRemoteAddr)},
            {"remote_port", static_cast<uint64_t>(port_from_dword(row.dwRemotePort))},
            {"state", tcp_state_name(row.dwState)}
        };
        events.push_back(std::move(event));
    }

    known_connections_ = std::move(current_connections);
    return events;
}

} // namespace edr::sensor
