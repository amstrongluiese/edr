#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

static std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (char c : input) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << c; break;
        }
    }
    return out.str();
}

static std::string now_iso() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buffer[64];
    sprintf_s(buffer, "%04d-%02d-%02dT%02d:%02d:%02dZ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

static std::string wide_to_utf8(const wchar_t* value) {
    if (!value) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), size, nullptr, nullptr);
    return result;
}

static std::string ipv4_to_string(DWORD addr) {
    IN_ADDR in_addr;
    in_addr.S_un.S_addr = addr;
    char buffer[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &in_addr, buffer, sizeof(buffer));
    return std::string(buffer);
}

static void emit(std::ostream& out, const std::string& json) {
    out << json << std::endl;
}

static void collect_processes(std::ostream& out) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::ostringstream json;
            json << "{"
                 << "\"event_type\":\"process\","
                 << "\"timestamp\":\"" << now_iso() << "\","
                 << "\"process_name\":\"" << json_escape(wide_to_utf8(entry.szExeFile)) << "\","
                 << "\"pid\":" << entry.th32ProcessID
                 << "}";
            emit(out, json.str());
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

static void collect_tcp_connections(std::ostream& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<unsigned char> buffer(size);
    PMIB_TCPTABLE_OWNER_PID table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID& row = table->table[i];
        DWORD local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        DWORD remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        if (row.dwRemoteAddr == 0 || remote_port == 0) continue;

        std::ostringstream json;
        json << "{"
             << "\"event_type\":\"connection\","
             << "\"timestamp\":\"" << now_iso() << "\","
             << "\"source_ip\":\"" << ipv4_to_string(row.dwLocalAddr) << "\","
             << "\"destination_ip\":\"" << ipv4_to_string(row.dwRemoteAddr) << "\","
             << "\"port\":" << remote_port << ","
             << "\"source_port\":" << local_port << ","
             << "\"protocol\":\"TCP\","
             << "\"pid\":" << row.dwOwningPid
             << "}";
        emit(out, json.str());
    }
}

static void collect_dns_cache(std::ostream& out) {
    FILE* pipe = _popen("ipconfig /displaydns", "r");
    if (!pipe) return;

    char line[512];
    while (fgets(line, sizeof(line), pipe)) {
        std::string text(line);
        std::string marker = "Record Name";
        std::size_t pos = text.find(marker);
        if (pos == std::string::npos) continue;
        std::size_t colon = text.find(':', pos);
        if (colon == std::string::npos) continue;
        std::string domain = text.substr(colon + 1);
        while (!domain.empty() && (domain.front() == ' ' || domain.front() == '\t')) domain.erase(domain.begin());
        while (!domain.empty() && (domain.back() == '\r' || domain.back() == '\n' || domain.back() == ' ')) domain.pop_back();
        if (domain.empty()) continue;

        std::ostringstream json;
        json << "{"
             << "\"event_type\":\"dns\","
             << "\"timestamp\":\"" << now_iso() << "\","
             << "\"domain\":\"" << json_escape(domain) << "\""
             << "}";
        emit(out, json.str());
    }
    _pclose(pipe);
}

int main(int argc, char** argv) {
    std::string output_path;
    int interval_seconds = 10;
    int iterations = 1;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        } else if (arg == "--interval" && i + 1 < argc) {
            interval_seconds = std::max(1, std::stoi(argv[++i]));
            iterations = 0;
        } else if (arg == "--once") {
            iterations = 1;
        }
    }

    std::ofstream file;
    std::ostream* out = &std::cout;
    if (!output_path.empty()) {
        file.open(output_path, std::ios::app);
        if (!file) {
            std::cerr << "Unable to open output file: " << output_path << std::endl;
            return 2;
        }
        out = &file;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    int count = 0;
    while (iterations == 0 || count < iterations) {
        emit(*out, "{\"event_type\":\"heartbeat\",\"timestamp\":\"" + now_iso() + "\",\"sensor\":\"cpp-windows-sensor\"}");
        collect_processes(*out);
        collect_tcp_connections(*out);
        collect_dns_cache(*out);
        out->flush();
        ++count;
        if (iterations == 0) {
            std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
        }
    }

    WSACleanup();
    return 0;
}
