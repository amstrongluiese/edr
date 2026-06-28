cmake_minimum_required(VERSION 3.20)
project(edr_sensor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(edr_sensor_interfaces INTERFACE)
target_include_directories(edr_sensor_interfaces INTERFACE include)

add_executable(edr_windows_sensor
    src/JsonlEventWriter.cpp
    src/WindowsNetworkCollector.cpp
    src/WindowsProcessCollector.cpp
    src/WindowsUtil.cpp
    src/main.cpp
)

target_include_directories(edr_windows_sensor PRIVATE include)
target_link_libraries(edr_windows_sensor PRIVATE iphlpapi ws2_32)
