cmake_minimum_required(VERSION 3.25)

project(RecSpoof LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_library(recspoof_core STATIC
    src/core/WindowManager.cpp
    src/core/ProcessManager.cpp
    src/core/ProtectionManager.cpp
    src/platform/WindowsAPI.cpp
    src/config/ConfigManager.cpp
    src/ui/ConsoleUI.cpp
)
target_include_directories(recspoof_core PUBLIC include)
target_compile_definitions(recspoof_core PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(recspoof_core PUBLIC user32 shell32 psapi)

add_executable(RecSpoof WIN32 src/main.cpp)
target_link_libraries(RecSpoof PRIVATE recspoof_core)

add_executable(selfcheck tests/selfcheck.cpp)
target_link_libraries(selfcheck PRIVATE recspoof_core)

if(MSVC)
    target_compile_options(recspoof_core PRIVATE /W4 /utf-8)
    target_compile_options(RecSpoof PRIVATE /W4 /utf-8)
    target_compile_options(selfcheck PRIVATE /W4 /utf-8)
else()
    target_compile_options(recspoof_core PRIVATE -Wall -Wextra)
    target_compile_options(RecSpoof PRIVATE -Wall -Wextra)
    target_compile_options(selfcheck PRIVATE -Wall -Wextra)
endif()

enable_testing()
add_test(NAME selfcheck COMMAND selfcheck)
add_test(NAME version COMMAND RecSpoof --version)
add_test(NAME help COMMAND RecSpoof --help)
