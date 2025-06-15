cmake_minimum_required(VERSION 3.16)
project(ebpf_mmap_stall_demo VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)

# Check for BCC
pkg_check_modules(BCC REQUIRED libbcc)

# Check for Python3 (needed for BCC Python bindings)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# Threading support
find_package(Threads REQUIRED)

# Common include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${BCC_INCLUDE_DIRS})

# Common compile options
add_compile_options(-Wall -Wextra -g)

# Add subdirectories
add_subdirectory(src)
add_subdirectory(tools)
add_subdirectory(scripts)

# Custom targets for convenience
add_custom_target(run_demo
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_demo.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running the complete eBPF mmap stall demonstration"
)

# Install targets
install(DIRECTORY scripts/ 
    DESTINATION bin
    FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    PATTERN "*.sh"
)

install(DIRECTORY ebpf/
    DESTINATION share/ebpf_mmap_demo
    FILES_MATCHING PATTERN "*.c"
)