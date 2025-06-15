# Data generator tool
add_executable(data_generator data_generator.c)
target_link_libraries(data_generator ${CMAKE_THREAD_LIBS_INIT})

# Target application that will be monitored
add_executable(mmap_workload mmap_workload.c)
target_link_libraries(mmap_workload ${CMAKE_THREAD_LIBS_INIT})

# C++ monitor application using BCC
add_executable(fault_monitor fault_monitor.cpp)
target_link_libraries(fault_monitor 
    ${BCC_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
)
target_include_directories(fault_monitor PRIVATE ${BCC_INCLUDE_DIRS})
target_compile_definitions(fault_monitor PRIVATE ${BCC_CFLAGS_OTHER})

# Install binaries
install(TARGETS data_generator mmap_workload fault_monitor
    RUNTIME DESTINATION bin
)