# Python-based monitoring tools
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pagefault_monitor.py.in
    ${CMAKE_CURRENT_BINARY_DIR}/pagefault_monitor.py
    @ONLY
)

# Make Python script executable
file(COPY ${CMAKE_CURRENT_BINARY_DIR}/pagefault_monitor.py
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
     FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# Install Python tools
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/pagefault_monitor.py
    DESTINATION bin
)