#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

// Common constants
#define DEFAULT_FILE_SIZE_MB 512
#define DEFAULT_ACCESS_COUNT 10000
#define PAGE_SIZE 4096
#define MEGABYTE (1024 * 1024)

// Access patterns
typedef enum {
    ACCESS_SEQUENTIAL = 0,
    ACCESS_RANDOM = 1,
    ACCESS_STRIDE = 2,
    ACCESS_MIXED = 3
} access_pattern_t;

// Statistics structure for sharing between components
typedef struct {
    uint64_t total_accesses;
    uint64_t major_faults;
    uint64_t minor_faults;
    uint64_t total_fault_time_ns;
    uint64_t max_fault_time_ns;
    uint64_t min_fault_time_ns;
    double avg_fault_time_ns;
} fault_stats_t;

// Configuration structure
typedef struct {
    char* file_path;
    size_t file_size_mb;
    access_pattern_t pattern;
    uint32_t access_count;
    uint32_t stride_size;
    bool verbose;
    pid_t target_pid;
} config_t;

// Function declarations
void print_stats(const fault_stats_t* stats);
void init_config(config_t* config);
void cleanup_config(config_t* config);

#endif // COMMON_H