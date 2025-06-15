#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>

#include <bcc/BPF.h>
#include <bcc/perf_reader.h>

extern "C" {
#include "common.h"
}

// Global state
static volatile bool running = true;
static bool verbose = false;
static int target_pid = 0;
static int sample_interval_ms = 1000;

// BPF event structures
struct fault_event_t {
    uint32_t pid;
    uint32_t tid;
    uint64_t duration_ns;
    uint64_t fault_address;
    uint32_t fault_flags;
    uint8_t is_major;
    char comm[16];
};

struct fault_key_t {
    uint32_t pid;
    uint32_t tid;
};

// BPF-specific stats structure (different from common.h fault_stats_t)
struct bpf_fault_stats_t {
    uint64_t timestamp_ns;
    uint64_t total_fault_time_ns;
    uint64_t major_fault_count;
    uint64_t minor_fault_count;
    uint64_t max_fault_time_ns;
    uint64_t min_fault_time_ns;
    char comm[16];
};

// Statistics tracking
struct ThreadStats {
    std::string comm;
    uint64_t total_fault_time_ns = 0;
    uint64_t major_fault_count = 0;
    uint64_t minor_fault_count = 0;
    uint64_t max_fault_time_ns = 0;
    uint64_t min_fault_time_ns = UINT64_MAX;
    uint64_t last_update_ns = 0;
};

static std::map<std::pair<uint32_t, uint32_t>, ThreadStats> thread_stats;

// BPF program source - embedded for simplicity
static const std::string bpf_program = R"(
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

#define VM_FAULT_MAJOR 0x00000004

struct fault_key_t {
    u32 pid;
    u32 tid;
};

struct fault_data_t {
    u64 timestamp_ns;
    u64 total_fault_time_ns;
    u64 major_fault_count;
    u64 minor_fault_count;
    u64 max_fault_time_ns;
    u64 min_fault_time_ns;
    char comm[TASK_COMM_LEN];
};

struct fault_event_t {
    u32 pid;
    u32 tid;
    u64 duration_ns;
    u64 fault_address;
    u32 fault_flags;
    u8 is_major;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start_times, struct fault_key_t, u64);
BPF_HASH(fault_stats, struct fault_key_t, struct fault_data_t);
BPF_PERF_OUTPUT(fault_events);
BPF_HASH(config, u32, u32);

static inline int should_trace_process(u32 pid) {
    u32 key = 0;
    u32 *target_pid = config.lookup(&key);
    
    if (!target_pid || *target_pid == 0) {
        return 1;
    }
    
    return (pid == *target_pid);
}

int trace_handle_mm_fault_entry(struct pt_regs *ctx, struct mm_struct *mm,
                                struct vm_area_struct *vma, unsigned long address,
                                unsigned int flags) {
    struct fault_key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    
    if (!should_trace_process(key.pid)) {
        return 0;
    }
    
    u64 timestamp = bpf_ktime_get_ns();
    start_times.update(&key, &timestamp);
    
    return 0;
}

int trace_handle_mm_fault_exit(struct pt_regs *ctx) {
    struct fault_key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    
    if (!should_trace_process(key.pid)) {
        return 0;
    }
    
    u64 *start_time = start_times.lookup(&key);
    if (!start_time) {
        return 0;
    }
    
    u64 end_time = bpf_ktime_get_ns();
    u64 duration = end_time - *start_time;
    
    vm_fault_t ret = PT_REGS_RC(ctx);
    int is_major = (ret & VM_FAULT_MAJOR) ? 1 : 0;
    
    struct fault_data_t *stats = fault_stats.lookup(&key);
    if (stats) {
        stats->total_fault_time_ns += duration;
        if (is_major) {
            stats->major_fault_count++;
        } else {
            stats->minor_fault_count++;
        }
        
        if (duration > stats->max_fault_time_ns) {
            stats->max_fault_time_ns = duration;
        }
        if (stats->min_fault_time_ns == 0 || duration < stats->min_fault_time_ns) {
            stats->min_fault_time_ns = duration;
        }
    } else {
        struct fault_data_t new_stats = {};
        new_stats.timestamp_ns = end_time;
        new_stats.total_fault_time_ns = duration;
        new_stats.major_fault_count = is_major ? 1 : 0;
        new_stats.minor_fault_count = is_major ? 0 : 1;
        new_stats.max_fault_time_ns = duration;
        new_stats.min_fault_time_ns = duration;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        
        fault_stats.update(&key, &new_stats);
    }
    
    if (is_major) {
        struct fault_event_t event = {};
        event.pid = key.pid;
        event.tid = key.tid;
        event.duration_ns = duration;
        event.fault_address = 0;
        event.fault_flags = 0;
        event.is_major = 1;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        
        fault_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    start_times.delete(&key);
    return 0;
}
)";

static void signal_handler(int sig) {
    (void)sig;
    running = false;
}

static void usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS]\n";
    std::cout << "eBPF-based page fault monitor for mmap workloads\n\n";
    std::cout << "Options:\n";
    std::cout << "  -p, --pid PID       Target process ID (0 = all processes)\n";
    std::cout << "  -i, --interval MS   Sample interval in milliseconds (default: 1000)\n";
    std::cout << "  -v, --verbose       Enable verbose output\n";
    std::cout << "  -h, --help          Show this help\n";
}

static void handle_fault_event(void* cb_cookie, void* data, int data_size) {
    (void)cb_cookie;
    
    if (data_size < (int)sizeof(fault_event_t)) {
        return;
    }
    
    auto* event = static_cast<fault_event_t*>(data);
    
    if (verbose) {
        std::cout << "Major fault: PID=" << event->pid 
                  << " TID=" << event->tid
                  << " Duration=" << (event->duration_ns / 1000) << "μs"
                  << " Comm=" << std::string(event->comm, 16)
                  << std::endl;
    }
}

static void print_statistics(ebpf::BPF& bpf) {
    auto fault_stats_table = bpf.get_hash_table<fault_key_t, bpf_fault_stats_t>("fault_stats");
    
    system("clear");
    
    std::cout << "\n=== eBPF Page Fault Monitor ===\n";
    std::cout << "Target PID: " << (target_pid == 0 ? "ALL" : std::to_string(target_pid)) << "\n";
    std::cout << "Sample interval: " << sample_interval_ms << "ms\n\n";
    
    std::cout << std::setw(8) << "PID"
              << std::setw(8) << "TID"
              << std::setw(16) << "COMM"
              << std::setw(12) << "MAJOR"
              << std::setw(12) << "MINOR"
              << std::setw(15) << "TOTAL_TIME_MS"
              << std::setw(12) << "AVG_MS"
              << std::setw(12) << "MAX_MS"
              << std::setw(12) << "MIN_US"
              << std::endl;
    
    std::cout << std::string(120, '-') << std::endl;
    
    uint64_t total_major_faults = 0;
    uint64_t total_minor_faults = 0;
    double total_fault_time_ms = 0;
    
    auto stats_map = fault_stats_table.get_table_offline();
    for (auto& entry : stats_map) {
        auto key = entry.first;
        auto stats = entry.second;
        
        if (stats.major_fault_count == 0 && stats.minor_fault_count == 0) {
            continue;
        }
        
        total_major_faults += stats.major_fault_count;
        total_minor_faults += stats.minor_fault_count;
        
        double total_time_ms = stats.total_fault_time_ns / 1e6;
        double avg_time_ms = (stats.major_fault_count + stats.minor_fault_count) > 0 ?
                            total_time_ms / (stats.major_fault_count + stats.minor_fault_count) : 0;
        double max_time_ms = stats.max_fault_time_ns / 1e6;
        double min_time_us = stats.min_fault_time_ns / 1e3;
        
        total_fault_time_ms += total_time_ms;
        
        std::string comm(stats.comm, 16);
        comm.resize(15);  // Truncate if necessary
        
        std::cout << std::setw(8) << key.pid
                  << std::setw(8) << key.tid
                  << std::setw(16) << comm
                  << std::setw(12) << stats.major_fault_count
                  << std::setw(12) << stats.minor_fault_count
                  << std::setw(15) << std::fixed << std::setprecision(2) << total_time_ms
                  << std::setw(12) << std::fixed << std::setprecision(3) << avg_time_ms
                  << std::setw(12) << std::fixed << std::setprecision(3) << max_time_ms
                  << std::setw(12) << std::fixed << std::setprecision(1) << min_time_us
                  << std::endl;
    }
    
    std::cout << std::string(120, '-') << std::endl;
    std::cout << "TOTAL: Major=" << total_major_faults 
              << " Minor=" << total_minor_faults 
              << " Time=" << std::fixed << std::setprecision(2) << total_fault_time_ms << "ms"
              << std::endl;
    
    if (running) {
        std::cout << "\nPress Ctrl+C to stop monitoring..." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"pid", required_argument, 0, 'p'},
        {"interval", required_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:i:vh", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'p':
            target_pid = atoi(optarg);
            break;
        case 'i':
            sample_interval_ms = atoi(optarg);
            if (sample_interval_ms < 100) {
                std::cerr << "Minimum sample interval is 100ms\n";
                exit(1);
            }
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    
    // Check for root privileges
    if (geteuid() != 0) {
        std::cerr << "This program requires root privileges to load eBPF programs.\n";
        exit(1);
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::cout << "Initializing eBPF page fault monitor...\n";
    
    try {
        // Initialize BPF
        ebpf::BPF bpf;
        auto init_res = bpf.init(bpf_program);
        if (init_res.code() != 0) {
            std::cerr << "Failed to initialize BPF program: " << init_res.msg() << std::endl;
            exit(1);
        }
        
        // Set target PID in config map
        auto config_table = bpf.get_hash_table<uint32_t, uint32_t>("config");
        uint32_t key = 0;
        uint32_t pid_value = target_pid;
        config_table.update_value(key, pid_value);
        
        // Attach kprobes
        auto attach_entry = bpf.attach_kprobe("handle_mm_fault", "trace_handle_mm_fault_entry");
        if (attach_entry.code() != 0) {
            std::cerr << "Failed to attach entry kprobe: " << attach_entry.msg() << std::endl;
            exit(1);
        }
        
        auto attach_exit = bpf.attach_kprobe("handle_mm_fault", "trace_handle_mm_fault_exit", 0, BPF_PROBE_RETURN);
        if (attach_exit.code() != 0) {
            std::cerr << "Failed to attach exit kretprobe: " << attach_exit.msg() << std::endl;
            exit(1);
        }
        
        // Open perf buffer for real-time events
        auto perf_buffer = bpf.open_perf_buffer("fault_events", handle_fault_event);
        if (perf_buffer.code() != 0) {
            std::cerr << "Failed to open perf buffer: " << perf_buffer.msg() << std::endl;
            exit(1);
        }
        
        std::cout << "eBPF program loaded and attached successfully.\n";
        std::cout << "Monitoring page faults";
        if (target_pid != 0) {
            std::cout << " for PID " << target_pid;
        }
        std::cout << "...\n\n";
        
        // Main monitoring loop
        while (running) {
            // Poll for perf events
            bpf.poll_perf_buffer("fault_events", 100);
            
            // Print statistics at intervals
            static auto last_print = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_print);
            
            if (elapsed.count() >= sample_interval_ms) {
                print_statistics(bpf);
                last_print = now;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        std::cout << "\nDetaching eBPF program...\n";
        bpf.detach_kprobe("handle_mm_fault");
        
        // Print final statistics
        std::cout << "\nFinal Statistics:\n";
        print_statistics(bpf);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(1);
    }
    
    return 0;
}