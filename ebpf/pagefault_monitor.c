#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

// VM_FAULT_MAJOR flag indicating major page fault (disk I/O required)
#define VM_FAULT_MAJOR 0x00000004

// Data structures for tracking page faults
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

// BPF maps
// Map to store start timestamps for ongoing page faults
BPF_HASH(start_times, struct fault_key_t, u64);

// Map to store accumulated fault statistics per thread
BPF_HASH(fault_stats, struct fault_key_t, struct fault_data_t);

// Perf buffer for real-time fault events
BPF_PERF_OUTPUT(fault_events);

// Configuration map
BPF_HASH(config, u32, u32);

// Helper function to check if we should trace this process
static inline int should_trace_process(u32 pid) {
    u32 key = 0;  // target_pid key
    u32 *target_pid = config.lookup(&key);
    
    // If no target PID is configured, trace all processes
    if (!target_pid || *target_pid == 0) {
        return 1;
    }
    
    return (pid == *target_pid);
}

// Kprobe on handle_mm_fault - called when page fault occurs
int trace_handle_mm_fault_entry(struct pt_regs *ctx, struct mm_struct *mm,
                                struct vm_area_struct *vma, unsigned long address,
                                unsigned int flags) {
    struct fault_key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    
    // Filter by target process if configured
    if (!should_trace_process(key.pid)) {
        return 0;
    }
    
    u64 timestamp = bpf_ktime_get_ns();
    start_times.update(&key, &timestamp);
    
    return 0;
}

// Kretprobe on handle_mm_fault - called when page fault handling completes
int trace_handle_mm_fault_exit(struct pt_regs *ctx) {
    struct fault_key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    
    // Filter by target process if configured
    if (!should_trace_process(key.pid)) {
        return 0;
    }
    
    // Look up start time
    u64 *start_time = start_times.lookup(&key);
    if (!start_time) {
        return 0;  // No start time found
    }
    
    u64 end_time = bpf_ktime_get_ns();
    u64 duration = end_time - *start_time;
    
    // Get return value to check if this was a major fault
    vm_fault_t ret = PT_REGS_RC(ctx);
    int is_major = (ret & VM_FAULT_MAJOR) ? 1 : 0;
    
    // Update statistics
    struct fault_data_t *stats = fault_stats.lookup(&key);
    if (stats) {
        // Update existing stats
        stats->total_fault_time_ns += duration;
        if (is_major) {
            stats->major_fault_count++;
        } else {
            stats->minor_fault_count++;
        }
        
        // Update min/max fault times
        if (duration > stats->max_fault_time_ns) {
            stats->max_fault_time_ns = duration;
        }
        if (stats->min_fault_time_ns == 0 || duration < stats->min_fault_time_ns) {
            stats->min_fault_time_ns = duration;
        }
    } else {
        // Create new stats entry
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
    
    // Send event for real-time monitoring (only for major faults to reduce overhead)
    if (is_major) {
        struct fault_event_t event = {};
        event.pid = key.pid;
        event.tid = key.tid;
        event.duration_ns = duration;
        event.fault_address = 0;  // We don't have access to the fault address in the kretprobe
        event.fault_flags = 0;
        event.is_major = 1;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        
        fault_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    // Clean up start time
    start_times.delete(&key);
    
    return 0;
}

// Alternative tracepoint-based approach for page fault monitoring
// This provides more fault context but less precise timing
TRACEPOINT_PROBE(exceptions, page_fault_user) {
    struct fault_key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    
    // Filter by target process if configured
    if (!should_trace_process(key.pid)) {
        return 0;
    }
    
    // This tracepoint gives us fault address and error code
    // but doesn't directly tell us if it's major/minor
    // We can infer this from the error code flags
    
    struct fault_event_t event = {};
    event.pid = key.pid;
    event.tid = key.tid;
    event.duration_ns = 0;  // No duration available from tracepoint
    event.fault_address = args->address;
    event.fault_flags = args->error_code;
    event.is_major = 0;  // Cannot determine from this tracepoint alone
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Only submit if we're in detailed tracing mode
    u32 detail_key = 1;  // detailed_tracing key
    u32 *detailed = config.lookup(&detail_key);
    if (detailed && *detailed == 1) {
        fault_events.perf_submit(args, &event, sizeof(event));
    }
    
    return 0;
}

// Helper function to reset statistics for a specific process/thread
int reset_stats(struct pt_regs *ctx) {
    struct fault_key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    key.pid = pid_tgid >> 32;
    key.tid = (u32)pid_tgid;
    
    fault_stats.delete(&key);
    start_times.delete(&key);
    
    return 0;
}