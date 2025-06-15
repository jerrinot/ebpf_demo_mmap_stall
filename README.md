# eBPF Memory-Mapped File Page Fault Monitor

This project demonstrates how to use eBPF to monitor major page faults in memory-mapped files and measure I/O wait time per query in concurrent workloads. It provides real-time insights into page fault behavior and helps identify I/O stalls in applications that use memory-mapped files.

## Overview

The demonstration consists of several components:

1. **Data Generator** (`data_generator`) - Creates test files with different patterns
2. **Workload Application** (`mmap_workload`) - Memory-maps files and performs configurable access patterns
3. **eBPF Monitor** (`fault_monitor.cpp` and `pagefault_monitor.py`) - Monitors page faults using kernel probes
4. **Demo Scripts** - Automated demonstration and environment setup

## Key Features

- **Real-time Page Fault Monitoring**: Uses eBPF kprobes on `handle_mm_fault` to capture major/minor page faults
- **Per-Thread Attribution**: Tracks I/O wait time and fault counts per thread/query
- **Multiple Access Patterns**: Sequential, random, stride, and mixed access patterns
- **Configurable Workloads**: Adjustable file sizes, thread counts, and access patterns  
- **Low Overhead**: In-kernel aggregation minimizes monitoring impact
- **Cross-Platform**: Works on modern Linux distributions with eBPF support

## Architecture

### eBPF Monitoring Strategy

The monitoring approach hooks into the kernel's page fault handling path:

1. **Entry Probe**: `kprobe` on `handle_mm_fault` records timestamp when page fault handling begins
2. **Exit Probe**: `kretprobe` on `handle_mm_fault` measures elapsed time and checks return flags
3. **Major Fault Detection**: Uses `VM_FAULT_MAJOR` flag (0x4) to distinguish major faults requiring disk I/O
4. **Per-Thread Tracking**: Uses thread ID as key for fault time accumulation and statistics

### Data Structures

```c
struct fault_key_t {
    u32 pid;    // Process ID
    u32 tid;    // Thread ID  
};

struct fault_data_t {
    u64 total_fault_time_ns;    // Accumulated I/O wait time
    u64 major_fault_count;      // Count of major faults
    u64 minor_fault_count;      // Count of minor faults
    u64 max_fault_time_ns;      // Maximum single fault time
    u64 min_fault_time_ns;      // Minimum single fault time
    char comm[16];              // Process/thread name
};
```

## Building

### Prerequisites

- Linux kernel 4.1+ with eBPF support
- CMake 3.16+
- GCC/G++ with C11/C++17 support
- BCC (BPF Compiler Collection)
- Python 3 with BCC bindings
- Kernel headers

### Quick Setup

```bash
# Run environment setup (requires root)
sudo scripts/setup_environment.sh

# Build the project
mkdir build && cd build
cmake ..
make
```

### Manual Dependency Installation

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential cmake
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
sudo apt-get install python3-bcc libbpf-dev libbcc-dev
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install gcc gcc-c++ make cmake kernel-devel
sudo dnf install bcc-tools python3-bcc bcc-devel
```

**Arch Linux:**
```bash
sudo pacman -S base-devel cmake linux-headers
sudo pacman -S bcc bcc-tools python-bcc
```

## Usage

### Automated Demo

```bash
# Run the complete demonstration (requires root)
sudo ./scripts/run_demo.sh

# Customize demo parameters
sudo ./scripts/run_demo.sh --size 256 --pattern random --threads 4
```

### Manual Usage

1. **Generate test data:**
```bash
./src/data_generator -f test_data.bin -s 128 -p random
```

2. **Start the eBPF monitor (in one terminal):**
```bash
# Python version
sudo python3 tools/pagefault_monitor.py -p <PID> -i 1000

# C++ version  
sudo ./src/fault_monitor -p <PID> -i 1000
```

3. **Run the workload (in another terminal):**
```bash
./src/mmap_workload -f test_data.bin -p random -c 10000 -t 2
```

### Command Line Options

**Data Generator (`data_generator`):**
- `-f, --file PATH`: Output file path
- `-s, --size MB`: File size in megabytes
- `-p, --pattern TYPE`: Data pattern (random, sequential, sparse)

**Workload Application (`mmap_workload`):**
- `-f, --file PATH`: Input file to memory-map
- `-p, --pattern TYPE`: Access pattern (seq, random, stride, mixed)
- `-c, --count COUNT`: Number of accesses per thread
- `-t, --threads NUM`: Number of worker threads
- `-s, --stride SIZE`: Stride size for stride pattern
- `-d, --delay MS`: Delay between accesses

**Fault Monitor (`fault_monitor` / `pagefault_monitor.py`):**
- `-p, --pid PID`: Target process ID (0 = all processes)
- `-i, --interval MS`: Statistics update interval
- `-v, --verbose`: Enable verbose real-time fault logging

## Understanding the Output

The monitor displays real-time statistics in a table format:

```
PID      TID     COMM            MAJOR    MINOR    TOTAL_MS     AVG_MS    MAX_MS    MIN_US
-------- -------- --------------- -------- -------- ------------ --------- --------- ---------
1234     1234     mmap_workload   145      23       1247.32      8.456     45.123    234.5
1234     1235     mmap_workload   167      19       1456.78      9.123     52.456    198.2
```

**Key Metrics:**
- **MAJOR**: Count of major page faults (required disk I/O)
- **MINOR**: Count of minor page faults (page in memory, no I/O)
- **TOTAL_MS**: Total I/O wait time for this thread in milliseconds
- **AVG_MS**: Average fault handling time per fault
- **MAX_MS**: Maximum time for any single fault
- **MIN_US**: Minimum fault time in microseconds

## Access Patterns

The workload generator supports different access patterns to demonstrate various page fault behaviors:

### Sequential (`seq`)
- Accesses pages in order (0, 1, 2, 3, ...)
- Best case for readahead and minimal major faults
- Demonstrates optimal I/O patterns

### Random (`random`)  
- Accesses pages in random order
- Worst case for page cache efficiency
- High major fault rate, demonstrates I/O stalls

### Stride (`stride`)
- Accesses every Nth page (configurable stride)
- Useful for testing specific memory access patterns
- Can defeat readahead mechanisms

### Mixed (`mixed`)
- Combination of 70% random + 30% sequential
- Realistic workload simulation
- Shows mixed fault patterns

## Interpreting Results

### Major vs Minor Faults

- **Major Faults**: Indicate actual disk I/O operations
  - High counts suggest insufficient memory or poor access patterns
  - Long durations indicate slow storage or heavy I/O load
  
- **Minor Faults**: Page table misses resolved without I/O
  - Normal part of memory management
  - Should be much faster than major faults

### Performance Analysis

1. **High Major Fault Rate**: 
   - File size exceeds available memory
   - Random access patterns defeating cache
   - Consider increasing memory or optimizing access patterns

2. **Long Average Fault Times**:
   - Slow storage (check with `iostat`)
   - High I/O contention
   - Storage bottleneck

3. **Per-Thread Analysis**:
   - Compare threads to identify outliers
   - Uneven workload distribution
   - Thread synchronization issues

## Advanced Usage

### Monitoring Specific Processes

```bash
# Monitor only a specific PID
sudo python3 tools/pagefault_monitor.py -p 1234

# Monitor all processes (careful with overhead)
sudo python3 tools/pagefault_monitor.py
```

### Custom Workload Testing

```bash
# Test large files that exceed RAM
./src/data_generator -s 2048 -f large_test.bin

# Test with many threads
./src/mmap_workload -f large_test.bin -t 8 -c 50000

# Test different patterns
for pattern in seq random stride mixed; do
    echo "Testing pattern: $pattern"
    ./src/mmap_workload -f test_data.bin -p $pattern -c 5000
done
```

### Integration with Other Tools

The eBPF monitoring can be combined with other system tools:

```bash
# Monitor I/O statistics
iostat -x 1 &

# Monitor memory usage  
vmstat 1 &

# Run the eBPF page fault monitor
sudo python3 tools/pagefault_monitor.py -p <PID>
```

## Troubleshooting

### Common Issues

1. **"Operation not permitted" when loading eBPF:**
   - Ensure running as root: `sudo ./fault_monitor`
   - Check if debugfs is mounted: `mount | grep debugfs`
   - Verify kernel has eBPF support: `zcat /proc/config.gz | grep BPF`

2. **"handle_mm_fault not found" error:**
   - Check available functions: `sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep handle_mm_fault`
   - Update to a newer kernel version

3. **No major faults observed:**
   - File might be cached - clear page cache: `sudo echo 3 > /proc/sys/vm/drop_caches`
   - Increase file size beyond available RAM
   - Use random access pattern

4. **Build failures:**
   - Install missing dependencies: `sudo ./scripts/setup_environment.sh`
   - Check BCC installation: `python3 -c "import bcc; print('BCC OK')"`

### Debugging

Enable verbose mode for detailed fault information:

```bash
sudo python3 tools/pagefault_monitor.py -v -p <PID>
```

Check kernel logs for eBPF related messages:
```bash
sudo dmesg | tail -20
```

## Performance Considerations

### Monitor Overhead

The eBPF approach has minimal overhead:
- Kprobe/kretprobe cost: ~1-2μs per fault
- In-kernel aggregation avoids frequent userspace communication
- Filtering by PID reduces unnecessary events

### Scalability

- Memory usage scales with number of active threads
- BPF map sizes can be adjusted in source code
- Consider sampling for very high fault rates

## Limitations

1. **Kernel Function Dependency**: Relies on `handle_mm_fault` function signature
2. **Root Privileges**: Required for kprobe attachment
3. **Kernel Version**: Requires Linux 4.1+ with eBPF support
4. **Architecture**: Tested on x86_64, may need adjustments for other architectures

## Contributing

This project demonstrates eBPF techniques for system monitoring. Contributions welcome:

1. Additional access patterns
2. Support for other filesystems  
3. Userspace probe (USDT) integration
4. Performance optimizations
5. Additional monitoring metrics

## References

- [BCC Documentation](https://github.com/iovisor/bcc)
- [eBPF Documentation](https://ebpf.io/)
- [Linux Memory Management](https://www.kernel.org/doc/html/latest/admin-guide/mm/index.html)
- [Page Fault Handling in Linux](https://www.kernel.org/doc/gorman/html/understand/understand013.html)

## License

This project is provided as educational material for learning eBPF and system monitoring techniques.