#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include "common.h"

static volatile bool running = true;
static config_t global_config;
static fault_stats_t global_stats = {0};
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int sig) {
    (void)sig;
    running = false;
}

static void usage(const char* prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Memory-mapped file workload generator for eBPF fault monitoring\n\n");
    printf("Options:\n");
    printf("  -f, --file PATH     Input file path (default: test_data.bin)\n");
    printf("  -p, --pattern TYPE  Access pattern: seq, random, stride, mixed (default: random)\n");
    printf("  -c, --count COUNT   Number of accesses (default: %d)\n", DEFAULT_ACCESS_COUNT);
    printf("  -s, --stride SIZE   Stride size for stride pattern (default: 64)\n");
    printf("  -t, --threads NUM   Number of worker threads (default: 1)\n");
    printf("  -d, --delay MS      Delay between accesses in ms (default: 0)\n");
    printf("  -v, --verbose       Verbose output\n");
    printf("  -h, --help          Show this help\n");
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void update_stats(uint64_t access_time) {
    pthread_mutex_lock(&stats_mutex);
    global_stats.total_accesses++;
    // Note: fault counts will be updated by eBPF program
    pthread_mutex_unlock(&stats_mutex);
}

static void print_progress(size_t current, size_t total, const char* pattern) {
    if (current % 1000 == 0 || current == total) {
        printf("\r[%s] Progress: %zu/%zu (%.1f%%) - PID: %d", 
               pattern, current, total, 
               (double)current / total * 100.0, getpid());
        fflush(stdout);
    }
}

static int perform_sequential_access(void* mapped_data, size_t file_size, 
                                   uint32_t access_count, uint32_t delay_ms, bool verbose) {
    size_t page_size = getpagesize();
    size_t max_pages = file_size / page_size;
    volatile char* data = (volatile char*)mapped_data;
    
    for (uint32_t i = 0; i < access_count && running; i++) {
        size_t page_idx = i % max_pages;
        size_t offset = page_idx * page_size;
        
        uint64_t start_time = get_time_ns();
        
        // Access the page (trigger potential page fault)
        volatile char dummy = data[offset];
        (void)dummy; // Prevent optimization
        
        uint64_t end_time = get_time_ns();
        update_stats(end_time - start_time);
        
        if (verbose) {
            print_progress(i + 1, access_count, "SEQUENTIAL");
        }
        
        if (delay_ms > 0) {
            usleep(delay_ms * 1000);
        }
    }
    
    if (verbose) printf("\n");
    return 0;
}

static int perform_random_access(void* mapped_data, size_t file_size,
                                uint32_t access_count, uint32_t delay_ms, bool verbose) {
    size_t page_size = getpagesize();
    size_t max_pages = file_size / page_size;
    volatile char* data = (volatile char*)mapped_data;
    
    srand(time(NULL) + getpid());
    
    for (uint32_t i = 0; i < access_count && running; i++) {
        size_t page_idx = rand() % max_pages;
        size_t offset = page_idx * page_size;
        
        uint64_t start_time = get_time_ns();
        
        // Access random page
        volatile char dummy = data[offset];
        (void)dummy;
        
        uint64_t end_time = get_time_ns();
        update_stats(end_time - start_time);
        
        if (verbose) {
            print_progress(i + 1, access_count, "RANDOM");
        }
        
        if (delay_ms > 0) {
            usleep(delay_ms * 1000);
        }
    }
    
    if (verbose) printf("\n");
    return 0;
}

static int perform_stride_access(void* mapped_data, size_t file_size,
                                uint32_t access_count, uint32_t stride_size, 
                                uint32_t delay_ms, bool verbose) {
    size_t page_size = getpagesize();
    size_t max_pages = file_size / page_size;
    volatile char* data = (volatile char*)mapped_data;
    
    size_t current_page = 0;
    
    for (uint32_t i = 0; i < access_count && running; i++) {
        size_t offset = current_page * page_size;
        
        uint64_t start_time = get_time_ns();
        
        // Access with stride pattern
        volatile char dummy = data[offset];
        (void)dummy;
        
        uint64_t end_time = get_time_ns();
        update_stats(end_time - start_time);
        
        current_page = (current_page + stride_size) % max_pages;
        
        if (verbose) {
            print_progress(i + 1, access_count, "STRIDE");
        }
        
        if (delay_ms > 0) {
            usleep(delay_ms * 1000);
        }
    }
    
    if (verbose) printf("\n");
    return 0;
}

static int perform_mixed_access(void* mapped_data, size_t file_size,
                               uint32_t access_count, uint32_t delay_ms, bool verbose) {
    size_t page_size = getpagesize();
    size_t max_pages = file_size / page_size;
    volatile char* data = (volatile char*)mapped_data;
    
    srand(time(NULL) + getpid());
    size_t seq_page = 0;
    
    for (uint32_t i = 0; i < access_count && running; i++) {
        size_t offset;
        
        // Mix of sequential and random (70% random, 30% sequential)
        if (rand() % 100 < 70) {
            // Random access
            size_t page_idx = rand() % max_pages;
            offset = page_idx * page_size;
        } else {
            // Sequential access
            offset = seq_page * page_size;
            seq_page = (seq_page + 1) % max_pages;
        }
        
        uint64_t start_time = get_time_ns();
        
        volatile char dummy = data[offset];
        (void)dummy;
        
        uint64_t end_time = get_time_ns();
        update_stats(end_time - start_time);
        
        if (verbose) {
            print_progress(i + 1, access_count, "MIXED");
        }
        
        if (delay_ms > 0) {
            usleep(delay_ms * 1000);
        }
    }
    
    if (verbose) printf("\n");
    return 0;
}

typedef struct {
    void* mapped_data;
    size_t file_size;
    uint32_t access_count;
    uint32_t thread_id;
    access_pattern_t pattern;
    uint32_t stride_size;
    uint32_t delay_ms;
    bool verbose;
} thread_args_t;

static void* worker_thread(void* arg) {
    thread_args_t* args = (thread_args_t*)arg;
    
    if (args->verbose) {
        printf("Thread %u starting with %u accesses\n", 
               args->thread_id, args->access_count);
    }
    
    int result = 0;
    switch (args->pattern) {
    case ACCESS_SEQUENTIAL:
        result = perform_sequential_access(args->mapped_data, args->file_size,
                                         args->access_count, args->delay_ms, false);
        break;
    case ACCESS_RANDOM:
        result = perform_random_access(args->mapped_data, args->file_size,
                                     args->access_count, args->delay_ms, false);
        break;
    case ACCESS_STRIDE:
        result = perform_stride_access(args->mapped_data, args->file_size,
                                     args->access_count, args->stride_size,
                                     args->delay_ms, false);
        break;
    case ACCESS_MIXED:
        result = perform_mixed_access(args->mapped_data, args->file_size,
                                    args->access_count, args->delay_ms, false);
        break;
    }
    
    if (args->verbose) {
        printf("Thread %u completed\n", args->thread_id);
    }
    
    return (void*)(long)result;
}

int main(int argc, char* argv[]) {
    const char* file_path = "test_data.bin";
    access_pattern_t pattern = ACCESS_RANDOM;
    uint32_t access_count = DEFAULT_ACCESS_COUNT;
    uint32_t stride_size = 64;
    uint32_t num_threads = 1;
    uint32_t delay_ms = 0;
    bool verbose = false;
    
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"pattern", required_argument, 0, 'p'},
        {"count", required_argument, 0, 'c'},
        {"stride", required_argument, 0, 's'},
        {"threads", required_argument, 0, 't'},
        {"delay", required_argument, 0, 'd'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "f:p:c:s:t:d:vh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'f':
            file_path = optarg;
            break;
        case 'p':
            if (strcmp(optarg, "seq") == 0) {
                pattern = ACCESS_SEQUENTIAL;
            } else if (strcmp(optarg, "random") == 0) {
                pattern = ACCESS_RANDOM;
            } else if (strcmp(optarg, "stride") == 0) {
                pattern = ACCESS_STRIDE;
            } else if (strcmp(optarg, "mixed") == 0) {
                pattern = ACCESS_MIXED;
            } else {
                fprintf(stderr, "Invalid pattern: %s\n", optarg);
                exit(1);
            }
            break;
        case 'c':
            access_count = atoi(optarg);
            break;
        case 's':
            stride_size = atoi(optarg);
            break;
        case 't':
            num_threads = atoi(optarg);
            if (num_threads == 0 || num_threads > 32) {
                fprintf(stderr, "Invalid thread count: %s\n", optarg);
                exit(1);
            }
            break;
        case 'd':
            delay_ms = atoi(optarg);
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
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Open and map the file
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        exit(1);
    }
    
    void* mapped_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped_data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(1);
    }
    
    close(fd); // Can close fd after mmap
    
    const char* pattern_names[] = {"sequential", "random", "stride", "mixed"};
    
    printf("Starting mmap workload:\n");
    printf("  File: %s (%zu MB)\n", file_path, st.st_size / MEGABYTE);
    printf("  Pattern: %s\n", pattern_names[pattern]);
    printf("  Accesses per thread: %u\n", access_count);
    printf("  Threads: %u\n", num_threads);
    printf("  PID: %d\n", getpid());
    if (pattern == ACCESS_STRIDE) {
        printf("  Stride size: %u pages\n", stride_size);
    }
    if (delay_ms > 0) {
        printf("  Delay: %u ms\n", delay_ms);
    }
    printf("\nUse this PID with the eBPF monitor.\n\n");
    
    uint64_t start_time = get_time_ns();
    
    if (num_threads == 1) {
        // Single-threaded execution
        int result = 0;
        switch (pattern) {
        case ACCESS_SEQUENTIAL:
            result = perform_sequential_access(mapped_data, st.st_size,
                                             access_count, delay_ms, verbose);
            break;
        case ACCESS_RANDOM:
            result = perform_random_access(mapped_data, st.st_size,
                                         access_count, delay_ms, verbose);
            break;
        case ACCESS_STRIDE:
            result = perform_stride_access(mapped_data, st.st_size,
                                         access_count, stride_size, delay_ms, verbose);
            break;
        case ACCESS_MIXED:
            result = perform_mixed_access(mapped_data, st.st_size,
                                        access_count, delay_ms, verbose);
            break;
        }
        
        if (result != 0) {
            fprintf(stderr, "Workload execution failed\n");
            munmap(mapped_data, st.st_size);
            exit(1);
        }
    } else {
        // Multi-threaded execution
        pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
        thread_args_t* thread_args = malloc(num_threads * sizeof(thread_args_t));
        
        if (!threads || !thread_args) {
            perror("malloc");
            munmap(mapped_data, st.st_size);
            exit(1);
        }
        
        // Create threads
        for (uint32_t i = 0; i < num_threads; i++) {
            thread_args[i].mapped_data = mapped_data;
            thread_args[i].file_size = st.st_size;
            thread_args[i].access_count = access_count;
            thread_args[i].thread_id = i;
            thread_args[i].pattern = pattern;
            thread_args[i].stride_size = stride_size;
            thread_args[i].delay_ms = delay_ms;
            thread_args[i].verbose = verbose;
            
            if (pthread_create(&threads[i], NULL, worker_thread, &thread_args[i]) != 0) {
                perror("pthread_create");
                free(threads);
                free(thread_args);
                munmap(mapped_data, st.st_size);
                exit(1);
            }
        }
        
        // Wait for threads to complete
        for (uint32_t i = 0; i < num_threads; i++) {
            void* thread_result;
            pthread_join(threads[i], &thread_result);
            if ((long)thread_result != 0) {
                fprintf(stderr, "Thread %u failed\n", i);
            }
        }
        
        free(threads);
        free(thread_args);
    }
    
    uint64_t end_time = get_time_ns();
    double total_time_sec = (end_time - start_time) / 1e9;
    
    printf("\nWorkload completed:\n");
    printf("  Total time: %.2f seconds\n", total_time_sec);
    printf("  Total accesses: %lu\n", global_stats.total_accesses);
    printf("  Access rate: %.0f accesses/sec\n", 
           global_stats.total_accesses / total_time_sec);
    
    munmap(mapped_data, st.st_size);
    return 0;
}