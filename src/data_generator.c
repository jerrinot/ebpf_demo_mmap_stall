#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include "common.h"

static void usage(const char* prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Generate test data file for mmap demonstration\n\n");
    printf("Options:\n");
    printf("  -f, --file PATH     Output file path (default: test_data.bin)\n");
    printf("  -s, --size SIZE     File size in MB (default: %d)\n", DEFAULT_FILE_SIZE_MB);
    printf("  -p, --pattern TYPE  Data pattern: random, sequential, sparse (default: random)\n");
    printf("  -v, --verbose       Verbose output\n");
    printf("  -h, --help          Show this help\n");
}

typedef enum {
    PATTERN_RANDOM = 0,
    PATTERN_SEQUENTIAL = 1,
    PATTERN_SPARSE = 2
} data_pattern_t;

static int generate_random_data(int fd, size_t size, bool verbose) {
    const size_t chunk_size = 64 * 1024; // 64KB chunks
    char* buffer = malloc(chunk_size);
    if (!buffer) {
        perror("malloc");
        return -1;
    }
    
    srand(time(NULL));
    size_t remaining = size;
    size_t total_written = 0;
    
    while (remaining > 0) {
        size_t to_write = (remaining > chunk_size) ? chunk_size : remaining;
        
        // Fill buffer with random data
        for (size_t i = 0; i < to_write; i++) {
            buffer[i] = (char)(rand() & 0xFF);
        }
        
        ssize_t written = write(fd, buffer, to_write);
        if (written < 0) {
            perror("write");
            free(buffer);
            return -1;
        }
        
        remaining -= written;
        total_written += written;
        
        if (verbose && (total_written % (10 * MEGABYTE)) == 0) {
            printf("Generated %zu MB / %zu MB\n", 
                   total_written / MEGABYTE, size / MEGABYTE);
        }
    }
    
    free(buffer);
    return 0;
}

static int generate_sequential_data(int fd, size_t size, bool verbose) {
    const size_t chunk_size = 64 * 1024;
    char* buffer = malloc(chunk_size);
    if (!buffer) {
        perror("malloc");
        return -1;
    }
    
    size_t remaining = size;
    size_t total_written = 0;
    uint64_t counter = 0;
    
    while (remaining > 0) {
        size_t to_write = (remaining > chunk_size) ? chunk_size : remaining;
        
        // Fill buffer with sequential pattern
        uint64_t* uint64_buf = (uint64_t*)buffer;
        for (size_t i = 0; i < to_write / sizeof(uint64_t); i++) {
            uint64_buf[i] = counter++;
        }
        
        ssize_t written = write(fd, buffer, to_write);
        if (written < 0) {
            perror("write");
            free(buffer);
            return -1;
        }
        
        remaining -= written;
        total_written += written;
        
        if (verbose && (total_written % (10 * MEGABYTE)) == 0) {
            printf("Generated %zu MB / %zu MB\n", 
                   total_written / MEGABYTE, size / MEGABYTE);
        }
    }
    
    free(buffer);
    return 0;
}

static int generate_sparse_data(int fd, size_t size, bool verbose) {
    // Create sparse file with data every 64KB
    const size_t data_chunk = 4096;  // 4KB of data
    const size_t hole_size = 60 * 1024; // 60KB hole
    const size_t pattern_size = data_chunk + hole_size;
    
    char* buffer = malloc(data_chunk);
    if (!buffer) {
        perror("malloc");
        return -1;
    }
    
    srand(time(NULL));
    size_t total_written = 0;
    off_t file_pos = 0;
    
    while (file_pos < (off_t)size) {
        // Write data chunk
        for (size_t i = 0; i < data_chunk; i++) {
            buffer[i] = (char)(rand() & 0xFF);
        }
        
        if (lseek(fd, file_pos, SEEK_SET) < 0) {
            perror("lseek");
            free(buffer);
            return -1;
        }
        
        ssize_t written = write(fd, buffer, data_chunk);
        if (written < 0) {
            perror("write");
            free(buffer);
            return -1;
        }
        
        file_pos += pattern_size;
        total_written += written;
        
        if (verbose && (file_pos % (10 * MEGABYTE)) == 0) {
            printf("Generated sparse data at position %zu MB\n", file_pos / MEGABYTE);
        }
    }
    
    // Ensure file has the correct size
    if (ftruncate(fd, size) < 0) {
        perror("ftruncate");
        free(buffer);
        return -1;
    }
    
    free(buffer);
    return 0;
}

int main(int argc, char* argv[]) {
    const char* file_path = "test_data.bin";
    size_t file_size_mb = DEFAULT_FILE_SIZE_MB;
    data_pattern_t pattern = PATTERN_RANDOM;
    bool verbose = false;
    
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"size", required_argument, 0, 's'},
        {"pattern", required_argument, 0, 'p'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "f:s:p:vh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'f':
            file_path = optarg;
            break;
        case 's':
            file_size_mb = atoi(optarg);
            if (file_size_mb == 0) {
                fprintf(stderr, "Invalid size: %s\n", optarg);
                exit(1);
            }
            break;
        case 'p':
            if (strcmp(optarg, "random") == 0) {
                pattern = PATTERN_RANDOM;
            } else if (strcmp(optarg, "sequential") == 0) {
                pattern = PATTERN_SEQUENTIAL;
            } else if (strcmp(optarg, "sparse") == 0) {
                pattern = PATTERN_SPARSE;
            } else {
                fprintf(stderr, "Invalid pattern: %s\n", optarg);
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
    
    size_t file_size = file_size_mb * MEGABYTE;
    
    if (verbose) {
        printf("Generating %zu MB test file: %s\n", file_size_mb, file_path);
        printf("Pattern: %s\n", 
               pattern == PATTERN_RANDOM ? "random" :
               pattern == PATTERN_SEQUENTIAL ? "sequential" : "sparse");
    }
    
    int fd = open(file_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    
    int result;
    switch (pattern) {
    case PATTERN_RANDOM:
        result = generate_random_data(fd, file_size, verbose);
        break;
    case PATTERN_SEQUENTIAL:
        result = generate_sequential_data(fd, file_size, verbose);
        break;
    case PATTERN_SPARSE:
        result = generate_sparse_data(fd, file_size, verbose);
        break;
    default:
        result = -1;
        break;
    }
    
    close(fd);
    
    if (result == 0) {
        printf("Successfully generated %s (%zu MB)\n", file_path, file_size_mb);
    } else {
        fprintf(stderr, "Failed to generate test file\n");
        exit(1);
    }
    
    return 0;
}