/* gcc -static -o disk_mon disk_mon.c */

#include <sys/inotify.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/statvfs.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + NAME_MAX + 1))
#define DISK_CHECK_INTERVAL 5  // Seconds between disk checks
#define USAGE_THRESHOLD  5     // Percentage change to trigger alert

typedef struct {
    unsigned long total;
    unsigned long used;
    unsigned long free;
    double usage_percent;
} DiskStats;

void print_timestamp() {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("[%s] ", buffer);
}

DiskStats get_disk_stats(const char *path) {
    struct statvfs vfs;
    DiskStats stats = {0};
    
    if(statvfs(path, &vfs) == 0) {
        unsigned long block_size = vfs.f_frsize;
        stats.total = vfs.f_blocks * block_size;
        stats.free = vfs.f_bfree * block_size;
        stats.used = stats.total - stats.free;
        stats.usage_percent = ((double)stats.used / stats.total) * 100;
    }
    return stats;
}

void log_disk_usage(DiskStats *prev, DiskStats *current) {
    double diff = current->usage_percent - prev->usage_percent;
    
    if(fabs(diff) >= USAGE_THRESHOLD) {
        print_timestamp();
        printf("DISK USAGE CHANGE: %.2f%% -> %.2f%% (Δ%.2f%%)\n",
              prev->usage_percent, current->usage_percent, diff);
    }
}

void track_large_files(const char *path) {
    static time_t last_check = 0;
    time_t now = time(NULL);
    
    if((now - last_check) > 300) {  // Every 5 minutes
        char cmd[256];
        snprintf(cmd, sizeof(cmd), 
               "find %s -type f -exec du -sh {} + 2>/dev/null | sort -rh | head -n 5", path);
        
        print_timestamp();
        printf("TOP LARGE FILES:\n");
        system(cmd);
        last_check = now;
    }
}

int main() {
    const char *target_dir = "/var/log";
    int inotify_fd, wd;
    DiskStats prev_stats = get_disk_stats(target_dir);
    time_t last_disk_check = time(NULL);
    
    inotify_fd = inotify_init();
    if(inotify_fd == -1) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    wd = inotify_add_watch(inotify_fd, target_dir, 
                          IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVE);
    if(wd == -1) {
        fprintf(stderr, "Failed to watch %s: %s\n", target_dir, strerror(errno));
        close(inotify_fd);
        exit(EXIT_FAILURE);
    }

    printf("Monitoring: %s (Disk: %.2f%% used)\n", target_dir, prev_stats.usage_percent);
    
    while(1) {
        char buffer[BUF_LEN];
        ssize_t len = read(inotify_fd, buffer, BUF_LEN);
        time_t now = time(NULL);
        
        // Check disk usage periodically
        if((now - last_disk_check) >= DISK_CHECK_INTERVAL) {
            DiskStats current_stats = get_disk_stats(target_dir);
            log_disk_usage(&prev_stats, &current_stats);
            prev_stats = current_stats;
            last_disk_check = now;
            
            if(current_stats.usage_percent > 90) {
                track_large_files(target_dir);
            }
        }

        // Process inotify events
        if(len > 0) {
            for(char *ptr = buffer; ptr < buffer + len; ) {
                struct inotify_event *event = (struct inotify_event *)ptr;
                
                if(!(event->mask & IN_ISDIR)) {
                    print_timestamp();
                    char path[PATH_MAX];
                    snprintf(path, sizeof(path), "%s/%s", target_dir, event->name);
                    
                    if(event->mask & IN_CREATE) printf("CREATED: %s\n", path);
                    if(event->mask & IN_DELETE) printf("DELETED: %s\n", path);
                    if(event->mask & IN_MODIFY) printf("MODIFIED: %s\n", path);
                    if(event->mask & IN_MOVED_FROM) printf("MOVED_FROM: %s\n", path);
                    if(event->mask & IN_MOVED_TO) printf("MOVED_TO: %s\n", path);
                }
                ptr += EVENT_SIZE + event->len;
            }
        }
        usleep(100000);
    }

    close(inotify_fd);
    return 0;
}
