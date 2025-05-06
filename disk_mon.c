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
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>

#define EVENT_SIZE      (sizeof(struct inotify_event))
#define BUF_LEN         (1024 * (EVENT_SIZE + NAME_MAX + 1))
#define DISK_CHECK_INTERVAL 5
#define USAGE_THRESHOLD  5
#define PID_FILE        "/var/run/disk_mon.pid"
#define LOG_FILE        "/var/tmp/disk_mon.log"

// Debug mode (uncomment for debug output to /tmp)
// #define DEBUG 1

#ifdef DEBUG
#undef LOG_FILE
#define LOG_FILE "/tmp/disk_mon.debug.log"
#undef PID_FILE
#define PID_FILE "/tmp/disk_mon.pid"
#endif

typedef struct {
    unsigned long total;
    unsigned long used;
    unsigned long free;
    double usage_percent;
} DiskStats;

volatile sig_atomic_t daemon_run = 1;

void signal_handler(int sig) {
    daemon_run = 0;
    syslog(LOG_INFO, "Received shutdown signal");
}

void log_message(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    // Log to syslog
//    vsyslog(LOG_INFO, format, args);
    
    // Log to file with timestamp
    FILE *logfile = fopen(LOG_FILE, "a");
    if(logfile) {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        fprintf(logfile, "[%04d-%02d-%02d %02d:%02d:%02d] ",
                tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
        vfprintf(logfile, format, args);
        fflush(logfile);
        fclose(logfile);
    }
    va_end(args);
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        log_message("First fork failed: %m\n");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) {
        log_message("setsid failed: %m\n");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        log_message("Second fork failed: %m\n");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Ensure log file exists and is writable
    if(access(LOG_FILE, F_OK) == -1) {
        FILE *fp = fopen(LOG_FILE, "w");
        if(fp) fclose(fp);
    }

    int fd = open(LOG_FILE, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if(fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    } else {
        log_message("Failed to open log file: %m\n");
    }
}

void write_pid() {
    FILE *fp = fopen(PID_FILE, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    } else {
        log_message("Failed to create PID file: %m\n");
    }
}

DiskStats get_disk_stats(const char *path) {
    struct statvfs vfs;
    DiskStats stats = {0};
    
    if (statvfs(path, &vfs) == 0) {
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
    
    if (fabs(diff) >= USAGE_THRESHOLD) {
        log_message("DISK USAGE CHANGE: %.2f%% -> %.2f%% (Δ%.2f%%)\n",
               prev->usage_percent, current->usage_percent, diff);
    }
}

void track_large_files(const char *path) {
    static time_t last_check = 0;
    time_t now = time(NULL);
    
    if ((now - last_check) > 300) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), 
               "find %s -type f -exec du -sh {} + 2>/dev/null | sort -rh | head -n 5", path);
        
        log_message("TOP LARGE FILES:\n");
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                log_message("%s", line);
            }
            pclose(fp);
        }
        last_check = now;
    }
}

void cleanup() {
    remove(PID_FILE);
    closelog();
}

int main() {
    const char *target_dir = "/var/log";
    int inotify_fd = -1, wd = -1;

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    openlog("disk_mon", LOG_PID, LOG_DAEMON);
    daemonize();
    atexit(cleanup);
    
    // Pre-startup checks
    if(access(LOG_FILE, W_OK) == -1) {
        log_message("FATAL: No write permission for log file: %m\n");
        exit(EXIT_FAILURE);
    }

    if(access(PID_FILE, W_OK) == -1) {
        log_message("FATAL: PID file directory not writable: %m\n");
        exit(EXIT_FAILURE);
    }

    write_pid();
    log_message("Starting disk monitor daemon\n");

    inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        log_message("inotify_init failed: %m\n");
        exit(EXIT_FAILURE);
    }

    wd = inotify_add_watch(inotify_fd, target_dir, 
                          IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE);
    if (wd == -1) {
        log_message("inotify_add_watch failed: %m\n");
        close(inotify_fd);
        exit(EXIT_FAILURE);
    }

    DiskStats prev_stats = get_disk_stats(target_dir);
    time_t last_disk_check = time(NULL);

    while (daemon_run) {
        char buffer[BUF_LEN];
        ssize_t len = read(inotify_fd, buffer, BUF_LEN);
        time_t now = time(NULL);

        if ((now - last_disk_check) >= DISK_CHECK_INTERVAL) {
            DiskStats current_stats = get_disk_stats(target_dir);
            log_disk_usage(&prev_stats, &current_stats);
            prev_stats = current_stats;
            last_disk_check = now;
            
            if (current_stats.usage_percent > 90) {
                track_large_files(target_dir);
            }
        }

        if (len > 0) {
            for (char *ptr = buffer; ptr < buffer + len; ) {
                struct inotify_event *event = (struct inotify_event *)ptr;
                
                if (!(event->mask & IN_ISDIR)) {
                    char path[PATH_MAX];
                    snprintf(path, sizeof(path), "%s/%s", target_dir, event->name);
                    
                    if (event->mask & IN_CREATE)
                        log_message("CREATED: %s\n", path);
                    if (event->mask & IN_DELETE)
                        log_message("DELETED: %s\n", path);
                    if (event->mask & IN_MODIFY)
                        log_message("MODIFIED: %s\n", path);
                    if (event->mask & IN_MOVED_FROM)
                        log_message("MOVED_FROM: %s\n", path);
                    if (event->mask & IN_MOVED_TO)
                        log_message("MOVED_TO: %s\n", path);
                }
                ptr += EVENT_SIZE + event->len;
            }
        }
        usleep(100000);
    }

    log_message("Shutting down disk monitor\n");
    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);

    return EXIT_SUCCESS;
}
