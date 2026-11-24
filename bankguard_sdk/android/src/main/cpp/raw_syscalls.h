#pragma once

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#if defined(__aarch64__)

// ARM64 inline assembly for 4-argument syscall (openat)
inline long raw_syscall4(long num, long arg1, long arg2, long arg3, long arg4) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    register long x3 __asm__("x3") = arg4;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3)
        : "memory"
    );
    return x0;
}

// ARM64 inline assembly for 3-argument syscall (read)
inline long raw_syscall3(long num, long arg1, long arg2, long arg3) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x0), "r"(x1), "r"(x2)
        : "memory"
    );
    return x0;
}

// ARM64 inline assembly for 1-argument syscall (close)
inline long raw_syscall1(long num, long arg1) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = arg1;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x0)
        : "memory"
    );
    return x0;
}

inline int sys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    return (int)raw_syscall4(__NR_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode);
}

inline ssize_t sys_read(int fd, void *buf, size_t count) {
    return (ssize_t)raw_syscall3(__NR_read, (long)fd, (long)buf, (long)count);
}

inline int sys_close(int fd) {
    return (int)raw_syscall1(__NR_close, (long)fd);
}

#elif defined(__x86_64__)

// x86_64 inline assembly for 4-argument syscall (openat)
inline long raw_syscall4(long num, long arg1, long arg2, long arg3, long arg4) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

// x86_64 inline assembly for 3-argument syscall (read)
inline long raw_syscall3(long num, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

// x86_64 inline assembly for 1-argument syscall (close)
inline long raw_syscall1(long num, long arg1) {
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

inline int sys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    return (int)raw_syscall4(__NR_openat, (long)dirfd, (long)pathname, (long)flags, (long)mode);
}

inline ssize_t sys_read(int fd, void *buf, size_t count) {
    return (ssize_t)raw_syscall3(__NR_read, (long)fd, (long)buf, (long)count);
}

inline int sys_close(int fd) {
    return (int)raw_syscall1(__NR_close, (long)fd);
}

#else

// Fallback to standard libc-wrapped syscall() for 32-bit or other platforms
inline int sys_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    return (int)syscall(__NR_openat, dirfd, pathname, flags, mode);
}

inline ssize_t sys_read(int fd, void *buf, size_t count) {
    return (ssize_t)syscall(__NR_read, fd, buf, count);
}

inline int sys_close(int fd) {
    return (int)syscall(__NR_close, fd);
}

#endif

// Generic sys_open wrapping sys_openat
inline int sys_open(const char *pathname, int flags, mode_t mode = 0) {
    return sys_openat(AT_FDCWD, pathname, flags, mode);
}
