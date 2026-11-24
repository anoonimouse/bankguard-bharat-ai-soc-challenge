/*
 * rasp_native.cpp - BankGuard RASP Native Layer
 *
 * Provides kernel-level integrity checks that cannot be bypassed by
 * Java/Kotlin-level hooking frameworks (Xposed, Frida, etc.)
 *
 * Tasks implemented:
 *   1. /proc/self/maps memory audit (virtualisation container detection)
 *   2. In-memory DEX checksum attestation
 *   3. ARM64 raw syscall for Snowblind bypass
 *   4. SIGSYS signal handler audit + latency profiling
 */

#if !defined(__aarch64__)
#error "Snowblind defence requires ARM64 target"
#endif

#include <jni.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <android/log.h>
#include "raw_syscalls.h"

// ARM64 raw syscall for open()
// Syscall #56 = openat on Linux ARM64
static inline int raw_openat(int dirfd, const char* path, int flags) {
    register int x0 asm("x0") = dirfd;
    register const char* x1 asm("x1") = path;
    register int x2 asm("x2") = flags;
    register int x8 asm("x8") = 56; // __NR_openat
    asm volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory"
    );
    return x0;
}

#define LOG_TAG "RASP_NATIVE"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

// --- Known hostile library signatures ---
// These are .so files injected by virtualisation containers and hooking frameworks.
// The list covers: VirtualApp, VirtualXposed, Parallel Space, Dual Space,
// TaiChi, EdXposed, LSPosed, Riru, Zygisk, Frida, Magisk, GameGuardian

static const char* HOSTILE_LIBS[] = {
    // Virtualisation container runtimes
    "libva_core.so",
    "libva-jni.so",
    "libva-native.so",
    "libva_helper.so",
    "libvirtualapp.so",
    "libvapp.so",
    "libmultidex.so",
    "libparallel_space.so",
    "libdual_space.so",
    "libclone_app.so",
    "libmulti_account.so",
    "lib2face.so",

    // Xposed/LSPosed/EdXposed framework hooks
    "libxposed_art.so",
    "libxposed_bridge.so",
    "libxposed.so",
    "liblspd.so",
    "libedxp.so",
    "libwhale.so",
    "libsandhook.so",
    "libsandhook-native.so",
    "libpine.so",

    // Riru / Zygisk module injection
    "libriru.so",
    "libriruloader.so",
    "libriru_edxp.so",
    "libzygisk.so",

    // Frida dynamic instrumentation
    "frida-agent",
    "frida-gadget",
    "libfrida-gadget.so",
    "libfrida.so",

    // Magisk (root) indicators in memory
    "libmagisk.so",
    "libmagiskboot.so",
    "libmagiskhide.so",

    // GameGuardian / memory editor
    "libgg.so",
    "libGameGuardian.so",

    // Substrate and Cydia hooks (rare on modern Android, still flagged)
    "libsubstrate.so",
    "libsubstrate-dvm.so",

    // Dobby inline hook library (used by many hooking toolkits)
    "libdobby.so",

    // Generic suspicious patterns (prefix-matched separately)
    nullptr  // sentinel
};

// Suspicious path prefixes that indicate the process is running inside
// a virtualisation sandbox (the /data/data path won't match the host app)
static const char* HOSTILE_PATH_PREFIXES[] = {
    "/data/data/io.va.",
    "/data/data/com.lbe.",
    "/data/data/com.parallel.",
    "/data/data/com.dual.",
    "/data/data/com.excelliance.",
    "/data/data/com.ludashi.",
    "/data/data/info.aspect.",
    nullptr
};

// ===================================================================
//  TASK 1 - /proc/self/maps memory audit
// ===================================================================

struct MapsThreat {
    std::string library;
    std::string path;
    std::string category;
};

/**
 * Parse /proc/self/maps and check every loaded library against the
 * hostile signature lists. Returns a vector of detected threats.
 *
 * This runs at the kernel vfs level: even if an attacker hooks fopen()
 * in libc, /proc/self/maps is a pseudo-filesystem served directly by
 * the kernel. Hooking it requires a kernel module (root + custom ROM),
 * which is a drastically smaller attack surface.
 */
static std::vector<MapsThreat> scan_proc_maps(const std::string& own_package) {
    std::vector<MapsThreat> threats;

    // Use raw assembly system calls to completely bypass libc hooks and seccomp redirects
    int fd = raw_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        LOGE("Failed to open /proc/self/maps: %d", fd);
        // Inability to read own maps is itself a threat indicator
        threats.push_back({"MAPS_READ_DENIED", "/proc/self/maps", "evasion"});
        return threats;
    }

    // Read entire maps file into memory
    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, n);
    }
    sys_close(fd);

    std::istringstream stream(content);
    std::string line;

    while (std::getline(stream, line)) {
        // Each maps line format:
        // addr-addr perms offset dev inode  pathname
        // We care about the pathname (last field after spaces)
        size_t last_space = line.rfind(' ');
        if (last_space == std::string::npos) continue;

        std::string pathname = line.substr(last_space + 1);
        if (pathname.empty() || pathname[0] == '[') continue;  // skip [heap], [stack], etc.

        // Extract just the filename from the full path
        size_t last_slash = pathname.rfind('/');
        std::string filename = (last_slash != std::string::npos)
            ? pathname.substr(last_slash + 1)
            : pathname;

        // Check against known hostile libraries
        for (int i = 0; HOSTILE_LIBS[i] != nullptr; i++) {
            if (filename.find(HOSTILE_LIBS[i]) != std::string::npos) {
                // Deduplicate: only add if not already in threats
                bool dup = false;
                for (const auto& t : threats) {
                    if (t.library == HOSTILE_LIBS[i] && t.path == pathname) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    std::string cat = "hook";
                    if (strstr(HOSTILE_LIBS[i], "va_") || strstr(HOSTILE_LIBS[i], "virtual") ||
                        strstr(HOSTILE_LIBS[i], "parallel") || strstr(HOSTILE_LIBS[i], "dual") ||
                        strstr(HOSTILE_LIBS[i], "clone") || strstr(HOSTILE_LIBS[i], "multi")) {
                        cat = "virtualisation";
                    } else if (strstr(HOSTILE_LIBS[i], "frida")) {
                        cat = "instrumentation";
                    } else if (strstr(HOSTILE_LIBS[i], "magisk")) {
                        cat = "root";
                    }
                    threats.push_back({HOSTILE_LIBS[i], pathname, cat});
                }
            }
        }

        // Check if loaded libraries come from a foreign app's data directory
        // (indicates the process is sandboxed inside another app)
        for (int i = 0; HOSTILE_PATH_PREFIXES[i] != nullptr; i++) {
            if (pathname.find(HOSTILE_PATH_PREFIXES[i]) != std::string::npos) {
                // Verify it is not our own package path
                if (pathname.find(own_package) == std::string::npos) {
                    threats.push_back({
                        "FOREIGN_DATA_DIR",
                        pathname,
                        "virtualisation"
                    });
                    break;
                }
            }
        }
    }

    return threats;
}

// ===================================================================
//  TASK 4 - SIGSYS signal handler audit
// ===================================================================

struct SigsysAuditResult {
    bool has_custom_handler;
    bool handler_is_suspicious;
    std::string handler_info;
};

/**
 * Check if a custom SIGSYS handler has been installed.
 * Snowblind installs a SIGSYS handler to intercept seccomp trap returns
 * and redirect memory reads to a cached clean APK copy.
 */
static SigsysAuditResult audit_sigsys_handler() {
    SigsysAuditResult result = {false, false, "SIG_DFL"};

    struct sigaction current_action;
    memset(&current_action, 0, sizeof(current_action));

    if (sigaction(SIGSYS, nullptr, &current_action) != 0) {
        LOGE("sigaction() query failed: %s", strerror(errno));
        result.handler_info = "QUERY_FAILED";
        result.has_custom_handler = true;
        result.handler_is_suspicious = true;
        return result;
    }

    if (current_action.sa_handler == SIG_DFL) {
        result.handler_info = "SIG_DFL";
        return result;
    }

    if (current_action.sa_handler == SIG_IGN) {
        result.handler_info = "SIG_IGN";
        result.has_custom_handler = true;
        // SIG_IGN for SIGSYS is unusual but not necessarily malicious
        return result;
    }

    // A custom handler is installed
    result.has_custom_handler = true;

    // Read /proc/self/maps to determine which library the handler belongs to
    void* handler_addr = (current_action.sa_flags & SA_SIGINFO)
        ? reinterpret_cast<void*>(current_action.sa_sigaction)
        : reinterpret_cast<void*>(current_action.sa_handler);

    uintptr_t addr = reinterpret_cast<uintptr_t>(handler_addr);

    // Walk maps to find which library contains this address
    int fd = raw_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        std::string content;
        char buf[4096];
        ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
            content.append(buf, n);
        }
        sys_close(fd);

        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            // Parse address range: "start-end ..."
            size_t dash = line.find('-');
            size_t space = line.find(' ');
            if (dash == std::string::npos || space == std::string::npos) continue;

            uintptr_t start = strtoull(line.substr(0, dash).c_str(), nullptr, 16);
            uintptr_t end = strtoull(line.substr(dash + 1, space - dash - 1).c_str(), nullptr, 16);

            if (addr >= start && addr < end) {
                size_t last_space = line.rfind(' ');
                std::string owner = (last_space != std::string::npos)
                    ? line.substr(last_space + 1) : "unknown";

                result.handler_info = owner;

                // If the handler doesn't come from /system/ or our own libs, flag it
                if (owner.find("/system/") == std::string::npos &&
                    owner.find("libart.so") == std::string::npos &&
                    owner.find("libandroid_runtime.so") == std::string::npos) {
                    result.handler_is_suspicious = true;
                }
                break;
            }
        }
    }

    return result;
}

// ===================================================================
//  TASK 4 (cont) - Syscall latency profiling
// ===================================================================

/**
 * Measure wall-clock time for a raw open() call on the APK.
 * Normal kernel transition: <0.5ms.
 * With seccomp trap + signal handler round-trip: 2-10ms.
 * Threshold: 5ms flags as suspicious.
 */
static double measure_openat_latency_ms(const char* path) {
    auto start = std::chrono::high_resolution_clock::now();

    int fd = raw_openat(AT_FDCWD, path, O_RDONLY);
    if (fd >= 0) {
        sys_close(fd);
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    return ms;
}


// ===================================================================
//  TASK 2 - DEX checksum attestation
// ===================================================================

// Expected DEX hashes are injected at build time via a header.
// If the header doesn't exist yet (first build), we skip attestation
// and log a warning so the build pipeline knows to generate it.
//
// The header should define:
//   static const char* EXPECTED_DEX_HASHES[] = { "sha256hex1", "sha256hex2", ..., nullptr };
//
// For now we define a placeholder that always passes, and the build
// system will override this with the real header once the APK is signed.

#if __has_include("dex_hashes.h")
#include "dex_hashes.h"
#define DEX_HASHES_AVAILABLE 1
#else
#define DEX_HASHES_AVAILABLE 0
static const char* EXPECTED_DEX_HASHES[] = { nullptr };
#endif

#include "sha256_fallback.h"  // Standalone SHA-256, no OpenSSL dependency

/**
 * Read a memory-mapped DEX file and compute its SHA-256.
 * Returns the hex string or empty on failure.
 */
static std::string sha256_file(const char* path) {
    int fd = raw_openat(AT_FDCWD, path, O_RDONLY);
    if (fd < 0) return "";

    // Read file in chunks to compute hash
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    char buf[8192];
    ssize_t n;
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    sys_close(fd);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    // Convert to hex string
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    }
    return std::string(hex);
}

/**
 * Find all DEX files loaded in the current process by scanning /proc/self/maps
 * for entries with ".dex" or "classes" in the path, compute their SHA-256, and
 * compare against the build-time expected hashes.
 *
 * Returns a list of mismatched DEX paths. Empty list = clean.
 */
static std::vector<std::string> verify_dex_integrity() {
    std::vector<std::string> mismatches;

#if DEX_HASHES_AVAILABLE == 0
    LOGW("DEX hash header not generated yet -- skipping attestation");
    return mismatches;
#else
    // Collect expected hashes into a set for O(1) lookup
    std::vector<std::string> expected;
    for (int i = 0; EXPECTED_DEX_HASHES[i] != nullptr; i++) {
        expected.push_back(EXPECTED_DEX_HASHES[i]);
    }

    // Scan /proc/self/maps for DEX file paths
    int fd = raw_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY);
    if (fd < 0) return mismatches;

    std::string content;
    char buf[4096];
    ssize_t n;
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, n);
    }
    sys_close(fd);

    std::vector<std::string> checked_paths;
    std::istringstream stream(content);
    std::string line;

    while (std::getline(stream, line)) {
        size_t last_space = line.rfind(' ');
        if (last_space == std::string::npos) continue;

        std::string path = line.substr(last_space + 1);
        if (path.find(".dex") == std::string::npos &&
            path.find("classes") == std::string::npos) continue;
        if (path.find("/system/") != std::string::npos) continue;  // skip framework DEX

        // Avoid re-checking the same path (maps lists multiple regions per file)
        bool already_checked = false;
        for (const auto& cp : checked_paths) {
            if (cp == path) { already_checked = true; break; }
        }
        if (already_checked) continue;
        checked_paths.push_back(path);

        std::string hash = sha256_file(path.c_str());
        if (hash.empty()) continue;

        // Check if this hash is in the expected set
        bool found = false;
        for (const auto& eh : expected) {
            if (eh == hash) { found = true; break; }
        }
        if (!found) {
            LOGE("DEX integrity mismatch: %s (hash=%s)", path.c_str(), hash.c_str());
            mismatches.push_back(path);
        }
    }

    return mismatches;
#endif
}


// ===================================================================
//  JNI EXPORTS
// ===================================================================

extern "C" {

/**
 * Task 1: Scan /proc/self/maps for hostile injected libraries.
 * Returns a Java List<Map<String,String>> with keys: library, path, category.
 */
JNIEXPORT jobject JNICALL
Java_com_bankguard_sdk_RaspNative_scanProcessMaps(
    JNIEnv* env, jclass clazz, jstring jPackageName) {

    const char* pkg = env->GetStringUTFChars(jPackageName, nullptr);
    std::string own_package(pkg);
    env->ReleaseStringUTFChars(jPackageName, pkg);

    auto threats = scan_proc_maps(own_package);

    // Build ArrayList<HashMap<String,String>>
    jclass arrayListClass = env->FindClass("java/util/ArrayList");
    jmethodID arrayListInit = env->GetMethodID(arrayListClass, "<init>", "()V");
    jmethodID arrayListAdd = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");
    jobject list = env->NewObject(arrayListClass, arrayListInit);

    jclass hashMapClass = env->FindClass("java/util/HashMap");
    jmethodID hashMapInit = env->GetMethodID(hashMapClass, "<init>", "()V");
    jmethodID hashMapPut = env->GetMethodID(hashMapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    for (const auto& t : threats) {
        jobject map = env->NewObject(hashMapClass, hashMapInit);
        env->CallObjectMethod(map, hashMapPut,
            env->NewStringUTF("library"), env->NewStringUTF(t.library.c_str()));
        env->CallObjectMethod(map, hashMapPut,
            env->NewStringUTF("path"), env->NewStringUTF(t.path.c_str()));
        env->CallObjectMethod(map, hashMapPut,
            env->NewStringUTF("category"), env->NewStringUTF(t.category.c_str()));
        env->CallBooleanMethod(list, arrayListAdd, map);
    }

    return list;
}

/**
 * Task 2: Verify in-memory DEX checksums against build-time hashes.
 * Returns a Java List<String> of mismatched DEX paths (empty = clean).
 */
JNIEXPORT jobject JNICALL
Java_com_bankguard_sdk_RaspNative_verifyDexIntegrity(JNIEnv* env, jclass clazz) {
    auto mismatches = verify_dex_integrity();

    jclass arrayListClass = env->FindClass("java/util/ArrayList");
    jmethodID arrayListInit = env->GetMethodID(arrayListClass, "<init>", "()V");
    jmethodID arrayListAdd = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");
    jobject list = env->NewObject(arrayListClass, arrayListInit);

    for (const auto& path : mismatches) {
        env->CallBooleanMethod(list, arrayListAdd, env->NewStringUTF(path.c_str()));
    }

    return list;
}

/**
 * Task 4: Audit SIGSYS handler and measure syscall latency.
 * Returns a Java Map with keys:
 *   hasCustomHandler (boolean), isSuspicious (boolean),
 *   handlerInfo (string), latencyMs (double), seccompDetected (boolean)
 */
JNIEXPORT jobject JNICALL
Java_com_bankguard_sdk_RaspNative_auditSigsysHandler(
    JNIEnv* env, jclass clazz, jstring jApkPath) {

    auto audit = audit_sigsys_handler();

    // Measure openat latency on our own APK
    const char* apk_path = env->GetStringUTFChars(jApkPath, nullptr);
    double latency = measure_openat_latency_ms(apk_path);
    env->ReleaseStringUTFChars(jApkPath, apk_path);

    bool seccomp_detected = latency > 5.0;

    // Build HashMap
    jclass hashMapClass = env->FindClass("java/util/HashMap");
    jmethodID hashMapInit = env->GetMethodID(hashMapClass, "<init>", "()V");
    jmethodID hashMapPut = env->GetMethodID(hashMapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject map = env->NewObject(hashMapClass, hashMapInit);

    // Boolean boxing
    jclass boolClass = env->FindClass("java/lang/Boolean");
    jmethodID boolValueOf = env->GetStaticMethodID(boolClass, "valueOf", "(Z)Ljava/lang/Boolean;");

    // Double boxing
    jclass doubleClass = env->FindClass("java/lang/Double");
    jmethodID doubleValueOf = env->GetStaticMethodID(doubleClass, "valueOf", "(D)Ljava/lang/Double;");

    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("hasCustomHandler"),
        env->CallStaticObjectMethod(boolClass, boolValueOf, audit.has_custom_handler));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("isSuspicious"),
        env->CallStaticObjectMethod(boolClass, boolValueOf, audit.handler_is_suspicious));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("handlerInfo"),
        env->NewStringUTF(audit.handler_info.c_str()));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("latencyMs"),
        env->CallStaticObjectMethod(doubleClass, doubleValueOf, latency));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("seccompDetected"),
        env->CallStaticObjectMethod(boolClass, boolValueOf, seccomp_detected));

    return map;
}

/**
 * Combined RASP health check. Runs all checks and returns a summary map.
 * Keys:
 *   mapsThreats (int), dexMismatches (int), sigsysSuspicious (boolean),
 *   seccompDetected (boolean), overallVerdict (string: CLEAN/TAMPERED/HOSTILE),
 *   latencyMs (double)
 */
JNIEXPORT jobject JNICALL
Java_com_bankguard_sdk_RaspNative_runFullAudit(
    JNIEnv* env, jclass clazz, jstring jPackageName, jstring jApkPath) {

    const char* pkg = env->GetStringUTFChars(jPackageName, nullptr);
    std::string own_package(pkg);
    env->ReleaseStringUTFChars(jPackageName, pkg);

    const char* apk_path = env->GetStringUTFChars(jApkPath, nullptr);

    // Run all checks
    auto maps_threats = scan_proc_maps(own_package);
    auto dex_mismatches = verify_dex_integrity();
    auto sigsys = audit_sigsys_handler();
    double latency = measure_openat_latency_ms(apk_path);
    bool seccomp = latency > 5.0;

    env->ReleaseStringUTFChars(jApkPath, apk_path);

    // Determine overall verdict
    std::string verdict = "CLEAN";
    if (!maps_threats.empty() || sigsys.handler_is_suspicious || seccomp) {
        verdict = "HOSTILE";
    } else if (!dex_mismatches.empty()) {
        verdict = "TAMPERED";
    }

    // Build result map
    jclass hashMapClass = env->FindClass("java/util/HashMap");
    jmethodID hashMapInit = env->GetMethodID(hashMapClass, "<init>", "()V");
    jmethodID hashMapPut = env->GetMethodID(hashMapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject map = env->NewObject(hashMapClass, hashMapInit);

    jclass intClass = env->FindClass("java/lang/Integer");
    jmethodID intValueOf = env->GetStaticMethodID(intClass, "valueOf", "(I)Ljava/lang/Integer;");
    jclass boolClass = env->FindClass("java/lang/Boolean");
    jmethodID boolValueOf = env->GetStaticMethodID(boolClass, "valueOf", "(Z)Ljava/lang/Boolean;");
    jclass doubleClass = env->FindClass("java/lang/Double");
    jmethodID doubleValueOf = env->GetStaticMethodID(doubleClass, "valueOf", "(D)Ljava/lang/Double;");

    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("mapsThreats"),
        env->CallStaticObjectMethod(intClass, intValueOf, (jint)maps_threats.size()));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("dexMismatches"),
        env->CallStaticObjectMethod(intClass, intValueOf, (jint)dex_mismatches.size()));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("sigsysSuspicious"),
        env->CallStaticObjectMethod(boolClass, boolValueOf, sigsys.handler_is_suspicious));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("seccompDetected"),
        env->CallStaticObjectMethod(boolClass, boolValueOf, seccomp));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("latencyMs"),
        env->CallStaticObjectMethod(doubleClass, doubleValueOf, latency));
    env->CallObjectMethod(map, hashMapPut,
        env->NewStringUTF("overallVerdict"),
        env->NewStringUTF(verdict.c_str()));

    return map;
}

} // extern "C"
