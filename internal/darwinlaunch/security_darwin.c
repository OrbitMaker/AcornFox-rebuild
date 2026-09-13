//go:build darwin && cgo

#include "security_darwin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

int check_process_sstop(pid_t pid, int *out_pstat) {
    if (!out_pstat || pid <= 0) {
        return -1;
    }
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, size);
    int ret = sysctl(mib, 4, &info, &size, NULL, 0);
    if (ret != 0 || size < sizeof(info)) {
        return -1;
    }
    *out_pstat = (int)info.kp_proc.p_stat;
    return 0;
}

int validate_host_self(char *out_team_id, size_t team_id_size, uint32_t *out_flags) {
    if (!out_flags) {
        return -1;
    }
    *out_flags = 0;
    if (out_team_id && team_id_size > 0) {
        out_team_id[0] = '\0';
    }

    SecCodeRef selfCode = NULL;
    OSStatus st = SecCodeCopySelf(kSecCSDefaultFlags, &selfCode);
    if (st != errSecSuccess || !selfCode) {
        return (int)st;
    }

    st = SecCodeCheckValidity(selfCode, kSecCSDefaultFlags, NULL);
    if (st != errSecSuccess) {
        CFRelease(selfCode);
        return (int)st;
    }

    CFDictionaryRef signInfo = NULL;
    st = SecCodeCopySigningInformation(selfCode, kSecCSDefaultFlags, &signInfo);
    if (st != errSecSuccess || !signInfo) {
        CFRelease(selfCode);
        return (int)st;
    }

    CFTypeRef teamRef = CFDictionaryGetValue(signInfo, kSecCodeInfoTeamIdentifier);
    if (teamRef && CFGetTypeID(teamRef) == CFStringGetTypeID()) {
        CFStringGetCString((CFStringRef)teamRef, out_team_id, (CFIndex)team_id_size, kCFStringEncodingUTF8);
    }

    CFTypeRef flagsRef = CFDictionaryGetValue(signInfo, kSecCodeInfoFlags);
    if (flagsRef && CFGetTypeID(flagsRef) == CFNumberGetTypeID()) {
        CFNumberGetValue((CFNumberRef)flagsRef, kCFNumberSInt32Type, out_flags);
    }

    CFRelease(signInfo);
    CFRelease(selfCode);
    return 0;
}

int inspect_static_code(
    const char *path,
    char *out_identifier,
    size_t id_size,
    char *out_team_id,
    size_t team_size,
    char *out_cdhash_hex,
    size_t cdhash_size,
    uint32_t *out_flags,
    int *out_is_valid
) {
    if (!path || !out_is_valid) {
        return -1;
    }
    *out_is_valid = 0;
    if (out_identifier && id_size > 0) out_identifier[0] = '\0';
    if (out_team_id && team_size > 0) out_team_id[0] = '\0';
    if (out_cdhash_hex && cdhash_size > 0) out_cdhash_hex[0] = '\0';
    if (out_flags) *out_flags = 0;

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) {
        return -1;
    }

    SecStaticCodeRef staticCode = NULL;
    OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);
    if (st != errSecSuccess || !staticCode) {
        return (int)st;
    }

    SecCSFlags valFlags = kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSDoNotValidateResources;
    st = SecStaticCodeCheckValidity(staticCode, valFlags, NULL);
    if (st == errSecSuccess) {
        *out_is_valid = 1;
    }

    CFDictionaryRef signInfo = NULL;
    OSStatus infoSt = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &signInfo);
    if (infoSt == errSecSuccess && signInfo) {
        CFTypeRef uniqueRef = CFDictionaryGetValue(signInfo, kSecCodeInfoUnique);
        if (uniqueRef && CFGetTypeID(uniqueRef) == CFDataGetTypeID()) {
            CFDataRef data = (CFDataRef)uniqueRef;
            CFIndex len = CFDataGetLength(data);
            const UInt8 *bytes = CFDataGetBytePtr(data);
            if (out_cdhash_hex && cdhash_size > (size_t)(len * 2)) {
                for (CFIndex i = 0; i < len; i++) {
                    snprintf(out_cdhash_hex + (i * 2), cdhash_size - (i * 2), "%02x", bytes[i]);
                }
                out_cdhash_hex[len * 2] = '\0';
            }
        }

        CFTypeRef idRef = CFDictionaryGetValue(signInfo, kSecCodeInfoIdentifier);
        if (idRef && CFGetTypeID(idRef) == CFStringGetTypeID()) {
            if (out_identifier && id_size > 0) {
                CFStringGetCString((CFStringRef)idRef, out_identifier, (CFIndex)id_size, kCFStringEncodingUTF8);
            }
        }

        CFTypeRef teamRef = CFDictionaryGetValue(signInfo, kSecCodeInfoTeamIdentifier);
        if (teamRef && CFGetTypeID(teamRef) == CFStringGetTypeID()) {
            if (out_team_id && team_size > 0) {
                CFStringGetCString((CFStringRef)teamRef, out_team_id, (CFIndex)team_size, kCFStringEncodingUTF8);
            }
        }

        CFTypeRef flagsRef = CFDictionaryGetValue(signInfo, kSecCodeInfoFlags);
        if (flagsRef && CFGetTypeID(flagsRef) == CFNumberGetTypeID()) {
            if (out_flags) {
                CFNumberGetValue((CFNumberRef)flagsRef, kCFNumberSInt32Type, out_flags);
            }
        }

        CFRelease(signInfo);
    }

    CFRelease(staticCode);
    return (int)st;
}

int compile_exact_requirement(
    const char *team_id,
    const char *identifier,
    const char *cdhash_hex,
    int allow_adhoc,
    SecRequirementRef *out_req,
    char *out_req_str,
    size_t req_str_size
) {
    if (!out_req || !identifier || !cdhash_hex) {
        return -1;
    }
    *out_req = NULL;

    char req_buf[1024];
    if (allow_adhoc) {
        snprintf(req_buf, sizeof(req_buf),
                 "identifier \"%s\" and cdhash H\"%s\"",
                 identifier, cdhash_hex);
    } else {
        if (!team_id || strlen(team_id) == 0) {
            return -1;
        }
        snprintf(req_buf, sizeof(req_buf),
                 "anchor apple generic and certificate leaf[subject.OU] = \"%s\" and identifier \"%s\" and cdhash H\"%s\"",
                 team_id, identifier, cdhash_hex);
    }

    if (out_req_str && req_str_size > 0) {
        snprintf(out_req_str, req_str_size, "%s", req_buf);
    }

    CFStringRef cfStr = CFStringCreateWithCString(kCFAllocatorDefault, req_buf, kCFStringEncodingUTF8);
    if (!cfStr) {
        return -1;
    }

    OSStatus st = SecRequirementCreateWithString(cfStr, kSecCSDefaultFlags, out_req);
    CFRelease(cfStr);
    return (int)st;
}

int validate_dynamic_guest(pid_t pid, SecRequirementRef req) {
    if (pid <= 0 || !req) {
        return -1;
    }

    int pidVal = (int)pid;
    CFNumberRef pidNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pidVal);
    if (!pidNum) {
        return -1;
    }

    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { pidNum };
    CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFRelease(pidNum);
    if (!attrs) {
        return -1;
    }

    SecCodeRef guestCode = NULL;
    OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &guestCode);
    CFRelease(attrs);
    if (st != errSecSuccess || !guestCode) {
        return (int)st;
    }

    st = SecCodeCheckValidity(guestCode, kSecCSDefaultFlags, req);
    CFRelease(guestCode);
    return (int)st;
}

void release_requirement(SecRequirementRef req) {
    if (req) {
        CFRelease(req);
    }
}

int is_null_requirement(SecRequirementRef req) {
    return req == NULL;
}

SecRequirementRef null_requirement(void) {
    return NULL;
}
