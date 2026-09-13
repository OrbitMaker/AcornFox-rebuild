#ifndef SECURITY_DARWIN_H
#define SECURITY_DARWIN_H

#include <sys/types.h>
#include <stdint.h>
#include <Security/Security.h>

#ifndef CS_RUNTIME
#define CS_RUNTIME 0x00010000
#endif

#ifndef CS_ADHOC
#define CS_ADHOC 0x00000002
#endif

// Check process raw p_stat via sysctl KERN_PROC_PID
// Returns 0 on success, fills out_pstat. SSTOP is 4.
int check_process_sstop(pid_t pid, int *out_pstat);

// Validates the running host process (SecCodeCopySelf)
// Fills out_team_id and out_flags.
int validate_host_self(char *out_team_id, size_t team_id_size, uint32_t *out_flags);

// Inspects static code on disk at path
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
);

// Compiles exact public SecRequirement
// For production: requires team_id, identifier, cdhash_hex.
// For fixture (allow_adhoc): requires identifier and cdhash_hex.
int compile_exact_requirement(
    const char *team_id,
    const char *identifier,
    const char *cdhash_hex,
    int allow_adhoc,
    SecRequirementRef *out_req,
    char *out_req_str,
    size_t req_str_size
);

// Validates dynamic guest process by PID against compiled requirement
int validate_dynamic_guest(pid_t pid, SecRequirementRef req);

// Releases a SecRequirementRef
void release_requirement(SecRequirementRef req);

// Requirement null checks
int is_null_requirement(SecRequirementRef req);
SecRequirementRef null_requirement(void);

// Spawns suspended child with posix_spawn
int spawn_suspended_child(
    const char *path,
    char *const argv[],
    char *const envp[],
    int devnull_fd,
    int stdout_write_fd,
    int stderr_write_fd,
    int lifecycle_child_fd,
    pid_t *out_pid
);

#ifdef ACORNFOX_INTERNAL_TESTING
// Fault injection hooks for posix_spawn attributes and file actions (internal testing only)
void inject_spawn_failure(int failure_code);
void clear_spawn_failure(void);
#endif

#endif /* SECURITY_DARWIN_H */
