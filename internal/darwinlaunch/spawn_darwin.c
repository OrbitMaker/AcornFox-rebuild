//go:build darwin && cgo

#include "security_darwin.h"

#include <spawn.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef ACORNFOX_INTERNAL_TESTING
static int g_injected_spawn_failure = 0;

void inject_spawn_failure(int failure_code) {
    g_injected_spawn_failure = failure_code;
}

void clear_spawn_failure(void) {
    g_injected_spawn_failure = 0;
}
#endif

int spawn_suspended_child(
    const char *path,
    char *const argv[],
    char *const envp[],
    int devnull_fd,
    int stdout_write_fd,
    int stderr_write_fd,
    int lifecycle_child_fd,
    pid_t *out_pid
) {
    if (!path || !argv || !out_pid) {
        return EINVAL;
    }

    posix_spawnattr_t attr;
    int err = posix_spawnattr_init(&attr);
    if (err != 0) {
        return err;
    }

    short flags = POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
#ifdef ACORNFOX_INTERNAL_TESTING
    if (g_injected_spawn_failure == 1) {
        err = EINVAL;
    } else {
        err = posix_spawnattr_setflags(&attr, flags);
    }
#else
    err = posix_spawnattr_setflags(&attr, flags);
#endif
    if (err != 0) {
        posix_spawnattr_destroy(&attr);
        return err;
    }

#ifdef ACORNFOX_INTERNAL_TESTING
    if (g_injected_spawn_failure == 2) {
        err = EINVAL;
    } else {
        err = posix_spawnattr_setpgroup(&attr, 0);
    }
#else
    err = posix_spawnattr_setpgroup(&attr, 0);
#endif
    if (err != 0) {
        posix_spawnattr_destroy(&attr);
        return err;
    }

    sigset_t defsignals;
    sigfillset(&defsignals);
#ifdef ACORNFOX_INTERNAL_TESTING
    if (g_injected_spawn_failure == 3) {
        err = EINVAL;
    } else {
        err = posix_spawnattr_setsigdefault(&attr, &defsignals);
    }
#else
    err = posix_spawnattr_setsigdefault(&attr, &defsignals);
#endif
    if (err != 0) {
        posix_spawnattr_destroy(&attr);
        return err;
    }

    sigset_t emptymask;
    sigemptyset(&emptymask);
#ifdef ACORNFOX_INTERNAL_TESTING
    if (g_injected_spawn_failure == 4) {
        err = EINVAL;
    } else {
        err = posix_spawnattr_setsigmask(&attr, &emptymask);
    }
#else
    err = posix_spawnattr_setsigmask(&attr, &emptymask);
#endif
    if (err != 0) {
        posix_spawnattr_destroy(&attr);
        return err;
    }

    posix_spawn_file_actions_t actions;
    err = posix_spawn_file_actions_init(&actions);
    if (err != 0) {
        posix_spawnattr_destroy(&attr);
        return err;
    }

    if (devnull_fd >= 0) {
#ifdef ACORNFOX_INTERNAL_TESTING
        if (g_injected_spawn_failure == 5) {
            err = EBADF;
        } else {
            err = posix_spawn_file_actions_adddup2(&actions, devnull_fd, STDIN_FILENO);
        }
#else
        err = posix_spawn_file_actions_adddup2(&actions, devnull_fd, STDIN_FILENO);
#endif
        if (err != 0) {
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attr);
            return err;
        }
    }
    if (stdout_write_fd >= 0) {
#ifdef ACORNFOX_INTERNAL_TESTING
        if (g_injected_spawn_failure == 6) {
            err = EBADF;
        } else {
            err = posix_spawn_file_actions_adddup2(&actions, stdout_write_fd, STDOUT_FILENO);
        }
#else
        err = posix_spawn_file_actions_adddup2(&actions, stdout_write_fd, STDOUT_FILENO);
#endif
        if (err != 0) {
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attr);
            return err;
        }
    }
    if (stderr_write_fd >= 0) {
#ifdef ACORNFOX_INTERNAL_TESTING
        if (g_injected_spawn_failure == 7) {
            err = EBADF;
        } else {
            err = posix_spawn_file_actions_adddup2(&actions, stderr_write_fd, STDERR_FILENO);
        }
#else
        err = posix_spawn_file_actions_adddup2(&actions, stderr_write_fd, STDERR_FILENO);
#endif
        if (err != 0) {
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attr);
            return err;
        }
    }
    if (lifecycle_child_fd >= 0) {
#ifdef ACORNFOX_INTERNAL_TESTING
        if (g_injected_spawn_failure == 8) {
            err = EBADF;
        } else {
            err = posix_spawn_file_actions_adddup2(&actions, lifecycle_child_fd, 3);
        }
#else
        err = posix_spawn_file_actions_adddup2(&actions, lifecycle_child_fd, 3);
#endif
        if (err != 0) {
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attr);
            return err;
        }
    }

    pid_t pid = 0;
    err = posix_spawn(&pid, path, &actions, &attr, argv, envp);

    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);

    if (err == 0) {
        *out_pid = pid;
    }
    return err;
}
