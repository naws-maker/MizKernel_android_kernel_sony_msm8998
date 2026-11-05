#!/usr/bin/env python3
"""
Patch MizKernel (Linux 4.4, yoshino) source for BakaSU manual hooks.

What it fixes:
  * fs/exec.c:
      - broken `ksu_handle_execve`/`ksu_handle_post_execve` externs
        (missing semicolon + wrong API for kernels >= 3.14)
        -> replaced with `ksu_handle_execveat`/`ksu_handle_post_execveat`
      - calls in do_execveat_common updated to the 3.14+ API
      - deprecated do_execve/compat_do_execve calls removed (would double-hook)
  * fs/read_write.c:
      - drop commented `ksu_vfs_read_hook` leftovers (BakaSU treats them
        as an incompatible hook and fails the build)
  * security/selinux/hooks.c:
      - drop `is_ksu_transition` (KernelSU-Next/SukiSU specific, BakaSU
        treats it as an incompatible hook)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(".")


def patch_file(path, replacements):
    p = ROOT / path
    text = p.read_text(encoding="utf-8", errors="surrogateescape")
    for label, pattern, repl, count in replacements:
        text, n = re.subn(pattern, repl, text, count=count, flags=re.S)
        if n != count:
            sys.exit(
                "PATCH FAILED: %s: %s (replaced %d, expected %d)"
                % (path, label, n, count)
            )
    p.write_text(text, encoding="utf-8", errors="surrogateescape")
    print("patched %s" % path)


# ---------------------------------------------------------------- fs/exec.c
EXEC_DECL_OLD = (
    r"#ifdef CONFIG_KSU_MANUAL_HOOK[ \t]*\n"
    r"[ \t]*__attribute__\(\(hot\)\)[ \t]*\n"
    r"[ \t]*extern int ksu_handle_execve\([^)]*\);[ \t]*\n"
    r"[ \t]*__attribute__\(\(hot\)\)[ \t]*\n"
    r"[ \t]*extern int ksu_handle_post_execve\([^)]*\)[ \t]*\n"
    r"#endif"
)
EXEC_DECL_NEW = (
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\t__attribute__((hot))\n"
    "\textern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
    "\t\t\t\t\tvoid *argv, void *envp, int *flags);\n"
    "\t__attribute__((hot))\n"
    "\textern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,\n"
    "\t\t\t\t\tvoid *argv, void *envp, int *flags, int *retval);\n"
    "#endif"
)

EXEC_CALL_OLD = (
    r"#ifdef CONFIG_KSU_MANUAL_HOOK[ \t]*\n"
    r"[ \t]*ksu_handle_execve\(\(int \*\)AT_FDCWD, filename, &argv, &envp, 0\);[ \t]*\n"
    r"[ \t]*#endif"
)
EXEC_CALL_NEW = (
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
    "#endif"
)

POST_CALL_OLD = (
    r"#ifdef CONFIG_KSU_MANUAL_HOOK[ \t]*\n"
    r"[ \t]*ksu_handle_post_execve\(\(int \*\)AT_FDCWD, &filename, &argv, &envp, 0, &retval\);[ \t]*\n"
    r"[ \t]*#endif"
)
POST_CALL_NEW = (
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);\n"
    "#endif"
)

# deprecated 3.14+ hooks in do_execve()/compat_do_execve() -> remove (double hook)
DEPRECATED_CALL = (
    r"#ifdef CONFIG_KSU[^\n]*\n"
    r"[ \t]*ksu_handle_execveat\(\(int \*\)AT_FDCWD, &filename, &argv, &envp, 0\);[ \t]*\n"
    r"[ \t]*#endif[^\n]*\n"
)

patch_file(
    "fs/exec.c",
    [
        ("execve externs", EXEC_DECL_OLD, EXEC_DECL_NEW, 1),
        ("execve call", EXEC_CALL_OLD, EXEC_CALL_NEW, 1),
        ("post_execve call", POST_CALL_OLD, POST_CALL_NEW, 1),
        ("deprecated calls", DEPRECATED_CALL, "", 2),
    ],
)

# ---------------------------------------------------------- fs/read_write.c
p = ROOT / "fs/read_write.c"
lines = p.read_text(encoding="utf-8", errors="surrogateescape").splitlines(True)
kept = [line for line in lines if "ksu_vfs_read_hook" not in line]
if len(kept) == len(lines):
    sys.exit("PATCH FAILED: fs/read_write.c: ksu_vfs_read_hook not found")
p.write_text("".join(kept), encoding="utf-8", errors="surrogateescape")
print("patched fs/read_write.c (removed %d lines)" % (len(lines) - len(kept)))

# -------------------------------------------------- security/selinux/hooks.c
SELINUX_EXTERN = (
    r"#ifdef CONFIG_KSU[ \t]*\n"
    r"[ \t]*extern bool is_ksu_transition\([^)]*\);[ \t]*\n"
    r"[ \t]*#endif[ \t]*\n"
)
SELINUX_USE = (
    r"#ifdef CONFIG_KSU[ \t]*\n"
    r"\s*if \(is_ksu_transition\([^)]*\)\) \{\s*"
    r"return 0;\s*"
    r"\}\s*"
    r"#endif[ \t]*\n"
)
patch_file(
    "security/selinux/hooks.c",
    [
        ("is_ksu_transition extern", SELINUX_EXTERN, "", 1),
        ("is_ksu_transition use", SELINUX_USE, "", 1),
    ],
)

# -------------------------------------------- security/selinux/ss/services.c
patch_file(
    "security/selinux/ss/services.c",
    [
        ("is_ksu_transition extern", SELINUX_EXTERN, "", 1),
        ("is_ksu_transition use", SELINUX_USE, "", 1),
    ],
)

print("all BakaSU manual-hook patches applied")
