#ifndef APOLLO_LINUX_ABI_H
#define APOLLO_LINUX_ABI_H

#include "program.h"

#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define EBADF 9
#define ECHILD 10
#define EAGAIN 11
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define EEXIST 17
#define ENOTDIR 20
#define EISDIR 21
#define EINVAL 22
#define EMFILE 24
#define ENOTTY 25
#define EFBIG 27
#define ENOSPC 28
#define ESPIPE 29
#define ERANGE 34
#define ENAMETOOLONG 36
#define ENOSYS 38
#define ENOTEMPTY 39
#define ENODEV 19
#define ETIMEDOUT 110
#define ERESTARTSYS 512

#define SIGINT 2
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGSEGV 11
#define SIGPIPE 13
#define SIGTERM 15
#define SIGSTOP 19
#define LINUX_SIGNALS 64

#define AT_FDCWD (-100)

#define ARG0(f) ((f)->rdi)
#define ARG1(f) ((f)->rsi)
#define ARG2(f) ((f)->rdx)
#define ARG3(f) ((f)->r10)
#define ARG4(f) ((f)->r8)
#define ARG5(f) ((f)->r9)

typedef int64_t (*linux_call_t)(interrupt_frame_t* frame);

int64_t linux_read(interrupt_frame_t* f);
int64_t linux_write(interrupt_frame_t* f);
int64_t linux_open(interrupt_frame_t* f);
int64_t linux_openat(interrupt_frame_t* f);
int64_t linux_close(interrupt_frame_t* f);
int64_t linux_stat(interrupt_frame_t* f);
int64_t linux_fstat(interrupt_frame_t* f);
int64_t linux_newfstatat(interrupt_frame_t* f);
int64_t linux_lseek(interrupt_frame_t* f);
int64_t linux_pread(interrupt_frame_t* f);
int64_t linux_pwrite(interrupt_frame_t* f);
int64_t linux_readv(interrupt_frame_t* f);
int64_t linux_writev(interrupt_frame_t* f);
int64_t linux_access(interrupt_frame_t* f);
int64_t linux_faccessat(interrupt_frame_t* f);
int64_t linux_ioctl(interrupt_frame_t* f);
int64_t linux_fcntl(interrupt_frame_t* f);
int64_t linux_dup(interrupt_frame_t* f);
int64_t linux_dup2(interrupt_frame_t* f);
int64_t linux_dup3(interrupt_frame_t* f);
int64_t linux_getdents64(interrupt_frame_t* f);
int64_t linux_getcwd(interrupt_frame_t* f);
int64_t linux_chdir(interrupt_frame_t* f);
int64_t linux_mkdir(interrupt_frame_t* f);
int64_t linux_mkdirat(interrupt_frame_t* f);
int64_t linux_rmdir(interrupt_frame_t* f);
int64_t linux_unlink(interrupt_frame_t* f);
int64_t linux_unlinkat(interrupt_frame_t* f);
int64_t linux_rename(interrupt_frame_t* f);
int64_t linux_renameat(interrupt_frame_t* f);
int64_t linux_readlink(interrupt_frame_t* f);
int64_t linux_readlinkat(interrupt_frame_t* f);
int64_t linux_fsync(interrupt_frame_t* f);
int64_t linux_ftruncate(interrupt_frame_t* f);
void linux_files_reset(void);
int64_t linux_file_read_at(int64_t fd, uint64_t buffer, uint64_t length, uint64_t offset);

int64_t linux_rt_sigaction(interrupt_frame_t* f);
int64_t linux_rt_sigprocmask(interrupt_frame_t* f);
int64_t linux_rt_sigreturn(interrupt_frame_t* f);
int64_t linux_sigaltstack(interrupt_frame_t* f);
int64_t linux_kill(interrupt_frame_t* f);
int64_t linux_tgkill(interrupt_frame_t* f);
void linux_signals_reset(void);
bool linux_signal_waiting(void);
void linux_deliver_pending(interrupt_frame_t* frame, uint64_t call, int64_t result);

#endif