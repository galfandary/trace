#include <bits/stdc++.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include "hash.hpp"
using namespace std;

static inline const char *
add_file(const char *file, size_t n = 0, bool newOnly = true) {
    static MMH3Set_t s;
    return s.add(file, n, newOnly);
}

struct list_t : vector<const char *> {
    void add(const char *v, size_t n = 0) {
        auto f = add_file(v, n);
        if (f) push_back(f);
    }
    void save(const char *file) {
        if (empty()) return;
        auto fp = fopen(file, "wb");
        if (!fp) return;
        sort(begin(), end(),
             [](const char *a, const char *b) {
                 return strcmp(a, b) < 0;
             });
        for (auto &i: *this)
            fprintf(fp, "%s\n", i);
        fclose(fp);
    }
};

static list_t file_list;

static inline bool add_input(const char *file) {
    if (!file) return false;
    struct stat s;
    if (stat(file, &s)) return false;
    if (S_ISDIR(s.st_mode)) return false;
    if (!s.st_size) return false;
    return true;
}

static inline long get_link(const char *file, char *buf) {
    auto r = readlink(file, buf, PATH_MAX);
    if (r >= 0) buf[r] = 0;
    return r;
}

static inline void add_exe(pid_t pid) {
    char file[64];
    sprintf(file, "/proc/%d/exe", pid);
    char buf[PATH_MAX];
    auto r = get_link(file, buf);
    if (r >= 0) file_list.add(buf, r);
}

static inline bool add_fd(pid_t pid, int fd, char *buf) {
    char file[64];
    sprintf(file, "/proc/%d/fd/%d", pid, fd);
    auto r = get_link(file, buf);
    if (r < 0 || !add_input(buf)) return false;
    file_list.add(buf, r);
    return true;
}

static inline int add_cwd(pid_t pid, char *file) {
    if (file[0] == '/') return 0;
    char buf[PATH_MAX], cwd[64];
    sprintf(cwd, "/proc/%d/cwd", pid);
    auto r = get_link(cwd, buf);
    if (r < 0) return -1;
    auto s = buf + r;
    *s++ = '/';
    strcpy(s, file);
    strcpy(file, buf);
    return 0;
}

static inline void add_relative(pid_t pid, char *file) {
    if (add_cwd(pid, file) || !add_file(file)) return;
    auto f = strrchr(file, '/');
    if (!f) return;
    *f++ = 0;
    char buf[PATH_MAX];
    if (!realpath(file, buf)) return;
    auto l = strlen(buf);
    auto s = buf + l;
    *s++ = '/';
    strcpy(s, f);
    file_list.add(buf);
}

static inline void get_text(pid_t pid, int fd, long adr) {
    const size_t N = 513, B = sizeof(long);
    long buf[N], *s = buf;
    auto file = (char *) s;
    if (!add_fd(pid, fd, file)) return;
    for (size_t i = 1; i < N; i++) {
        auto x = ptrace(PTRACE_PEEKDATA, pid, adr);
        if (x == -1) break;
        *s++ = x;
        if (memchr(&x, 0, B)) {
            add_relative(pid, file);
            return;
        }
        adr += B;
    }
    *s = 0;
    add_relative(pid, file);
}

static inline int get_func_id(const user_regs_struct &rg) {
    switch (rg.orig_rax) {
    case __NR_open: return 1;
    case __NR_openat: return 2;
    case __NR_execve: return 3;
    case __NR_creat: return 4;
    }
    return 0;
}

static inline void process(pid_t pid) {
    user_regs_struct rg;
    auto r = ptrace(PTRACE_GETREGS, pid, 0, &rg);
    if (r == -1 || rg.rax < 0) return;
    auto fid = get_func_id(rg);
    auto adr = fid == 2 ? rg.rsi : rg.rdi;
    if (!fid || fid == 4) return;
    if (fid == 3) add_exe(pid);
    else get_text(pid, rg.rax, adr);
}

static inline bool loop(bool &opt) {
    int status;
    auto pid = waitpid(-1, &status, __WALL);
    if (pid == -1) return false;
    if (opt) {
        size_t opt =
            PTRACE_O_TRACEFORK |
            PTRACE_O_TRACEVFORK |
            PTRACE_O_TRACECLONE |
            PTRACE_O_TRACESYSGOOD;
        ptrace(PTRACE_SETOPTIONS, pid, 0, opt);
        opt = false;
    }
    process(pid);
    auto sig = WSTOPSIG(status);
    if (sig & 0x80 || sig == SIGSTOP || sig == SIGTRAP) sig = 0;
    ptrace(PTRACE_SYSCALL, pid, 0, sig);
    return true;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s output cmd ...\n", argv[0]);
        return -1;
    }
    auto pid = fork();
    if (pid) {
        auto opt = true;
        while (loop(opt));
        file_list.save(argv[1]);
    } else {
        ptrace(PTRACE_TRACEME);
        kill(getpid(), SIGSTOP);
        execvp(argv[2], &argv[2]);
    }
    printf("Done\n");
    return 0;
}
