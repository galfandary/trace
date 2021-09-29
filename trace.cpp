#include <bits/stdc++.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
using namespace std;

struct FID_t {
    ino_t id;
    dev_t dev;
    operator bool() const {
        return id || dev;
    }
    bool operator ==(const FID_t &x) const {
        return x.id == id && x.dev == dev;
    }
};

class FileHash_t {
    size_t size;
    size_t load;
    size_t grow;
    size_t allc;
    FID_t *data;
    void alloc(size_t n) {
        data = (FID_t *) calloc(allc = n, sizeof(FID_t));
    }
    void put(const FID_t &id) {
        auto i = id.id % allc;
        while (data[i]) i = (i + 1) % allc;
        data[i] = id;
    }
    bool resize() {
        if (++size * 100 < allc * load) return false;
        auto n = allc;
        auto d = data;
        alloc(grow * allc / 100);
        for (size_t i = 0; i < n; i++)
            put(d[i]);
        free(d);
        return true;
    }
public:
    bool add(const FID_t &id) {
        if (!id) return false;
        auto i = id.id % allc;
        for (;;) {
            auto &x = data[i];
            if (!x) break;
            if (x == id) return false;
            i = (i + 1) % allc;
        }
        auto r = resize();
        if (r) put(id); else data[i] = id;
        return true;
    }
    FileHash_t(size_t n = 1024, size_t l = 25, size_t g = 400) {
        size = 0;
        load = l;
        grow = g;
        alloc(n);
    }
    ~FileHash_t() {
        free(data);
    }
};

static inline bool add_ID(const FID_t &id) {
    static FileHash_t s;
    return s.add(id);
}

struct Stat_t : FID_t {
    bool dir;
    bool link;
    bool empty;
    Stat_t(const char *file, int fd = AT_FDCWD, bool lkn = false) {
        struct stat s;
        int flags = lkn ? AT_SYMLINK_NOFOLLOW : 0;
        if (fstatat(fd, file, &s, flags)) {
            id = dev = 0;
            return;
        }
        id = s.st_ino;
        dev = s.st_dev;
        dir = S_ISDIR(s.st_mode);
        link = S_ISLNK(s.st_mode);
        empty = s.st_size < 1;
    }
};

struct list_t : vector<string> {
    void add(const char *file) {
        push_back(file);
    }
    void save(const char *file) {
        if (empty()) return;
        auto fp = fopen(file, "wb");
        if (!fp) return;
        sort(begin(), end());
        for (auto &i: *this)
            fprintf(fp, "%s\n", i.data());
        fclose(fp);
    }
};

static list_t file_list;

static int get_link(const char *file, char *buf) {
    auto r = readlink(file, buf, PATH_MAX);
    if (r >= 0) buf[r] = 0;
    return r;
}

static void add_link(const char *file) {
    char buf[PATH_MAX];
    if (get_link(file, buf) >= 0)
        file_list.add(buf);
}

static void add_exe(pid_t pid) {
    char file[64];
    sprintf(file, "/proc/%d/exe", pid);
    if (add_ID(Stat_t(file))) add_link(file);
}

static void get_path(char *buf, pid_t pid, int fd) {
    if (fd == AT_FDCWD) sprintf(buf, "/proc/%d/cwd", pid);
    else sprintf(buf, "/proc/%d/fd/%d", pid, fd);
}

static bool add_fd(pid_t pid, int fd, bool add = true) {
    char file[64];
    get_path(file, pid, fd);
    Stat_t id(file);
    if (!id) return false;
    if (add) add = !id.empty && !id.dir;
    if (add_ID(id) && add) add_link(file);
    return add;
}

static int add_dir(const char *dir, char *file) {
    char buf[PATH_MAX];
    auto r = get_link(dir, buf);
    if (r < 0) return -1;
    auto s = buf + r;
    *s++ = '/';
    strcpy(s, file);
    strcpy(file, buf);
    return 0;
}

static void add_relative(pid_t pid, int dirfd, char *file) {
    char dir[64];
    int fd = AT_FDCWD;
    auto relative = file[0] != '/';
    if (relative) {
        get_path(dir, pid, dirfd);
        fd = open(dir, O_PATH|O_DIRECTORY);
        if (fd == -1) return;
    }
    Stat_t id(file, fd, true);
    if (relative) close(fd);
    if (!id || !id.link || !add_ID(id)) return;
    if (relative && add_dir(dir, file)) return;
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

static void get_text(pid_t pid, int fd, int dirfd, long adr) {
    const size_t N = 513, B = sizeof(long);
    long buf[N], *s = buf;
    auto file = (char *) s;
    if (!add_fd(pid, fd)) return;
    for (size_t i = 1; i < N; i++) {
        auto x = ptrace(PTRACE_PEEKDATA, pid, adr);
        if (x == -1) break;
        *s++ = x;
        if (memchr(&x, 0, B)) {
            add_relative(pid, dirfd, file);
            return;
        }
        adr += B;
    }
    *s = 0;
    add_relative(pid, dirfd, file);
}

static void process(pid_t pid) {
    user_regs_struct rg;
    auto r = ptrace(PTRACE_GETREGS, pid, 0, &rg);
    if (r == -1) return;
    auto fd = rg.rax;
    if (fd < 0) return;
    auto id = rg.orig_rax;
    auto r1 = rg.rdi;
    auto r2 = rg.rsi;
    if (id == __NR_open) {
        get_text(pid, fd, AT_FDCWD, r1);
    } else if (id == __NR_openat) {
        get_text(pid, fd, r1, r2);
    } else if (id == __NR_creat) {
        add_fd(pid, fd, false);
    } else if (id == __NR_execve) {
        add_exe(pid);
    }
}

static bool loop(bool &opt) {
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
