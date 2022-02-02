#include <bits/stdc++.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <fcntl.h>
using namespace std;
static auto follow_links = true;

struct FID_t {
    typedef unordered_set<string> set_t;
    ino_t id;
    dev_t dev;
    set_t *files;
    set_t *out = (set_t *) 1;
    operator bool() const {
        return id || dev;
    }
    bool isSet() const {
        return files;
    }
    bool operator ==(const FID_t &x) const {
        return x.id == id && x.dev == dev;
    }
    void get(vector<string> &v) {
        if (!files || files == out) return;
        for (auto &i: *files) v.push_back(i);
        delete files;
        files = 0;
    }
    void add(const char *file) {
        if (files == out) return;
        if (file) {
            if (!files) files = new set_t();
            if (files) files->insert(file);
        } else if (!files) {
            files = out;
        }
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
    size_t find(const FID_t &id) {
        auto i = id.id % allc;
        while (data[i]) i = (i + 1) % allc;
        return i;
    }
    void put(const FID_t &id) {
        if (id) data[find(id)] = id;
    }
    bool resize() {
        if (++size * 100 < allc * load)
            return false;
        auto n = allc;
        auto d = data;
        alloc(grow * allc / 100);
        for (size_t i = 0; i < n; i++)
            put(d[i]);
        free(d);
        return true;
    }
public:
    FID_t *add(const FID_t &id) {
        if (!id) return 0;
        auto i = id.id % allc;
        for (;;) {
            auto &x = data[i];
            if (!x) break;
            if (x == id) return &x;
            i = (i + 1) % allc;
        }
        if (resize()) i = find(id);
        auto &x = data[i] = id;
        return &x;
    }
    void save(const char *file) {
        vector<string> v;
        for (size_t i = 0; i < allc; i++)
            data[i].get(v);
        if (v.empty()) return;
        auto fp = fopen(file, "wb");
        if (!fp) return;
        sort(v.begin(), v.end());
        for (auto &i: v)
            fprintf(fp, "%s\n", i.data());
        fclose(fp);
        free(data);
        data = 0;
    }
    FileHash_t(size_t n = 1024, size_t l = 25, size_t g = 400) {
        size = 0;
        load = l;
        grow = g;
        alloc(n);
    }
};

static FileHash_t IDS;

static FID_t *add_ID(const FID_t &id) {
    return IDS.add(id);
}

static void save_list(const char *file) {
    IDS.save(file);
}

struct Stat_t : FID_t {
    bool dir;
    bool link;
    bool empty;
    Stat_t(const char *file, int fd = AT_FDCWD, bool lnk = false) {
        struct stat s;
        int flags = lnk ? AT_SYMLINK_NOFOLLOW : 0;
        if (fstatat(fd, file, &s, flags)) {
            id = dev = 0;
            return;
        }
        id = s.st_ino;
        dev = s.st_dev;
        dir = S_ISDIR(s.st_mode);
        link = S_ISLNK(s.st_mode);
        empty = s.st_size < 1;
        files = 0;
    }
};

static int get_link(const char *file, char *buf) {
    auto r = readlink(file, buf, PATH_MAX);
    if (r >= 0) buf[r] = 0;
    return r;
}

static void add_link(Stat_t &id, const char *file, bool add = true) {
    if (!id) return;
    char buf[PATH_MAX];
    if (get_link(file, buf) < 0) return;
    auto d = add_ID(id);
    if (d) d->add(add ? buf : 0);
}

static void add_exe(pid_t pid) {
    char file[64];
    sprintf(file, "/proc/%d/exe", pid);
    Stat_t id(file);
    add_link(id, file);
}

static void get_fd_path(char *buf, pid_t pid, int fd) {
    if (fd == AT_FDCWD) sprintf(buf, "/proc/%d/cwd", pid);
    else sprintf(buf, "/proc/%d/fd/%d", pid, fd);
}

static bool add_fd(pid_t pid, int fd, bool add = true) {
    char file[64];
    get_fd_path(file, pid, fd);
    Stat_t id(file);
    if (!id) return false;
    if (add) add = !id.empty && !id.dir;
    add_link(id, file, add);
    return add;
}

static void add_dir(char *dir, char *file) {
    auto s = dir + strlen(dir);
    *s++ = '/';
    strcpy(s, file);
}

static int abs_path(char *file, char *dir, char *buf) {
    auto f = strrchr(file, '/');
    if (!f) return -1;
    *f++ = 0;
    if (!realpath(file, buf)) return -1;
    strcpy(dir, buf);
    add_dir(buf, f);
    return 0;
}

static bool do_link(char *file, char *dir,
                    char *buf, bool add, size_t &n) {
    int fd = AT_FDCWD;
    auto relative = file[0] != '/';
    if (relative) {
        fd = open(dir, O_PATH|O_DIRECTORY);
        if (fd == -1) return false;
    }
    Stat_t id(file, fd, true);
    if (relative) close(fd);
    if (!id || !id.link) return false;
    auto d = add_ID(id);
    n++;
    if (!d || d->isSet()) return false;
    if (!add) {
        d->add(0);
        return false;
    }
    if (relative) {
        add_dir(dir, file);
        strcpy(file, dir);
    }
    if (abs_path(file, dir, buf)) return false;
    d->add(buf);
    return true;
}

static size_t do_relative(pid_t pid, int dirfd, char *file, bool add) {
    char dir[PATH_MAX], buf[PATH_MAX];
    if (file[0] != '/') get_fd_path(dir, pid, dirfd);
    size_t n = 0;
    while (do_link(file, dir, buf, add, n) && follow_links) {
        auto r = get_link(buf, file);
        if (r < 0) break;
        add = true;
    }
    return n;
}

static void get_path(pid_t pid, long adr, long *s, size_t N) {
    const size_t B = sizeof(long);
    for (size_t i = 1; i < N; i++) {
        auto x = ptrace(PTRACE_PEEKDATA, pid, adr);
        if (x == -1) break;
        *s++ = x;
        if (memchr(&x, 0, B))
            return;
        adr += B;
    }
    *s = 0;
}

static void do_open(pid_t pid, int fd, int dirfd, long adr) {
    if (follow_links && !add_fd(pid, fd)) return;
    const size_t N = 513; long buf[N];
    get_path(pid, adr, buf, N);
    auto n = do_relative(pid, dirfd, (char *) buf, true);
    if (!follow_links && !n) add_fd(pid, fd);
}

static void do_symlink(pid_t pid, int dirfd, long adr) {
    const size_t N = 513; long buf[N];
    get_path(pid, adr, buf, N);
    do_relative(pid, dirfd, (char *) buf, false);
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
    auto r3 = rg.rdx;
    if (id == __NR_open) {
        do_open(pid, fd, AT_FDCWD, r1);
    } else if (id == __NR_openat) {
        do_open(pid, fd, r1, r2);
    } else if (id == __NR_creat) {
        add_fd(pid, fd, false);
    } else if (id == __NR_execve) {
        add_exe(pid);
    } else if (id == __NR_symlink) {
        do_symlink(pid, AT_FDCWD, r2);
    } else if (id == __NR_symlinkat) {
        do_symlink(pid, r2, r3);
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
        printf("Usage: %s [OPTION] output cmd ...\n", argv[0]);
        printf("Options:\n"
               " -l: Don't follow links\n");
        return -1;
    }
    int i = 1;
    while (argv[i][0] == '-') {
        switch (argv[i][1]) {
        case 'l': follow_links = false; break;
        default: printf("Unknown option: %s\n", argv[i]);
        }
        i++;
    }
    auto pid = fork();
    if (pid) {
        auto opt = true;
        while (loop(opt));
        save_list(argv[i]);
    } else {
        i++;
        ptrace(PTRACE_TRACEME);
        kill(getpid(), SIGSTOP);
        execvp(argv[i], &argv[i]);
    }
    printf("Done\n");
    return 0;
}
