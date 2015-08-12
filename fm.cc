#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <iostream>
#include <string>
#include <sstream>

typedef int syserror_t;

struct Errno {
    syserror_t err;
    Errno(syserror_t err_ = -1) : err(err_ == -1 ? errno : err) {}
};

std::ostream &
operator << (std::ostream &os, const Errno &e) {
    return os << strerror(e.err);
}

struct FanMask {
    __u64 mask;
    FanMask(__u64 mask_) : mask(mask_) {}
};

std::ostream &
operator << (std::ostream &os, const FanMask &e) {
    struct tableent {
        __u64 value;
        const char *name;
    };
    #define ENT(a) { a, #a }
    static tableent table[] = {
        ENT(FAN_ACCESS),
        ENT(FAN_OPEN),
        ENT(FAN_MODIFY),
        ENT(FAN_CLOSE_WRITE),
        ENT(FAN_CLOSE_NOWRITE),
        ENT(FAN_Q_OVERFLOW),
        ENT(FAN_ACCESS_PERM),
        ENT(FAN_OPEN_PERM),
        { 0, 0 }
    };
    const char *sep = "";
    for (size_t i = 0; table[i].name; ++i) {
        if (e.mask & table[i].value) {
            os << sep << table[i].name;
            sep = "|";
        }
    }
    return os;
}

struct FileFlags {
    int flags;
    FileFlags(int flags_) : flags(flags_) {}
};

std::ostream &
operator << (std::ostream &os, const FileFlags &e) {
    struct tableent {
        int value;
        const char *name;
    };
    #define ENT(a) { a, #a }
    static tableent table[] = {
        ENT(O_CREAT),
        ENT(O_EXCL),
        ENT(O_NOCTTY),
        ENT(O_TRUNC),
        ENT(O_APPEND),
        ENT(O_NONBLOCK),
        ENT(O_DSYNC),
        ENT(O_DIRECT),
        ENT(O_LARGEFILE),
        ENT(O_DIRECTORY),
        ENT(O_CLOEXEC),
        ENT(FAN_OPEN_PERM),
        { 0, 0 }
    };
    const char *sep = "";

    int mode = e.flags & O_ACCMODE;

    switch (mode) {
        case O_RDWR: os << "O_RDWR"; break;
        case O_RDONLY: os << "O_RDONLY"; break;
        case O_WRONLY: os << "O_WRONLY"; break;
        default : os << "??ACCESS??"; break;
    }

    for (size_t i = 0; table[i].name; ++i) {
        if (e.flags & table[i].value) {
            os << "|" << table[i].name;
        }
    }
    return os;
}


struct FDCloser {
    int fd;
    FDCloser(int fd_) : fd(fd_) {}
    ~FDCloser() { close(fd); }
    operator int() { return fd; }
};

struct Proc {
    pid_t pid;

    std::string procfsPath(const char *stem, ...) {
        va_list args;
        va_start(args, stem);

        char path[PATH_MAX];
        char *p = path;
        char *e = path + sizeof path;
        p += snprintf(p, e - p, "/proc/%d/", int(pid));
        vsnprintf(p, e - p, stem, args);
        va_end(args);
        return path;
    }

    std::string readData(int fd) {
        std::ostringstream os;
        char buf[1024];
        for (;;) {
            ssize_t rc = read(fd, buf, sizeof buf);
            switch (rc) {
                case 0:
                   return os.str();
                case -1:
                    throw Errno();
                default:
                    for (size_t i = 0; i < rc; ++i)
                        if (buf[i] == '\0')
                            buf[i] = ' ';
                    os.write(buf, rc);
            }
        }
    }
public:
    Proc(pid_t pid_) : pid(pid_) {
    }

    std::string commandLine() {
        std::string name = procfsPath("cmdline");
        try {
            FDCloser fd = open(name.c_str(), O_RDONLY);
            if (fd == -1)
                throw Errno();
            return readData(fd);
        }
        catch (const Errno &err) {
            std::ostringstream errstr;
            errstr << "(" << err << ")";
            return errstr.str();
        }
    }

    std::string filePath(int fd) {
        std::string name = procfsPath("fd/%d", fd);
        char buf[PATH_MAX];
        int rc = readlink(name.c_str(), buf, sizeof buf - 1);
        if (rc == -1)
            throw Errno();
        buf[rc] = 0;
        return buf;
    }
};

static void
usage(std::ostream &os)
{
    os << "usage: [options] <files...>" 
        << "\nOptions:"
        << "\n\t-a:\tmonitor access"
        << "\n\t-m:\tmonitor modify"
        << "\n\t-o:\tmonitor open"
        << "\n\t-r:\tmonitor close (read)"
        << "\n\t-w:\tmonitor close (write)"
        << "\n";
    exit(1);
}

int
main(int argc, char *argv[])
{

    uint64_t mask = 0;
    int c;
    while ((c = getopt(argc, argv, "aomrwh")) != -1) {
        switch (c) {
            case 'a': mask |= FAN_ACCESS; break;
            case 'm': mask |= FAN_MODIFY; break;
            case 'o': mask |= FAN_OPEN; break;
            case 'r': mask |= FAN_CLOSE_NOWRITE; break;
            case 'w': mask |= FAN_CLOSE_WRITE; break;
            case 'h': usage(std::cout);
            default:
                usage(std::clog);
                break;
        }
    }
    if (argc == optind)
        usage(std::clog);

    if (mask == 0)
        mask = FAN_MODIFY|FAN_CLOSE;

    std::clog << "mask events: " << FanMask(mask) << "\n";

    int fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
    if (fd == -1) {
        std::clog << "fa init failed: " << Errno() << "\n";
        exit(1);
    }

    for (size_t i = optind; i < argc; ++i) {
        int rc = fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, argv[i]);
        if (rc == -1) {
            std::clog << "failed to mark FD: " << Errno() << "\n";
            exit(1);
        }
        std::clog << "added " << argv[i] << "\n";
    }

    Proc self(getpid());

    for (;;) {
        char buf[8192];
        ssize_t received = read(fd, buf, sizeof buf);
        if (received == 0)
            break;
        const char *e = buf + received;

        struct fanotify_event_metadata *data;
        for (char *p = buf; p < e; p += data->event_len) {
            try {
                data = (struct fanotify_event_metadata *)p;
                FDCloser fd(data->fd);
                int flags = fcntl(data->fd, F_GETFL);

                std::cout
                    << "mask: " << FanMask(data->mask)
                    << ", fd: " << data->fd
                    << ", pid: " << data->pid
                    << ", file: " << self.filePath(data->fd)
                    << ", command: " << Proc(data->pid).commandLine()
                    << "\n";
            }
            catch (const Errno &e) {
                std::clog << e << "\n";
            }
        }
    }
}
