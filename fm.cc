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
#include <utility>
#include <exception>

class Errno : public std::exception {
public:
    typedef int syserror_t;
private:
    syserror_t err;
    const char *str;
    mutable std::string formattedText;
public:
    const char *what() const throw() override;
    Errno(const char *str_, syserror_t err_ = -1) : str(str_), err(err_ == -1 ? errno : err) {}
};

struct FanMask {
    uint64_t mask;
    FanMask(uint64_t mask_) : mask(mask_) {}
};

struct FDCloser {
    int fd;
    FDCloser(int fd_) : fd(fd_) {}
    ~FDCloser() { close(fd); }
    operator int() { return fd; }
};

struct Proc {
    pid_t pid;
    std::string procfsPath(const char *stem, ...); 
    std::string readData(int fd);
public:
    Proc(pid_t pid_) : pid(pid_) { }
    std::string commandLine();
    std::string filePath(int fd);
};

std::ostream &
operator << (std::ostream &os, const std::exception &e) {
    return os << e.what();
}

std::ostream &
operator << (std::ostream &os, const FanMask &e) {
    #define ENT(a) { a, #a }
    static std::pair<uint64_t, const char *> table[] = {
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
    #undef ENT
    const char *sep = "";
    for (size_t i = 0; table[i].second; ++i) {
        if (e.mask & table[i].first) {
            os << sep << table[i].second;
            sep = "|";
        }
    }
    return os;
}

const char *
Errno::what() const throw()
{
    if (formattedText.size() == 0)
        formattedText = std::string(str) + ": " + strerror(err);
    return formattedText.c_str();
}

std::string
Proc::procfsPath(const char *stem, ...)
{
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

std::string
Proc::readData(int fd)
{
    std::ostringstream os;
    char buf[1024];
    for (;;) {
        ssize_t rc = read(fd, buf, sizeof buf);
        switch (rc) {
            case 0:
               return os.str();
            case -1:
                throw Errno("read /proc");
            default:
                for (size_t i = 0; i < rc; ++i)
                    if (buf[i] == '\0')
                        buf[i] = ' ';
                os.write(buf, rc);
        }
    }
}

std::string
Proc::commandLine()
{
    std::string name = procfsPath("cmdline");
    try {
        FDCloser fd = open(name.c_str(), O_RDONLY);
        if (fd == -1)
            throw Errno("open cmdline");
        return readData(fd);
    }
    catch (const Errno &err) {
        std::ostringstream errstr;
        errstr << "(" << err << ")";
        return errstr.str();
    }
}

std::string
Proc::filePath(int fd)
{
    std::string name = procfsPath("fd/%d", fd);
    char buf[PATH_MAX];
    int rc = readlink(name.c_str(), buf, sizeof buf - 1);
    if (rc == -1)
        throw Errno("readlink");
    buf[rc] = 0;
    return buf;
}

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
    try {
        std::clog << "checking for events " << FanMask(mask) << "\n";
        int fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
        if (fd == -1)
            throw Errno("fanotify_init");

        for (size_t i = optind; i < argc; ++i)
            if (fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, argv[i]) == -1)
                throw Errno("fanotify_mark failed");

        Proc self(getpid());
        for (;;) {
            char buf[8192];
            ssize_t received = read(fd, buf, sizeof buf);
            switch (received) {
                case 0:
                    return 0;
                case -1:
                    throw Errno("read");
                default: {
                    const char *e = buf + received;
                    struct fanotify_event_metadata *data;
                    for (char *p = buf; p < e; p += data->event_len) {
                        data = (struct fanotify_event_metadata *)p;
                        FDCloser fd(data->fd);
                        std::cout
                            << "mask: " << FanMask(data->mask)
                            << ", fd: " << data->fd
                            << ", pid: " << data->pid
                            << ", file: " << self.filePath(data->fd)
                            << ", command: " << Proc(data->pid).commandLine()
                            << "\n";
                    }
                    break;
                }
            }
        }
    }
    catch (const std::exception &ex) {
        std::cerr << "exception: " << ex << "\n";
    }
}
