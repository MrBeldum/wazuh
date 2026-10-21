// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <poll.h>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include <climits>
#include <fcntl.h>
#include <filesystem>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/managerLogSink.hpp>
#include <base/process.hpp>

namespace base::process
{

namespace
{
constexpr std::size_t LOOKUP_BUFFER_CAP = 65536;    ///< Largest buffer offered to getpwnam_r/getgrnam_r
constexpr std::size_t LOOKUP_BUFFER_DEFAULT = 1024; ///< Used when sysconf gives no hint

/// "<strerror> (<code>)" for an errno-style code.
std::string describeError(int code)
{
    return fmt::format("{} ({})", std::strerror(code), code);
}

/// Copy of sys with every empty member set to the real system call.
ProcessSysCalls withDefaults(ProcessSysCalls sys)
{
    if (!sys.fork)
    {
        sys.fork = []()
        {
            return ::fork();
        };
    }
    if (!sys.setsid)
    {
        sys.setsid = []()
        {
            return ::setsid();
        };
    }
    if (!sys.umask)
    {
        sys.umask = [](mode_t mask)
        {
            return ::umask(mask);
        };
    }
    if (!sys.open)
    {
        sys.open = [](const char* path, int flags, mode_t mode)
        {
            return ::open(path, flags, mode);
        };
    }
    if (!sys.dup2)
    {
        sys.dup2 = [](int oldFd, int newFd)
        {
            return ::dup2(oldFd, newFd);
        };
    }
    if (!sys.close)
    {
        sys.close = [](int fd)
        {
            return ::close(fd);
        };
    }
    if (!sys.fchmod)
    {
        sys.fchmod = [](int fd, mode_t mode)
        {
            return ::fchmod(fd, mode);
        };
    }
    if (!sys.write)
    {
        sys.write = [](int fd, const void* data, size_t size)
        {
            return ::write(fd, data, size);
        };
    }
    if (!sys.setgroups)
    {
        sys.setgroups = [](size_t size, const gid_t* list)
        {
            return ::setgroups(size, list);
        };
    }
    if (!sys.setgid)
    {
        sys.setgid = [](gid_t gid)
        {
            return ::setgid(gid);
        };
    }
    if (!sys.setuid)
    {
        sys.setuid = [](uid_t uid)
        {
            return ::setuid(uid);
        };
    }
    if (!sys.seteuid)
    {
        sys.seteuid = [](uid_t uid)
        {
            return ::seteuid(uid);
        };
    }
    if (!sys.sysconf)
    {
        sys.sysconf = [](int name)
        {
            return ::sysconf(name);
        };
    }
    return sys;
}

/// Initial buffer size for a reentrant lookup: the sysconf hint, or the default; never above the cap.
std::size_t initialLookupSize(int sysconfName, const ProcessSysCalls& s)
{
    const long hint = s.sysconf(sysconfName);
    const auto size = hint > 0 ? static_cast<std::size_t>(hint) : LOOKUP_BUFFER_DEFAULT;
    return std::min(size, LOOKUP_BUFFER_CAP);
}

/**
 * @brief Runs a getpwnam_r/getgrnam_r-style lookup, doubling the buffer on ERANGE up to the cap.
 *
 * Only the return code of the lookup decides; errno is never read. Returns idOf(entry) while the buffer that
 * backs the entry's strings is still alive.
 */
template<typename Entry, typename Lookup, typename IdOf>
auto lookupId(const char* kind,
              const std::string& name,
              int sysconfName,
              const Lookup& lookup,
              IdOf idOf,
              const ProcessSysCalls& s)
{
    std::vector<char> buffer(initialLookupSize(sysconfName, s));

    while (true)
    {
        Entry entry {};
        Entry* found = nullptr;
        const int rc = lookup(name.c_str(), &entry, buffer.data(), buffer.size(), &found);

        if (rc == 0)
        {
            if (found == nullptr)
            {
                throw std::runtime_error {fmt::format("{} '{}' not found", kind, name)};
            }
            return idOf(*found);
        }

        if (rc != ERANGE)
        {
            throw std::runtime_error {fmt::format("could not look up {} '{}': {}", kind, name, describeError(rc))};
        }

        if (buffer.size() >= LOOKUP_BUFFER_CAP)
        {
            throw std::runtime_error {
                fmt::format("could not look up {} '{}': entry larger than {} bytes", kind, name, LOOKUP_BUFFER_CAP)};
        }
        buffer.resize(std::min(buffer.size() * 2, LOOKUP_BUFFER_CAP));
    }
}

/// fork(); returns the child pid in the parent and 0 in the child. Throws on failure.
pid_t forkOrThrow(const char* stage, const ProcessSysCalls& s)
{
    const pid_t pid = s.fork();
    if (pid < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("fork failed ({}): {}", stage, describeError(err))};
    }
    return pid;
}

/// Redirects stdin, stdout and stderr to /dev/null (shared by goDaemon and goDaemonSynced).
void redirectStdioToDevNull(const ProcessSysCalls& s)
{
    const int fd = s.open("/dev/null", O_RDWR | O_CLOEXEC, 0);
    if (fd < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not open /dev/null: {}", describeError(err))};
    }

    for (const int target : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO})
    {
        if (s.dup2(fd, target) < 0)
        {
            const int err = errno;
            if (fd > STDERR_FILENO)
            {
                s.close(fd);
            }
            throw std::runtime_error {
                fmt::format("could not redirect fd {} to /dev/null: {}", target, describeError(err))};
        }
    }

    if (fd > STDERR_FILENO)
    {
        s.close(fd);
    }
}

/// Writes the whole buffer, retrying on EINTR. Returns false on any other failure.
bool writeAll(int fd, const char* data, std::size_t size, const ProcessSysCalls& s)
{
    std::size_t written = 0;
    while (written < size)
    {
        const ssize_t rc = s.write(fd, data + written, size - written);
        if (rc < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        if (rc == 0)
        {
            return false; // short write
        }
        written += static_cast<std::size_t>(rc);
    }
    return true;
}

/// Single-line startup-report protocol between the daemonized child and the launcher.
constexpr std::string_view STARTUP_OK_LINE = "OK\n";
constexpr std::string_view STARTUP_FAIL_PREFIX = "FAIL ";
/// Cap on the failure message so the whole report fits in one PIPE_BUF-sized atomic write.
constexpr std::size_t STARTUP_MESSAGE_MAX = 4000;
/// Cap on how much of the pipe the launcher reads while waiting for the status line.
constexpr std::size_t STARTUP_READ_MAX = 8192;

/// Reads the child's status line: blocks (with timeout) until a full line arrives or the pipe closes.
DaemonStartupResult awaitDaemonStartup(int readFd, std::chrono::seconds timeout)
{
    DaemonStartupResult result {};
    std::string raw;
    raw.reserve(256);

    // poll(2)/read(2) are intentionally direct: no fake survives the real forks of goDaemonSynced().
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (raw.size() < STARTUP_READ_MAX)
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
        {
            return result; // reported == false: timed out
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        struct pollfd pfd {.fd = readFd, .events = POLLIN, .revents = 0};
        const int prc = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (prc < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return result;
        }
        if (prc == 0)
        {
            return result; // timed out
        }
        char buf[256];
        const ssize_t n = ::read(readFd, buf, sizeof(buf));
        if (n == 0)
        {
            result.childGone = true;
            return result; // EOF: every write end is closed, so the child died without reporting.
        }
        if (n < 0)
        {
            return result; // Read error: treat like a timeout (the launcher cannot know).
        }
        raw.append(buf, static_cast<std::size_t>(n));
        if (raw.find('\n') != std::string::npos)
        {
            break;
        }
    }

    result.reported = true;
    const std::string line = raw.substr(0, raw.find('\n'));
    if (line == "OK")
    {
        result.started = true;
    }
    else if (line.rfind(STARTUP_FAIL_PREFIX, 0) == 0)
    {
        result.message = line.substr(STARTUP_FAIL_PREFIX.size());
    }
    // Anything else: reported but unparseable; started stays false with an empty message.
    return result;
}
} // namespace

void goDaemon(const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);

    if (forkOrThrow("first", s) > 0)
    {
        _exit(EXIT_SUCCESS);
    }

    if (s.setsid() < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("setsid failed: {}", describeError(err))};
    }

    if (forkOrThrow("second", s) > 0)
    {
        _exit(EXIT_SUCCESS);
    }

    s.umask(027);
    redirectStdioToDevNull(s);
}

DaemonStartupSync createStartupSync(const ProcessSysCalls&)
{
    // pipe(2) is intentionally direct (see the header): no fake can cross the real forks below.
    int fds[2] = {-1, -1};
    if (::pipe(fds) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not create startup-status pipe: {}", describeError(err))};
    }
    return DaemonStartupSync {.readFd = fds[0], .writeFd = fds[1]};
}

void goDaemonSynced(DaemonStartupSync sync, std::chrono::seconds timeout, const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);

    // First fork: unlike goDaemon(), the original process does NOT exit blindly. It closes its copy of
    // the write end (so EOF is meaningful) and blocks until the daemonized child reports startup status,
    // then leaves with the child's status. stderr here is still the original one.
    if (forkOrThrow("first", s) > 0)
    {
        s.close(sync.writeFd);
        const auto result = awaitDaemonStartup(sync.readFd, timeout);
        s.close(sync.readFd);
        if (result.childGone)
        {
            // Every write end is closed without a report: the daemon died during startup.
            const std::string err =
                "error: wazuh-engine failed to start (daemon terminated without reporting startup status)\n";
            writeAll(STDERR_FILENO, err.data(), err.size(), s);
            _exit(EXIT_FAILURE);
        }
        if (!result.reported)
        {
            // The child never reported in time: keep the historical fire-and-forget behavior, so a
            // hung child cannot wedge the starter (the starter's own readiness checks stay
            // authoritative).
            const std::string warning =
                "warning: wazuh-engine did not report startup status; continuing in background\n";
            writeAll(STDERR_FILENO, warning.data(), warning.size(), s);
            _exit(EXIT_SUCCESS);
        }
        if (!result.started)
        {
            std::string err = "error: wazuh-engine failed to start";
            if (!result.message.empty())
            {
                err += ": ";
                err += result.message;
            }
            err += "\n";
            writeAll(STDERR_FILENO, err.data(), err.size(), s);
            _exit(EXIT_FAILURE);
        }
        _exit(EXIT_SUCCESS);
    }

    // Intermediate child: hand the write end to the final child, then leave immediately as in goDaemon().
    s.close(sync.readFd);
    if (s.setsid() < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("setsid failed: {}", describeError(err))};
    }
    if (forkOrThrow("second", s) > 0)
    {
        s.close(sync.writeFd);
        _exit(EXIT_SUCCESS);
    }

    // Final daemon child: the only remaining holder of the write end. It must call
    // reportDaemonStartup() exactly once when startup completes or fails.
    s.umask(027);
    // The status pipe's reader (the launcher) may vanish before the child reports (e.g. after the
    // await timeout); the report must never kill the daemon with SIGPIPE. main() re-asserts SIG_IGN
    // later for its own reasons (uvw/libuv/libev).
    ::signal(SIGPIPE, SIG_IGN);
    redirectStdioToDevNull(s);
}

void reportDaemonStartup(DaemonStartupSync& sync,
                         bool started,
                         std::string_view message,
                         const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);
    if (sync.writeFd >= 0)
    {
        std::string line;
        if (started)
        {
            line = std::string(STARTUP_OK_LINE);
        }
        else
        {
            line.reserve(STARTUP_FAIL_PREFIX.size() + STARTUP_MESSAGE_MAX + 1);
            line += STARTUP_FAIL_PREFIX;
            for (const char c : message.substr(0, STARTUP_MESSAGE_MAX))
            {
                line += (c == '\n' || c == '\r') ? ' ' : c;
            }
            line += '\n';
        }
        // Best effort: the launcher may already be gone; there is nothing sensible to do on failure here.
        writeAll(sync.writeFd, line.data(), line.size(), s);
        s.close(sync.writeFd);
        sync.writeFd = -1;
    }
    if (sync.readFd >= 0)
    {
        s.close(sync.readFd);
        sync.readFd = -1;
    }
}

OptError createPID(const std::string& path, const std::string& name, int pid, const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);
    const auto file = (std::filesystem::path(path) / fmt::format("{}-{}.pid", name, pid)).string();

    const int fd = s.open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0)
    {
        const int err = errno;
        return Error {fmt::format("could not create PID file {}: {}", file, describeError(err))};
    }

    // The mode given to open() is filtered by the umask; fchmod sets it exactly.
    if (s.fchmod(fd, 0640) != 0)
    {
        const int err = errno;
        s.close(fd);
        return Error {fmt::format("could not set mode 0640 on PID file {}: {}", file, describeError(err))};
    }

    const auto content = fmt::format("{}\n", pid);
    std::size_t written = 0;
    while (written < content.size())
    {
        const ssize_t rc = s.write(fd, content.data() + written, content.size() - written);
        if (rc < 0)
        {
            const int err = errno;
            if (err == EINTR)
            {
                continue;
            }
            s.close(fd);
            return Error {fmt::format("could not write PID file {}: {}", file, describeError(err))};
        }
        if (rc == 0)
        {
            s.close(fd);
            return Error {fmt::format("could not write PID file {}: short write", file)};
        }
        written += static_cast<std::size_t>(rc);
    }

    if (s.close(fd) != 0)
    {
        const int err = errno;
        return Error {fmt::format("could not close PID file {}: {}", file, describeError(err))};
    }

    return std::nullopt;
}

uid_t lookupUid(const std::string& name, const UserLookup& lookup, const ProcessSysCalls& sys)
{
    return lookupId<struct passwd>(
        "user",
        name,
        _SC_GETPW_R_SIZE_MAX,
        lookup,
        [](const struct passwd& entry) { return entry.pw_uid; },
        withDefaults(sys));
}

gid_t lookupGid(const std::string& name, const GroupLookup& lookup, const ProcessSysCalls& sys)
{
    return lookupId<struct group>(
        "group",
        name,
        _SC_GETGR_R_SIZE_MAX,
        lookup,
        [](const struct group& entry) { return entry.gr_gid; },
        withDefaults(sys));
}

void dropToGroup(gid_t gid, const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);

    if (s.setgroups(1, &gid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not drop supplementary groups: {}", describeError(err))};
    }

    if (s.setgid(gid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set group ID {}: {}", gid, describeError(err))};
    }
}

void dropToUser(uid_t uid, const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);

    if (s.setuid(uid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set user ID {}: {}", uid, describeError(err))};
    }

    if (s.seteuid(uid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set effective user ID {}: {}", uid, describeError(err))};
    }
}

namespace
{
std::atomic<bool> g_managerMode {false};

/// dirname(3) of a path without touching it; "" stays "" (unresolvable executable => no home).
std::string dirName(const std::string& path)
{
    if (path.empty())
    {
        return {};
    }

    auto end = path.find_last_not_of('/');
    if (end == std::string::npos)
    {
        return "/";
    }
    const auto slash = path.rfind('/', end);
    if (slash == std::string::npos)
    {
        return ".";
    }
    end = path.find_last_not_of('/', slash);
    return end == std::string::npos ? std::string("/") : path.substr(0, end + 1);
}

[[noreturn]] void exitHomeNotFound()
{
    const auto line = base::logging::formatPlainLine(base::logging::localTimestamp(),
                                                     "wazuh-manager-analysisd",
                                                     "CRITICAL",
                                                     "(1108): Unable to find Wazuh install directory. Export it to "
                                                     "WAZUH_MANAGER_HOME environment variable.");
    // Best effort: the process exits right after, so a failed write has nowhere to be reported.
    const ssize_t written = ::write(STDERR_FILENO, line.data(), line.size());
    static_cast<void>(written);
    std::exit(EXIT_FAILURE);
}
} // namespace

std::filesystem::path resolveManagerHome(const std::function<const char*(const char*)>& getenv,
                                         const std::string& exePath,
                                         const std::function<bool(const std::string&)>& isDirectory)
{
    // Forced home: returned as is, without any check
    if (const char* forced = getenv("WAZUH_MANAGER_FORCE_HOME"))
    {
        return std::filesystem::path(forced);
    }

    std::string home;
    if (const char* env = getenv("WAZUH_MANAGER_HOME"); env != nullptr && env[0] != '\0')
    {
        home = env;
    }
    else
    {
        // <home>/bin/<executable>: cut the executable's directory at the first "/bin"
        home = dirName(exePath);
        if (const auto pos = home.find("/bin"); pos != std::string::npos)
        {
            home.resize(pos);
        }
    }

    if (!isDirectory(home))
    {
        exitHomeNotFound();
    }
    return std::filesystem::path(home);
}

void setManagerMode()
{
    g_managerMode.store(true);
}

std::filesystem::path getWazuhHome()
{
    if (g_managerMode.load())
    {
        static const std::filesystem::path home = []()
        {
            std::error_code ec;
            const auto exePath = std::filesystem::read_symlink("/proc/self/exe", ec);
            return resolveManagerHome([](const char* name) -> const char* { return std::getenv(name); },
                                      ec ? std::string() : exePath.string(),
                                      [](const std::string& path)
                                      {
                                          std::error_code dirEc;
                                          return !path.empty() && std::filesystem::is_directory(path, dirEc);
                                      });
        }();
        return home;
    }

    // Standalone mode / unit tests: conf::Conf may still use this value to build default paths when the
    // dedicated environment variables are not set.
    return std::filesystem::current_path();
}

void setThreadName(const std::string& name)
{
    if (name.empty())
    {
        return; // No name to set
    }

    // Limit thread name to 15 characters (Linux limit)
    std::string threadName = name.substr(0, 15);
    pthread_setname_np(pthread_self(), threadName.c_str());
}

bool isStandaloneModeEnable()
{
    static const bool enabled = []()
    {
        const char* env = std::getenv(ENV_ENGINE_STANDALONE);
        if (!env)
            return false;

        std::string val(env);
        std::transform(
            val.begin(), val.end(), val.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        return val == "true";
    }();

    return enabled;
}

std::string getEnvOrDefault(const char* name, const std::string& defaultValue)
{
    const char* val = std::getenv(name);
    return val ? std::string(val) : defaultValue;
}

std::size_t getEnvSizeOrDefault(const char* name, std::size_t defaultValue)
{
    const char* val = std::getenv(name);
    if (val)
    {
        try
        {
            return std::stoull(val);
        }
        catch (...)
        {
            return defaultValue;
        }
    }
    return defaultValue;
}

int getEnvIntOrDefault(const char* name, int defaultValue)
{
    const char* val = std::getenv(name);
    if (val)
    {
        try
        {
            return std::stoi(val);
        }
        catch (...)
        {
            return defaultValue;
        }
    }
    return defaultValue;
}

bool getEnvBoolOrDefault(const char* name, bool defaultValue)
{
    const char* val = std::getenv(name);
    if (val)
    {
        std::string v(val);
        std::transform(
            v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return v == "true" || v == "1" || v == "yes";
    }
    return defaultValue;
}

} // namespace base::process
