#include "KittyMemOp.hpp"
#include <cerrno>

// [v6] 内核驱动模式需要的头文件
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>

// process_vm_readv & process_vm_writev
#if defined(__aarch64__)
#define syscall_rpmv_n 270
#define syscall_wpmv_n 271
#elif defined(__arm__)
#define syscall_rpmv_n 376
#define syscall_wpmv_n 377
#elif defined(__i386__)
#define syscall_rpmv_n 347
#define syscall_wpmv_n 348
#elif defined(__x86_64__)
#define syscall_rpmv_n 310
#define syscall_wpmv_n 311
#else
#error "Unsupported ABI"
#endif

static ssize_t call_process_vm_readv(pid_t pid,
                                     const iovec *lvec, unsigned long liovcnt,
                                     const iovec *rvec, unsigned long riovcnt,
                                     unsigned long flags)
{
    return syscall(syscall_rpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

static ssize_t call_process_vm_writev(pid_t pid,
                                      const iovec *lvec, unsigned long liovcnt,
                                      const iovec *rvec, unsigned long riovcnt,
                                      unsigned long flags)
{
    return syscall(syscall_wpmv_n, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

/* =================== IKittyMemOp =================== */

std::string IKittyMemOp::ReadStr(uintptr_t address, size_t maxLen)
{
    std::vector<char> chars(maxLen);

    if (!Read(address, &chars[0], maxLen))
        return "";

    std::string str = "";
    for (size_t i = 0; i < chars.size(); i++)
    {
        if (chars[i] == '\0')
            break;

        str.push_back(chars[i]);
    }

    if ((int)str[0] == 0 && str.size() == 1)
        return "";

    return str;
}

bool IKittyMemOp::WriteStr(uintptr_t address, std::string str)
{
    size_t len = str.length() + 1; // extra for \0;
    return Write(address, &str[0], len) == len;
}

/* =================== KittyMemSys =================== */

bool KittyMemSys::init(pid_t pid)
{
    if (pid < 1)
    {
        KITTY_LOGE("KittyMemSys: Invalid PID.");
        return false;
    }

    errno = 0;
    ssize_t rt = syscall(syscall_rpmv_n, 0, 0, 0, 0, 0, 0);
    if (rt == -1 && errno == ENOSYS)
    {
        KITTY_LOGE("KittyMemSys: syscall not supported.");
        return false;
    }

    _pid = pid;
    return true;
}

size_t KittyMemSys::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    struct iovec lvec { .iov_base = buffer, .iov_len = 0 };
    struct iovec rvec { .iov_base = reinterpret_cast<void*>(address), .iov_len = 0 };

    ssize_t n = 0;
    size_t bytes_read = 0, remaining = len;
    bool read_one_page = false;
    do {
        size_t remaining_or_pglen = remaining;
        if (read_one_page)
            remaining_or_pglen = std::min(KT_PAGE_LEN(rvec.iov_base), remaining);

        lvec.iov_len = remaining_or_pglen;
        rvec.iov_len = remaining_or_pglen;

        errno = 0;
        n = KT_EINTR_RETRY(call_process_vm_readv(_pid, &lvec, 1, &rvec, 1, 0));
        if (n > 0)
        {
            remaining -= n;
            bytes_read += n;
            lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + n;
            rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + n;
        }
        else
        {
            if (n == -1)
            {
                int err = errno;
                switch (err)
                {
                case EPERM:
                    KITTY_LOGE("Failed vm_readv(%p + %p, %p) | Can't access the address space of process ID (%d).",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ESRCH:
                    KITTY_LOGE("Failed vm_readv(%p + %p, %p) | No process with ID (%d) exists.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ENOMEM:
                    KITTY_LOGE("Failed vm_readv(%p + %p, %p) | Could not allocate memory for internal copies of the iovec structures.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len);
                    break;
                default:
                    KITTY_LOGD("Failed vm_readv(%p + %p, %p) | error(%d): %s.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, err, strerror(err));
                }
            }
            if (read_one_page)
            {
                remaining -= remaining_or_pglen;
                lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + remaining_or_pglen;
                rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + remaining_or_pglen;
            }
        }
        read_one_page = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return bytes_read;
}

size_t KittyMemSys::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len)
        return 0;

    struct iovec lvec { .iov_base = buffer, .iov_len = 0 };
    struct iovec rvec { .iov_base = reinterpret_cast<void*>(address), .iov_len = 0 };

    ssize_t n = 0;
    size_t bytes_written = 0, remaining = len;
    bool write_one_page = false;
    do {
        size_t remaining_or_pglen = remaining;
        if (write_one_page)
            remaining_or_pglen = std::min(KT_PAGE_LEN(rvec.iov_base), remaining);

        lvec.iov_len = remaining_or_pglen;
        rvec.iov_len = remaining_or_pglen;

        errno = 0;
        n = KT_EINTR_RETRY(call_process_vm_writev(_pid, &lvec, 1, &rvec, 1, 0));
        if (n > 0)
        {
            remaining -= n;
            bytes_written += n;
            lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + n;
            rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + n;
        }
        else
        {
            if (n == -1)
            {
                int err = errno;
                switch (err)
                {
                case EPERM:
                    KITTY_LOGE("Failed vm_writev(%p + %p, %p) | Can't access the address space of process ID (%d).",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ESRCH:
                    KITTY_LOGE("Failed vm_writev(%p + %p, %p) | No process with ID (%d) exists.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, _pid);
                    break;
                case ENOMEM:
                    KITTY_LOGE("Failed vm_writev(%p + %p, %p) | Could not allocate memory for internal copies of the iovec structures.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len);
                    break;
                default:
                    KITTY_LOGD("Failed vm_writev(%p + %p, %p) | error(%d): %s.",
                        (void*)address, (void*)(uintptr_t(rvec.iov_base) - address), (void*)rvec.iov_len, err, strerror(err));
                }
            }
            if (write_one_page)
            {
                remaining -= remaining_or_pglen;
                lvec.iov_base = reinterpret_cast<char*>(lvec.iov_base) + remaining_or_pglen;
                rvec.iov_base = reinterpret_cast<char*>(rvec.iov_base) + remaining_or_pglen;
            }
        }
        write_one_page = n == -1 || size_t(n) != remaining_or_pglen;
    } while (remaining > 0);
    return bytes_written;
}

/* =================== KittyMemIO =================== */

bool KittyMemIO::init(pid_t pid)
{
    if (pid < 1)
    {
        KITTY_LOGE("KittyMemIO: Invalid PID.");
        return false;
    }

    _pid = pid;

    char memPath[256] = {0};
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", _pid);
    _pMem = std::make_unique<KittyIOFile>(memPath, O_RDWR);
    if (!_pMem->Open())
    {
        KITTY_LOGE("Couldn't open mem file %s, error=%s", _pMem->Path().c_str(), _pMem->lastStrError().c_str());
        return false;
    }

    return _pid > 0 && _pMem.get();
}

size_t KittyMemIO::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    ssize_t bytes = _pMem->Read(address, buffer, len);
    return bytes > 0 ? bytes : 0;
}

size_t KittyMemIO::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_pid < 1 || !address || !buffer || !len || !_pMem.get())
        return 0;

    ssize_t bytes = _pMem->Write(address, buffer, len);
    return bytes > 0 ? bytes : 0;
}

/* =================== KittyMemDriver（[v6] TearGame 内核驱动） =================== */

// 驱动设备节点（泪心开源驱动默认值）
static constexpr const char *kDriverDevicePath = "/dev/TearGame";

KittyMemDriver::~KittyMemDriver()
{
    if (_fd >= 0)
    {
        ::close(_fd);
        _fd = -1;
    }
}

bool KittyMemDriver::init(pid_t pid)
{
    if (pid < 1)
    {
        KITTY_LOGE("KittyMemDriver: Invalid PID.");
        return false;
    }

    if (_fd >= 0)
    {
        ::close(_fd);
        _fd = -1;
    }

    _fd = ::open(kDriverDevicePath, O_RDWR);
    if (_fd < 0)
    {
        KITTY_LOGW("KittyMemDriver: %s not available (errno=%d), fallback expected.",
                   kDriverDevicePath, errno);
        return false;
    }

    _pid = pid;
    KITTY_LOGI("KittyMemDriver: attached to pid %d via %s", pid, kDriverDevicePath);
    return true;
}

size_t KittyMemDriver::Read(uintptr_t address, void *buffer, size_t len) const
{
    if (_fd < 0 || _pid < 1 || !address || !buffer || !len)
    {
        KITTY_LOGE("KittyMemDriver::Read bad args: fd=%d pid=%d addr=%p buf=%p len=%zu",
                   _fd, (int)_pid, (void*)address, buffer, len);
        return 0;
    }

    size_t done = 0;
    while (done < len)
    {
        const size_t chunk = std::min(kMaxChunk, len - done);
        CopyMemory cm;
        cm.pid = _pid;
        cm.addr = address + done;
        cm.buffer = static_cast<char *>(buffer) + done;
        cm.size = chunk;

        errno = 0;
        const int rc = ::ioctl(_fd, kOpReadMem, &cm);
        if (rc != 0)
        {
            KITTY_LOGE("KittyMemDriver::Read ioctl failed: rc=%d errno=%d (%s) pid=%d addr=0x%lx size=%zu",
                       rc, errno, strerror(errno), (int)_pid, (unsigned long)(address + done), chunk);
            break;
        }
        done += chunk;
    }
    if (done > 0 && done < len)
        KITTY_LOGW("KittyMemDriver::Read partial: %zu/%zu", done, len);
    return done;
}

size_t KittyMemDriver::Write(uintptr_t address, void *buffer, size_t len) const
{
    if (_fd < 0 || _pid < 1 || !address || !buffer || !len)
        return 0;

    size_t done = 0;
    while (done < len)
    {
        const size_t chunk = std::min(kMaxChunk, len - done);
        CopyMemory cm;
        cm.pid = _pid;
        cm.addr = address + done;
        cm.buffer = static_cast<char *>(buffer) + done;
        cm.size = chunk;

        if (::ioctl(_fd, kOpWriteMem, &cm) != 0)
            break;
        done += chunk;
    }
    return done;
}
