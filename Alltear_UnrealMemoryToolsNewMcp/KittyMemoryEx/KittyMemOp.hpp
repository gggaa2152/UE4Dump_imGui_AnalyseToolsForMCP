#pragma once

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"

enum EKittyMemOP
{
    EK_MEM_OP_NONE = 0,
    EK_MEM_OP_SYSCALL,
    EK_MEM_OP_IO,
    // [v6] 内核驱动模式：经 /dev/TearGame ioctl 读写（内核态 access_process_vm）。
    // 不产生 process_vm_readv 系统调用痕迹，反作弊检测面不同；驱动未加载时 init 失败，
    // 上层回退 SYSCALL / IO。
    EK_MEM_OP_DRIVER
};

class IKittyMemOp
{
protected:
    pid_t _pid;

public:
    IKittyMemOp() : _pid(0) {}
    virtual ~IKittyMemOp() = default;

    virtual bool init(pid_t pid) = 0;

    inline pid_t processID() const { return _pid; }

    virtual size_t Read(uintptr_t address, void *buffer, size_t len) const = 0;
    virtual size_t Write(uintptr_t address, void *buffer, size_t len) const = 0;

    std::string ReadStr(uintptr_t address, size_t maxLen);
    bool WriteStr(uintptr_t address, std::string str);
};

class KittyMemSys : public IKittyMemOp
{
public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};

class KittyMemIO : public IKittyMemOp
{
private:
    std::unique_ptr<KittyIOFile> _pMem;

public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};

// [v6] TearGame 内核驱动内存操作（/dev/TearGame + ioctl）
// 协议参考泪心开源驱动：OP_READ_MEM=0x801 / OP_WRITE_MEM=0x802
// 单次 ioctl 上限 1MB（驱动侧限制），本类自动分块。
class KittyMemDriver : public IKittyMemOp
{
private:
    int _fd = -1;

    struct CopyMemory
    {
        pid_t pid;
        uintptr_t addr;
        void *buffer;
        size_t size;
    };

    static constexpr unsigned long kOpReadMem = 0x801;
    static constexpr unsigned long kOpWriteMem = 0x802;
    static constexpr size_t kMaxChunk = 1024 * 1024;

    bool ReadChunk(uintptr_t address, void *buffer, size_t len, bool quiet) const;

public:
    KittyMemDriver() = default;
    ~KittyMemDriver() override;

    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};