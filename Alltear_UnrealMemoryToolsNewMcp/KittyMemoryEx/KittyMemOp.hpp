#pragma once

#include "KittyUtils.hpp"
#include <sys/ioctl.h>
#include <cstdint>
#include "KittyIOFile.hpp"

enum EKittyMemOP
{
    EK_MEM_OP_NONE = 0,
    EK_MEM_OP_SYSCALL,
    EK_MEM_OP_IO,
    // [v6] 内核驱动模式：经 /dev/TearGame ioctl 读写（内核态 access_process_vm）。
    // 不产生 process_vm_readv 系统调用痕迹，反作弊检测面不同；驱动未加载时 init 失败，
    // 上层回退 SYSCALL / IO。
    EK_MEM_OP_DRIVER,
    // [v9] KPM 物理内存模式：经 APatch/KernelPatch 的 kpm_kread 内核模块物理地址直读。
    // 不经过 access_process_vm（无页表 walk 痕迹），反作弊检测面最小。
    // 需要：APatch 已加载 kpm_kread.kpm；密钥通过 kpm ctl0 get_key 动态获取。
    EK_MEM_OP_KPM
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

// [v9] KPM 物理内存读取（APatch / KernelPatch kpm_kread 模块）
//
// 原理：kpm_kread 内核模块 hook 了 ioctl 系统调用入口。
// 用户态调用 ioctl(-1, cmd_read, &kread) 时：
//   1. 内核侧校验 key（key_vertify，模块加载时随机生成）
//   2. 通过 pid 找到 task/mm，遍历页表拿到物理地址
//   3. 物理地址 → 内核线性映射 → copy_to_user 返回数据
// 特点：
//   - 完全绕过 access_process_vm / process_vm_readv（无系统调用痕迹）
//   - 未驻留页返回失败（不触发缺页，不惊动游戏的页监控）
//   - 单次调用限制 64KB（实测 256KB+ 失败），需自动分块
//
// 密钥获取：kpatch su kpm ctl0 kpm_kread get_key → 输出 "key-cmd"（十六进制）
class KittyMemKPM : public IKittyMemOp
{
private:
    struct KpmRead
    {
        uint64_t key;
        int32_t pid;
        int32_t size;
        uint64_t addr;
        void *buffer;
    };

    struct KpmMod
    {
        uint64_t key;
        int32_t pid;
        const char *name;
        uintptr_t base;
    };

    uint64_t _key = 0;      // key_vertify
    uint32_t _cmdRead = 0;  // cmd_read
    uint32_t _cmdWrite = 0; // cmd_read + 1
    uint32_t _cmdMod = 0;   // cmd_read + 2

    static constexpr size_t kMaxChunk = 64 * 1024; // KPM 单次读取上限（实测）

public:
    KittyMemKPM() = default;

    // 设置密钥（从 kpm ctl0 get_key 获取）
    void setKey(uint64_t key, uint32_t cmdRead)
    {
        _key = key;
        _cmdRead = cmdRead;
        _cmdWrite = cmdRead + 1;
        _cmdMod = cmdRead + 2;
    }

    bool init(pid_t pid)
    {
        if (pid < 1 || _key == 0 || _cmdRead == 0)
        {
            KITTY_LOGE("KittyMemKPM: invalid init (pid=%d key=%llx cmd=%x)", (int)pid,
                       (unsigned long long)_key, _cmdRead);
            return false;
        }
        _pid = pid;
        return true;
    }

    size_t Read(uintptr_t address, void *buffer, size_t len) const
    {
        if (_pid < 1 || !address || !buffer || !len)
            return 0;

        size_t done = 0;
        while (done < len)
        {
            const size_t chunk = std::min(kMaxChunk, len - done);
            KpmRead kr;
            kr.key = _key;
            kr.pid = (int32_t)_pid;
            kr.size = (int32_t)chunk;
            kr.addr = address + done;
            kr.buffer = static_cast<char *>(buffer) + done;

            if (::ioctl(-1, _cmdRead, &kr) < 0)
            {
                // 单页失败：尝试页级读取，跳过坏页
                if (chunk > 4096)
                {
                    // 降级到页级
                    const size_t page_chunk = std::min((size_t)4096, chunk);
                    KpmRead pr;
                    pr.key = _key;
                    pr.pid = (int32_t)_pid;
                    pr.size = (int32_t)page_chunk;
                    pr.addr = address + done;
                    pr.buffer = static_cast<char *>(buffer) + done;
                    if (::ioctl(-1, _cmdRead, &pr) < 0)
                    {
                        done += page_chunk; // 跳过坏页
                        continue;
                    }
                    done += page_chunk;
                    continue;
                }
                done += chunk;
                continue;
            }
            done += chunk;
        }
        return done;
    }

    size_t Write(uintptr_t address, void *buffer, size_t len) const
    {
        if (_pid < 1 || !address || !buffer || !len)
            return 0;

        size_t done = 0;
        while (done < len)
        {
            const size_t chunk = std::min(kMaxChunk, len - done);
            KpmRead kr;
            kr.key = _key;
            kr.pid = (int32_t)_pid;
            kr.size = (int32_t)chunk;
            kr.addr = address + done;
            kr.buffer = static_cast<char *>(buffer) + done;

            if (::ioctl(-1, _cmdWrite, &kr) < 0)
            {
                done += chunk;
                continue;
            }
            done += chunk;
        }
        return done;
    }

    // 获取模块基址（KPM 的 cmd_mod）
    uintptr_t getModuleBase(const char *name)
    {
        KpmMod km;
        km.key = _key;
        km.pid = (int32_t)_pid;
        km.name = name;
        km.base = 0;
        if (::ioctl(-1, _cmdMod, &km) < 0)
            return 0;
        return km.base;
    }
};
