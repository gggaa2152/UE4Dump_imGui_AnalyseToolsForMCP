#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <KittyMemoryMgr.hpp>

namespace UmtMcp::Analysis
{
using json = nlohmann::json;

struct MapSnapshot
{
    pid_t pid = 0;
    uint64_t processStartTime = 0;
    std::string revision;
    std::vector<KittyMemoryEx::ProcMap> maps;
};

MapSnapshot CaptureMaps(const KittyMemoryMgr &mgr);
std::string CurrentMapRevision(const KittyMemoryMgr &mgr);

// [修复] 轻量进程存活检查：扫描循环内定期调用，目标进程已退出时立即中止。
// 避免对死进程持续 readMem 刷错误日志（真机实测：无此检查时单次扫描可产生
// 90MB / 100 万行 "No process with ID" 日志）。expectedStartTime=0 时跳过 pid 复用检测。
bool IsProcessAlive(pid_t pid, uint64_t expectedStartTime);
bool IsReadableAddress(const MapSnapshot &snapshot, uintptr_t address, size_t size = 1);
bool IsWritableAddress(const MapSnapshot &snapshot, uintptr_t address, size_t size = 1);
ElfScanner FindUnrealElf(const KittyMemoryMgr &mgr, const std::string &moduleHint = {});

json ListModules(const json &args, const KittyMemoryMgr &mgr);
json ScanPattern(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);
json SearchMemory(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);
json FindReferences(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);

void InvalidateSessions();
}
