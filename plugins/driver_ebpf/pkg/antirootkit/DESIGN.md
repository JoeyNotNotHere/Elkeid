# Anti-Rootkit 模块设计文档

## 概述

Anti-Rootkit 模块负责检测内核级 Rootkit，从原 LKM 版本 (`driver/LKM/src/anti_rootkit.c`) 迁移到 eBPF 版本。

## 迁移策略分析

### 原 LKM 实现方式

原 LKM 版本通过内核模块直接访问内核数据结构进行检测：

| 检测项 | 事件 ID | LKM 实现方式 |
|--------|---------|-------------|
| /proc 文件 Hook | 700 | 打开 /proc，检查 f_op->iterate 地址是否在内核代码段 |
| 系统调用 Hook | 701 | 遍历 sys_call_table，检查每个地址是否在内核代码段 |
| 隐藏模块 | 702 | 对比 module_kset 和 find_module() 结果 |
| 中断 Hook | 703 | 遍历 IDT 表，检查中断处理地址是否在内核代码段 |

### eBPF 限制

1. **无法直接访问内核全局变量**: sys_call_table, idt_table 等
2. **无法遍历内核链表**: module list, kset 等
3. **无法打开文件**: eBPF 中不能使用 filp_open
4. **只能在特定上下文执行**: kprobe, tracepoint 等

### 迁移方案

采用 **Go 用户态定时扫描** 方案，通过 `/proc` 和 `/sys` 文件系统获取内核信息：

```
┌─────────────────────────────────────────────────────────┐
│                   Anti-Rootkit Scanner                   │
│                   (Go 用户态实现)                        │
├─────────────────────────────────────────────────────────┤
│  定时器 (默认 15 分钟)                                   │
│       │                                                  │
│       ├─► detectHiddenModules()  → 事件 702             │
│       │   └─ 对比 /proc/modules 与 /sys/module/         │
│       │                                                  │
│       ├─► detectSyscallHooks()   → 事件 701             │
│       │   └─ 读取 /proc/kallsyms 检查系统调用地址        │
│       │                                                  │
│       ├─► detectProcHooks()      → 事件 700             │
│       │   └─ 检查 /proc 文件操作函数地址                 │
│       │                                                  │
│       └─► detectInterruptHooks() → 事件 703 (x86 only)  │
│           └─ 读取 /sys/kernel/debug/x86/idt_table       │
└─────────────────────────────────────────────────────────┘
```

## 检测方法详解

### 1. 隐藏模块检测 (事件 ID 702)

**原理**: Rootkit 常用手法是从 module list 中删除自己，但仍保留在 kobject 系统中。

**实现**:
1. 读取 `/proc/modules` 获取可见模块列表
2. 遍历 `/sys/module/` 目录获取 kobject 中的模块
3. 如果 /sys/module/ 中有模块不在 /proc/modules 中，报告为隐藏模块

```go
// 伪代码
procModules := readProcModules()        // 从 /proc/modules 获取
sysModules := readSysModuleDir()        // 从 /sys/module/ 获取
for _, mod := range sysModules {
    if !procModules[mod] {
        reportHiddenModule(mod)         // 事件 702
    }
}
```

### 2. 系统调用 Hook 检测 (事件 ID 701)

**原理**: Rootkit 可能替换系统调用表中的函数指针，指向模块代码。

**实现**:
1. 从 `/proc/kallsyms` 读取系统调用表地址范围
2. 从 `/proc/kallsyms` 读取内核代码段范围 (`_stext` 到 `_etext`)
3. 检查系统调用指针是否在内核代码段内

```go
// 伪代码
kallsyms := parseKallsyms()
kernelTextStart := kallsyms["_stext"]
kernelTextEnd := kallsyms["_etext"]

for syscallNr, addr := range getSyscallAddresses() {
    if addr < kernelTextStart || addr > kernelTextEnd {
        // 地址不在内核代码段，可能被 hook
        modName := findModuleByAddr(addr)
        reportSyscallHook(modName, syscallNr)  // 事件 701
    }
}
```

### 3. /proc 文件操作 Hook 检测 (事件 ID 700)

**原理**: Rootkit 可能替换 /proc 目录的 iterate/readdir 函数来隐藏进程。

**实现**:
1. 从 `/proc/kallsyms` 查找 `proc_root_operations` 地址
2. 检查其 iterate_shared 函数指针是否指向内核代码

```go
// 伪代码
procOps := kallsyms["proc_root_operations"]
iterateFunc := readProcOpsIterate(procOps)

if !isInKernelText(iterateFunc) {
    modName := findModuleByAddr(iterateFunc)
    reportProcHook(modName)  // 事件 700
}
```

### 4. 中断处理 Hook 检测 (事件 ID 703, 仅 x86)

**原理**: Rootkit 可能修改 IDT (中断描述符表) 来劫持中断处理。

**实现**:
1. 读取 `/sys/kernel/debug/x86/idt_table` (需要 debugfs 挂载且有权限)
2. 检查每个中断处理地址是否在内核代码段

**注意**: 此检测需要 root 权限和 debugfs 支持，可能不是所有系统都可用。

## 输出格式

与原 LKM 保持兼容，事件字段定义：

| 事件 ID | 字段 |
|---------|------|
| 700 (PROC_FILE_HOOK) | module_name |
| 701 (SYSCALL_HOOK) | module_name, syscall_number |
| 702 (LKM_HIDDEN) | module_name |
| 703 (INTERRUPTS_HOOK) | module_name, interrupt_number |

## 限制与注意事项

1. **权限要求**: 部分检测需要 root 权限
2. **准确性**: 用户态检测可能存在 TOCTOU 问题
3. **性能**: 定时扫描而非实时监控，有时间窗口
4. **兼容性**: IDT 检测仅支持 x86 架构

## 与原 LKM 的差异

| 方面 | LKM 版本 | eBPF 版本 |
|------|----------|-----------|
| 执行位置 | 内核态 | 用户态 |
| 检测时机 | 定时 15 分钟 | 定时 15 分钟 (保持一致) |
| 数据来源 | 直接内核结构 | /proc, /sys 文件系统 |
| TOCTOU 风险 | 低 | 较高 |
| 部署复杂度 | 需要内核模块 | 无特殊要求 |
