/* 测试样本: 缓冲区溢出漏洞 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 漏洞1: 栈缓冲区溢出 - 使用gets()
void vulnerable_gets() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  // 危险: 无边界检查
    printf("Hello, %s\n", buffer);
}

// 漏洞2: strcpy无长度检查
void vulnerable_strcpy(char *user_input) {
    char local_buf[128];
    strcpy(local_buf, user_input);  // 危险: 如果user_input > 128字节
    printf("Copied: %s\n", local_buf);
}

// 漏洞3: 格式化字符串漏洞
void vulnerable_format_string(char *user_data) {
    printf(user_data);  // 危险: 用户可控的格式化字符串
}

// 漏洞4: 整数溢出导致缓冲区分配不足
void vulnerable_integer_overflow(int size) {
    int alloc_size = size + 10;  // 可能溢出
    char *buf = (char *)malloc(alloc_size);
    if (buf) {
        memset(buf, 'A', size);  // 如果size溢出,将写入越界
        free(buf);
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_strcpy(argv[1]);
        vulnerable_format_string(argv[1]);
    }
    vulnerable_gets();
    return 0;
}