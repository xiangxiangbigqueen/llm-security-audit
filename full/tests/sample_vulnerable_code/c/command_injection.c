/* 测试样本: 命令注入漏洞 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 漏洞: 命令注入 - 直接将用户输入拼接到system()调用
void vulnerable_system_call(const char *filename) {
    char command[256];
    sprintf(command, "cat %s", filename);  // 用户输入直接拼接
    system(command);  // 危险: 如果filename = "; rm -rf /"
}

// 漏洞: 通过popen执行命令
void vulnerable_popen(const char *host) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ping -c 3 %s", host);  // 未过滤host
    FILE *fp = popen(cmd, "r");  // 危险: host = "127.0.0.1; cat /etc/passwd"
    if (fp) {
        char result[1024];
        while (fgets(result, sizeof(result), fp)) {
            printf("%s", result);
        }
        pclose(fp);
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_system_call(argv[1]);
        vulnerable_popen(argv[1]);
    }
    return 0;
}