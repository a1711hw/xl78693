# xl78693

个人工具集合。

shadowsocks-manager.sh
-
shadowsocks-manager 一键安装脚本。

[项目地址](https://github.com/shadowsocks/shadowsocks-manager)

要求
- 系统：CentOS 7+

- 用户：root

使用：
```shell
# 安装：
/bin/bash shadowsocks-manager.sh

# 卸载：
/bin/bash shadowsocks-manager.sh uninstall
```

dl-ss.sh
=
自动获取ss客户端脚本。

[项目地址](https://github.com/shadowsocks)

使用：
```shell
crontab -e
0 0 * * * /bin/bash dl-ss.sh >/dev/null 2>&1
```
每天学一次最新的客户端。

fb.sh
=
从/var/log/secure日志中获取恶意登录服务器的IP，将之封禁。

使用：
```shell
crontab -e
0 0 * * * /bin/bash fb.sh >/dev/null 2>&1
```
每天检查一次。

mail.py
=
学来的Python发邮件脚本，25端口。

配合其它脚本使用，前提是服务器开邮件端口。
