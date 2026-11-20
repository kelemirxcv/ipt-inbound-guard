# ipt-inbound-guard

Debian / Ubuntu / Alpine Linux 通用 **IPv4 + IPv6 入站防火墙及 DDNS 白名单管理脚本**。不需要 Docker。

## 主要功能

- 根据 `/etc/os-release` 自动识别 Debian、Ubuntu、Alpine。
- 安装时检测并安装缺少的命令及依赖（使用 `apt-get` 或 `apk`）。
- Debian / Ubuntu 使用 systemd service + timer，Alpine 使用 OpenRC + cron。
- DDNS 默认 **每 1 分钟检测一次**，支持 1–1440 分钟自定义；旧配置的用户自选间隔会保留。
- IPv4 / IPv6、单独 IP、CIDR、DDNS A/AAAA 记录。
- 规则类型：保护端口（DROP 未获准的入站）、指定来源允许（ACCEPT）、公开端口（ACCEPT）。
- 支持 TCP、UDP、all、ICMP，端口段及多个端口。
- 添加、启用/禁用、删除、查看规则，检测和放行当前 SSH 来源。
- **DNS 没有变化且规则未改变时不会每分钟重建 iptables 链**；DDNS 解析失败时保留原有规则。
- 仅清除由脚本管理的链，或者完整卸载。
- 无 Docker；不修改其他服务原本的规则、监听或 SSH 配置。

## 安装

将本仓库下载或克隆到服务器，随后执行：

```bash
sudo sh install.sh
```

安装程序会自动安装必要依赖，安装脚本到：

```
/usr/local/sbin/ipt-inbound-guard.sh
```

安装不会立即执行 `apply`，以尽量避免 SSH 会话中途被封锁；但安装的 systemd timer 会在启动后开始运行，Alpine OpenRC 会在下次开机时套用规则，cron 会按设定周期刷新。**如现有规则包含保护 SSH 端口，应先确保白名单正确以及云控制台可用于回滚。**

## 运行与管理

```bash
sudo bash /usr/local/sbin/ipt-inbound-guard.sh
```

常用非交互命令：

```bash
sudo /usr/local/sbin/ipt-inbound-guard.sh init-system
sudo /usr/local/sbin/ipt-inbound-guard.sh validate
sudo /usr/local/sbin/ipt-inbound-guard.sh status
sudo /usr/local/sbin/ipt-inbound-guard.sh apply
sudo /usr/local/sbin/ipt-inbound-guard.sh refresh-if-due
```

配置位置：

```
/etc/ipt-inbound-guard/rules.db
/etc/ipt-inbound-guard/interval.conf
```

默认间隔为 1 分钟，且**只有每分钟检查一次 DDNS，并非每分钟强制刷新防火墙**。已有 `interval.conf` 的服务器会保持原本设定，可以在菜单选项 13 改成 1 分钟。

## SSH 安全提醒

这个脚本管理的是宿主机 **INPUT** 入站规则，部分规则能够封锁所有公网入站。应先在管理菜单选项 12 自动加入当前 SSH 来源，再添加保护端口；更推荐先单独加入可信的 IP/CIDR/DDNS 白名单，再保护特定端口。

如无救援控制台，不建议直接开启 `all + all` 的全端口保护规则。现有 SSH 会话可因 `ESTABLISHED,RELATED` 保留，但**不保证重新连接不会被锁定**。

**使用者需自行负责云安全组放行和现有防火墙冲突检查。**

## 系统支持

| 系统 | 套件管理 | 开机启动 | 每分钟 DDNS 检测 |
| --- | --- | --- | --- |
| Debian 12/13 | apt-get | systemd | systemd timer |
| Ubuntu 22.04/24.04 及更新版 | apt-get | systemd | systemd timer |
| Alpine Linux 3.20–3.23 | apk | OpenRC | cron |

依赖：bash、iptables/ip6tables、getent、flock、awk、grep、sed、coreutils 等。若缺失，安装程序会按系统补齐。

## 开源安全

仅发布源码与说明，不包含生产服务器的 `rules.db`、DDNS 主机名、凭证、SSH key 或服务器 IP。请勿将 `/etc/ipt-inbound-guard` 上传至公开仓库。

## 卸载

执行菜单选项 11（需要明确输入 YES），或：

```bash
sudo /usr/local/sbin/ipt-inbound-guard.sh uninstall
```

会移除本程序管理的服务、定时任务、链及其配置，不主动清空其他 iptables 链。
