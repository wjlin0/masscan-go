<h4 align="center">masscan-go 是一个用Go编写的扫描工具，它与masscan一样,采用syn,允许您快速可靠的扫描端口。</h4>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/wjlin0/masscan-go?filename=go.mod" alt="">
<a href="https://github.com/wjlin0/masscan-go/releases/"><img src="https://img.shields.io/github/release/wjlin0/masscan-go" alt=""></a> 
<a href="https://github.com/wjlin0/masscan-go" ><img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/wjlin0/masscan-go"></a>
<a href="https://github.com/wjlin0/masscan-go/releases"><img src="https://img.shields.io/github/downloads/wjlin0/masscan-go/total" alt=""></a> 
<a href="https://github.com/wjlin0/masscan-go"><img src="https://img.shields.io/github/last-commit/wjlin0/masscan-go" alt=""></a> 
<a href="https://blog.wjlin0.com/"><img src="https://img.shields.io/badge/wjlin0-blog-green" alt=""></a>
</p>

# 为什么会出现 `masscan-go`?

在使用 `masscan` 我遇到一下问题
- 扫到存在防火墙的设备，往往会产生大量的端口误报
- 没有重复发包，以免扫漏的情况

针对以上问题，我创建了 `masscan-go`

- 如果当到端口探测到一定数量时，则停止该IP的端口探测，其他的则不受任何影响。
- 并且再次基础上还进行了排错，若该IP的端口数量大于`50`（默认`50`,由参数`-m`控制），则会开启`tcp`连接扫描`Top1000`端口，并不会完全的排出，以免产生遗漏。

# 适用的平台
目前仅支持`macOS`和`Linux`系统。

# 合适的发包量

发包量是由 `-r` 控制的，它的参数意义是每秒发包量。

- 对于家庭用户的路由器/光猫来说，200-500 才是合适的。
- 对于企业带宽来说，2000-3000 才算合适。
超时参数 `-timeout`, 它的参数意义是超时时间。
- 对于家庭用户来说，3 秒是一个合适的值。
- 对于企业带宽来说，1 秒是一个合适的值。



# 安装masscan-go


下载准备运行的[二进制文件](https://github.com/wjlin0/masscan-go/releases/latest)

- [macOS-arm64](https://github.com/wjlin0/masscan-go/releases/download/v1.0.0/masscan-go_1.0.0_macOS_arm64.zip)

- [macOS-amd64](https://github.com/wjlin0/masscan-go/releases/download/v1.0.0/masscan-go_1.0.0_macOS_amd64.zip)

- [linux-amd64](https://github.com/wjlin0/masscan-go/releases/download/v1.0.0/masscan-go_1.0.0_linux_amd64.zip)

- [linux-arm64](https://github.com/wjlin0/masscan-go/releases/download/v1.0.0/masscan-go_1.0.0_linux_arm64.zip)


# 用法

```shell
masscan-go -h
```
```yaml
masscan-go is a fast and simple port scanner written in Go.

Usage:
  masscan-go [flags]

Flags:
INPUT:
  -t, -target string[]  Target to scan
  -p, -ports string     Ports to scan
  -tp, -top-port int    Top port to scan (default 100)
  -l, -list string[]    List of targets to scan

CONFIG:
  -r, -rate int            Rate of packets per second (default 2000)
  -timeout value           Timeout for each port scan (default 5s)
  -v, -verbose             Verbose output
  -i, -interface string    Interface to use for scanning
  -si, -source-ip string   Source IP address to use for scanning
  -sp, -source-port int    Source port to use for scanning
  -m, -max-open-ports int  Maximum number of open ports to scan (default 100)

OUTPUT:
  -o, -output string  Output file to write found ports

UPDATE:
  -update                      更新版本
  -duc, -disable-update-check  跳过自动检查更新


EXAMPLES:

运行 masscan-go 指定IP/CIDR:
  $ sudo masscan-go -t 192.168.1.1 -t 192.168.1.1/24

运行 masscan-go 从文件中读取:
  $ sudo masscan-go -list file.txt

  运行 masscan-go 联动 nmap：
  $ # 目前暂不支持，未来会联动

运行 masscan-go 收集端口 并配合 nuclei 进行自动化漏洞扫描:
  $ sudo masscan-go -t 192.168.1.1/24 -o output.txt && nuclei -list output.txt

其他文档可在以下网址获得: https://github.com/wjlin0/masscan-go/
```

# 感谢

- [projectdiscovery.io](https://projectdiscovery.io/#/)
