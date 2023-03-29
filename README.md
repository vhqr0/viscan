Intro
=====

本项目为支持本人（[vhqr](https://github.com/vhqr0)）在研究生期间的研究，
主要分为三部分内容：基于 DHCPv6 协议的网络扫描方法、基于 IPv6 协议指纹
的操作系统识别方法和 IPv6 网络扫描平台设计实现。本项目是开源（GPLv3）
的，但是在本人的关于 DHCPv6 网络扫描的研究发表前不会公开。本项目实现了
一个 IPv6 网络扫描框架与若干扫描方法。包括 DeHCP、rDNS 等 IPv6 网络远
程主动扫描方法和本人提出的可以与这些扫描方法配合使用的 DHCPv6 扫描方法
以支持第一项研究内容；包括端口扫描和通用的操作系统底层协议指纹提取框架
以支持第二项研究内容；本项目还将作为第三项研究内容要实现的 IPv6 网络扫
描平台的基础。

Usage
=====

```
python -m viscan.traceroute.ping -h
python -m viscan.traceroute.dns -h
python -m viscan.traceroute.dhcp -h
python -m viscan.traceroute.syn -h
python -m viscan.delimit -h
python -m viscan.hostscan -h
python -m viscan.portscan -h
python -m viscan.osscan.nmap -h
python -m viscan.dnsscan -h
python -m viscan.dhcpscan -h
```
