# APNIC China IP Ranges

自动从 APNIC 获取中国 IP 地址段

## 文件说明

- `china_ipv4_ranges.txt` - IPv4 地址段
- `china_ipv6_ranges.txt` - IPv6 地址段
- `*.sha256sum` - 校验和文件
- `*.xz` - 压缩文件

## 自动更新

每天北京时间 10:00 自动更新

## 手动运行

```bash
python3 parse_apnic_china_ip.py
```