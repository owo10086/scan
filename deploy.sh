#!/bin/bash
# 打包 VPS 版并上传。只打包 VPS 需要的文件：脚本、文档、Linux 版扫描器（Xray 在 VPS 上首次运行时自动下载）
# 用法：./deploy.sh                  只打包，生成 dist/reality-scan-vps.tar.gz，自己用任意方式上传
#       ./deploy.sh myvps            打包并上传到 myvps:/root/reality-scan（myvps 是 ~/.ssh/config 里的别名）
#       ./deploy.sh root@1.2.3.4 22  用户@IP 加端口
set -e
cd "$(dirname "$0")"
mkdir -p dist
PKG=dist/reality-scan-vps.tar.gz
# 本地有 Linux 版扫描器就一起打包；没有的话 scan.sh 在 VPS 上首次运行时会下载官方 Release
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs -czf "$PKG" \
  scan.sh README.md REALITY目标扫描教程.md reality-verify/*.py $(ls RealiTLScanner/realitlscanner-linux-* 2>/dev/null)
echo "已打包：$PKG（$(du -h "$PKG" | cut -f1)）"

if [ -z "$1" ]; then
  echo
  echo "上传到 VPS 后执行："
  echo "  mkdir -p /root/reality-scan && tar xzf reality-scan-vps.tar.gz -C /root/reality-scan"
  echo "  cd /root/reality-scan && ./scan.sh <VPS_IP>"
  exit 0
fi

ssh ${2:+-p "$2"} "$1" 'mkdir -p /root/reality-scan && tar xzf - -C /root/reality-scan' < "$PKG"
echo "已上传到 $1:/root/reality-scan"
echo
echo "在 VPS 上执行："
echo "  ssh ${2:+-p $2 }$1"
echo "  cd /root/reality-scan && ./scan.sh <VPS_IP>"
