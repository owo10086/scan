#!/bin/bash
# 一键扫描 REALITY 伪装目标。Mac（开着 Clash TUN）和 Linux VPS 都能直接运行
# 用法：./scan.sh <VPS_IP> [-n 推荐数量，默认10] [-t 并发，默认10] [--max-prefix 最大网段，默认20]
# 例子：./scan.sh 1.2.3.4
#       ./scan.sh 1.2.3.4 -n 5
# 结果：scan-<IP>/report.md（报告）和 scan-<IP>/candidates.csv（全部候选及剔除原因）
set -e
cd "$(dirname "$0")"
if [ -z "$1" ]; then
  sed -n '2,6p' "$0"
  exit 1
fi

XRAY_VER=v26.10.31
SCANNER_VER=v0.2.3

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

prepare_linux() {
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64; xray_zip=Xray-linux-64.zip ;;
    aarch64|arm64) arch=arm64; xray_zip=Xray-linux-arm64-v8a.zip ;;
    *) echo "不支持的 CPU 架构：$(uname -m)"; exit 1 ;;
  esac

  missing=""
  for c in python3 curl openssl unzip; do
    command -v "$c" >/dev/null || missing="$missing $c"
  done
  if [ -n "$missing" ]; then
    echo "安装缺少的依赖：$missing"
    if [ "$(id -u)" != 0 ]; then
      echo "请用 root 运行，或先手动安装：$missing"; exit 1
    fi
    if command -v apt-get >/dev/null; then
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing ca-certificates >/dev/null
    elif command -v dnf >/dev/null; then
      dnf install -y -q $missing ca-certificates
    elif command -v yum >/dev/null; then
      yum install -y -q $missing ca-certificates
    else
      echo "请先手动安装：$missing"; exit 1
    fi
  fi
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 7))' || { echo "需要 Python 3.7 以上"; exit 1; }

  scanner=RealiTLScanner/realitlscanner-linux-$arch
  if [ ! -f "$scanner" ]; then
    echo "下载 RealiTLScanner $SCANNER_VER（linux-$arch）…"
    mkdir -p RealiTLScanner
    curl -fsSL --retry 2 -o "$scanner" \
      "https://github.com/XTLS/RealiTLScanner/releases/download/$SCANNER_VER/RealiTLScanner-linux-$arch"
  fi
  chmod +x "$scanner"

  xray=xray/xray-linux-$arch
  if [ ! -x "$xray" ]; then
    echo "下载 Xray $XRAY_VER（$xray_zip）并校验 SHA256…"
    tmp=$(mktemp -d)
    base=https://github.com/XTLS/Xray-core/releases/download/$XRAY_VER
    curl -fsSL --retry 2 -o "$tmp/$xray_zip" "$base/$xray_zip"
    curl -fsSL --retry 2 -o "$tmp/$xray_zip.dgst" "$base/$xray_zip.dgst"
    want=$(grep -i '^SHA2-256=' "$tmp/$xray_zip.dgst" | head -1 | sed 's/.*= *//')
    got=$(sha256 "$tmp/$xray_zip")
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
      echo "Xray SHA256 校验失败（期望 $want，实际 $got）"; rm -rf "$tmp"; exit 1
    fi
    unzip -oq "$tmp/$xray_zip" xray -d "$tmp"
    mkdir -p xray && mv "$tmp/xray" "$xray" && chmod +x "$xray"
    rm -rf "$tmp"
  fi
}

prepare_mac() {
  for f in RealiTLScanner/realitlscanner xray/xray; do
    [ -x "$f" ] || { echo "缺少 $f"; exit 1; }
  done
  [ -x /opt/homebrew/bin/openssl ] || echo "提示：没找到 Homebrew 的 OpenSSL 3（brew install openssl@3），系统自带的 LibreSSL 会让 TLS 检测不准"
}

case "$(uname -s)" in
  Linux) prepare_linux ;;
  Darwin) prepare_mac ;;
  *) echo "不支持的系统：$(uname -s)"; exit 1 ;;
esac

exec python3 -I reality-verify/oneclick.py "$@"
