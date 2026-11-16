#!/usr/bin/env bash
# 依赖自愈：补齐系统级可选依赖，保证“全命令可执行”口径在环境重建后仍然成立。
#
# 背景：云主机/容器重建会清掉 apt 安装的包，xkeystone 依赖的 nickle 解释器随之消失，
#       命令巡检会由 broken=0 退化为 broken=1。此脚本幂等，可安全重复执行：
#       * 已存在则跳过安装；
#       * 缺失则 apt-get 安装；
#       * 安装后用 xkeystone 的真实 execve 探测复核。
#
# 用法：bash scripts/bootstrap_deps.sh [--check-only]
set -euo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=1

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

log()  { printf '[bootstrap] %s\n' "$*"; }
warn() { printf '[bootstrap][warn] %s\n' "$*" >&2; }

install_nickle() {
    if command -v nickle >/dev/null 2>&1; then
        log "nickle 已存在：$(command -v nickle)"
        return 0
    fi
    if [[ "$CHECK_ONLY" == "1" ]]; then
        warn "nickle 缺失（--check-only 不安装）"
        return 1
    fi
    log "nickle 缺失，开始安装（apt-get）"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nickle
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y nickle
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y nickle
    else
        warn "未识别的包管理器，无法自动安装 nickle"
        return 1
    fi
    command -v nickle >/dev/null 2>&1 || { warn "安装后仍找不到 nickle"; return 1; }
    log "nickle 安装完成：$(command -v nickle)"
}

verify_xkeystone() {
    # 用项目自身的探测逻辑，避免“能 ls 到文件”被误判为可执行。
    local code
    code=$(
        cd "$PROJECT_ROOT" && "$PYTHON" - <<'PY'
import json, sys
from linux_cmd_mcp.exec_probe import probe_executability
info = probe_executability("/usr/bin/xkeystone")
print(json.dumps({"runnable": info.runnable, "reason": info.reason}))
sys.exit(0 if info.runnable else 1)
PY
    ) || { warn "xkeystone 不可执行"; return 1; }
    log "xkeystone 可执行：$code"
}

install_nickle
verify_xkeystone
log "依赖自愈完成（幂等，可重复执行）"
