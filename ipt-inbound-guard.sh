#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

APP="ipt-inbound-guard"
BIN="/usr/local/sbin/${APP}.sh"
CONF_DIR="/etc/${APP}"
RULE_FILE="${CONF_DIR}/rules.db"
INTERVAL_FILE="${CONF_DIR}/interval.conf"
SERVICE_FILE="/etc/systemd/system/${APP}.service"
TIMER_FILE="/etc/systemd/system/${APP}.timer"
OPENRC_FILE="/etc/init.d/${APP}"
LAST_REFRESH_FILE="${CONF_DIR}/last_refresh"
REFRESH_LOCK_FILE="${CONF_DIR}/refresh.lock"
SIGNATURE_FILE="${CONF_DIR}/last_applied.sha256"
CRON_MARKER="# ${APP} managed"

CHAIN="IPT_IN_GUARD"

IPT4="${IPT4:-iptables}"
IPT6="${IPT6:-ip6tables}"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "请用 root 运行"
    exit 1
  fi

  if ! command -v "$IPT4" >/dev/null 2>&1; then
    echo "缺少 iptables；Debian/Ubuntu: apt install iptables，Alpine: apk add iptables"
    exit 1
  fi

  if ! command -v "$IPT6" >/dev/null 2>&1; then
    echo "缺少 ip6tables；Debian/Ubuntu: apt install iptables，Alpine: apk add iptables"
    exit 1
  fi
}

detect_distro() {
  [ -r /etc/os-release ] || { echo unknown; return; }
  . /etc/os-release
  case "$ID" in
    alpine|debian|ubuntu) echo "$ID" ;;
    *) echo unknown ;;
  esac
}

# Install missing components on explicit use; scheduled refresh never runs apt/apk.
ensure_dependencies() {
  [ "$(id -u)" -eq 0 ] || { echo "请用 root 运行" >&2; return 1; }
  local os init cmd pkg
  local -a packages=()
  os="$(detect_distro)"
  init="$(detect_init_system)"
  [ "$os" != unknown ] || { echo "仅支持 Alpine、Debian、Ubuntu" >&2; return 1; }
  for cmd in iptables ip6tables getent flock awk sed sort grep tr mktemp install readlink sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 && continue
    case "$cmd" in
      iptables|ip6tables) pkg=iptables ;;
      getent) if [ "$os" = alpine ]; then pkg=musl-utils; else pkg=libc-bin; fi ;;
      flock) if [ "$os" = alpine ]; then pkg=flock; else pkg=util-linux; fi ;;
      awk) pkg=gawk ;;
      sed) pkg=sed ;;
      grep) pkg=grep ;;
      sort|tr|mktemp|install|readlink|sha256sum) pkg=coreutils ;;
    esac
    if [[ " ${packages[*]} " != *" $pkg "* ]]; then packages+=("$pkg"); fi
  done
  local busybox_crontab=0
  if [ "$init" = openrc ] && ! command -v crontab >/dev/null 2>&1; then
    if [ "$os" = alpine ] && command -v busybox >/dev/null 2>&1 &&
       busybox --list | grep -qx crontab; then
      busybox_crontab=1
    else
      packages+=(dcron dcron-openrc)
    fi
  fi
  if [ "${#packages[@]}" -gt 0 ]; then
    printf '安装缺少的依赖 (%s): %s\n' "$os" "${packages[*]}"
    case "$os" in
      alpine) apk add --no-cache "${packages[@]}" ;;
      debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends "${packages[@]}"
        ;;
    esac
  fi
  if [ "$busybox_crontab" -eq 1 ]; then
    mkdir -p /usr/local/bin
    printf '#!/bin/sh\nexec %s crontab "$@"\n' "$(command -v busybox)" > /usr/local/bin/crontab
    chmod 0755 /usr/local/bin/crontab
  fi
  for cmd in iptables ip6tables getent flock awk sed sort grep tr mktemp install readlink sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "安装后仍缺少 $cmd" >&2; return 1; }
  done
  if [ "$init" = openrc ]; then
    command -v crontab >/dev/null 2>&1 || { echo "缺少 crontab" >&2; return 1; }
  fi
}

ensure_files() {
  mkdir -p "$CONF_DIR"
  touch "$RULE_FILE"
  chmod 700 "$CONF_DIR"
  chmod 600 "$RULE_FILE"
}

get_interval() {
  local interval="1"

  if [ -f "$INTERVAL_FILE" ]; then
    interval="$(cat "$INTERVAL_FILE" 2>/dev/null || echo 1)"
  fi

  if ! echo "$interval" | grep -Eq '^[0-9]+$'; then
    interval="1"
  fi

  interval=$((10#$interval))
  if [ "$interval" -lt 1 ] || [ "$interval" -gt 1440 ]; then
    interval="1"
  fi

  echo "$interval"
}

clean_field() {
  echo "${1:-}" | tr '|' ' ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//'
}

new_id() {
  printf '%s-%s-%05d\n' "$(date +%Y%m%d%H%M%S)" "$BASHPID" "$RANDOM"
}

is_ipv4_or_cidr() {
  echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
}

is_ipv6_or_cidr() {
  local x="$1"

  echo "$x" | grep -q ':' || return 1
  echo "$x" | grep -Eq '^[0-9A-Fa-f:]+(/[0-9]{1,3})?$'
}

normalize_proto() {
  local p="${1,,}"

  case "$p" in
    tcp|udp|all|icmp) echo "$p" ;;
    *) echo "" ;;
  esac
}

normalize_ports() {
  local ports="${1:-all}"

  ports="$(echo "$ports" | tr -d ' ' | tr '-' ':')"
  [ -z "$ports" ] && ports="all"

  echo "$ports"
}

valid_ports() {
  local ports="$1"

  [ "$ports" = "all" ] && return 0

  echo "$ports" | grep -Eq '^[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?)*$' || return 1

  local IFS=',' item a b

  for item in $ports; do
    a="${item%%:*}"
    b="${item#*:}"

    [ "$a" -ge 1 ] 2>/dev/null && [ "$a" -le 65535 ] || return 1
    [ "$b" -ge 1 ] 2>/dev/null && [ "$b" -le 65535 ] || return 1
    [ "$a" -le "$b" ] || return 1
  done

  return 0
}

resolve_v4() {
  local target="$1"

  if is_ipv4_or_cidr "$target"; then
    echo "$target"
    return 0
  fi

  if is_ipv6_or_cidr "$target"; then
    return 0
  fi

  getent ahostsv4 "$target" 2>/dev/null | awk '{print $1}' | sort -u
}

resolve_v6() {
  local target="$1"

  if is_ipv6_or_cidr "$target"; then
    echo "$target"
    return 0
  fi

  if is_ipv4_or_cidr "$target"; then
    return 0
  fi

  getent ahostsv6 "$target" 2>/dev/null | awk '$1 ~ /:/ && tolower($1) !~ /::ffff:/ {print $1}' | sort -u
}

ipt4() {
  $IPT4 "$@"
}

ipt6() {
  $IPT6 "$@"
}

flush_chain_one() {
  local family="$1"

  if [ "$family" = "4" ]; then
    ipt4 -N "$CHAIN" 2>/dev/null || true
    ipt4 -F "$CHAIN" 2>/dev/null || true
  else
    ipt6 -N "$CHAIN" 2>/dev/null || true
    ipt6 -F "$CHAIN" 2>/dev/null || true
  fi
}

remove_hook_one() {
  local family="$1"

  if [ "$family" = "4" ]; then
    while ipt4 -C INPUT -j "$CHAIN" 2>/dev/null; do
      ipt4 -D INPUT -j "$CHAIN" 2>/dev/null || break
    done
  else
    while ipt6 -C INPUT -j "$CHAIN" 2>/dev/null; do
      ipt6 -D INPUT -j "$CHAIN" 2>/dev/null || break
    done
  fi
}

install_hook_one() {
  local family="$1"

  if [ "$family" = "4" ]; then
    ipt4 -N "$CHAIN" 2>/dev/null || true

    if ! ipt4 -C INPUT -j "$CHAIN" 2>/dev/null; then
      ipt4 -I INPUT 1 -j "$CHAIN"
    fi
  else
    ipt6 -N "$CHAIN" 2>/dev/null || true

    if ! ipt6 -C INPUT -j "$CHAIN" 2>/dev/null; then
      ipt6 -I INPUT 1 -j "$CHAIN"
    fi
  fi
}

add_match_rule_one() {
  local family="$1"
  local action="$2"
  local proto="$3"
  local ports="$4"
  local src="$5"
  local comment="$6"

  local cmd
  local icmp_proto
  local src_args=()
  local comment_args=()

  if [ "$family" = "4" ]; then
    cmd="$IPT4"
    icmp_proto="icmp"
  else
    cmd="$IPT6"
    icmp_proto="ipv6-icmp"
  fi

  [ -n "$comment" ] && comment_args=(-m comment --comment "$APP: $comment")
  [ -n "$src" ] && [ "$src" != "-" ] && src_args=(-s "$src")

  add_one_proto() {
    local one_proto="$1"

    if [ "$one_proto" = "icmp" ]; then
      "$cmd" -A "$CHAIN" -p "$icmp_proto" "${src_args[@]}" "${comment_args[@]}" -j "$action"
      return
    fi

    if [ "$ports" = "all" ]; then
      "$cmd" -A "$CHAIN" -p "$one_proto" "${src_args[@]}" "${comment_args[@]}" -j "$action"
    else
      local IFS=',' arr=($ports) chunk="" count=0 item

      for item in "${arr[@]}"; do
        if [ -z "$chunk" ]; then
          chunk="$item"
          count=1
        else
          chunk="$chunk,$item"
          count=$((count + 1))
        fi

        if [ "$count" -ge 7 ]; then
          "$cmd" -A "$CHAIN" -p "$one_proto" -m multiport --dports "$chunk" "${src_args[@]}" "${comment_args[@]}" -j "$action"
          chunk=""
          count=0
        fi
      done

      [ -n "$chunk" ] && "$cmd" -A "$CHAIN" -p "$one_proto" -m multiport --dports "$chunk" "${src_args[@]}" "${comment_args[@]}" -j "$action"
    fi
  }

  case "$proto" in
    tcp|udp|icmp)
      add_one_proto "$proto"
      ;;
    all)
      if [ "$ports" = "all" ]; then
        "$cmd" -A "$CHAIN" "${src_args[@]}" "${comment_args[@]}" -j "$action"
      else
        add_one_proto tcp
        add_one_proto udp
      fi
      ;;
  esac
}

# Fingerprint rule database and current DDNS A/AAAA answers. Runs each minute,
# but only rebuilds iptables when the effective rules have changed.
rules_signature() {
  {
    cat "$RULE_FILE"
    local id enabled kind proto ports target comment
    local -a ips4 ips6
    while IFS='|' read -r id enabled kind proto ports target comment; do
      [ -n "${id:-}" ] || continue
      [[ "$id" = \#* ]] && continue
      [ "$enabled" = "1" ] && [ "$kind" = "allow" ] || continue
      if is_ipv4_or_cidr "$target" || is_ipv6_or_cidr "$target"; then
        continue
      fi
      mapfile -t ips4 < <(resolve_v4 "$target")
      mapfile -t ips6 < <(resolve_v6 "$target")
      if [ "${#ips4[@]}" -eq 0 ] && [ "${#ips6[@]}" -eq 0 ]; then
        echo "DDNS 解析失败: $target；保留现有防火墙规则" >&2
        return 1
      fi
      printf '%s A=%s AAAA=%s\n' "$target" "${ips4[*]}" "${ips6[*]}"
    done < "$RULE_FILE"
  } | sha256sum | awk '{print $1}'
}

preflight_rules() {
  # 在任何 iptables 链发生修改之前预检规则和所有启用的 DDNS。
  local id enabled kind proto ports target comment
  local -a ips4 ips6
  while IFS='|' read -r id enabled kind proto ports target comment; do
    [ -z "${id:-}" ] && continue
    [[ "$id" = \#* ]] && continue
    [ "${enabled:-}" = "1" ] || continue
    case "$kind" in
      open|allow|protect) ;;
      *) echo "错误：规则类型不支持：$kind" >&2; return 1 ;;
    esac
    case "$proto" in
      tcp|udp|all|icmp) ;;
      *) echo "错误：协议不支持：$proto" >&2; return 1 ;;
    esac
    if ! valid_ports "$ports"; then
      echo "错误：端口格式不合法：$ports" >&2
      return 1
    fi
    if [ "$kind" = "allow" ]; then
      mapfile -t ips4 < <(resolve_v4 "$target")
      mapfile -t ips6 < <(resolve_v6 "$target")
      if [ "${#ips4[@]}" -eq 0 ] && [ "${#ips6[@]}" -eq 0 ]; then
        echo "错误：$target 暂时没有 A/AAAA，保留现有白名单并取消刷新。" >&2
        return 1
      fi
    fi
  done < "$RULE_FILE"
  return 0
}

apply_rules() {
  need_root
  ensure_files
  preflight_rules || return 1

  # Check both IP families before mutating active firewall chains.
  ipt4 -S INPUT >/dev/null || { echo "错误：IPv4 INPUT 链不可用，规则未修改" >&2; return 1; }
  ipt6 -S INPUT >/dev/null || { echo "错误：IPv6 INPUT 链不可用，规则未修改" >&2; return 1; }

  install_hook_one 4
  install_hook_one 6

  flush_chain_one 4
  flush_chain_one 6

  ipt4 -A "$CHAIN" -i lo -j RETURN
  ipt4 -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

  ipt6 -A "$CHAIN" -i lo -j RETURN
  ipt6 -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

  # open 规则优先：公开放行端口，IPv4 + IPv6 都放行
  while IFS='|' read -r id enabled kind proto ports target comment; do
    [ -z "${id:-}" ] && continue
    echo "$id" | grep -q '^#' && continue
    [ "${enabled:-}" = "1" ] || continue
    [ "${kind:-}" = "open" ] || continue

    add_match_rule_one 4 ACCEPT "$proto" "$ports" "-" "open:$comment"
    add_match_rule_one 6 ACCEPT "$proto" "$ports" "-" "open:$comment"
  done < "$RULE_FILE"

  # allow 规则其次：IP / CIDR / DDNS，域名会同时解析 A + AAAA
  while IFS='|' read -r id enabled kind proto ports target comment; do
    [ -z "${id:-}" ] && continue
    echo "$id" | grep -q '^#' && continue
    [ "${enabled:-}" = "1" ] || continue
    [ "${kind:-}" = "allow" ] || continue

    mapfile -t ips4 < <(resolve_v4 "$target")
    mapfile -t ips6 < <(resolve_v6 "$target")

    if [ "${#ips4[@]}" -eq 0 ] && [ "${#ips6[@]}" -eq 0 ]; then
      echo "警告：$target 解析不到 IPv4/IPv6，已跳过：$comment" >&2
      continue
    fi

    for ip in "${ips4[@]}"; do
      add_match_rule_one 4 ACCEPT "$proto" "$ports" "$ip" "allow:${target}:${comment}"
    done

    for ip in "${ips6[@]}"; do
      add_match_rule_one 6 ACCEPT "$proto" "$ports" "$ip" "allow:${target}:${comment}"
    done
  done < "$RULE_FILE"

  # protect 规则最后：IPv4 + IPv6 都保护
  while IFS='|' read -r id enabled kind proto ports target comment; do
    [ -z "${id:-}" ] && continue
    echo "$id" | grep -q '^#' && continue
    [ "${enabled:-}" = "1" ] || continue
    [ "${kind:-}" = "protect" ] || continue

    add_match_rule_one 4 DROP "$proto" "$ports" "-" "protect:$comment"
    add_match_rule_one 6 DROP "$proto" "$ports" "-" "protect:$comment"
  done < "$RULE_FILE"

  ipt4 -A "$CHAIN" -j RETURN
  ipt6 -A "$CHAIN" -j RETURN
  local sig
  if sig="$(rules_signature)"; then
    printf '%s\n' "$sig" > "$SIGNATURE_FILE"
    chmod 0600 "$SIGNATURE_FILE"
  else
    rm -f "$SIGNATURE_FILE"
  fi
}

show_rules_file() {
  ensure_files

  echo
  echo "规则库：$RULE_FILE"
  echo "格式：序号 | 状态 | 类型 | 协议 | 端口 | 目标 | 备注"
  echo "类型：protect=保护端口；allow=指定来源放行；open=公开放行端口"
  echo "目标支持：IPv4、IPv4 CIDR、IPv6、IPv6 CIDR、DDNS 域名"
  echo

  local n=0

  while IFS='|' read -r id enabled kind proto ports target comment; do
    [ -z "${id:-}" ] && continue
    echo "$id" | grep -q '^#' && continue

    n=$((n + 1))

    local st="启用"
    [ "${enabled:-}" = "1" ] || st="禁用"

    printf '%-4s %-6s %-8s %-5s %-18s %-38s %s\n' "$n" "$st" "$kind" "$proto" "$ports" "$target" "$comment"
  done < "$RULE_FILE"

  [ "$n" -eq 0 ] && echo "暂无规则"
  echo
}

show_iptables() {
  echo
  echo "========== IPv4 INPUT 挂载 =========="
  ipt4 -S INPUT | grep -- "-j $CHAIN" || echo "IPv4 未挂载 $CHAIN"

  echo
  echo "========== IPv4 $CHAIN =========="
  ipt4 -S "$CHAIN" 2>/dev/null || echo "IPv4 链不存在"

  echo
  echo "========== IPv6 INPUT 挂载 =========="
  ipt6 -S INPUT | grep -- "-j $CHAIN" || echo "IPv6 未挂载 $CHAIN"

  echo
  echo "========== IPv6 $CHAIN =========="
  ipt6 -S "$CHAIN" 2>/dev/null || echo "IPv6 链不存在"

  echo
}

append_rule() {
  local kind="$1"
  local proto="$2"
  local ports="$3"
  local target="$4"
  local comment="$5"

  ensure_files
  echo "$(new_id)|1|$kind|$proto|$ports|$target|$comment" >> "$RULE_FILE"
}

read_proto() {
  local proto

  while true; do
    read -rp "协议 tcp/udp/all/icmp [默认 all]: " proto
    proto="$(normalize_proto "${proto:-all}")"

    [ -n "$proto" ] && {
      echo "$proto"
      return
    }

    echo "协议不正确" >&2
  done
}

read_ports() {
  local proto="$1"
  local ports

  if [ "$proto" = "icmp" ]; then
    echo "all"
    return
  fi

  while true; do
    read -rp "端口，支持 22、80,443、10000-20000、all [默认 all]: " ports
    ports="$(normalize_ports "${ports:-all}")"

    if valid_ports "$ports"; then
      echo "$ports"
      return
    fi

    echo "端口格式不正确" >&2
  done
}

menu_add_protect() {
  local proto ports comment

  echo
  echo "添加保护端口：这些端口只允许 open/allow 规则命中，否则 DROP。"
  echo "注意：会同时保护 IPv4 和 IPv6。"
  echo "注意：如果协议 all + 端口 all，相当于没有匹配 allow/open 的全部入站都会被 DROP，慎用。"

  proto="$(read_proto)"
  ports="$(read_ports "$proto")"

  read -rp "备注：" comment
  comment="$(clean_field "$comment")"

  append_rule protect "$proto" "$ports" "-" "$comment"
  apply_rules

  echo "已添加保护端口并应用"
}

menu_add_allow() {
  local target proto ports comment yn

  echo
  echo "添加指定来源放行：来源可以是 IPv4、IPv4 CIDR、IPv6、IPv6 CIDR 或 DDNS 域名。"
  echo "DDNS 会同时解析 A 和 AAAA。"
  echo "直接回车协议默认 all，端口默认 all，即允许该来源访问全部入站。"

  read -rp "来源，例如 1.2.3.4、1.2.3.0/24、240e::1、240e::/64、abc.example.com：" target
  target="$(clean_field "$target")"

  [ -z "$target" ] && {
    echo "来源不能为空"
    return
  }

  proto="$(read_proto)"
  ports="$(read_ports "$proto")"

  read -rp "备注：" comment
  comment="$(clean_field "$comment")"

  append_rule allow "$proto" "$ports" "$target" "$comment"

  if [ "$ports" != "all" ]; then
    read -rp "是否同时保护这些端口，让其它来源不能进？[Y/n]: " yn
    yn="${yn:-Y}"

    if echo "$yn" | grep -Eq '^[Yy]$'; then
      append_rule protect "$proto" "$ports" "-" "auto protect for $comment"
    fi
  fi

  apply_rules

  echo "已添加来源放行并应用"
}

menu_add_open() {
  local proto ports comment

  echo
  echo "添加公开放行端口：任何 IPv4 / IPv6 来源都可以访问这些端口。"
  echo "注意：协议 all + 端口 all 等于公开放行全部入站，慎用。"

  proto="$(read_proto)"
  ports="$(read_ports "$proto")"

  read -rp "备注：" comment
  comment="$(clean_field "$comment")"

  append_rule open "$proto" "$ports" "-" "$comment"
  apply_rules

  echo "已添加公开放行并应用"
}

get_line_id_by_num() {
  local want="$1"
  local n=0
  local id

  while IFS='|' read -r id _; do
    [ -z "${id:-}" ] && continue
    echo "$id" | grep -q '^#' && continue

    n=$((n + 1))

    if [ "$n" = "$want" ]; then
      echo "$id"
      return 0
    fi
  done < "$RULE_FILE"

  return 1
}

menu_delete_rule() {
  local num id tmp

  show_rules_file

  read -rp "输入要删除的序号：" num
  id="$(get_line_id_by_num "$num" || true)"

  [ -z "$id" ] && {
    echo "序号不存在"
    return
  }

  tmp="$(mktemp)"
  awk -F'|' -v id="$id" '$1 != id {print}' "$RULE_FILE" > "$tmp"
  cat "$tmp" > "$RULE_FILE"
  rm -f "$tmp"

  apply_rules

  echo "已删除并应用"
}

menu_toggle_rule() {
  local num id tmp

  show_rules_file

  read -rp "输入要启用/禁用的序号：" num
  id="$(get_line_id_by_num "$num" || true)"

  [ -z "$id" ] && {
    echo "序号不存在"
    return
  }

  tmp="$(mktemp)"
  awk -F'|' -v OFS='|' -v id="$id" '$1 == id {$2=($2=="1"?"0":"1")} {print}' "$RULE_FILE" > "$tmp"
  cat "$tmp" > "$RULE_FILE"
  rm -f "$tmp"

  apply_rules

  echo "已切换状态并应用"
}


detect_init_system() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    echo systemd
  elif command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1; then
    echo openrc
  else
    echo unsupported
  fi
}

install_binary() {
  mkdir -p "$(dirname "$BIN")"
  if [ "$(readlink -f "$0")" != "$BIN" ]; then
    install -m 0755 "$0" "$BIN"
  else
    chmod 0755 "$BIN"
  fi
}

install_systemd() {
  need_root
  ensure_files
  install_binary
  mkdir -p /etc/systemd/system
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=IPTables IPv4/IPv6 inbound guard apply
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN refresh-if-due
EOF
  local interval
  interval="$(get_interval)"
  cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Refresh IPv4/IPv6 inbound guard DDNS every ${interval} minutes

[Timer]
OnBootSec=20s
OnUnitActiveSec=${interval}min
AccuracySec=10s
Unit=${APP}.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${APP}.timer"
  echo "systemd timer 已安装，每 ${interval} 分钟刷新 DDNS。"
}

install_cron_refresh() {
  local tmp
  command -v crontab >/dev/null 2>&1 || { echo "缺少 crontab" >&2; return 1; }
  command -v flock >/dev/null 2>&1 || { echo "缺少 flock（Debian: util-linux；Alpine: util-linux）" >&2; return 1; }
  tmp="$(mktemp)"
  crontab -l 2>/dev/null | grep -Fv "$CRON_MARKER" > "$tmp" || true
  printf '* * * * * %s refresh-if-due >/dev/null 2>&1 %s\n' "$BIN" "$CRON_MARKER" >> "$tmp"
  if ! crontab "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
}

remove_cron_refresh() {
  local tmp
  command -v crontab >/dev/null 2>&1 || return 0
  tmp="$(mktemp)"
  crontab -l 2>/dev/null | grep -Fv "$CRON_MARKER" > "$tmp" || true
  crontab "$tmp" || true
  rm -f "$tmp"
}

install_openrc() {
  need_root
  ensure_files
  install_binary
  cat > "$OPENRC_FILE" <<'EOF'
#!/sbin/openrc-run
description="IPTables IPv4/IPv6 inbound guard"
depend() {
  need localmount
  use net
  after net
}
start() {
  ebegin "Applying inbound guard"
  /usr/local/sbin/ipt-inbound-guard.sh apply
  eend $?
}
stop() {
  ebegin "Leaving current firewall rules unchanged"
  eend 0
}
EOF
  chmod 0755 "$OPENRC_FILE"
  rc-update add "$APP" default
  install_cron_refresh
  if [ -e /etc/init.d/crond ]; then
    rc-update add crond default 2>/dev/null || true
    rc-service crond status >/dev/null 2>&1 || rc-service crond start
  elif [ -e /etc/init.d/cron ]; then
    rc-update add cron default 2>/dev/null || true
    rc-service cron status >/dev/null 2>&1 || rc-service cron start
  elif [ -e /etc/init.d/dcron ]; then
    rc-update add dcron default 2>/dev/null || true
    rc-service dcron status >/dev/null 2>&1 || rc-service dcron start
  fi
  echo "OpenRC 开机启动及 Cron 已安装，DDNS 每 $(get_interval) 分钟刷新。"
  echo "安装时不重新应用正在运行的 INPUT 规则，以免远程 SSH 断线。"
}

install_autostart() {
  case "$(detect_init_system)" in
    systemd) install_systemd ;;
    openrc) install_openrc ;;
    *) echo "不支持的 init 系统；当前自动安装支持 systemd / OpenRC" >&2; return 1 ;;
  esac
}

refresh_if_due() {
  need_root
  ensure_files
  command -v flock >/dev/null 2>&1 || { echo "缺少 flock" >&2; return 1; }
  (
    flock -n 9 || exit 0
    local now last interval
    now="$(date +%s)"
    interval="$(get_interval)"
    last=0
    if [ -r "$LAST_REFRESH_FILE" ]; then
      read -r last < "$LAST_REFRESH_FILE" || true
    fi
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
    # After reboot, missing INPUT hooks must be restored even during cooldown.
    local hooks_ok=0 sig previous=""
    if ipt4 -C INPUT -j "$CHAIN" 2>/dev/null &&
       ipt6 -C INPUT -j "$CHAIN" 2>/dev/null; then
      hooks_ok=1
    fi
    if [ "$hooks_ok" -eq 1 ] && [ "$now" -ge "$last" ] &&
       [ $((now-last)) -lt $((interval*60)) ]; then
      exit 0
    fi
    sig="$(rules_signature)" || exit 1
    [ -r "$SIGNATURE_FILE" ] && read -r previous < "$SIGNATURE_FILE" || true
    if [ "$hooks_ok" -eq 1 ] && [ "$sig" = "$previous" ]; then
      : # No DNS/rule change: skip iptables -F/-A entirely.
    else
      apply_rules
    fi
    date +%s > "$LAST_REFRESH_FILE"
    chmod 0600 "$LAST_REFRESH_FILE"
  ) 9> "$REFRESH_LOCK_FILE"
}



menu_set_interval() {
  ensure_files
  local current interval
  current="$(get_interval)"
  echo
  echo "当前 DDNS 同步间隔：${current} 分钟"
  echo "允许范围：1-1440 分钟"
  read -rp "请输入新的同步间隔（分钟）[默认 1]： " interval
  interval="${interval:-1}"
  if ! echo "$interval" | grep -Eq '^[0-9]+$'; then
    echo "输入错误，只能输入整数分钟"
    return
  fi
  interval=$((10#$interval))
  if [ "$interval" -lt 1 ] || [ "$interval" -gt 1440 ]; then
    echo "输入错误，范围必须是 1-1440 分钟"
    return
  fi
  echo "$interval" > "$INTERVAL_FILE"
  chmod 0600 "$INTERVAL_FILE"
  echo "DDNS 同步间隔已修改为：${interval} 分钟"
  if [ -f "$TIMER_FILE" ] && [ "$(detect_init_system)" = systemd ]; then
    install_systemd
    systemctl restart "${APP}.timer"
    echo "systemd timer 已重新加载"
  elif [ -f "$OPENRC_FILE" ]; then
    echo "OpenRC Cron 将于下一分钟读取新的同步间隔，无须重启。"
  else
    echo "尚未安装开机启动，请执行菜单 9。"
  fi
}

uninstall_autostart() {
  need_root
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "${APP}.timer" 2>/dev/null || true
    systemctl disable --now "${APP}.service" 2>/dev/null || true
  fi
  rm -f "$SERVICE_FILE" "$TIMER_FILE"
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
  if command -v rc-update >/dev/null 2>&1; then
    rc-update del "$APP" default 2>/dev/null || true
  fi
  rm -f "$OPENRC_FILE"
  remove_cron_refresh
  echo "已移除 systemd/OpenRC/Cron 自动任务"
}


clear_firewall() {
  need_root

  remove_hook_one 4
  remove_hook_one 6

  ipt4 -F "$CHAIN" 2>/dev/null || true
  ipt4 -X "$CHAIN" 2>/dev/null || true

  ipt6 -F "$CHAIN" 2>/dev/null || true
  ipt6 -X "$CHAIN" 2>/dev/null || true

  echo "已清除 IPv4/IPv6 $CHAIN 和 INPUT 挂载，不删除规则库"
}

full_uninstall() {
  uninstall_autostart
  clear_firewall

  rm -rf "$CONF_DIR"
  rm -f "$BIN"

  echo "已完整卸载并删除配置"
}

auto_allow_ssh_client() {
  ensure_files

  local client_ip ssh_port

  client_ip="${SSH_CONNECTION%% *}"
  ssh_port="$(echo "${SSH_CONNECTION:-}" | awk '{print $4}')"

  [ -z "$client_ip" ] && {
    echo "未检测到 SSH_CONNECTION"
    return
  }

  [ -z "$ssh_port" ] && ssh_port="22"

  append_rule allow tcp "$ssh_port" "$client_ip" "auto current ssh client"
  append_rule protect tcp "$ssh_port" "-" "auto protect ssh port"

  apply_rules

  echo "已放行当前 SSH 来源 $client_ip 访问 TCP $ssh_port，并保护该端口"
}

menu() {
  need_root
  ensure_files

  while true; do
    echo "============================================================"
    echo " $APP IPv4 + IPv6"
    echo "============================================================"
    echo "1) 查看规则库"
    echo "2) 添加：指定 IP/CIDR/DDNS 放行入站"
    echo "3) 添加：保护端口，未放行来源一律禁止"
    echo "4) 添加：公开放行端口"
    echo "5) 删除规则"
    echo "6) 启用/禁用规则"
    echo "7) 立即应用/刷新 DDNS"
    echo "8) 查看当前 iptables/ip6tables 链"
    echo "9) 安装开机启动 + DDNS 定时刷新"
    echo "10) 仅清除 iptables/ip6tables 链，不删规则库"
    echo "11) 完整卸载"
    echo "12) 自动放行当前 SSH 来源"
    echo "13) 修改 DDNS 同步间隔（默认 1 分钟）"
    echo "0) 退出"

    read -rp "请选择：" c

    case "$c" in
      1) show_rules_file ;;
      2) menu_add_allow ;;
      3) menu_add_protect ;;
      4) menu_add_open ;;
      5) menu_delete_rule ;;
      6) menu_toggle_rule ;;
      7) apply_rules; echo "已应用/刷新 IPv4/IPv6" ;;
      8) show_iptables ;;
      9) install_autostart ;;
      10) clear_firewall ;;
      11)
        read -rp "确认完整卸载？输入 YES：" y
        [ "$y" = "YES" ] && full_uninstall
        ;;
      12) auto_allow_ssh_client ;;
      13) menu_set_interval ;;
      0) exit 0 ;;
      *) echo "无效选择" ;;
    esac

    echo
  done
}

case "${1:-menu}" in
  menu|install|apply|refresh|validate|status) ensure_dependencies ;;
esac

case "${1:-menu}" in
  menu) menu ;;
  apply|refresh) apply_rules ;;
  status) show_rules_file; show_iptables ;;
  install) install_autostart ;;
  refresh-if-due) refresh_if_due ;;
  validate) need_root; ensure_files; preflight_rules && echo '规则和 DDNS 预检通过，未修改防火墙' ;;
  init-system) detect_init_system ;;
  clear) clear_firewall ;;
  uninstall) full_uninstall ;;
  *)
    echo "用法：$0 {menu|apply|refresh|status|validate|init-system|install|refresh-if-due|clear|uninstall}"
    exit 1
    ;;
esac
