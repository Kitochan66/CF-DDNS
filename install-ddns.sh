#!/bin/sh
set -eu
umask 077
export PYTHONDONTWRITEBYTECODE=1
quiet=false
for option in "$@"; do
    if [ "$option" = '--quiet' ]; then quiet=true; fi
done
if [ "$quiet" = true ]; then
    # Set up logging before argument validation and dependency installation.
    if [ "$(id -u)" -ne 0 ]; then exit 1; fi
    if ! install -d -o root -g root -m 700 /var/log/cloudflare-ddns-install 2>/dev/null; then exit 1; fi
    if ! (touch /var/log/cloudflare-ddns-install/install.log) 2>/dev/null; then exit 1; fi
    chmod 600 /var/log/cloudflare-ddns-install/install.log 2>/dev/null || exit 1
    exec >>/var/log/cloudflare-ddns-install/install.log 2>&1 </dev/null
    printf '\n--- Cloudflare DDNS installer %s ---\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
fi
task_dir=$(mktemp -d)
trap 'rm -f -- "$task_dir/cloudflare_ddns.py" "$task_dir/config.example.json" "$task_dir/cloudflare-ddns.service" "$task_dir/cloudflare-ddns.timer" "$task_dir/install.sh"; rmdir -- "$task_dir"' EXIT
trap 'exit 1' HUP INT TERM
cat > "$task_dir/cloudflare_ddns.py" <<'CF_DDNS_PAYLOAD_0_END'
#!/usr/bin/env python3
"""Cloudflare DDNS; Python 3 standard library + curl, intended for Debian."""
import argparse
import ipaddress
import json
import logging
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LOG = logging.getLogger("cloudflare-ddns")
API = "https://api.cloudflare.com/client/v4"
DEFAULT_SOURCES = {
    "A": [
        "https://api.ipify.org", "https://api-ipv4.ip.sb/ip",
        "https://ipv4.icanhazip.com", "https://4.ident.me",
        "https://ifconfig.co/ip", "https://ifconfig.me/ip",
    ],
    "AAAA": [
        "https://api6.ipify.org", "https://api-ipv6.ip.sb/ip",
        "https://ipv6.icanhazip.com", "https://6.ident.me",
        "https://ifconfig.co/ip", "https://ifconfig.me/ip",
    ],
}


class DDNSError(Exception):
    pass


def load_config(path):
    with open(path, encoding="utf-8") as stream:
        config = json.load(stream)
    if not isinstance(config, dict):
        raise DDNSError("配置必须是 JSON 对象")
    token = config.get("api_token", "")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", token) or token == "YOUR_API_TOKEN":
        raise DDNSError("请填写有效的 api_token")
    if not re.fullmatch(r"[a-fA-F0-9]{32}", str(config.get("zone_id", ""))):
        raise DDNSError("zone_id 必须是 32 位十六进制 ID")
    records = config.get("records")
    if not isinstance(records, list) or not records:
        raise DDNSError("records 必须是非空数组")
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise DDNSError("每条记录必须是 JSON 对象")
        kind = record.get("type")
        name = record.get("name", "")
        if kind not in DEFAULT_SOURCES or not isinstance(name, str):
            raise DDNSError("记录 type 只能是 A 或 AAAA，name 必须是完整域名")
        try:
            name = name.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise DDNSError("域名编码无效") from exc
        labels = name.split(".")
        if len(name) > 253 or len(labels) < 2 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise DDNSError("name 必须是完整域名，例如 home.example.com")
        record["name"] = name
        key = (kind, name)
        if key in seen:
            raise DDNSError("records 中有重复记录")
        seen.add(key)
        if "proxied" in record and type(record["proxied"]) is not bool:
            raise DDNSError("proxied 必须是 true 或 false")
        ttl = record.get("ttl", 1)
        if type(ttl) is not int or not (ttl == 1 or 60 <= ttl <= 86400):
            raise DDNSError("ttl 必须为 1（自动）或 60 至 86400 秒")
        if record.get("proxied") and ttl != 1:
            raise DDNSError("开启 proxied 时请将 ttl 设为 1")
    sources = config.get("ip_sources", DEFAULT_SOURCES)
    if not isinstance(sources, dict):
        raise DDNSError("ip_sources 必须是 JSON 对象")
    for kind in {r["type"] for r in records}:
        urls = sources.get(kind, DEFAULT_SOURCES[kind])
        if not isinstance(urls, list) or not urls or any(
            not isinstance(url, str) or not url.startswith("https://")
            or not urllib.parse.urlsplit(url).hostname for url in urls
        ):
            raise DDNSError("IP 查询源必须是非空 HTTPS URL 数组")
    return config


def public_ip(kind, sources):
    version = 4 if kind == "A" else 6
    for url in sources:
        try:
            result = subprocess.run(
                ["curl", "--disable", "--silent", "--show-error", "--fail",
                 "--noproxy", "*", "--ipv4" if version == 4 else "--ipv6",
                 "--connect-timeout", "3", "--max-time", "6",
                 "--user-agent", "cloudflare-ddns/1.1", "--header", "Accept: text/plain",
                 "--max-filesize", "1024", "--proto", "=https", url],
                capture_output=True, text=True, timeout=8, check=True,
            )
            address = ipaddress.ip_address(result.stdout.strip())
            if address.version == version and address.is_global and not address.is_multicast and not address.is_reserved:
                return str(address)
        except (subprocess.SubprocessError, ValueError):
            pass
    raise DDNSError("无法取得 IPv%d 公网地址，请检查网络或 ip_sources" % version)


class Cloudflare:
    def __init__(self, config):
        self.token = config["api_token"]
        self.base = "/zones/" + config["zone_id"] + "/dns_records"
        # Avoid accidental use of an environment proxy when discovering/updating IPs.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(API + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json",
            "User-Agent": "cloudflare-ddns/1.1",
        })
        for attempt in range(3):
            try:
                with self.opener.open(request, timeout=15) as response:
                    body = json.load(response)
                if not isinstance(body, dict) or body.get("success") is not True:
                    # Log codes only: API messages might echo sensitive request data.
                    errors = body.get("errors", []) if isinstance(body, dict) else []
                    codes = [e.get("code") for e in errors if isinstance(e, dict)]
                    raise DDNSError("Cloudflare API 返回失败，错误码 %s" % codes)
                return body
            except urllib.error.HTTPError as exc:
                status = exc.code
                exc.close()
                if method != "POST" and (status == 429 or status >= 500) and attempt < 2:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise DDNSError("Cloudflare HTTP %s，请检查令牌权限、Zone ID 或服务状态" % status) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if method != "POST" and attempt < 2:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise DDNSError("Cloudflare 网络请求失败；下一次定时执行会重新查询") from None
            except (ValueError, UnicodeError):
                raise DDNSError("Cloudflare 返回了无效 JSON") from None

    def sync(self, record, address, dry_run=False):
        query = urllib.parse.urlencode({
            "type": record["type"], "name": record["name"], "per_page": 100,
        })
        body = self.request("GET", self.base + "?" + query)
        matches = body.get("result")
        if not isinstance(matches, list):
            raise DDNSError("Cloudflare 记录查询结果格式错误")
        if len(matches) > 1 or body.get("result_info", {}).get("total_count", len(matches)) > 1:
            raise DDNSError("同名同类型记录超过一条，拒绝覆盖；请先整理 DNS 记录")
        desired = {"type": record["type"], "name": record["name"], "content": address}
        # Omitted fields preserve existing values; new records default to DNS-only/auto TTL.
        for field in ("ttl", "proxied"):
            if field in record:
                desired[field] = record[field]
        label = record["name"] + " " + record["type"]
        if matches:
            current = matches[0]
            if all(current.get(k) == v for k, v in desired.items()):
                LOG.info("无需更新 %s = %s", label, address)
                return
            method, path = "PATCH", self.base + "/" + current["id"]
        else:
            method, path = "POST", self.base
            desired.setdefault("ttl", 1)
            desired.setdefault("proxied", False)
        if dry_run:
            LOG.info("预览：将%s %s = %s", "创建" if method == "POST" else "更新", label, address)
            return
        self.request(method, path, desired)
        LOG.info("已%s %s = %s", "创建" if method == "POST" else "更新", label, address)


def run(config, dry_run=False):
    client = Cloudflare(config)
    addresses, failures = {}, 0
    for kind in dict.fromkeys(r["type"] for r in config["records"]):
        try:
            addresses[kind] = public_ip(kind, config.get("ip_sources", {}).get(kind, DEFAULT_SOURCES[kind]))
        except DDNSError as exc:
            LOG.error("%s", exc)
            failures += 1
    for record in config["records"]:
        if record["type"] not in addresses:
            continue
        try:
            client.sync(record, addresses[record["type"]], dry_run)
        except DDNSError as exc:
            LOG.error("%s %s: %s", record["name"], record["type"], exc)
            failures += 1
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/cloudflare-ddns/config.json")
    parser.add_argument("--dry-run", action="store_true", help="只查询和预览，不写入 DNS")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = load_config(args.config)
        # Debian process lock; serializes manual and timer invocations by config inode.
        import fcntl
        with open(args.config, "rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                LOG.info("已有实例运行，本次跳过")
                return 0
            return run(config, args.dry_run)
    except DDNSError as exc:
        LOG.error("%s", exc)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        LOG.error("执行失败：检查配置格式、依赖、文件权限及网络；详细配置要求见 README")
        return 1


if __name__ == "__main__":
    sys.exit(main())
CF_DDNS_PAYLOAD_0_END
cat > "$task_dir/config.example.json" <<'CF_DDNS_PAYLOAD_1_END'
{
  "api_token": "YOUR_API_TOKEN",
  "zone_id": "YOUR_ZONE_ID",
  "records": [
    {"name": "home.example.com", "type": "A", "proxied": false, "ttl": 1}
  ]
}
CF_DDNS_PAYLOAD_1_END
cat > "$task_dir/cloudflare-ddns.service" <<'CF_DDNS_PAYLOAD_2_END'
[Unit]
Description=Update Cloudflare DNS with current public IP
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=cloudflare-ddns
Group=cloudflare-ddns
ExecStart=/usr/bin/python3 /opt/cloudflare-ddns/cloudflare_ddns.py --config /etc/cloudflare-ddns/config.json
TimeoutStartSec=4min
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=
UMask=0077
Environment=PYTHONUNBUFFERED=1
Environment=LANG=C.UTF-8
CF_DDNS_PAYLOAD_2_END
cat > "$task_dir/cloudflare-ddns.timer" <<'CF_DDNS_PAYLOAD_3_END'
[Unit]
Description=Check public IP every five minutes

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
RandomizedDelaySec=15s
AccuracySec=1s
Unit=cloudflare-ddns.service

[Install]
WantedBy=timers.target
CF_DDNS_PAYLOAD_3_END
cat > "$task_dir/install.sh" <<'CF_DDNS_PAYLOAD_4_END'
#!/bin/sh
set -eu
umask 077
export PYTHONDONTWRITEBYTECODE=1
# QUIET_SETUP_BEGIN
quiet=false
for option in "$@"; do
    if [ "$option" = '--quiet' ]; then quiet=true; fi
done
if [ "$quiet" = true ]; then
    # Set up logging before argument validation and dependency installation.
    if [ "$(id -u)" -ne 0 ]; then exit 1; fi
    if ! install -d -o root -g root -m 700 /var/log/cloudflare-ddns-install 2>/dev/null; then exit 1; fi
    if ! (touch /var/log/cloudflare-ddns-install/install.log) 2>/dev/null; then exit 1; fi
    chmod 600 /var/log/cloudflare-ddns-install/install.log 2>/dev/null || exit 1
    exec >>/var/log/cloudflare-ddns-install/install.log 2>&1 </dev/null
    printf '\n--- Cloudflare DDNS installer %s ---\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
fi
# QUIET_SETUP_END
usage() {
    cat <<'HELP'
用法：sudo sh install.sh --token TOKEN --zone-id ZONE_ID --domain home.example.com [选项]
  --domain NAME             完整域名，可重复指定
  --type A|AAAA|both         默认 A；both 同时更新 IPv4 和 IPv6
  --interval-seconds N       检查间隔秒数，60..86400，默认 300
  --proxied true|false       Cloudflare 代理，默认 false
  --ttl N                    默认 1（自动）
  --quiet                    静默无交互安装，输出写入 /var/log/cloudflare-ddns-install/install.log
无参数：仅安装文件，保留原有手动配置方式，不启用定时器。
HELP
}
configured=false
if [ "$#" -gt 0 ]; then configured=true; fi
CF_DDNS_TOKEN='' CF_DDNS_ZONE='' CF_DDNS_DOMAINS=''
CF_DDNS_TYPE=A CF_DDNS_INTERVAL=300 CF_DDNS_PROXIED=false CF_DDNS_TTL=1
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --quiet) shift ;;
        --token|--zone-id|--domain|--type|--interval-seconds|--proxied|--ttl)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo '参数缺少值，使用 --help 查看用法' >&2; exit 1
            fi
            case "$1" in
                --token) CF_DDNS_TOKEN=$2 ;;
                --zone-id) CF_DDNS_ZONE=$2 ;;
                --domain) CF_DDNS_DOMAINS="${CF_DDNS_DOMAINS}${2}
" ;;
                --type) CF_DDNS_TYPE=$2 ;;
                --interval-seconds) CF_DDNS_INTERVAL=$2 ;;
                --proxied) CF_DDNS_PROXIED=$2 ;;
                --ttl) CF_DDNS_TTL=$2 ;;
            esac
            shift 2 ;;
        *) echo '未知参数，使用 --help 查看用法' >&2; exit 1 ;;
    esac
done
if [ "$configured" = true ]; then
    if [ -z "$CF_DDNS_TOKEN" ] || [ -z "$CF_DDNS_ZONE" ] || [ -z "$CF_DDNS_DOMAINS" ]; then
        echo '必须同时填写 --token、--zone-id 和 --domain' >&2; exit 1
    fi
    case "$CF_DDNS_TYPE" in A|AAAA|both) ;; *) echo '--type 只能是 A、AAAA 或 both' >&2; exit 1 ;; esac
    case "$CF_DDNS_PROXIED" in true|false) ;; *) echo '--proxied 只能是 true 或 false' >&2; exit 1 ;; esac
    case "$CF_DDNS_INTERVAL" in ''|*[!0-9]*|????????*) echo '间隔必须是 60..86400 的整数' >&2; exit 1 ;; esac
    if [ "$CF_DDNS_INTERVAL" -lt 60 ] || [ "$CF_DDNS_INTERVAL" -gt 86400 ]; then
        echo '间隔必须是 60..86400 秒' >&2; exit 1
    fi
fi
if [ "$(id -u)" -ne 0 ]; then
    echo '请使用 sudo sh install.sh 或以 root 运行' >&2
    exit 1
fi
cd -- "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
command -v systemctl >/dev/null
if [ ! -d /run/systemd/system ]; then
    echo '一键安装要求正在运行 systemd 的 Debian 主机' >&2; exit 1
fi
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a
export UCF_FORCE_CONFFOLD=1
apt-get -q -o Dpkg::Use-Pty=0 update
apt-get -y -q -o Dpkg::Use-Pty=0 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install python3 curl ca-certificates
config_tmp=''
trap 'if [ -n "$config_tmp" ]; then rm -f -- "$config_tmp"; fi' EXIT
trap 'exit 1' HUP INT TERM
if [ "$configured" = true ]; then
    export CF_DDNS_TOKEN CF_DDNS_ZONE CF_DDNS_DOMAINS CF_DDNS_TYPE CF_DDNS_PROXIED CF_DDNS_TTL
    config_tmp=$(mktemp)
    python3 - "$config_tmp" <<'PY'
import json
import os
import sys
sys.path.insert(0, os.getcwd())
from cloudflare_ddns import load_config, DDNSError
try:
    kinds = ["A", "AAAA"] if os.environ["CF_DDNS_TYPE"] == "both" else [os.environ["CF_DDNS_TYPE"]]
    config = {
        "api_token": os.environ["CF_DDNS_TOKEN"],
        "zone_id": os.environ["CF_DDNS_ZONE"],
        "records": [
            {"name": name, "type": kind, "proxied": os.environ["CF_DDNS_PROXIED"] == "true",
             "ttl": int(os.environ["CF_DDNS_TTL"])}
            for name in os.environ["CF_DDNS_DOMAINS"].splitlines() for kind in kinds
        ],
    }
    with open(sys.argv[1], "w", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2)
        stream.write("\n")
    load_config(sys.argv[1])
except (DDNSError, ValueError) as exc:
    # Never print supplied values, including an invalid token/TTL.
    print("配置校验失败，请检查令牌、Zone ID、域名及 TTL", file=sys.stderr)
    sys.exit(1)
PY
    unset CF_DDNS_TOKEN CF_DDNS_ZONE CF_DDNS_DOMAINS
    systemctl stop cloudflare-ddns.timer cloudflare-ddns.service 2>/dev/null || true
fi
if ! getent passwd cloudflare-ddns >/dev/null; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin cloudflare-ddns
fi
install -d -o root -g root -m 755 /opt/cloudflare-ddns
install -d -o root -g cloudflare-ddns -m 750 /etc/cloudflare-ddns
install -o root -g root -m 755 cloudflare_ddns.py /opt/cloudflare-ddns/cloudflare_ddns.py
if [ "$configured" = true ]; then
    install -o root -g cloudflare-ddns -m 640 "$config_tmp" /etc/cloudflare-ddns/config.json
elif [ ! -e /etc/cloudflare-ddns/config.json ]; then
    install -o root -g cloudflare-ddns -m 640 config.example.json /etc/cloudflare-ddns/config.json
fi
install -o root -g root -m 644 cloudflare-ddns.service cloudflare-ddns.timer /etc/systemd/system/
if [ "$configured" = true ]; then
    install -d -o root -g root -m 755 /etc/systemd/system/cloudflare-ddns.timer.d
    printf '[Timer]\nOnUnitActiveSec=\nOnUnitActiveSec=%ss\n' "$CF_DDNS_INTERVAL" > /etc/systemd/system/cloudflare-ddns.timer.d/10-ddns-interval.conf
    chmod 644 /etc/systemd/system/cloudflare-ddns.timer.d/10-ddns-interval.conf
fi
systemctl daemon-reload
if [ "$configured" = true ]; then
    if ! systemctl start cloudflare-ddns.service; then
        journalctl -u cloudflare-ddns.service -n 30 --no-pager || true
        echo '首次更新失败，已保留配置，定时器未启动。查看：journalctl -u cloudflare-ddns.service -n 30 --no-pager' >&2
        exit 1
    fi
    systemctl enable --now cloudflare-ddns.timer
    if [ "$quiet" = true ]; then
        journalctl -u cloudflare-ddns.service -n 20 --no-pager || true
    fi
    echo "安装成功：已完成首次更新，之后每 ${CF_DDNS_INTERVAL} 秒检查。"
else
    echo '安装完成。编辑 /etc/cloudflare-ddns/config.json，手动验证后启用 timer（详见 README.md）。'
fi
CF_DDNS_PAYLOAD_4_END
sh "$task_dir/install.sh" "$@"
