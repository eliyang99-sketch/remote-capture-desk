"""Validated RGOS capture arguments, never arbitrary CLI input."""
import ipaddress
import re

FIELDS = ("src_mac", "dst_mac", "etype", "ipv4_sip", "ipv4_dip", "ipv4_sport", "ipv4_dport",
          "ipv6_sip", "ipv6_dip", "ipv6_sport", "ipv6_dport", "v4_protocol", "v6_protocol",
          "icmpv4_type", "icmpv4_code", "icmpv6_type", "icmpv6_code")


def validate_server(server):
    if server.remote_base not in {"tmp:", "flash:"}:
        raise ValueError("RGOS 文件系统只支持 tmp: 或 flash:")
    if server.direction not in {"both", "in", "out"}:
        raise ValueError("抓包方向无效")
    if server.interface != "control-plane" and not re.fullmatch(
            r"(?:GigabitEthernet|TenGigabitEthernet|AggregatePort)\s+\d+(?:/\d+){0,2}", server.interface):
        raise ValueError("请选择明确的 RGOS 接口，或 control-plane")
    if server.receiver_ip:
        ipaddress.IPv4Address(server.receiver_ip)


def capture_arguments(options, capabilities=None):
    cfg = dict(minutes=1, packets=1024, buffer_mb=2, filters={})
    cfg.update(options)
    caps = capabilities or {}
    for key, maximum in (("minutes", 60), ("packets", caps.get("packets", 300000)),
                         ("buffer_mb", caps.get("buffer_mb", 15))):
        if type(cfg[key]) is not int or not 1 <= cfg[key] <= maximum:
            raise ValueError(f"RGOS {key} 范围为 1–{maximum}")
    parts = []
    filters = cfg["filters"]
    if not isinstance(filters, dict) or set(filters) - set(FIELDS):
        raise ValueError("不支持的 RGOS 过滤字段")
    for key in FIELDS:
        value = str(filters.get(key, "")).strip()
        if not value:
            continue
        if caps.get("fields") is not None and key not in caps["fields"]:
            raise ValueError("设备不支持过滤字段：" + key)
        if key.startswith("ipv4_") and key.endswith(("sip", "dip")):
            if "/" in value:
                net = ipaddress.IPv4Network(value, strict=False)
                value = f"{net.network_address} {net.hostmask}"
            else:
                value = "host " + str(ipaddress.IPv4Address(value))
        elif key.startswith("ipv6_") and key.endswith(("sip", "dip")):
            value = str(ipaddress.IPv6Address(value))
        elif key.endswith(("sport", "dport")):
            if not value.isdigit() or not 0 <= int(value) <= 65535:
                raise ValueError("端口范围为 0–65535")
            value = "eq " + str(int(value))
        elif key in {"src_mac", "dst_mac"}:
            compact = re.sub(r"[:.\-]", "", value)
            if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
                raise ValueError("MAC 地址无效")
            value = ".".join(compact[i:i+4] for i in (0, 4, 8))
        elif key == "etype":
            if value not in {"arp", "ip", "ipv6", "802.1q"}:
                n = int(value, 16 if value.lower().startswith("0x") else 10)
                if not 0 <= n <= 65535:
                    raise ValueError("EtherType 超出范围")
                value = hex(n)
        else:
            protocols = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "gre": 47, "ospf": 89}
            value = str(protocols.get(value, value))
            if not value.isdigit() or not 0 <= int(value) <= 255:
                raise ValueError("协议或 ICMP 字段必须为 0–255")
        parts.extend((key, value))
    if any(k.startswith("ipv4_") or k.startswith("icmpv4_") or k == "v4_protocol" for k in filters if filters[k]) and any(
            k.startswith("ipv6_") or k.startswith("icmpv6_") or k == "v6_protocol" for k in filters if filters[k]):
        raise ValueError("同一规则不能混用 IPv4 和 IPv6 字段")
    cfg["filter_cli"] = " ".join(parts)
    return cfg
