"""Strict, restorable snapshots of supported RGOS capture configuration."""
import json
import re
from .rgos_options import capture_arguments


def section(text, start, following):
    match = re.search(r"(?ms)^"+start+r":\s*\n(.*?)(?=^"+following+r":|\Z)", text)
    return match[1] if match else ""


def snapshot(status):
    if status['running']:
        raise ValueError('设备正在抓包，不能临时接管；请先确认并停止原任务')
    text = status['raw']
    rules = {}
    block = section(text, 'Capture rules', '(?:Capture points|Capture file|Capture Statistic)')
    name = None
    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.fullmatch(r'Capture rules ([A-Za-z0-9_.-]{1,15}):', line)
        if match:
            name = match[1]
            rules[name] = {}
            continue
        if name is None:
            raise ValueError('旧规则格式无法完整备份')
        key, sep, value = line.partition(':')
        if not sep:
            raise ValueError('旧规则包含无法还原的字段：'+line)
        key, value = key.strip(), value.strip()
        if key == 'Etype':
            rules[name]['etype'] = hex(int(value, 0))
        elif key == 'Protocol':
            field = 'v6_protocol' if rules[name].get('etype') == '0x86dd' else 'v4_protocol'
            rules[name][field] = str(int(value, 0))
        else:
            # Never infer a potentially different filter from an unfamiliar display label.
            raise ValueError('旧规则字段尚不支持自动恢复：'+key)
    if set(rules) != status['rules']:
        raise ValueError('旧规则备份不完整')
    points = {}
    block = section(text, 'Capture points', '(?:Capture file|Capture Statistic)')
    name = None
    for line in block.splitlines():
        line = line.strip()
        if not line or re.match(r'(?i)packets captured', line):
            continue
        match = re.fullmatch(r'Capture point ([A-Za-z0-9_.-]{1,15}):', line)
        if match:
            name = match[1]
            points[name] = {}
            continue
        key, sep, value = line.partition(':')
        if name is None or not sep or key not in {'Capture rules','Location','Direction'}:
            raise ValueError('旧抓包点包含无法还原的字段：'+line)
        points[name][key] = value.strip()
    if set(points) != status['points']:
        raise ValueError('旧抓包点备份不完整')
    for point in points.values():
        if set(point) != {'Capture rules','Location','Direction'} or point['Capture rules'] not in rules:
            raise ValueError('旧抓包点与规则关系无法完整备份')
        location = point['Location']
        for short, full in (('Gi','GigabitEthernet'),('Te','TenGigabitEthernet'),('Ag','AggregatePort')):
            if re.fullmatch(short+r'\d+(?:/\d+){0,2}', location):
                location = full+' '+location[len(short):]
        if location != 'control-plane' and not re.fullmatch(r'(?:GigabitEthernet|TenGigabitEthernet|AggregatePort)\s+\d+(?:/\d+){0,2}', location):
            raise ValueError('旧抓包位置尚不支持恢复：'+location)
        point['Location'] = location
        point['Direction'] = {'all':'both'}.get(point['Direction'],point['Direction'])
        if point['Direction'] not in {'in','out','both'}:
            raise ValueError('旧抓包方向无法恢复')
    file = None
    if status['file']:
        if not re.fullmatch(r'(?:tmp|flash):/?[A-Za-z0-9_.-]+', status['file']):
            raise ValueError('旧文件路径无法安全恢复')
        values = []
        for pattern in (r'Buffer size:\s*(\d+)\(MB\)',r'Timeout:\s*(\d+)\(minutes\)',r'Packets limit:\s*(\d+)'):
            match = re.search(pattern,text)
            if not match or int(match[1]) < 1:
                raise ValueError('旧文件参数无法完整备份')
            values.append(int(match[1]))
        file = dict(path=status['file'],buffer_mb=values[0],minutes=values[1],packets=values[2])
    return dict(file=file,rules=rules,points=points)


def signature(config):
    return json.dumps(config,sort_keys=True,separators=(',',':'))


def restore_commands(config):
    commands = []
    if config['file']:
        f = config['file']
        commands.append(('file',f['path'],f"packet capture file {f['path']} buffer-size {f['buffer_mb']} packet-num {f['packets']} timeout {f['minutes']}"))
    for name, filters in sorted(config['rules'].items()):
        expression = capture_arguments({'filters':filters})['filter_cli']
        commands.append(('rule',name,f'packet capture rule {name} filter'+(' '+expression if expression else '')))
    for name, point in sorted(config['points'].items()):
        location = point['Location']
        if location != 'control-plane':location = 'interface '+location
        commands.append(('point',name,f"packet capture point {name} rule {point['Capture rules']} location {location} {point['Direction']}"))
    return commands


def validate_subset(current, expected):
    if current['file'] is not None and current['file'] != expected['file']:
        raise RuntimeError('接管期间设备文件配置发生外部变化，已停止自动处理')
    for kind in ('rules','points'):
        if any(name not in expected[kind] or value != expected[kind][name] for name,value in current[kind].items()):
            raise RuntimeError('接管期间旧配置发生外部变化，已停止自动处理')
