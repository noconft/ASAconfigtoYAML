import re
import yaml
import os
import sys
import ipaddress
import datetime
from collections import defaultdict
from logger import get_logger
from service_name_to_port import SERVICE_NAME_TO_PORT
from asa_icmp_type_map import ASA_ICMP_TYPE_MAP
from typing import Any, Dict, List, Optional, Tuple

class AsaYamlParseError(Exception):
    """Custom exception for ASA to YAML parsing errors."""
    pass

logger = get_logger()

ERROR_REPORT_PATH = os.path.join("log", "error_report_asa.yaml")

# --- Utility Functions ---
def translate_service_name_to_port(port: Any, protocol: Optional[str] = None) -> Any:
    """
    Translate ASA service name to port number if possible, else return original.
    For ICMP, map type name to (type, code) if possible.
    """
    if protocol and protocol.lower() == 'icmp':
        # For ICMP, ASA config only accepts exact names as in the mapping
        if isinstance(port, str):
            if port in ASA_ICMP_TYPE_MAP:
                return ASA_ICMP_TYPE_MAP[port]
            logger.warning(f"Unknown ICMP type name '{port}' encountered; leaving as string.")
            return port
        return port
    if isinstance(port, int):
        return port
    if isinstance(port, str):
        # Use port name as-is for lookup
        try:
            return int(port)
        except ValueError:
            if port in SERVICE_NAME_TO_PORT:
                return SERVICE_NAME_TO_PORT[port]
            logger.warning(f"Unknown service name '{port}' encountered; leaving as string.")
            return port
    return port

def extract_description(line: str) -> str:
    """
    Extract description from a config line if present.
    Returns the description string or an empty string if not present.
    """
    return line[12:] if line.startswith('description ') else ''

def append_group_member(members: List[dict], member: dict) -> None:
    """
    Append a member to a group, avoiding duplicates.
    """
    if member not in members:
        members.append(member)

# --- Parsing Functions ---
def parse_asa_config(filepath: str) -> Tuple[List[dict], List[dict], List[dict], List[dict], Dict[str, List[dict]], dict]:
    """
    Parse ASA config file and extract objects, object-groups, and access-lists.
    Returns all parsed objects, object-groups, access-lists, and stats.
    """
    with open(filepath, encoding="utf-8") as f:
        lines = [line.rstrip() for line in f]

    net_objects, svc_objects = [], []
    net_object_groups, svc_object_groups = [], []
    access_lists = defaultdict(list)

    # Stats for summary
    stats = {k: {'parsed': 0, 'skipped': 0} for k in ['net_objects', 'svc_objects', 'net_obj_groups', 'svc_obj_groups', 'acl_entries']}
    stats['critical_errors'] = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        try:
            if line.startswith("object network"):
                obj, i = parse_network_object(lines, i)
                if sanity_check_network_object(obj):
                    net_objects.append(obj)
                    stats['net_objects']['parsed'] += 1
                else:
                    logger.warning(f"Invalid network object at line {i}: {obj}")
                    stats['net_objects']['skipped'] += 1
            elif line.startswith("object service"):
                obj, i = parse_service_object(lines, i)
                if sanity_check_service_object(obj):
                    svc_objects.append(obj)
                    stats['svc_objects']['parsed'] += 1
                else:
                    logger.warning(f"Invalid service object at line {i}: {obj}")
                    stats['svc_objects']['skipped'] += 1
            elif line.startswith("object-group network"):
                obj_grp, i = parse_network_object_group(lines, i)
                if sanity_check_network_object_group(obj_grp):
                    net_object_groups.append(obj_grp)
                    stats['net_obj_groups']['parsed'] += 1
                else:
                    logger.warning(f"Invalid network object-group at line {i}: {obj_grp}")
                    stats['net_obj_groups']['skipped'] += 1
            elif line.startswith("object-group service"):
                obj_grp, i = parse_service_object_group(lines, i)
                if sanity_check_service_object_group(obj_grp):
                    svc_object_groups.append(obj_grp)
                    stats['svc_obj_groups']['parsed'] += 1
                else:
                    logger.warning(f"Invalid service object-group at line {i}: {obj_grp}")
                    stats['svc_obj_groups']['skipped'] += 1
            elif line.startswith("access-list"):
                # Ignore ACL remarks
                if "remark" in line:
                    i += 1
                    continue
                acl = parse_access_list(line)
                if acl and sanity_check_acl_entry(acl['entry']):
                    access_lists[acl['acl_name']].append(acl['entry'])
                    stats['acl_entries']['parsed'] += 1
                else:
                    logger.warning(f"Invalid access-list at line {i}: {line}")
                    stats['acl_entries']['skipped'] += 1
                i += 1
            else:
                i += 1
        except Exception as e:
            logger.error(f"Exception at line {i}: {line} | Error: {e}")
            stats['critical_errors'] += 1
            i += 1
    return net_objects, svc_objects, net_object_groups, svc_object_groups, access_lists, stats

def parse_network_object(lines: List[str], idx: int) -> Tuple[dict, int]:
    """
    Parse network object block from ASA config lines.
    Returns the parsed object and the next line index.
    """
    header = lines[idx].split()
    obj = {'name': header[-1]}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        if l.startswith('host '):
            ip = l.split(' ', 1)[1]
            try:
                ipaddress.ip_address(ip)  # Validate
                obj['type'] = 'host'
                obj['ip_address'] = ip
            except ValueError:
                logger.warning(f"Invalid host IP address: {ip}")
        elif l.startswith('subnet '):
            parts = l.split()
            if len(parts) == 3:
                network, netmask = parts[1], parts[2]
                try:
                    ipaddress.IPv4Network(f"{network}/{netmask}")
                    obj['type'] = 'subnet'
                    obj['network'] = network
                    obj['netmask'] = netmask
                except ValueError:
                    logger.warning(f"Invalid subnet: {network} {netmask}")
        elif l.startswith('fqdn '):
            obj['type'] = 'fqdn'
            obj['fqdn'] = l.split(' ', 1)[1]
        elif l.startswith('range '):
            parts = l.split()
            if len(parts) == 3:
                start, end = parts[1], parts[2]
                try:
                    ipaddress.ip_address(start)
                    ipaddress.ip_address(end)
                    obj['type'] = 'range'
                    obj['ip_range'] = {'start': start, 'end': end}
                except ValueError:
                    logger.warning(f"Invalid IP range: {start} {end}")
        desc = extract_description(l)
        if desc:
            obj['description'] = desc
        idx += 1
    return obj, idx

def parse_service_object(lines: List[str], idx: int) -> Tuple[dict, int]:
    """
    Parse service object block from ASA config lines.
    Returns the parsed object and the next line index.
    """
    header = lines[idx].split()
    obj = {'name': header[-1]}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        if l.startswith('service '):
            m_icmp = re.match(r'service\s+icmp\s+([\w\-]+)(?:\s+(\d+))?', l)
            if m_icmp:
                obj['protocol'] = 'icmp'
                icmp_type = m_icmp.group(1)
                icmp_code = m_icmp.group(2)
                mapped = translate_service_name_to_port(icmp_type, protocol='icmp')
                if isinstance(mapped, tuple):
                    obj['icmp_type'] = mapped[0]
                    obj['icmp_code'] = int(icmp_code) if icmp_code is not None else mapped[1]
                else:
                    obj['icmp_type_name'] = icmp_type
                    if icmp_code is not None:
                        obj['icmp_code'] = int(icmp_code)
            elif 'destination eq' in l:
                pre, post = l.split('destination eq', 1)
                proto = pre.replace('service', '').strip()
                port = post.strip()
                obj['protocol'] = proto
                if proto.lower() == 'icmp':
                    mapped = translate_service_name_to_port(port, protocol='icmp')
                    if isinstance(mapped, tuple):
                        obj['icmp_type'] = mapped[0]
                        obj['icmp_code'] = mapped[1]
                    else:
                        obj['icmp_type_name'] = port
                else:
                    obj['destination_port'] = translate_service_name_to_port(port)
            elif 'destination range' in l:
                pre, post = l.split('destination range', 1)
                proto = pre.replace('service', '').strip()
                parts = post.strip().split()
                if len(parts) >= 2:
                    start = parts[0]
                    end = ' '.join(parts[1:])
                    obj['protocol'] = proto
                    if proto.lower() == 'icmp':
                        obj['icmp_type_range'] = {
                            'start': translate_service_name_to_port(start, protocol='icmp'),
                            'end': translate_service_name_to_port(end, protocol='icmp')
                        }
                    else:
                        obj['destination_port_range'] = {
                            'start': translate_service_name_to_port(start),
                            'end': translate_service_name_to_port(end)
                        }
        desc = extract_description(l)
        if desc:
            obj['description'] = desc
        idx += 1
    return obj, idx

def parse_network_object_group(lines: List[str], idx: int) -> Tuple[dict, int]:
    """
    Parse network object-group block from ASA config lines.
    Returns the parsed group and the next line index.
    """
    header = lines[idx].split()
    obj_grp = {'name': header[-1], 'members': []}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        desc = extract_description(l)
        if desc:
            obj_grp['description'] = desc
        elif l.startswith('group-object '):
            append_group_member(obj_grp['members'], {'type': 'group_object', 'name': l.split()[-1]})
        elif l.startswith('network-object object '):
            append_group_member(obj_grp['members'], {'type': 'object', 'name': l.split()[-1]})
        elif l.startswith('network-object host '):
            ip = l.split()[-1]
            try:
                ipaddress.ip_address(ip)
                append_group_member(obj_grp['members'], {'type': 'host', 'ip_address': ip})
            except ValueError:
                logger.warning(f"Invalid host IP in group: {ip}")
        elif l.startswith('network-object '):
            parts = l.split()
            # subnet
            if len(parts) == 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]) and re.match(r'\d+\.\d+\.\d+\.\d+', parts[2]):
                network, netmask = parts[1], parts[2]
                try:
                    ipaddress.IPv4Network(f"{network}/{netmask}")
                    append_group_member(obj_grp['members'], {'type': 'subnet', 'network': network, 'netmask': netmask})
                except ValueError:
                    logger.warning(f"Invalid subnet in group: {network} {netmask}")
            # host
            elif len(parts) == 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]):
                ip = parts[1]
                try:
                    ipaddress.ip_address(ip)
                    append_group_member(obj_grp['members'], {'type': 'host', 'ip_address': ip})
                except ValueError:
                    logger.warning(f"Invalid host IP in group: {ip}")
        idx += 1
    return obj_grp, idx

def parse_service_object_group(lines: List[str], idx: int) -> Tuple[dict, int]:
    """
    Parse service object-group block from ASA config lines.
    Returns the parsed group and the next line index.
    """
    header = lines[idx].split()
    obj_grp = {'name': header[-1], 'members': []}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        desc = extract_description(l)
        if desc:
            obj_grp['description'] = desc
        elif l.startswith('group-object '):
            append_group_member(obj_grp['members'], {'type': 'group_object', 'name': l.split()[-1]})
        elif l.startswith('service-object object '):
            append_group_member(obj_grp['members'], {'type': 'object', 'name': l.split()[-1]})
        elif l.startswith('service-object '):
            # eq (allow spaces and special chars in port name)
            m_eq = re.match(r'service-object ([\w\-_.:/+]+) destination eq (.+)', l)
            # range (allow spaces and special chars in port names)
            m_range = re.match(r'service-object ([\w\-_.:/+]+) destination range (.+) (.+)', l)
            if m_eq:
                port = m_eq.group(2).strip()
                append_group_member(obj_grp['members'], {'type': 'port', 'protocol': m_eq.group(1), 'value': translate_service_name_to_port(port)})
            elif m_range:
                start = m_range.group(2).strip()
                end = m_range.group(3).strip()
                append_group_member(obj_grp['members'], {
                    'type': 'port_range',
                    'protocol': m_range.group(1),
                    'start': translate_service_name_to_port(start),
                    'end': translate_service_name_to_port(end)
                })
        idx += 1
    return obj_grp, idx

def parse_acl_entity(tokens: List[str], idx: int) -> Tuple[dict, int]:
    """
    Parse source or destination entity in ACL.
    Returns the parsed entity and the next token index.
    """
    if idx >= len(tokens):
        return {'type': 'any', 'value': 'any'}, idx
    t = tokens[idx]
    # any
    if t == 'any':
        return {'type': 'any', 'value': 'any'}, idx + 1
    # host
    if t == 'host' and idx + 1 < len(tokens):
        return {'type': 'host', 'ip_address': tokens[idx + 1]}, idx + 2
    # object/object-group <name>
    if t in ('object', 'object-group') and idx + 1 < len(tokens):
        return {'type': t, 'name': tokens[idx + 1]}, idx + 2
    # subnet
    if re.match(r'\d+\.\d+\.\d+\.\d+', t):
        if idx + 1 < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[idx + 1]):
            return {'type': 'subnet', 'network': t, 'netmask': tokens[idx + 1]}, idx + 2
        return {'type': 'host', 'ip_address': t}, idx + 1
    return {'type': 'unknown', 'value': t}, idx + 1

def parse_access_list(line: str) -> Optional[dict]:
    """
    Parse a single access-list line into YAML structure.
    Handles all ASA ACL forms: protocol/service, source, destination, port (if present).
    Returns a dict with ACL name and entry, or None if invalid.
    """
    tokens = line.split()
    if len(tokens) < 6 or tokens[2] != 'extended':
        return None
    acl_name = tokens[1]
    action = tokens[3]
    if action not in ('permit', 'deny'):
        return None  # sanity check
    idx = 4

    # 1. Service/protocol (can be 2 tokens)
    proto_token = tokens[idx]
    service = {}
    if proto_token in ('tcp', 'udp', 'icmp', 'ip'):
        service['type'] = proto_token
        idx += 1
        port_after = True
    elif proto_token in ('object', 'object-group'):
        service['type'] = proto_token
        service['name'] = tokens[idx + 1]
        idx += 2
        port_after = False
    else:
        service['type'] = proto_token
        idx += 1
        port_after = True

    # 2. Source (can be 2 tokens)
    source, idx = parse_acl_entity(tokens, idx)
    # 3. Destination (can be 2 tokens)
    destination, idx = parse_acl_entity(tokens, idx)

    # Port (for tcp/udp, after destination)
    if port_after and service['type'] in ('tcp', 'udp') and idx < len(tokens):
        # eq or range, allow multi-token port names
        if tokens[idx] == 'eq':
            # Collect all tokens after 'eq' as port name (could be multi-word)
            port_tokens = []
            j = idx + 1
            while j < len(tokens) and not tokens[j] in ('log', 'inactive', 'time-range', 'established'):
                port_tokens.append(tokens[j])
                j += 1
            port = ' '.join(port_tokens)
            service['destination_port'] = translate_service_name_to_port(port)
            idx = j
        elif tokens[idx] == 'range':
            # Collect start and end (could be multi-word, but usually 2 tokens)
            start = tokens[idx + 1]
            end = tokens[idx + 2]
            service['destination_port_range'] = {
                'start': translate_service_name_to_port(start),
                'end': translate_service_name_to_port(end)
            }
            idx += 3

    entry = {
        'source': source,
        'destination': destination,
        'service': service,
        'action': action
    }
    return {'acl_name': acl_name, 'entry': entry}

# --- SANITY CHECKS ---

def sanity_check_network_object(obj: dict) -> bool:
    """
    Sanity check for network object structure and values.
    Returns True if valid, False otherwise.
    """
    if 'name' not in obj or 'type' not in obj:
        return False
    if obj['type'] == 'host':
        ip = obj.get('ip_address')
        try:
            ipaddress.ip_address(ip)
        except Exception:
            return False
    if obj['type'] == 'subnet':
        network = obj.get('network')
        netmask = obj.get('netmask')
        try:
            ipaddress.IPv4Network(f"{network}/{netmask}")
        except Exception:
            return False
    if obj['type'] == 'range':
        ipr = obj.get('ip_range', {})
        try:
            ipaddress.ip_address(ipr.get('start'))
            ipaddress.ip_address(ipr.get('end'))
        except Exception:
            return False
    if obj['type'] == 'fqdn' and 'fqdn' not in obj:
        return False
    return True

def sanity_check_service_object(obj: dict) -> bool:
    """
    Sanity check for service object structure and values.
    Returns True if valid, False otherwise.
    """
    if 'name' not in obj or 'protocol' not in obj:
        return False
    # protocol must be a known protocol
    if obj['protocol'] not in ('tcp', 'udp', 'icmp', 'ip'):
        return False
    # For ICMP, require icmp_type or icmp_type_range
    if obj['protocol'] == 'icmp':
        if 'icmp_type' not in obj and 'icmp_type_range' not in obj:
            return False
    return True

def sanity_check_network_object_group(obj_grp: dict) -> bool:
    """
    Sanity check for network object-group structure and values.
    Returns True if valid, False otherwise.
    """
    if 'name' not in obj_grp or 'members' not in obj_grp:
        return False
    if not isinstance(obj_grp['members'], list):
        return False
    return True

def sanity_check_service_object_group(obj_grp: dict) -> bool:
    """
    Sanity check for service object-group structure and values.
    Returns True if valid, False otherwise.
    """
    if 'name' not in obj_grp or 'members' not in obj_grp:
        return False
    if not isinstance(obj_grp['members'], list):
        return False
    return True

def sanity_check_acl_entry(entry: dict) -> bool:
    """
    Sanity check for ACL entry structure and values.
    Returns True if valid, False otherwise.
    """
    # action must be permit or deny
    if entry['action'] not in ('permit', 'deny'):
        return False
    s = entry['service']
    if 'type' not in s:
        return False
    if s['type'] not in ('tcp', 'udp', 'icmp', 'ip', 'object', 'object-group'):
        return False
    # Check source and destination
    for endpoint in ('source', 'destination'):
        ep = entry.get(endpoint, {})
        t = ep.get('type')
        if t == 'host':
            ip = ep.get('ip_address')
            try:
                ipaddress.ip_address(ip)
            except Exception:
                return False
        elif t == 'subnet':
            network = ep.get('network')
            netmask = ep.get('netmask')
            try:
                ipaddress.IPv4Network(f"{network}/{netmask}")
            except Exception:
                return False
        elif t == 'range':
            ipr = ep.get('ip_range', {})
            try:
                ipaddress.ip_address(ipr.get('start'))
                ipaddress.ip_address(ipr.get('end'))
            except Exception:
                return False
        elif t in ('object', 'object-group', 'any', 'group_object', 'unknown'):
            # These are references or special types, skip IP validation
            continue
        else:
            return False
    return True

def write_yaml(filepath: str, data: Any, top_level_key: Optional[str] = None) -> None:
    """
    Write data to YAML file, creating directories if needed, with optional top-level key.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if top_level_key:
        data = {top_level_key: data}
    with open(filepath, 'w', encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, allow_unicode=True)

def print_summary(stats: dict) -> None:
    """
    Print summary of ASA to YAML conversion.
    """
    print("\n=== ASA to YAML Conversion Summary ===")
    print(f"Network objects:        {stats['net_objects']['parsed']} parsed, {stats['net_objects']['skipped']} skipped")
    print(f"Service objects:        {stats['svc_objects']['parsed']} parsed, {stats['svc_objects']['skipped']} skipped")
    print(f"Network object-groups:  {stats['net_obj_groups']['parsed']} parsed, {stats['net_obj_groups']['skipped']} skipped")
    print(f"Service object-groups:  {stats['svc_obj_groups']['parsed']} parsed, {stats['svc_obj_groups']['skipped']} skipped")
    print(f"Access-list entries:    {stats['acl_entries']['parsed']} parsed, {stats['acl_entries']['skipped']} skipped")
    if stats['critical_errors']:
        print(f"Critical errors:        {stats['critical_errors']}")
    print("See ./log/asa2yaml.log for details on skipped/failed entries.\n")

def main() -> None:
    """
    Main entry point for ASA to YAML conversion.
    Parses config, writes YAML, prints summary, and exits with error code if needed.
    Also writes a structured error report to log/error_report_asa.yaml.
    """
    config_file = os.path.join("config", "sample_asa_config.txt")
    net_objects, svc_objects, net_object_groups, svc_object_groups, access_lists, stats = parse_asa_config(config_file)
    write_yaml(os.path.join("yaml", "objects_network.yaml"), net_objects, top_level_key="network_objects")
    write_yaml(os.path.join("yaml", "objects_service.yaml"), svc_objects, top_level_key="service_objects")
    write_yaml(os.path.join("yaml", "object-groups_network.yaml"), net_object_groups, top_level_key="network_object_groups")
    write_yaml(os.path.join("yaml", "object-groups_service.yaml"), svc_object_groups, top_level_key="service_object_groups")
    acl_yaml = [{'acl_name': name, 'entries': entries} for name, entries in access_lists.items()]
    write_yaml(os.path.join("yaml", "access-lists.yaml"), acl_yaml, top_level_key="access_lists")

    print_summary(stats)

    # Write structured error report
    error_report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'critical_errors': stats.get('critical_errors', 0),
        'skipped': {
            'network_objects': stats['net_objects']['skipped'],
            'service_objects': stats['svc_objects']['skipped'],
            'network_object_groups': stats['net_obj_groups']['skipped'],
            'service_object_groups': stats['svc_obj_groups']['skipped'],
            'acl_entries': stats['acl_entries']['skipped'],
        }
    }
    try:
        write_yaml(ERROR_REPORT_PATH, error_report)
        logger.info(f"Error report written to {ERROR_REPORT_PATH}")
    except Exception as e:
        logger.error(f"Failed to write error report: {e}")

    # Exit with non-zero code if critical errors occurred
    if stats['critical_errors'] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()