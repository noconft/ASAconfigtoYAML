import os
import re
import sys
import yaml
import ipaddress
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
from logger import get_logger
from service_name_to_port import SERVICE_NAME_TO_PORT
from asa_icmp_type_map import ASA_ICMP_TYPE_MAP
from ciscoconfparse2 import CiscoConfParse

logger = get_logger()

# --- Utility Functions ---
def translate_service_name_to_port(port: Any, protocol: Optional[str] = None) -> Any:
    """Translate ASA service name to port number if possible, else return original."""
    if protocol and protocol.lower() == 'icmp':
        if isinstance(port, str):
            if port in ASA_ICMP_TYPE_MAP:
                return ASA_ICMP_TYPE_MAP[port]
            logger.warning(f"Unknown ICMP type name '{port}' encountered; leaving as string.")
            return port
        return port
    if isinstance(port, int):
        return port
    if isinstance(port, str):
        try:
            return int(port)
        except ValueError:
            if port in SERVICE_NAME_TO_PORT:
                return SERVICE_NAME_TO_PORT[port]
            logger.warning(f"Unknown service name '{port}' encountered; leaving as string.")
            return port
    return port

def extract_description(line: str) -> str:
    """Extract description from a config line if present."""
    return line[12:] if line.startswith('description ') else ''

def append_group_member(members: List[dict], member: dict) -> None:
    """Append a member to a group, avoiding duplicates."""
    if member not in members:
        members.append(member)

# --- Parsing Functions ---
def parse_network_objects_ciscoconfparse(parse: CiscoConfParse) -> Tuple[List[dict], int]:
    """Parse network objects using ciscoconfparse2. Returns (objects, skipped_count)."""
    net_objects = []
    skipped = 0
    for obj in parse.find_objects(r"^object network "):
        name = obj.text.split()[-1]
        net_obj = {'name': name}
        for child in obj.children:
            line = child.text.strip()
            if line.startswith('host '):
                ip = line.split(' ', 1)[1]
                try:
                    ipaddress.ip_address(ip)
                    net_obj['type'] = 'host'
                    net_obj['ip_address'] = ip
                except ValueError:
                    logger.warning(f"Invalid host IP address: {ip}")
            elif line.startswith('subnet '):
                parts = line.split()
                if len(parts) == 3:
                    network, netmask = parts[1], parts[2]
                    try:
                        ipaddress.IPv4Network(f"{network}/{netmask}")
                        net_obj['type'] = 'subnet'
                        net_obj['network'] = network
                        net_obj['netmask'] = netmask
                    except ValueError:
                        logger.warning(f"Invalid subnet: {network} {netmask}")
            elif line.startswith('fqdn '):
                net_obj['type'] = 'fqdn'
                net_obj['fqdn'] = line.split(' ', 1)[1]
            elif line.startswith('range '):
                parts = line.split()
                if len(parts) == 3:
                    start, end = parts[1], parts[2]
                    try:
                        ipaddress.ip_address(start)
                        ipaddress.ip_address(end)
                        net_obj['type'] = 'range'
                        net_obj['ip_range'] = {'start': start, 'end': end}
                    except ValueError:
                        logger.warning(f"Invalid IP range: {start} {end}")
            desc = extract_description(line)
            if desc:
                net_obj['description'] = desc
        if sanity_check_network_object(net_obj):
            net_objects.append(net_obj)
        else:
            logger.warning(f"Invalid network object: {net_obj}")
            skipped += 1
    return net_objects, skipped

def parse_service_objects_ciscoconfparse(parse: CiscoConfParse) -> Tuple[List[dict], int]:
    """Parse service objects using ciscoconfparse2. Returns (objects, skipped_count)."""
    svc_objects = []
    skipped = 0
    for obj in parse.find_objects(r"^object service "):
        name = obj.text.split()[-1]
        svc_obj = {'name': name}
        for child in obj.children:
            line = child.text.strip()
            if line.startswith('service '):
                m_icmp = re.match(r'service\s+icmp\s+([\w\-]+)(?:\s+(\d+))?', line)
                if m_icmp:
                    svc_obj['protocol'] = 'icmp'
                    icmp_type = m_icmp.group(1)
                    icmp_code = m_icmp.group(2)
                    mapped = translate_service_name_to_port(icmp_type, protocol='icmp')
                    if isinstance(mapped, tuple):
                        svc_obj['icmp_type'] = mapped[0]
                        svc_obj['icmp_code'] = int(icmp_code) if icmp_code is not None else mapped[1]
                    else:
                        svc_obj['icmp_type_name'] = icmp_type
                        if icmp_code is not None:
                            svc_obj['icmp_code'] = int(icmp_code)
                elif 'destination eq' in line:
                    pre, post = line.split('destination eq', 1)
                    proto = pre.replace('service', '').strip()
                    port = post.strip()
                    svc_obj['protocol'] = proto
                    if proto.lower() == 'icmp':
                        mapped = translate_service_name_to_port(port, protocol='icmp')
                        if isinstance(mapped, tuple):
                            svc_obj['icmp_type'] = mapped[0]
                            svc_obj['icmp_code'] = mapped[1]
                        else:
                            svc_obj['icmp_type_name'] = port
                    else:
                        svc_obj['destination_port'] = translate_service_name_to_port(port)
                elif 'destination range' in line:
                    pre, post = line.split('destination range', 1)
                    proto = pre.replace('service', '').strip()
                    parts = post.strip().split()
                    if len(parts) >= 2:
                        start = parts[0]
                        end = ' '.join(parts[1:])
                        svc_obj['protocol'] = proto
                        if proto.lower() == 'icmp':
                            svc_obj['icmp_type_range'] = {
                                'start': translate_service_name_to_port(start, protocol='icmp'),
                                'end': translate_service_name_to_port(end, protocol='icmp')
                            }
                        else:
                            svc_obj['destination_port_range'] = {
                                'start': translate_service_name_to_port(start),
                                'end': translate_service_name_to_port(end)
                            }
            desc = extract_description(line)
            if desc:
                svc_obj['description'] = desc
        if sanity_check_service_object(svc_obj):
            svc_objects.append(svc_obj)
        else:
            logger.warning(f"Invalid service object: {svc_obj}")
            skipped += 1
    return svc_objects, skipped

def parse_object_group_members(lines: List[str], group_type: str) -> List[dict]:
    """Generic parser for object-group members."""
    members = []
    for line in lines:
        line = line.strip()
        if group_type == 'network':
            if line.startswith('group-object '):
                append_group_member(members, {'type': 'group_object', 'name': line.split()[-1]})
            elif line.startswith('network-object object '):
                append_group_member(members, {'type': 'object', 'name': line.split()[-1]})
            elif line.startswith('network-object host '):
                ip = line.split()[-1]
                try:
                    ipaddress.ip_address(ip)
                    append_group_member(members, {'type': 'host', 'ip_address': ip})
                except ValueError:
                    logger.warning(f"Invalid host IP in group: {ip}")
            elif line.startswith('network-object '):
                parts = line.split()
                if len(parts) == 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]) and re.match(r'\d+\.\d+\.\d+\.\d+', parts[2]):
                    network, netmask = parts[1], parts[2]
                    try:
                        ipaddress.IPv4Network(f"{network}/{netmask}")
                        append_group_member(members, {'type': 'subnet', 'network': network, 'netmask': netmask})
                    except ValueError:
                        logger.warning(f"Invalid subnet in group: {network} {netmask}")
                elif len(parts) == 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]):
                    ip = parts[1]
                    try:
                        ipaddress.ip_address(ip)
                        append_group_member(members, {'type': 'host', 'ip_address': ip})
                    except ValueError:
                        logger.warning(f"Invalid host IP in group: {ip}")
        elif group_type == 'service':
            if line.startswith('group-object '):
                append_group_member(members, {'type': 'group_object', 'name': line.split()[-1]})
            elif line.startswith('service-object object '):
                append_group_member(members, {'type': 'object', 'name': line.split()[-1]})
            elif line.startswith('service-object '):
                m_eq = re.match(r'service-object ([\w\-_.:/+]+) destination eq (.+)', line)
                m_range = re.match(r'service-object ([\w\-_.:/+]+) destination range (.+) (.+)', line)
                if m_eq:
                    port = m_eq.group(2).strip()
                    append_group_member(members, {'type': 'port', 'protocol': m_eq.group(1), 'value': translate_service_name_to_port(port)})
                elif m_range:
                    start = m_range.group(2).strip()
                    end = m_range.group(3).strip()
                    append_group_member(members, {
                        'type': 'port_range',
                        'protocol': m_range.group(1),
                        'start': translate_service_name_to_port(start),
                        'end': translate_service_name_to_port(end)
                    })
    return members

def parse_network_object_groups_ciscoconfparse(parse: CiscoConfParse) -> Tuple[List[dict], int]:
    """Parse network object-groups using ciscoconfparse2. Returns (groups, skipped_count)."""
    net_obj_groups = []
    skipped = 0
    for obj in parse.find_objects(r"^object-group network "):
        name = obj.text.split()[-1]
        obj_grp = {'name': name, 'members': []}
        desc = None
        member_lines = []
        for child in obj.children:
            line = child.text.strip()
            d = extract_description(line)
            if d:
                desc = d
            else:
                member_lines.append(line)
        if desc:
            obj_grp['description'] = desc
        obj_grp['members'] = parse_object_group_members(member_lines, 'network')
        if sanity_check_network_object_group(obj_grp):
            net_obj_groups.append(obj_grp)
        else:
            logger.warning(f"Invalid network object-group: {obj_grp}")
            skipped += 1
    return net_obj_groups, skipped

def parse_service_object_groups_ciscoconfparse(parse: CiscoConfParse) -> Tuple[List[dict], int]:
    """Parse service object-groups using ciscoconfparse2. Returns (groups, skipped_count)."""
    svc_obj_groups = []
    skipped = 0
    for obj in parse.find_objects(r"^object-group service "):
        name = obj.text.split()[-1]
        obj_grp = {'name': name, 'members': []}
        desc = None
        member_lines = []
        for child in obj.children:
            line = child.text.strip()
            d = extract_description(line)
            if d:
                desc = d
            else:
                member_lines.append(line)
        if desc:
            obj_grp['description'] = desc
        obj_grp['members'] = parse_object_group_members(member_lines, 'service')
        if sanity_check_service_object_group(obj_grp):
            svc_obj_groups.append(obj_grp)
        else:
            logger.warning(f"Invalid service object-group: {obj_grp}")
            skipped += 1
    return svc_obj_groups, skipped

def parse_access_lists_ciscoconfparse(parse: CiscoConfParse) -> Tuple[Dict[str, List[dict]], int]:
    """Parse access-list entries using ciscoconfparse2. Returns (acl_dict, skipped_count)."""
    access_lists = defaultdict(list)
    skipped = 0
    for obj in parse.find_objects(r"^access-list "):
        line = obj.text.strip()
        acl_entry = parse_access_list(line)
        if acl_entry and sanity_check_acl_entry(acl_entry['entry']):
            access_lists[acl_entry['acl_name']].append(acl_entry['entry'])
        else:
            logger.warning(f"Invalid ACL entry: {line}")
            skipped += 1
    return access_lists, skipped

def parse_asa_config(filepath: str) -> Tuple[List[dict], List[dict], List[dict], List[dict], Dict[str, List[dict]], dict]:
    """
    Parse ASA config file and extract objects, object-groups, and access-lists.
    Returns all parsed objects, object-groups, access-lists, and stats.
    """
    parse = CiscoConfParse(filepath, syntax='asa')
    net_objects, net_skipped = parse_network_objects_ciscoconfparse(parse)
    svc_objects, svc_skipped = parse_service_objects_ciscoconfparse(parse)
    net_object_groups, net_grp_skipped = parse_network_object_groups_ciscoconfparse(parse)
    svc_object_groups, svc_grp_skipped = parse_service_object_groups_ciscoconfparse(parse)
    access_lists, acl_skipped = parse_access_lists_ciscoconfparse(parse)

    stats = {k: {'parsed': 0, 'skipped': 0} for k in ['net_objects', 'svc_objects', 'net_obj_groups', 'svc_obj_groups', 'acl_entries']}
    stats['critical_errors'] = 0

    stats['net_objects']['parsed'] = len(net_objects)
    stats['svc_objects']['parsed'] = len(svc_objects)
    stats['net_obj_groups']['parsed'] = len(net_object_groups)
    stats['svc_obj_groups']['parsed'] = len(svc_object_groups)
    stats['acl_entries']['parsed'] = sum(len(v) for v in access_lists.values())

    stats['net_objects']['skipped'] = net_skipped
    stats['svc_objects']['skipped'] = svc_skipped
    stats['net_obj_groups']['skipped'] = net_grp_skipped
    stats['svc_obj_groups']['skipped'] = svc_grp_skipped
    stats['acl_entries']['skipped'] = acl_skipped

    return net_objects, svc_objects, net_object_groups, svc_object_groups, access_lists, stats

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
    """
    config_file = os.path.join("config", "asa_config.txt")
    net_objects, svc_objects, net_object_groups, svc_object_groups, access_lists, stats = parse_asa_config(config_file)
    write_yaml(os.path.join("yaml", "objects_network.yaml"), net_objects, top_level_key="network_objects")
    write_yaml(os.path.join("yaml", "objects_service.yaml"), svc_objects, top_level_key="service_objects")
    write_yaml(os.path.join("yaml", "object-groups_network.yaml"), net_object_groups, top_level_key="network_object_groups")
    write_yaml(os.path.join("yaml", "object-groups_service.yaml"), svc_object_groups, top_level_key="service_object_groups")
    acl_yaml = [{'acl_name': name, 'entries': entries} for name, entries in access_lists.items()]
    write_yaml(os.path.join("yaml", "access-lists.yaml"), acl_yaml, top_level_key="access_lists")

    print_summary(stats)

    if stats['critical_errors'] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()