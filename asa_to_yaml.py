import re
import yaml
import os
import sys
import ipaddress 
from collections import defaultdict
from logger import get_logger  # Import the centralized logger
from service_name_to_port import SERVICE_NAME_TO_PORT

logger = get_logger()  # Initialize the logger

def parse_asa_config(filepath):
    """Parse ASA config file and extract objects, object-groups, and access-lists."""
    with open(filepath, encoding="utf-8") as f:
        lines = [line.rstrip() for line in f]

    net_objects, svc_objects = [], []
    net_object_groups, svc_object_groups = [], []
    access_lists = defaultdict(list)

    # Stats for summary
    stats = {
        'net_objects': {'parsed': 0, 'skipped': 0},
        'svc_objects': {'parsed': 0, 'skipped': 0},
        'net_obj_groups': {'parsed': 0, 'skipped': 0},
        'svc_obj_groups': {'parsed': 0, 'skipped': 0},
        'acl_entries': {'parsed': 0, 'skipped': 0},
        'critical_errors': 0
    }

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

def parse_network_object(lines, idx):
    """Parse network object block."""
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
        if l.startswith('description '):
            obj['description'] = l[12:]
        idx += 1
    return obj, idx

def translate_service_name_to_port(port):
    """Translate ASA service name to port number if possible, else return original."""
    if isinstance(port, int):
        return port
    if isinstance(port, str):
        # Normalize: strip, lower, replace multiple spaces with single, replace spaces with dash/underscore
        port_norm = re.sub(r'\s+', '-', port.strip().lower())
        # Try direct int
        try:
            return int(port_norm)
        except ValueError:
            # Try direct lookup
            if port_norm in SERVICE_NAME_TO_PORT:
                return SERVICE_NAME_TO_PORT[port_norm]
            # Try with underscores (for some mappings)
            port_us = port_norm.replace('-', '_')
            if port_us in SERVICE_NAME_TO_PORT:
                return SERVICE_NAME_TO_PORT[port_us]
            # Try with spaces removed
            port_nospace = port_norm.replace('-', '')
            if port_nospace in SERVICE_NAME_TO_PORT:
                return SERVICE_NAME_TO_PORT[port_nospace]
            logger.warning(f"Unknown service name '{port}' (normalized: '{port_norm}') encountered; leaving as string.")
            return port
    return port

def parse_service_object(lines, idx):
    """Parse service object block, supporting multi-token service names and ports."""
    header = lines[idx].split()
    obj = {'name': header[-1]}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        # Support multi-token service names and ports
        if l.startswith('service '):
            # Split on 'destination eq' or 'destination range'
            if 'destination eq' in l:
                pre, post = l.split('destination eq', 1)
                proto = pre.replace('service', '').strip()
                port = post.strip()
                obj['protocol'] = proto
                obj['destination_port'] = translate_service_name_to_port(port)
            elif 'destination range' in l:
                pre, post = l.split('destination range', 1)
                proto = pre.replace('service', '').strip()
                # The post part may have multi-token start and end ports
                # Try to split only on the first space
                parts = post.strip().split()
                if len(parts) >= 2:
                    start = parts[0]
                    end = ' '.join(parts[1:])
                    obj['protocol'] = proto
                    obj['destination_port_range'] = {
                        'start': translate_service_name_to_port(start),
                        'end': translate_service_name_to_port(end)
                    }
        if l.startswith('description '):
            obj['description'] = l[12:]
        idx += 1
    return obj, idx

def parse_network_object_group(lines, idx):
    """Parse network object-group block."""
    header = lines[idx].split()
    obj_grp = {'name': header[-1], 'members': []}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        if l.startswith('description '):
            obj_grp['description'] = l[12:]
        elif l.startswith('group-object '):
            obj_grp['members'].append({'type': 'group_object', 'name': l.split()[-1]})
        elif l.startswith('network-object object '):
            obj_grp['members'].append({'type': 'object', 'name': l.split()[-1]})
        elif l.startswith('network-object host '):
            ip = l.split()[-1]
            try:
                ipaddress.ip_address(ip)
                obj_grp['members'].append({'type': 'host', 'ip_address': ip})
            except ValueError:
                logger.warning(f"Invalid host IP in group: {ip}")
        elif l.startswith('network-object '):
            parts = l.split()
            # subnet
            if len(parts) == 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]) and re.match(r'\d+\.\d+\.\d+\.\d+', parts[2]):
                network, netmask = parts[1], parts[2]
                try:
                    ipaddress.IPv4Network(f"{network}/{netmask}")
                    obj_grp['members'].append({'type': 'subnet', 'network': network, 'netmask': netmask})
                except ValueError:
                    logger.warning(f"Invalid subnet in group: {network} {netmask}")
            # host
            elif len(parts) == 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[1]):
                ip = parts[1]
                try:
                    ipaddress.ip_address(ip)
                    obj_grp['members'].append({'type': 'host', 'ip_address': ip})
                except ValueError:
                    logger.warning(f"Invalid host IP in group: {ip}")
        idx += 1
    return obj_grp, idx

def parse_service_object_group(lines, idx):
    """Parse service object-group block."""
    header = lines[idx].split()
    obj_grp = {'name': header[-1], 'members': []}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        if l.startswith('description '):
            obj_grp['description'] = l[12:]
        elif l.startswith('group-object '):
            obj_grp['members'].append({'type': 'group_object', 'name': l.split()[-1]})
        elif l.startswith('service-object object '):
            obj_grp['members'].append({'type': 'object', 'name': l.split()[-1]})
        elif l.startswith('service-object '):
            # eq (allow spaces and special chars in port name)
            m_eq = re.match(r'service-object ([\w\-_.:/+]+) destination eq (.+)', l)
            # range (allow spaces and special chars in port names)
            m_range = re.match(r'service-object ([\w\-_.:/+]+) destination range (.+) (.+)', l)
            if m_eq:
                port = m_eq.group(2).strip()
                obj_grp['members'].append({'type': 'port', 'protocol': m_eq.group(1), 'value': translate_service_name_to_port(port)})
            elif m_range:
                start = m_range.group(2).strip()
                end = m_range.group(3).strip()
                obj_grp['members'].append({
                    'type': 'port_range',
                    'protocol': m_range.group(1),
                    'start': translate_service_name_to_port(start),
                    'end': translate_service_name_to_port(end)
                })
        idx += 1
    return obj_grp, idx

def parse_acl_entity(tokens, idx):
    """Parse source or destination entity in ACL."""
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

def parse_access_list(line):
    """
    Parse a single access-list line into YAML structure.
    Handles all ASA ACL forms: protocol/service, source, destination, port (if present).
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

def sanity_check_network_object(obj):
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

def sanity_check_service_object(obj):
    if 'name' not in obj or 'protocol' not in obj:
        return False
    # protocol must be a known protocol
    if obj['protocol'] not in ('tcp', 'udp', 'icmp', 'ip'):
        return False
    return True

def sanity_check_network_object_group(obj_grp):
    if 'name' not in obj_grp or 'members' not in obj_grp:
        return False
    if not isinstance(obj_grp['members'], list):
        return False
    return True

def sanity_check_service_object_group(obj_grp):
    if 'name' not in obj_grp or 'members' not in obj_grp:
        return False
    if not isinstance(obj_grp['members'], list):
        return False
    return True

def sanity_check_acl_entry(entry):
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

def write_yaml(filepath, data, top_level_key=None):
    """Write data to YAML file, creating directories if needed, with optional top-level key."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if top_level_key:
        data = {top_level_key: data}
    with open(filepath, 'w', encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, allow_unicode=True)

def print_summary(stats):
    """Print summary of ASA to YAML conversion."""
    print("\n=== ASA to YAML Conversion Summary ===")
    print(f"Network objects:        {stats['net_objects']['parsed']} parsed, {stats['net_objects']['skipped']} skipped")
    print(f"Service objects:        {stats['svc_objects']['parsed']} parsed, {stats['svc_objects']['skipped']} skipped")
    print(f"Network object-groups:  {stats['net_obj_groups']['parsed']} parsed, {stats['net_obj_groups']['skipped']} skipped")
    print(f"Service object-groups:  {stats['svc_obj_groups']['parsed']} parsed, {stats['svc_obj_groups']['skipped']} skipped")
    print(f"Access-list entries:    {stats['acl_entries']['parsed']} parsed, {stats['acl_entries']['skipped']} skipped")
    if stats['critical_errors']:
        print(f"Critical errors:        {stats['critical_errors']}")
    print("See ./log/asa2yaml.log for details on skipped/failed entries.\n")

def main():
    config_file = os.path.join("config", "sample_asa_config.txt")
    net_objects, svc_objects, net_object_groups, svc_object_groups, access_lists, stats = parse_asa_config(config_file)
    write_yaml(os.path.join("yaml", "objects_network.yaml"), net_objects, top_level_key="network_objects")
    write_yaml(os.path.join("yaml", "objects_service.yaml"), svc_objects, top_level_key="service_objects")
    write_yaml(os.path.join("yaml", "object-groups_network.yaml"), net_object_groups, top_level_key="network_object_groups")
    write_yaml(os.path.join("yaml", "object-groups_service.yaml"), svc_object_groups, top_level_key="service_object_groups")
    acl_yaml = [{'acl_name': name, 'entries': entries} for name, entries in access_lists.items()]
    write_yaml(os.path.join("yaml", "access-lists.yaml"), acl_yaml, top_level_key="access_lists")

    print_summary(stats)

    # Exit with non-zero code if critical errors occurred
    if stats['critical_errors'] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()