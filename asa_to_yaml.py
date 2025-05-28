import re
import yaml
import os
import sys
from collections import defaultdict
from logger import get_logger  # Import the centralized logger

logger = get_logger()  # Initialize the logger

def parse_asa_config(filepath):
    """Parse ASA config file and extract objects, object-groups, and access-lists."""
    with open(filepath, encoding="utf-8") as f:
        lines = [line.rstrip() for line in f]

    net_objects, svc_objects = [], []
    net_obj_groups, svc_obj_groups = [], []
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
                    net_obj_groups.append(obj_grp)
                    stats['net_obj_groups']['parsed'] += 1
                else:
                    logger.warning(f"Invalid network object-group at line {i}: {obj_grp}")
                    stats['net_obj_groups']['skipped'] += 1
            elif line.startswith("object-group service"):
                obj_grp, i = parse_service_object_group(lines, i)
                if sanity_check_service_object_group(obj_grp):
                    svc_obj_groups.append(obj_grp)
                    stats['svc_obj_groups']['parsed'] += 1
                else:
                    logger.warning(f"Invalid service object-group at line {i}: {obj_grp}")
                    stats['svc_obj_groups']['skipped'] += 1
            elif line.startswith("access-list"):
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
    return net_objects, svc_objects, net_obj_groups, svc_obj_groups, access_lists, stats

def parse_network_object(lines, idx):
    """Parse network object block."""
    header = lines[idx].split()
    obj = {'name': header[-1]}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        if l.startswith('host '):
            obj['network_type'] = 'host'
            obj['value'] = l.split(' ', 1)[1]
        elif l.startswith('subnet '):
            obj['network_type'] = 'subnet'
            obj['value'] = l.split(' ', 1)[1]
        elif l.startswith('fqdn '):
            obj['network_type'] = 'fqdn'
            obj['value'] = l.split(' ', 1)[1]
        elif l.startswith('range '):
            obj['network_type'] = 'range'
            parts = l.split()
            if len(parts) == 3:
                obj['value'] = f"{parts[1]}-{parts[2]}"
        if l.startswith('description '):
            obj['description'] = l[12:]
        idx += 1
    return obj, idx

def parse_service_object(lines, idx):
    """Parse service object block."""
    header = lines[idx].split()
    obj = {'name': header[-1]}
    idx += 1
    while idx < len(lines) and lines[idx].startswith(' '):
        l = lines[idx].strip()
        m = re.match(r'service (\w+)(?: destination eq (\S+))?', l)
        if m:
            obj['protocol'] = m.group(1)
            if m.group(2):
                obj['destination_port'] = m.group(2)
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
            obj_grp['members'].append({'group_object': l.split()[-1]})
        elif l.startswith('network-object object '):
            obj_grp['members'].append({'object': l.split()[-1]})
        elif l.startswith('network-object '):
            parts = l.split()
            if len(parts) == 3:
                obj_grp['members'].append({'network_type': 'host', 'value': parts[1]})
            elif len(parts) == 4:
                obj_grp['members'].append({'network_type': 'subnet', 'value': f"{parts[1]} {parts[2]}"})
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
            obj_grp['members'].append({'group_object': l.split()[-1]})
        elif l.startswith('service-object object '):
            obj_grp['members'].append({'object': l.split()[-1]})
        elif l.startswith('service-object '):
            m = re.match(r'service-object (\w+)(?: destination eq (\S+))?', l)
            if m:
                member = {'protocol': m.group(1)}
                if m.group(2):
                    member['destination_port'] = m.group(2)
                obj_grp['members'].append(member)
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
    # host <ip>
    if t == 'host' and idx + 1 < len(tokens):
        return {'type': 'host', 'value': tokens[idx + 1]}, idx + 2
    # object/object-group <name>
    if t in ('object', 'object-group') and idx + 1 < len(tokens):
        return {'type': t, 'value': tokens[idx + 1]}, idx + 2
    # <ip> <mask> (subnet)
    if re.match(r'\d+\.\d+\.\d+\.\d+', t):
        if idx + 1 < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[idx + 1]):
            return {'type': 'subnet', 'value': f"{t} {tokens[idx + 1]}"}, idx + 2
        return {'type': 'host', 'value': t}, idx + 1
    # fallback
    return {'type': 'unknown', 'value': t}, idx + 1

def parse_access_list(line):
    """
    Parse a single access-list line into YAML structure.
    Handles all ASA ACL forms: protocol/service, source, destination, port (if present).
    """
    tokens = line.split()
    ### Debugging output
    # print("DEBUG LINE:", line)
    # print("TOKENS:", tokens)
    
    if len(tokens) < 6 or tokens[2] != 'extended':
        return None
    acl_name = tokens[1]
    action = tokens[3]  # Corrected: action is always at index 3 (permit/deny)
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
        service['value'] = tokens[idx + 1]
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

    # 4. Port (for tcp/udp, after destination)
    port = None
    if port_after and service['type'] in ('tcp', 'udp') and idx < len(tokens):
        if tokens[idx] == 'eq' and idx + 1 < len(tokens):
            port = tokens[idx + 1]
            idx += 2

    if port:
        service['port'] = port

    entry = {
        'source': source,
        'destination': destination,
        'service': service,
        'action': action
    }
    ### Debugging output
    # print("SERVICE:", service)
    # print("SOURCE:", source)
    # print("DESTINATION:", destination)
    # print("ENTRY:", entry)
    
    return {'acl_name': acl_name, 'entry': entry}

# --- SANITY CHECKS ---

def sanity_check_network_object(obj):
    if 'name' not in obj or 'network_type' not in obj or 'value' not in obj:
        return False
    if obj['network_type'] not in ('host', 'subnet', 'range', 'fqdn'):
        return False
    # host must be a valid IP
    if obj['network_type'] == 'host' and not re.match(r'^\d+\.\d+\.\d+\.\d+$', obj['value']):
        return False
    # subnet must be IP + mask
    if obj['network_type'] == 'subnet':
        parts = obj['value'].split()
        if len(parts) != 2 or not all(re.match(r'^\d+\.\d+\.\d+\.\d+$', p) for p in parts):
            return False
    # range must be start-end IP
    if obj['network_type'] == 'range' and not re.match(r'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$', obj['value']):
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
    # service type must be valid
    s = entry['service']
    if 'type' not in s:
        return False
    if s['type'] not in ('tcp', 'udp', 'icmp', 'ip', 'object', 'object-group'):
        return False
    # source/destination must have type and value
    for ent in ('source', 'destination'):
        e = entry[ent]
        if 'type' not in e or 'value' not in e:
            return False
    return True

def write_yaml(filepath, data):
    """Write data to YAML file, creating directories if needed."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
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
    config_file = os.path.join("config", "ASA_Config.txt")
    net_objs, svc_objs, net_obj_grps, svc_obj_grps, access_lists, stats = parse_asa_config(config_file)
    write_yaml(os.path.join("yaml", "objects_network.yaml"), net_objs)
    write_yaml(os.path.join("yaml", "objects_service.yaml"), svc_objs)
    write_yaml(os.path.join("yaml", "object-groups_network.yaml"), net_obj_grps)
    write_yaml(os.path.join("yaml", "object-groups_service.yaml"), svc_obj_grps)
    acl_yaml = [{'acl_name': name, 'entries': entries} for name, entries in access_lists.items()]
    write_yaml(os.path.join("yaml", "access-lists.yaml"), acl_yaml)

    print_summary(stats)

    # Exit with non-zero code if critical errors occurred
    if stats['critical_errors'] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()