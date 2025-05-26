import re
import yaml

def parse_network_object(lines, start_idx):
    obj = {'type': 'network', 'name': lines[start_idx].split()[-1]}
    idx = start_idx + 1
    while idx < len(lines) and not lines[idx].startswith('object'):
        line = lines[idx].strip()
        if line.startswith('host'):
            obj['host'] = line.split()[1]
        elif line.startswith('range'):
            _, start, end = line.split()
            obj['range'] = {'start': start, 'end': end}
        elif line.startswith('description'):
            obj['description'] = line[len('description '):]
        idx += 1
    return obj, idx

def parse_service_object(lines, start_idx):
    obj = {'type': 'service', 'name': lines[start_idx].split()[-1]}
    idx = start_idx + 1
    while idx < len(lines) and not lines[idx].startswith('object'):
        line = lines[idx].strip()
        if line.startswith('service'):
            parts = line.split()
            obj['service'] = {
                'protocol': parts[1],
                'direction': parts[2],
                'operator': parts[3],
                'port': parts[4]
            }
        idx += 1
    return obj, idx

def parse_object_group(lines, start_idx):
    group = {'type': 'network-group', 'name': lines[start_idx].split()[-1], 'members': []}
    idx = start_idx + 1
    while idx < len(lines) and not lines[idx].startswith('object'):
        line = lines[idx].strip()
        if line.startswith('group-object'):
            group['members'].append({'type': 'group', 'name': line.split()[-1]})
        elif line.startswith('network-object object'):
            group['members'].append({'type': 'object', 'name': line.split()[-1]})
        elif line.startswith('network-object'):
            parts = line.split()
            if len(parts) == 2:
                group['members'].append({'type': 'ip', 'ip': parts[1]})
            elif len(parts) == 3:
                group['members'].append({'type': 'range', 'start': parts[1], 'end': parts[2]})
        idx += 1
    return group, idx

def parse_access_list(line):
    # This is a simple parser; you may want to extend it for more complex ACLs
    acl_match = re.match(
        r'access-list (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+)(?: (\S+))?', line)
    if acl_match:
        return {
            'name': acl_match.group(1),
            'type': acl_match.group(2),
            'action': acl_match.group(3),
            'protocol': acl_match.group(4),
            'src': acl_match.group(5),
            'src_obj': acl_match.group(6),
            'dst': acl_match.group(7),
            'dst_obj': acl_match.group(8),
            'extra': acl_match.group(9)
        }
    return None

def parse_ios_config(config_lines):
    objects = []
    groups = []
    acls = []
    idx = 0
    while idx < len(config_lines):
        line = config_lines[idx].strip()
        if line.startswith('object network'):
            obj, idx = parse_network_object(config_lines, idx)
            objects.append(obj)
        elif line.startswith('object service'):
            obj, idx = parse_service_object(config_lines, idx)
            objects.append(obj)
        elif line.startswith('object-group network'):
            group, idx = parse_object_group(config_lines, idx)
            groups.append(group)
        elif line.startswith('access-list'):
            acl = parse_access_list(line)
            if acl:
                acls.append(acl)
            idx += 1
        else:
            idx += 1
    return {'objects': objects, 'groups': groups, 'acls': acls}

if __name__ == "__main__":
    with open('ASA_Config.txt') as f:
        config_lines = f.readlines()
    data = parse_ios_config(config_lines)
    with open('ASA_Config.yaml', 'w') as out_f:
        yaml.dump(data, out_f, sort_keys=False)