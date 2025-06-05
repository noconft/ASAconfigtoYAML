"""
YAML to TrusGuard Configuration Converter

This script reads vendor-neutral YAML files (produced by asa_to_yaml.py) and converts them to AhnLab TrusGuard configuration format.

- Reads: ./yaml/objects_network.yaml, objects_service.yaml, object-groups_network.yaml, object-groups_service.yaml, access-lists.yaml
- Writes: ./trusguard_config.txt (or as specified)
"""
import os
import sys
import yaml
from logger import get_logger
from asa_icmp_type_map import ASA_ICMP_TYPE_MAP
from typing import Any, Dict, List, Optional
import datetime

ERROR_REPORT_PATH = os.path.join("log", "error_report_trusguard.yaml")

class YamlLoadError(Exception):
    """Custom exception for YAML loading errors."""
    pass

logger = get_logger()

def load_yaml(filepath: str) -> Optional[dict]:
    """
    Load a YAML file and return its contents as a dictionary.
    Raises YamlLoadError on failure.
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load YAML file {filepath}: {e}")
        return None

def convert_network_objects(network_objects: List[Dict[str, Any]], stats: dict) -> List[str]:
    """
    Convert network objects from YAML to AhnLab TrusGuard CLI/config syntax.
    Syntax (best guess):
    object ip_address ipv4_address add <name> <type 0-host, 1-CIDR, 2-range> <ipaddress> <ipprefix> <interface_name> <empty> <description> <vlanid> <zone>
    - interface_name is for the moment always 'all'
    - description is included if it exists, otherwise ''
    - all further fields are set to '' (empty string)
    Returns a list of configuration lines.
    """
    config_lines = []
    for obj in network_objects:
        name = obj.get('name')
        obj_type = obj.get('type')
        description = obj.get('description', "")
        interface_name = 'all'
        empty = vlanid = zone = ""
        if not name or not obj_type:
            logger.warning(f"Skipping invalid network object: {obj}")
            stats['network_objects_skipped'] += 1
            continue
        if obj_type == 'host':
            ip = obj.get('ip_address') or obj.get('value')
            if not ip:
                logger.warning(f"Host object missing IP: {obj}")
                stats['network_objects_skipped'] += 1
                continue
            config_lines.append(f"object ip_address ipv4_address add {name} 0 {ip} 32 {interface_name} '' '{description}' '' '' {vlanid} {zone}")
        elif obj_type == 'subnet':
            network = obj.get('network')
            netmask = obj.get('netmask')
            if not network or not netmask:
                logger.warning(f"Subnet object missing network/netmask: {obj}")
                stats['network_objects_skipped'] += 1
                continue
            import ipaddress
            try:
                prefix = ipaddress.IPv4Network(f"{network}/{netmask}").prefixlen
            except Exception:
                logger.warning(f"Invalid subnet: {obj}")
                stats['network_objects_skipped'] += 1
                continue
            config_lines.append(f"object ip_address ipv4_address add {name} 1 {network} {prefix} {interface_name} '' '{description}' '' '' {vlanid} {zone}")
        elif obj_type == 'range':
            ipr = obj.get('ip_range') or obj.get('value')
            if not ipr or not ipr.get('start') or not ipr.get('end'):
                logger.warning(f"Range object missing start/end: {obj}")
                stats['network_objects_skipped'] += 1
                continue
            ip_range = f"{ipr['start']}-{ipr['end']}"
            config_lines.append(f"object ip_address ipv4_address add {name} 2 {ip_range} '' {interface_name} '' '{description}' '' '' {vlanid} {zone}")
        else:
            logger.warning(f"Unknown network object type: {obj_type} in {obj}")
            stats['network_objects_skipped'] += 1
            continue
        config_lines.append("")  # Blank line for readability
    return config_lines

def convert_service_objects(service_objects: List[Dict[str, Any]], stats: dict) -> List[str]:
    """
    Convert service objects from YAML to AhnLab TrusGuard CLI/config syntax.
    Syntax:
    object service service add <name> <protocol (tcp/udp/icmp)> <src port> <dst port> <session timeout> <description> <vid> <predefined 0/1>
    - src port is always 1-65535 for tcp/udp
    - session timeout is always 1800 for tcp/udp, 3 for icmp
    - description in quotes if present, else ''
    - vid is always ''
    - predefined is always 1
    - for port ranges, dst port is e.g. 8080-8090
    - for icmp: <name> icmp <type> <code> <timeout> <desc> <vid> <predefined>
    Returns a list of configuration lines.
    """
    config_lines = []
    for obj in service_objects:
        name = obj.get('name')
        protocol = obj.get('protocol')
        description = obj.get('description', '')
        vid = ''
        predefined = '1'
        if not name or not protocol:
            logger.warning(f"Skipping invalid service object: {obj}")
            stats['service_objects_skipped'] += 1
            continue
        if protocol in ('tcp', 'udp'):
            src_port = '1-65535'
            session_timeout = '1800'
            if 'destination_port' in obj:
                dst_port = str(obj['destination_port'])
            elif 'destination_port_range' in obj:
                pr = obj['destination_port_range']
                dst_port = f"{pr['start']}-{pr['end']}"
            else:
                logger.warning(f"No destination port for service object: {obj}")
                stats['service_objects_skipped'] += 1
                continue
            config_lines.append(f"object service service add {name} {protocol} {src_port} {dst_port} {session_timeout} '{description}' '{vid}' {predefined}")
        elif protocol == 'icmp':
            icmp_type = obj.get('icmp_type')
            icmp_code = obj.get('icmp_code')
            # If icmp_type is a string name, map it to (type, code), but allow explicit code override
            if isinstance(icmp_type, str) and not icmp_type.isdigit():
                mapped = ASA_ICMP_TYPE_MAP.get(icmp_type.lower())
                if mapped:
                    mapped_type, mapped_code = mapped
                    icmp_type = mapped_type
                    # Use explicit code if present, else mapped code
                    if icmp_code is None:
                        icmp_code = mapped_code
                else:
                    logger.warning(f"Unknown ICMP type name: {icmp_type} in {obj}")
                    stats['service_objects_skipped'] += 1
                    continue
            icmp_timeout = obj.get('icmp_timeout', '3')
            if icmp_type is None or icmp_code is None:
                logger.warning(f"ICMP service object missing type/code: {obj}")
                stats['service_objects_skipped'] += 1
                continue
            config_lines.append(f"object service service add {name} icmp {icmp_type} {icmp_code} {icmp_timeout} '{description}' '{vid}' {predefined}")
        else:
            logger.warning(f"Unknown protocol for service object: {obj}")
            stats['service_objects_skipped'] += 1
            continue
        config_lines.append("")  # Blank line for readability
    return config_lines

def convert_network_object_groups(network_object_groups: List[Dict[str, Any]], stats: dict) -> List[str]:
    """
    Convert network object-groups from YAML to TrusGuard CLI/config syntax.
    Returns a list of configuration lines.
    """
    # TODO: Implement mapping to TrusGuard format
    # For now, just count as skipped if not empty
    if network_object_groups:
        stats['network_object_groups_skipped'] += len(network_object_groups)
    return []

def convert_service_object_groups(service_object_groups: List[Dict[str, Any]], stats: dict) -> List[str]:
    """
    Convert service object-groups from YAML to TrusGuard CLI/config syntax.
    Returns a list of configuration lines.
    """
    # TODO: Implement mapping to TrusGuard format
    if service_object_groups:
        stats['service_object_groups_skipped'] += len(service_object_groups)
    return []

def convert_access_lists(access_lists: List[Dict[str, Any]], stats: dict) -> List[str]:
    """
    Convert access-lists from YAML to TrusGuard CLI/config syntax.
    Returns a list of configuration lines.
    """
    # TODO: Implement mapping to TrusGuard format
    if access_lists:
        stats['acl_entries_skipped'] += len(access_lists)
    return []

def write_trusguard_config(config_lines: List[str], outpath: str) -> None:
    """
    Write the generated TrusGuard configuration lines to a file.
    Creates directories as needed.
    """
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w', encoding="utf-8") as f:
        for line in config_lines:
            f.write(line + '\n')

def print_summary(error_report: dict) -> None:
    """
    Print summary of YAML to TrusGuard conversion to stdout.
    """
    print("\n=== YAML to TrusGuard Conversion Summary ===")
    if error_report['failed_loads']:
        print(f"YAML files failed to load: {', '.join(error_report['failed_loads'])}")
    print(f"Network objects skipped:        {error_report['skipped']['network_objects']}")
    print(f"Service objects skipped:        {error_report['skipped']['service_objects']}")
    # print(f"Network object-groups skipped:  {error_report['skipped'].get('network_object_groups', 0)}")
    # print(f"Service object-groups skipped:  {error_report['skipped'].get('service_object_groups', 0)}")
    # print(f"Access-list entries skipped:    {error_report['skipped'].get('acl_entries', 0)}")
    if error_report['critical_errors']:
        print(f"Critical errors:                {error_report['critical_errors']}")
    print(f"See {ERROR_REPORT_PATH} for details on skipped/failed entries.\n")

def main() -> None:
    """
    Main entry point for YAML to TrusGuard conversion.
    Loads YAML files, converts them, writes the TrusGuard config, and writes a structured error report.
    Exits with code 1 if any YAML file fails to load.
    """
    yaml_dir = os.path.join(os.path.dirname(__file__), 'yaml')
    outpath = os.path.join(os.path.dirname(__file__), 'config', 'trusguard_config.txt')

    net_objs = load_yaml(os.path.join(yaml_dir, 'objects_network.yaml'))
    svc_objs = load_yaml(os.path.join(yaml_dir, 'objects_service.yaml'))
    net_obj_grps = load_yaml(os.path.join(yaml_dir, 'object-groups_network.yaml'))
    svc_obj_grps = load_yaml(os.path.join(yaml_dir, 'object-groups_service.yaml'))
    acl_yaml = load_yaml(os.path.join(yaml_dir, 'access-lists.yaml'))

    error_report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'failed_loads': [
            name for name, obj in [
                ('objects_network.yaml', net_objs),
                ('objects_service.yaml', svc_objs),
                ('object-groups_network.yaml', net_obj_grps),
                ('object-groups_service.yaml', svc_obj_grps),
                ('access-lists.yaml', acl_yaml)
            ] if obj is None
        ],
        'skipped': {
            'network_objects': 0,
            'service_objects': 0
            # 'network_object_groups': 0,
            # 'service_object_groups': 0,
            # 'acl_entries': 0
        },
        'critical_errors': 0
    }
    stats = error_report['skipped']
    try:
        config_lines: List[str] = []
        config_lines += convert_network_objects(net_objs.get('network_objects', []), stats)
        config_lines += convert_service_objects(svc_objs.get('service_objects', []), stats)
        # config_lines += convert_network_object_groups(net_obj_grps.get('network_object_groups', []), stats)
        # config_lines += convert_service_object_groups(svc_obj_grps.get('service_object_groups', []), stats)
        # config_lines += convert_access_lists(acl_yaml.get('access_lists', []), stats)
        write_trusguard_config(config_lines, outpath)
        logger.info(f"TrusGuard configuration written to {outpath}")
    except Exception as e:
        logger.critical(f"Critical error during conversion: {e}")
        error_report['critical_errors'] += 1
    print_summary(error_report)
    # Write error report
    try:
        with open(ERROR_REPORT_PATH, 'w', encoding='utf-8') as f:
            yaml.dump(error_report, f, sort_keys=False, allow_unicode=True)
        logger.info(f"Error report written to {ERROR_REPORT_PATH}")
    except Exception as e:
        logger.error(f"Failed to write error report: {e}")
    if error_report['failed_loads'] or error_report['critical_errors'] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
