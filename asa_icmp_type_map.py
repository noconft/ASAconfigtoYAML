# ASA ICMP type name to (type, code) mapping
# Format: 'asa_icmp_name': (type, code)
ASA_ICMP_TYPE_MAP = {
    'alternate-address': (6, 0),
    'conversion-error': (31, 0),
    'echo': (8, 0),
    'echo-reply': (0, 0),
    'information-reply': (16, 0),
    'information-request': (15, 0),
    'mask-reply': (18, 0),
    'mask-request': (17, 0),
    'mobile-redirect': (32, 0),
    'parameter-problem': (12, 0),
    'redirect': (5, 0),
    'router-advertisement': (9, 0),
    'router-solicitation': (10, 0),
    'source-quench': (4, 0),
    'time-exceeded': (11, 0),
    'timestamp-reply': (14, 0),
    'timestamp-request': (13, 0),
    'traceroute': (30, 0),
    'unreachable': (3, 0)
}
