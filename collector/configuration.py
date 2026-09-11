"""Validate fleet identity and topology before any network or control action."""
import ipaddress
import re


def validate(cfg):
    if not isinstance(cfg, dict):
        raise ValueError('config must be a JSON object')
    for key, default, low, high in (('port',8816,1,65535), ('poll_interval',180,1,86400)):
        value = cfg.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'{key} must be an integer from {low} to {high}')
    hosts = cfg.get('hosts', [])
    if not isinstance(hosts, list):
        raise ValueError('hosts must be an array')
    seen = set()
    agents = {'linux','synology','openwrt','routeros','meshtastic','none','unifi','sonos'}
    for host in hosts:
        if not isinstance(host, dict):
            raise ValueError('each host must be an object')
        name = host.get('id')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
            raise ValueError('host id must contain only letters, digits, dots, dashes and underscores')
        if name in seen:
            raise ValueError(f'duplicate host id: {name}')
        seen.add(name)
        address = host.get('addr')
        if not isinstance(address, str) or not address or address.startswith('-') or any(c.isspace() for c in address):
            raise ValueError(f'invalid address for host {name}')
        if host.get('agent', 'linux') not in agents:
            raise ValueError(f'unknown agent for host {name}')
        if host.get('updatable') and host.get('agent', 'linux') != 'linux':
            raise ValueError(f'only Linux hosts can be updatable: {name}')
    subnets = cfg.get('subnets', [])
    if not isinstance(subnets, list):
        raise ValueError('subnets must be an array')
    parents = {}
    for subnet in subnets:
        if not isinstance(subnet, dict):
            raise ValueError('each subnet must be an object')
        cidr = subnet.get('cidr')
        ipaddress.ip_network(cidr, strict=False)
        if cidr in parents:
            raise ValueError(f'duplicate subnet: {cidr}')
        parents[cidr] = subnet.get('parent')
    for cidr in parents:
        visited = set()
        node = cidr
        while node:
            if node in visited:
                raise ValueError(f'cycle in subnet topology at {cidr}')
            if node not in parents:
                raise ValueError(f'unknown parent subnet: {node}')
            visited.add(node)
            node = parents[node]
