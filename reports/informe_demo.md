# Network Analysis Report

**Data:** SYNTHETIC EXAMPLES — not real captures

## Nmap results
Hosts: 2

### Host `192.0.2.10`
- tcp/22: open — reported service: ssh
- tcp/443: open — reported service: https

### Host `192.0.2.11`
- tcp/53: open — reported service: domain

## Traffic summary
Packets: 5

### Protocols
- TCP: 2
- DNS: 2
- TLSv1.3: 1

### Conversations
- `192.0.2.10` → `198.51.100.20`: 2
- `198.51.100.20` → `192.0.2.10`: 1
- `192.0.2.11` → `198.51.100.53`: 1
- `198.51.100.53` → `192.0.2.11`: 1

## Limitations
Metadata summaries do not prove vulnerabilities or intrusions. Validate findings manually.
