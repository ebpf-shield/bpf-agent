# eBPF Agent

## Firewall

```bash

# Print eBPF logs
`bpftool prog tracelog`

# Backend
```bash
uvicorn main:app --host 0.0.0.0 --port 8080
```

### Inbound
We are interested in src(remote) ip and dest(local) port

### Outbound
We are interested in dest(remote) ip and port