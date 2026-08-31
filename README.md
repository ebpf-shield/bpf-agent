# bpf-agent

**eBPF Per-Process Firewall**

A lightweight, kernel-level firewall agent built with eBPF that provides per-process network traffic control and monitoring on Linux systems.

## Overview

`bpf-agent` leverages eBPF (extended Berkeley Packet Filter) technology to enforce network policies at the kernel level, enabling efficient, low-overhead filtering of network connections on a per-process basis. By operating in kernel space, it avoids costly context switches and provides real-time visibility and control over outbound and inbound network activity.

## Features

- **Per-Process Firewall**: Enforce network policies based on process identity (PID, executable path, cgroup)
- **Kernel-Level Enforcement**: Policies are enforced directly in the kernel using eBPF hooks for minimal performance impact
- **Real-Time Monitoring**: Track network connections with detailed metadata (process, user, destination IP/port, protocol)
- **Low Overhead**: eBPF-based filtering avoids the performance penalties of userspace proxies or iptables rules
- **Dynamic Policy Updates**: Modify firewall rules without restarting the agent or reloading kernel modules
- **Container-Aware**: Supports filtering based on cgroup paths for containerized workloads - **Not supported**
- **CLI Interface**: Full-featured command-line interface for managing policies, viewing status, and monitoring events - **Not supported**

## Requirements

- Linux kernel 5.8+ (for full eBPF feature support)
- Root privileges or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` capabilities
- `libbpf` and kernel headers installed
- Go 1.21+ (for building from source)

# Not yet supported:

## Installation

### From Source

```bash
git clone https://github.com/ebpf-shield/bpf-agent.git
cd bpf-agent
make build
```

### Pre-Built Binaries

Download the latest release from the [Releases](https://github.com/ebpf-shield/bpf-agent/releases) page:

```bash
wget https://github.com/ebpf-shield/bpf-agent/releases/latest/download/bpf-agent-linux-amd64
chmod +x bpf-agent-linux-amd64
sudo ./bpf-agent-linux-amd64
```

## CLI Reference

The `bpf-agent` CLI provides a comprehensive interface for managing the firewall agent.

### Global Flags

```
--config PATH      Path to configuration file (default: /etc/bpf-agent/config.yaml)
--log-level LEVEL  Log level: debug, info, warn, error (default: info)
--help, -h         Show help for the command
--version, -v      Show version information
```

### Commands

#### `start`

Start the bpf-agent daemon with the loaded policies.

```bash
sudo bpf-agent start
```

Options:

- `--config PATH` - Path to configuration file
- `--foreground` - Run in foreground mode (don't daemonize)

#### `stop`

Stop the running bpf-agent daemon.

```bash
sudo bpf-agent stop
```

#### `status`

Display the current status of the bpf-agent daemon.

```bash
sudo bpf-agent status
```

Output includes:

- Daemon state (running/stopped)
- Number of loaded policies
- Active connections being monitored
- eBPF program attachment points

#### `policy`

Manage firewall policies.

```bash
# List all loaded policies
sudo bpf-agent policy list

# Add a new policy from YAML
sudo bpf-agent policy add --file policy.yaml

# Remove a policy by name
sudo bpf-agent policy remove --name policy-name

# Validate a policy file without applying
sudo bpf-agent policy validate --file policy.yaml
```

#### `events`

View real-time firewall events (blocked/allowed connections).

```bash
# Stream all events
sudo bpf-agent events

# Filter by action (allow/deny)
sudo bpf-agent events --action deny

# Filter by process name
sudo bpf-agent events --process curl

# Show last N events
sudo bpf-agent events --tail 100

# Output as JSON
sudo bpf-agent events --output json
```

#### `connections`

List active network connections being monitored.

```bash
# List all connections
sudo bpf-agent connections

# Filter by process PID
sudo bpf-agent connections --pid 1234

# Filter by destination port
sudo bpf-agent connections --port 443

# Show connection statistics
sudo bpf-agent connections --stats
```

#### `logs`

View agent logs.

```bash
# Print eBPF logs
bpftool prog tracelog
```

```bash
# Show recent logs
sudo bpf-agent logs

# Follow logs (tail -f)
sudo bpf-agent logs --follow

# Filter by log level
sudo bpf-agent logs --level error

# Show last N lines
sudo bpf-agent logs --tail 200
```

#### `metrics`

Access Prometheus-compatible metrics.

```bash
# Show metrics summary
sudo bpf-agent metrics

# Export metrics in Prometheus format
sudo bpf-agent metrics --format prometheus

# Start metrics HTTP server
sudo bpf-agent metrics serve --addr :9090
```

#### `config`

View or modify agent configuration.

```bash
# Show current configuration
sudo bpf-agent config show

# Validate configuration file
sudo bpf-agent config validate --file config.yaml

# Generate default configuration
bpf-agent config init > config.yaml
```

#### `version`

Display version information.

```bash
bpf-agent version
```

#### `completion`

Generate shell completion scripts.

```bash
# Bash
bpf-agent completion bash > /etc/bash_completion.d/bpf-agent

# Zsh
bpf-agent completion zsh > /usr/local/share/zsh/site-functions/_bpf-agent

# Fish
bpf-agent completion fish > ~/.config/fish/completions/bpf-agent.fish
```

## Configuration

### Example Configuration File

```yaml
# /etc/bpf-agent/config.yaml

# Agent settings
agent:
  log_level: info
  metrics_addr: ":9090"
  enable_syslog: true

# eBPF settings
ebpf:
  # Buffer size for event ring (in pages)
  ring_buffer_pages: 256
  # Enable verbose eBPF logging
  verbose: false

# Default policy action (allow or deny)
default_action: deny

# Policies
policies:
  - name: allow-https-outbound
    description: Allow HTTPS outbound for all processes
    action: allow
    match:
      direction: outbound
      destination:
        ports: [443]
        protocol: tcp

  - name: allow-dns
    description: Allow DNS queries
    action: allow
    match:
      direction: outbound
      destination:
        ports: [53]
        protocol: [udp, tcp]

  - name: allow-localhost
    description: Allow all localhost traffic
    action: allow
    match:
      destination:
        ip: ["127.0.0.0/8", "::1"]

  - name: block-external-db
    description: Block external database access
    action: deny
    match:
      direction: outbound
      destination:
        ports: [3306, 5432, 27017, 6379]
        cidr: ["0.0.0.0/0"]
      except:
        destination:
          ip: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

  - name: log-all-other
    description: Log all other connections
    action: log
    match:
      direction: any
```

## Policy Syntax

### Match Conditions

| Field                 | Type       | Description                                 |
| --------------------- | ---------- | ------------------------------------------- |
| `process.paths`       | `[]string` | Executable paths to match                   |
| `process.names`       | `[]string` | Process names (basename)                    |
| `process.pids`        | `[]int`    | Specific PIDs                               |
| `process.uids`        | `[]int`    | User IDs                                    |
| `process.gids`        | `[]int`    | Group IDs                                   |
| `process.cgroups`     | `[]string` | Cgroup paths                                |
| `direction`           | `string`   | `inbound`, `outbound`, or `any`             |
| `protocol`            | `string`   | `tcp`, `udp`, or `any`                      |
| `source.ip`           | `[]string` | Source IP addresses or CIDR ranges          |
| `source.ports`        | `[]int`    | Source ports                                |
| `destination.ip`      | `[]string` | Destination IP addresses or CIDR ranges     |
| `destination.ports`   | `[]int`    | Destination ports                           |
| `destination.domains` | `[]string` | Destination domains (requires DNS tracking) |
| `except`              | `object`   | Exclude rules (same schema as match)        |

### Actions

- `allow`: Permit the connection
- `deny`: Block the connection
- `log`: Log the connection without blocking

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Userspace                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │ bpf-agent   │───▶│ Policy      │───▶│ Metrics &       │  │
│  │ CLI (Go)    │    │ Engine      │    │ Logging         │  │
│  └─────────────┘    └─────────────┘    └─────────────────┘  │
│         │                                                    │
│         │ libbpf                                             │
└─────────┼────────────────────────────────────────────────────┘
          │
┌─────────┼────────────────────────────────────────────────────┐
│         ▼                      Kernel Space                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │ eBPF        │───▶│ eBPF        │───▶│ eBPF            │  │
│  │ Programs    │    │ Maps        │    │ LSM Hooks       │  │
│  │ (socket)    │    │ (policies)  │    │ (enforcement)   │  │
│  └─────────────┘    └─────────────┘    └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Metrics

The agent exposes Prometheus-compatible metrics on the configured metrics endpoint:

| Metric                                | Type    | Description                                        |
| ------------------------------------- | ------- | -------------------------------------------------- |
| `bpf_agent_policies_loaded`           | Gauge   | Number of active policies                          |
| `bpf_agent_connections_blocked_total` | Counter | Total connections blocked by policy                |
| `bpf_agent_connections_allowed_total` | Counter | Total connections allowed                          |
| `bpf_agent_events_total`              | Counter | Total events processed (labeled by action, policy) |
| `bpf_agent_active_connections`        | Gauge   | Current number of tracked connections              |
| `bpf_agent_ebpf_programs_loaded`      | Gauge   | Number of loaded eBPF programs                     |
| `bpf_agent_ring_buffer_drops`         | Counter | Events dropped due to ring buffer overflow         |

## Security Considerations

- Run with minimal required capabilities
- Use policy files with strict permissions (e.g., `chmod 600`)
- Regularly audit and update policies
- Monitor logs for policy violations
- Consider running in a container with appropriate eBPF capabilities

## Development

### Building eBPF Programs

```bash
make ebpf
```

### Running Tests

```bash
make test
```

### Building from Source

```bash
# Install dependencies
go mod download

# Build the CLI
go build -o bpf-agent ./cmd/bpf-agent

# Build with all features
make build
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## Troubleshooting

### Common Issues

**"permission denied" errors**

- Ensure you're running with `sudo` or have the required capabilities
- Check that eBPF is enabled: `cat /proc/sys/kernel/unprivileged_bpf_disabled`

**"failed to load eBPF program"**

- Verify kernel version: `uname -r` (requires 5.8+)
- Check that BTF is available: `ls /sys/kernel/btf/vmlinux`
- Ensure kernel headers are installed

**Policies not being enforced**

- Verify agent status: `sudo bpf-agent status`
- Check logs: `sudo bpf-agent logs --tail 50`
- Validate policy syntax: `sudo bpf-agent policy validate --file policy.yaml`

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [libbpf](https://github.com/libbpf/libbpf) - User-space API for eBPF
- [eBPF](https://ebpf.io/) - Extended Berkeley Packet Filter
- [Cilium](https://cilium.io/) - Inspiration for eBPF-based networking and security
- [Cobra](https://github.com/spf13/cobra) - CLI framework

## Support

For issues, questions, or feature requests, please open an issue on the [GitHub repository](https://github.com/ebpf-shield/bpf-agent/issues).
