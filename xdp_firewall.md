```bash
clang -O2 -g -target bpf -c ./bpf/xdp_firewall.c -o xdp_firewall.o
go build -o xdp-firewall main.go
./xdp_firewall ens33
```

# Print EBPF logs
cat /sys/kernel/debug/tracing/trace_pipe

# Backend
```bash
uvicorn main:app --host 0.0.0.0 --port 808
```