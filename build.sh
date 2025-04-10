clang -O2 -g -target bpf -c ./bpf/xdp_firewall.c -o xdp_firewall.o
go build -o xdp-firewall main.go
