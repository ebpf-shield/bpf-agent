package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -output-dir ebpf_loader --go-package ebpfloader firewall c_ebpf/firewall.c
