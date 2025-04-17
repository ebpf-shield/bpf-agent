package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -output-dir . --go-package main firewall ebpf/firewall.c
