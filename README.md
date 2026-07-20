# what's this
I'm building something similar to [toxiproxy](https://github.com/Shopify/toxiproxy) but in eBPF.

## Basic Usage
```shell
$ sudo jolt 8000 8001 8003
waiting for ports...
port 8000: new connection from client port 53996 (pid=213992)
```

## Roadmap
- [x] build a thin wrapper around libbpf, [bpf.zig](https://github.com/mohammedgqudah/jolt/blob/main/src/bpf.zig)
- [x] delay packets using tc with a bpf filter
- [x] track local connections
- [ ] a tc qdisc implementation in eBPF https://github.com/mohammedgqudah/jolt/issues/2
- [ ] a minimal inline tui (low priority)
