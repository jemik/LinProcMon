# eBPF Installation Guide

## Quick Install (Ubuntu 22.04/24.04)

```bash
# 1. Install dependencies (no bpftool needed!)
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# 2. Compile
chmod +x compile_ebpf.sh
./compile_ebpf.sh

# 3. Run
sudo ./ebpf_standalone
```

## What Gets Installed

| Package | Purpose |
|---------|---------|
| `clang` | Compiles eBPF programs to BPF bytecode |
| `llvm` | LLVM toolchain (llvm-objdump for verification) |
| `libbpf-dev` | eBPF userspace library (ring buffers, map access) |
| `linux-headers-$(uname -r)` | Kernel headers for current kernel |

**Note:** `bpftool` is optional and not required for compilation or runtime!

## Verify Installation

```bash
# Check clang
clang --version

# Check LLVM
llvm-objdump --version

# Check libbpf
pkg-config --modversion libbpf

# Check kernel headers
ls /lib/modules/$(uname -r)/build

# Check BTF support (optional but recommended)
ls /sys/kernel/btf/vmlinux
```

## Troubleshooting

### "Package libbpf-dev has no installation candidate"

Your distribution might use a different package name:

```bash
# Try these alternatives
apt-cache search libbpf
sudo apt-get install libbpf0 libbpf-dev

# Or build from source
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
make
sudo make install
```

### "linux-headers not found"

```bash
# Check your kernel version
uname -r

# Install matching headers
sudo apt-get install linux-headers-$(uname -r)

# If not available, install generic
sudo apt-get install linux-headers-generic
```

### "BTF not available"

BTF (BPF Type Format) is optional but helpful. Available in kernel 5.2+:

```bash
# Check kernel version
uname -r

# If < 5.2, eBPF will still work but may need manual type definitions
```

## Distribution-Specific

### Ubuntu 22.04 LTS
```bash
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Ubuntu 24.04 LTS
```bash
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Debian 11/12
```bash
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Fedora 38+
```bash
sudo dnf install clang llvm libbpf-devel kernel-devel
```

### RHEL/Rocky/Alma 8+
```bash
sudo dnf install clang llvm libbpf-devel kernel-devel
```

### Arch Linux
```bash
sudo pacman -S clang llvm libbpf linux-headers
```

## Minimal Docker Container

If you want to test in a clean environment:

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    gcc \
    make

WORKDIR /app
COPY . .

RUN ./compile_ebpf.sh
```

## Compilation Steps (Manual)

If `compile_ebpf.sh` fails, you can compile manually:

```bash
# 1. Compile eBPF kernel module
clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -I/usr/include \
    -c ebpf_monitor.c -o ebpf_monitor.o

# 2. Verify eBPF object
llvm-objdump -h ebpf_monitor.o | grep tracepoint

# 3. Compile userspace monitor
gcc -o ebpf_standalone ebpf_standalone.c -lbpf -lelf -lz

# 4. Test
sudo ./ebpf_standalone
```

## Minimum System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Kernel | 5.2+ (for ring buffers) | 5.15+ (stable BTF) |
| RAM | 2GB | 4GB+ |
| Architecture | x86_64 | x86_64 |
| Root access | Required | Required |

## Next Steps

Once installed:

1. **Test it:** `sudo ./demo_ebpf.sh`
2. **Monitor:** `sudo ./ebpf_standalone`
3. **Integrate:** Run with memory dumper

See `EBPF_QUICKSTART.md` for usage examples.
