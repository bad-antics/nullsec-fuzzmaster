# NullSec FuzzMaster

**Protocol Fuzzing Framework**

A powerful fuzzing framework written in Crystal, demonstrating high-performance mutation-based fuzzing with Ruby-like syntax and C-level performance.

![Crystal](https://img.shields.io/badge/Crystal-000000?style=for-the-badge&logo=crystal&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 Overview

NullSec FuzzMaster is a protocol-aware fuzzing framework that generates and mutates test cases to discover vulnerabilities in network services. It supports multiple protocols and fuzzing strategies with built-in crash detection.

## ✨ Features

- **Multiple Protocols** - HTTP, DNS, FTP, SMTP, MODBUS support
- **Fuzzing Strategies** - Random, mutation, generation, grammar-based
- **Mutation Engine** - Bit flip, byte flip, insert, delete, havoc
- **Crash Detection** - SegFault, heap corruption, stack overflow
- **Coverage Tracking** - Basic block and edge coverage
- **Corpus Management** - Seed-based input generation

## 🔍 Supported Protocols

| Protocol | Port | Generator |
|----------|------|-----------|
| HTTP | 80 | Request templates |
| DNS | 53 | Query structure |
| FTP | 21 | Command sequences |
| SMTP | 25 | Mail commands |
| MODBUS | 502 | Function codes |
| Custom | - | User defined |

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-fuzzmaster
cd nullsec-fuzzmaster

# Compile with Crystal
crystal build --release fuzzmaster.cr -o fuzzmaster

# Or run directly
crystal fuzzmaster.cr
```

## 🚀 Usage

```bash
# Fuzz HTTP server
./fuzzmaster -p http localhost:8080

# Mutation-based fuzzing
./fuzzmaster -s mutation -i seeds/ binary

# DNS fuzzing
./fuzzmaster -p dns 192.168.1.1:53

# Set timeout
./fuzzmaster -t 5000 target

# Run demo
./fuzzmaster
```

## 💻 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║           NullSec FuzzMaster - Protocol Fuzzing Framework        ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Running demonstration fuzzing session...

  Case #1
    Size:     29 bytes
    Mutation: Mutation
    Preview:  474554202f20485454502f312e310d0a

  Case #2
    Size:     45 bytes
    Mutation: Mutation
    Preview:  504f5354ff2f617069ff485454502f31

  Case #3
    Size:     32 bytes
    Mutation: Mutation
    Preview:  00010100000100000000000004746573

  Crashes Detected:

  [HIGH] CRASH
    Case ID: 2
    Type:    SegFault
    Signal:  11
    Size:    45 bytes

  [CRITICAL] CRASH
    Case ID: 4
    Type:    HeapCorruption
    Signal:  11
    Size:    67 bytes

═══════════════════════════════════════════

  Statistics:
    Runtime:       0s
    Total Cases:   5
    Crashes:       2
    Unique:        2
    Timeouts:      0
    Exec/sec:      1250.50
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Corpus Manager                            │
│                Seed Files | Generated Inputs                │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Mutation Engine                            │
│    bit_flip | byte_flip | insert | delete | havoc          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Protocol Generator                         │
│              HTTP | DNS | FTP | SMTP | Custom               │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Crash Detector                             │
│          SegFault | HeapCorruption | StackOverflow          │
└─────────────────────────────────────────────────────────────┘
```

## 💎 Crystal Features Demonstrated

- **Enums with Methods** - `Severity#color`, `Protocol#default_port`
- **Structs** - Value types for `FuzzCase`, `Crash`, `Coverage`
- **Classes** - Reference types for `Fuzzer` engine
- **Modules** - `Mutations` for mutation operations
- **Union Types** - `Int32?` for nullable signals
- **Bytes Type** - Efficient byte array handling
- **Macros** - Compile-time code generation
- **Type Inference** - Automatic type deduction

## 🔧 Mutation Operations

```crystal
module Mutations
  def bit_flip(data, pos)    # Flip single bit
  def byte_flip(data, pos)   # Flip byte (XOR 0xFF)
  def insert_random(data, pos)  # Insert random byte
  def delete_byte(data, pos) # Remove byte
  def replace_interesting(data, pos)  # Use magic values
  def havoc(data)            # Multiple random mutations
end
```

## 📊 Statistics Tracked

| Metric | Description |
|--------|-------------|
| Total Cases | Number of test cases generated |
| Crashes | Total crash count |
| Unique | Deduplicated crashes |
| Timeouts | Cases exceeding timeout |
| Coverage | Basic blocks/edges hit |
| Exec/sec | Execution rate |

## 🛡️ Security Use Cases

- **Vulnerability Discovery** - Find memory corruption bugs
- **Protocol Testing** - Test network service robustness
- **Regression Testing** - Catch new crashes in updates
- **Compliance** - Fuzz testing requirements
- **Security Auditing** - Black-box testing services

## ⚠️ Legal Disclaimer

This tool is intended for:
- ✅ Authorized security testing
- ✅ Bug bounty programs (with permission)
- ✅ Own systems and applications
- ✅ Research and education

**Only fuzz systems you own or have explicit permission to test.**

## 🔗 Links

- **Portal**: [bad-antics.github.io](https://bad-antics.github.io)
- **Discord**: [x.com/AnonAntics](https://x.com/AnonAntics)
- **GitHub**: [github.com/bad-antics](https://github.com/bad-antics)

## 📄 License

MIT License - See LICENSE file for details.

## 🏷️ Version History

- **v1.0.0** - Initial release with mutation fuzzing and crash detection

---

*Part of the NullSec Security Toolkit*
