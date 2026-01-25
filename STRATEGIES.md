# Fuzzing Strategies Guide

## Overview
Protocol fuzzing strategies and mutation techniques.

## Mutation Strategies

### Bit Flipping
- Single bit flips
- Multiple bit combinations
- Walking bit patterns
- Byte boundary focus

### Integer Manipulation
- Boundary values (0, -1, MAX)
- Powers of two
- Sign bit toggling
- Overflow triggers

### String Fuzzing
- Format string specifiers
- Long strings
- Unicode abuse
- Null injection

## Protocol Fuzzing

### Network Protocols
- TCP state machine
- Packet sequence
- Field corruption
- Timing manipulation

### File Formats
- Header corruption
- Chunk boundaries
- Magic number abuse
- Size field overflow

### API Fuzzing
- Parameter mutation
- Type confusion
- Sequence breaking
- Race conditions

## Coverage Guidance

### Instrumentation
- Code coverage tracking
- Branch counting
- Edge coverage
- Path tracking

### Feedback Loops
- Crash detection
- Hang detection
- Memory sanitizers
- New path discovery

## Corpus Management
- Minimization
- Deduplication
- Seed selection
- Dictionary generation

## Legal Notice
For authorized security testing.
