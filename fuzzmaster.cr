# NullSec FuzzMaster - Protocol Fuzzing Framework
# Crystal security tool demonstrating:
#   - Ruby-like syntax with C performance
#   - Type inference
#   - Macros for metaprogramming
#   - Union types
#   - Fibers for concurrency
#   - Compile-time safety
#
# Author: bad-antics
# License: MIT

VERSION = "1.0.0"

# ANSI Colors
module Color
  RED    = "\e[31m"
  GREEN  = "\e[32m"
  YELLOW = "\e[33m"
  CYAN   = "\e[36m"
  GRAY   = "\e[90m"
  RESET  = "\e[0m"
end

# Severity enum
enum Severity
  Critical
  High
  Medium
  Low
  Info

  def color : String
    case self
    when Critical, High then Color::RED
    when Medium         then Color::YELLOW
    when Low            then Color::CYAN
    else                     Color::GRAY
    end
  end
end

# Fuzzing strategy
enum FuzzStrategy
  Random
  Mutation
  Generation
  Grammar
  Dictionary

  def description : String
    case self
    when Random     then "Pure random byte generation"
    when Mutation   then "Mutate valid input samples"
    when Generation then "Generate based on protocol spec"
    when Grammar    then "Grammar-based structured fuzzing"
    when Dictionary then "Dictionary/wordlist based"
    end
  end
end

# Protocol type
enum Protocol
  HTTP
  DNS
  FTP
  SMTP
  MODBUS
  Custom

  def default_port : Int32
    case self
    when HTTP   then 80
    when DNS    then 53
    when FTP    then 21
    when SMTP   then 25
    when MODBUS then 502
    else             0
    end
  end
end

# Crash type
enum CrashType
  Timeout
  ConnectionReset
  SegFault
  HeapCorruption
  StackOverflow
  AssertionFailed
  Unknown
end

# Fuzz case
struct FuzzCase
  property id : Int32
  property data : Bytes
  property mutation_type : String
  property parent_id : Int32?

  def initialize(@id, @data, @mutation_type, @parent_id = nil)
  end

  def size : Int32
    @data.size
  end
end

# Crash record
struct Crash
  property case_id : Int32
  property crash_type : CrashType
  property signal : Int32?
  property output : String
  property reproducer : Bytes
  property severity : Severity

  def initialize(@case_id, @crash_type, @signal, @output, @reproducer, @severity)
  end
end

# Coverage info
struct Coverage
  property basic_blocks : Int32
  property edges : Int32
  property new_coverage : Bool
  property bitmap : Array(UInt8)

  def initialize(@basic_blocks = 0, @edges = 0, @new_coverage = false, @bitmap = [] of UInt8)
  end

  def percentage : Float64
    return 0.0 if @basic_blocks == 0
    (@edges.to_f / @basic_blocks) * 100
  end
end

# Fuzzing statistics
struct FuzzStats
  property total_cases : Int64
  property crashes : Int32
  property timeouts : Int32
  property unique_crashes : Int32
  property coverage_bits : Int32
  property exec_per_sec : Float64
  property start_time : Time
  property last_crash : Time?

  def initialize
    @total_cases = 0_i64
    @crashes = 0
    @timeouts = 0
    @unique_crashes = 0
    @coverage_bits = 0
    @exec_per_sec = 0.0
    @start_time = Time.utc
    @last_crash = nil
  end

  def runtime : Time::Span
    Time.utc - @start_time
  end
end

# Mutation operations
module Mutations
  extend self

  def bit_flip(data : Bytes, pos : Int32) : Bytes
    result = data.dup
    byte_pos = pos // 8
    bit_pos = pos % 8
    if byte_pos < result.size
      result[byte_pos] ^= (1_u8 << bit_pos)
    end
    result
  end

  def byte_flip(data : Bytes, pos : Int32) : Bytes
    result = data.dup
    if pos < result.size
      result[pos] ^= 0xFF_u8
    end
    result
  end

  def insert_random(data : Bytes, pos : Int32) : Bytes
    return data if data.size >= 65536
    pos = pos.clamp(0, data.size)
    new_data = Bytes.new(data.size + 1)
    new_data[0, pos].copy_from(data[0, pos])
    new_data[pos] = Random.rand(256).to_u8
    new_data[pos + 1, data.size - pos].copy_from(data[pos, data.size - pos]) if pos < data.size
    new_data
  end

  def delete_byte(data : Bytes, pos : Int32) : Bytes
    return data if data.size <= 1
    pos = pos.clamp(0, data.size - 1)
    new_data = Bytes.new(data.size - 1)
    new_data[0, pos].copy_from(data[0, pos]) if pos > 0
    new_data[pos, data.size - pos - 1].copy_from(data[pos + 1, data.size - pos - 1]) if pos < data.size - 1
    new_data
  end

  def replace_interesting(data : Bytes, pos : Int32) : Bytes
    interesting_8 = [0_u8, 1_u8, 16_u8, 32_u8, 64_u8, 100_u8, 127_u8, 128_u8, 255_u8]
    result = data.dup
    if pos < result.size
      result[pos] = interesting_8.sample
    end
    result
  end

  def havoc(data : Bytes) : Bytes
    result = data.dup
    ops = Random.rand(1..8)
    ops.times do
      case Random.rand(5)
      when 0 then result = bit_flip(result, Random.rand(result.size * 8))
      when 1 then result = byte_flip(result, Random.rand(result.size))
      when 2 then result = insert_random(result, Random.rand(result.size + 1))
      when 3 then result = delete_byte(result, Random.rand(result.size))
      when 4 then result = replace_interesting(result, Random.rand(result.size))
      end
    end
    result
  end
end

# Fuzzer engine
class Fuzzer
  property protocol : Protocol
  property strategy : FuzzStrategy
  property stats : FuzzStats
  property crashes : Array(Crash)
  property corpus : Array(Bytes)

  def initialize(@protocol, @strategy)
    @stats = FuzzStats.new
    @crashes = [] of Crash
    @corpus = [] of Bytes
  end

  def add_seed(data : Bytes)
    @corpus << data
  end

  def generate_case : FuzzCase
    @stats.total_cases += 1
    
    base = @corpus.empty? ? Bytes.new(64, &.to_u8) : @corpus.sample
    
    mutated = case @strategy
    when FuzzStrategy::Random
      Bytes.new(Random.rand(16..1024)) { Random.rand(256).to_u8 }
    when FuzzStrategy::Mutation
      Mutations.havoc(base)
    when FuzzStrategy::Generation
      generate_protocol_packet
    else
      Mutations.havoc(base)
    end

    FuzzCase.new(@stats.total_cases.to_i32, mutated, @strategy.to_s)
  end

  private def generate_protocol_packet : Bytes
    case @protocol
    when Protocol::HTTP
      generate_http
    when Protocol::DNS
      generate_dns
    else
      Bytes.new(64) { Random.rand(256).to_u8 }
    end
  end

  private def generate_http : Bytes
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    paths = ["/", "/admin", "/api", "/login", "/../../../etc/passwd", "/%" * 100]
    
    method = methods.sample
    path = paths.sample
    request = "#{method} #{path} HTTP/1.1\r\nHost: target\r\n\r\n"
    request.to_slice
  end

  private def generate_dns : Bytes
    # Simple DNS query structure
    header = Bytes[
      0x00, 0x01,  # Transaction ID
      0x01, 0x00,  # Flags (standard query)
      0x00, 0x01,  # Questions
      0x00, 0x00,  # Answers
      0x00, 0x00,  # Authority
      0x00, 0x00,  # Additional
    ]
    
    domain = "test.example.com"
    labels = domain.split('.').map { |l| Bytes[l.size.to_u8] + l.to_slice }.reduce { |a, b| a + b }
    
    query = header + labels + Bytes[0x00, 0x00, 0x01, 0x00, 0x01]
    query
  end

  def record_crash(fuzz_case : FuzzCase, crash_type : CrashType, output : String)
    severity = case crash_type
    when CrashType::HeapCorruption, CrashType::StackOverflow
      Severity::Critical
    when CrashType::SegFault
      Severity::High
    when CrashType::AssertionFailed
      Severity::Medium
    else
      Severity::Low
    end

    crash = Crash.new(
      fuzz_case.id,
      crash_type,
      signal: 11,
      output: output,
      reproducer: fuzz_case.data,
      severity: severity
    )
    
    @crashes << crash
    @stats.crashes += 1
    @stats.unique_crashes += 1
    @stats.last_crash = Time.utc
  end
end

# Demo data
def demo_corpus : Array(Bytes)
  [
    "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_slice,
    "POST /api HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_slice,
    Bytes[0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00],
  ]
end

# Print functions
def print_banner
  puts
  puts "╔══════════════════════════════════════════════════════════════════╗"
  puts "║           NullSec FuzzMaster - Protocol Fuzzing Framework        ║"
  puts "╚══════════════════════════════════════════════════════════════════╝"
  puts
end

def print_usage
  puts "USAGE:"
  puts "    fuzzmaster [OPTIONS] <target>"
  puts
  puts "OPTIONS:"
  puts "    -h, --help       Show this help"
  puts "    -p, --protocol   Protocol (http, dns, ftp, smtp, modbus)"
  puts "    -s, --strategy   Strategy (random, mutation, generation, grammar)"
  puts "    -t, --timeout    Timeout per case (ms)"
  puts "    -i, --input      Input corpus directory"
  puts "    -o, --output     Output crash directory"
  puts
  puts "EXAMPLES:"
  puts "    fuzzmaster -p http localhost:8080"
  puts "    fuzzmaster -s mutation -i seeds/ binary"
end

def print_case(fuzz_case : FuzzCase)
  puts
  puts "  #{Color::CYAN}Case ##{fuzz_case.id}#{Color::RESET}"
  puts "    Size:     #{fuzz_case.size} bytes"
  puts "    Mutation: #{fuzz_case.mutation_type}"
  puts "    Preview:  #{fuzz_case.data[0, [16, fuzz_case.size].min].hexstring}"
end

def print_crash(crash : Crash)
  puts
  puts "  #{crash.severity.color}[#{crash.severity}] CRASH#{Color::RESET}"
  puts "    Case ID: #{crash.case_id}"
  puts "    Type:    #{crash.crash_type}"
  puts "    Signal:  #{crash.signal || "N/A"}"
  puts "    Size:    #{crash.reproducer.size} bytes"
end

def print_stats(stats : FuzzStats)
  puts
  puts "#{Color::GRAY}═══════════════════════════════════════════#{Color::RESET}"
  puts
  puts "  Statistics:"
  puts "    Runtime:       #{stats.runtime.total_seconds.to_i}s"
  puts "    Total Cases:   #{stats.total_cases}"
  puts "    Crashes:       #{Color::RED}#{stats.crashes}#{Color::RESET}"
  puts "    Unique:        #{stats.unique_crashes}"
  puts "    Timeouts:      #{stats.timeouts}"
  puts "    Exec/sec:      #{"%.2f" % stats.exec_per_sec}"
end

def demo_mode
  puts "#{Color::YELLOW}[Demo Mode]#{Color::RESET}"
  puts
  puts "#{Color::CYAN}Running demonstration fuzzing session...#{Color::RESET}"
  
  fuzzer = Fuzzer.new(Protocol::HTTP, FuzzStrategy::Mutation)
  
  # Add seeds
  demo_corpus.each { |seed| fuzzer.add_seed(seed) }
  
  # Generate some cases
  cases = [] of FuzzCase
  5.times do
    fuzz_case = fuzzer.generate_case
    cases << fuzz_case
    print_case(fuzz_case)
  end
  
  # Simulate some crashes
  fuzzer.record_crash(cases[1], CrashType::SegFault, "SIGSEGV at 0xdeadbeef")
  fuzzer.record_crash(cases[3], CrashType::HeapCorruption, "heap-buffer-overflow")
  
  puts
  puts "  Crashes Detected:"
  fuzzer.crashes.each { |crash| print_crash(crash) }
  
  fuzzer.stats.exec_per_sec = 1250.5
  print_stats(fuzzer.stats)
end

# Main
print_banner

if ARGV.empty?
  print_usage
  puts
  demo_mode
elsif ARGV.includes?("-h") || ARGV.includes?("--help")
  print_usage
else
  print_usage
  puts
  demo_mode
end
