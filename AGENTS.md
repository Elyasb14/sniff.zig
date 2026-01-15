# Agent Context File

## Project Overview
This is a Zig-based network packet sniffer called "sniff" that uses libpcap for packet capture. The application captures and dissects network packets, with support for various protocols including HTTP, WireGuard, and basic TCP/UDP/ICMP parsing.

## Codebase Structure
- `src/main.zig` - Main application entry point, device listing, packet capture loop
- `src/packet.zig` - Core packet parsing structures (Ethernet, IPv4, TCP, UDP, ICMP)
- `src/Args.zig` - Command line argument parsing
- `src/application/http.zig` - HTTP packet parsing
- `src/application/wireguard.zig` - WireGuard packet parsing
- `build.zig` - Zig build configuration, links libpcap

## Key Architecture
- Uses libpcap for packet capture
- Supports multiple datalink types (DLT_EN10MB, DLT_RAW, DLT_NULL)
- Packet parsing follows layered approach: datalink -> network -> transport
- Transport layer is a union supporting TCP, UDP, ICMP
- Pretty printing via `pp()` method for packet display

## Build & Test Commands
- Build: `zig build`
- Run: `zig build run -- -d <device>` (use --list to see available devices)
- Test: `zig build test`

## Development Notes
- Code follows Zig conventions with explicit error handling
- Uses C interop for libpcap integration
- Endian-aware parsing (big endian for network protocols)
- Non-blocking packet capture with timeout handling
- Promiscuous mode disabled by default

## Protocol Support Status
- ✅ Ethernet (DLT_EN10MB)
- ✅ IPv4 
- ✅ TCP with flags and options
- ✅ UDP
- ✅ ICMP
- ✅ HTTP (basic)
- ✅ WireGuard
- ✅ CAN (basic SocketCAN support)
- ❌ IPv6 (not supported)
- 🔄 Victron CAN (planned - specific CAN message decoding)

## Important Instructions
- NEVER commit changes unless explicitly asked by the user
- Always ask before making git commits