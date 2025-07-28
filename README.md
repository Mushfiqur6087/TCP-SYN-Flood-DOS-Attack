# TCP SYN Flood DOS Attack

This project demonstrates a TCP SYN flood Denial of Service (DOS) attack implementation using Python. The project showcases different attack strategies and their effectiveness against network targets.

## Overview

A TCP SYN flood attack is a type of denial-of-service attack that exploits the three-way handshake mechanism of TCP connections. The attacker sends a large number of SYN packets to the target server without completing the handshake, causing the server to exhaust its resources while waiting for responses.

## Attack Mechanism

### How TCP Three-Way Handshake Works

1. **SYN**: Client sends a SYN packet to initiate connection
2. **SYN-ACK**: Server responds with SYN-ACK packet
3. **ACK**: Client sends ACK to complete the handshake

### SYN Flood Attack Process

In a SYN flood attack, the attacker:
1. Sends numerous SYN packets to the target
2. Never sends the final ACK packet
3. Causes the server to maintain many half-open connections
4. Exhausts server resources (memory, connection table)
5. Prevents legitimate connections from being established

## Implementation Details

### Core Components

#### 1. Packet Building Utilities
- **Checksum Function**: Computes Internet checksum for packet integrity
- **IP Packet Class**: Constructs IPv4 headers with configurable parameters
- **TCP Packet Class**: Builds TCP headers with SYN flags

#### 2. Attack Strategies

The implementation supports two primary attack modes:

##### Non-Spoofed Attack
- Uses the attacker's real IP address
- Easier to implement and debug
- More traceable by network administrators
- Limited by network bandwidth and connection limits

##### IP Spoofed Attack
- Uses randomized source IP addresses
- Harder to trace back to the attacker
- More effective at overwhelming targets
- Bypasses some rate limiting mechanisms

#### 3. Multi-Threading Support
- Distributes attack load across multiple threads
- Configurable packets per second (PPS) rate
- Scalable based on system resources

### Key Features

1. **Raw Socket Implementation**: Direct packet crafting for maximum control
2. **Response Monitoring**: Sniffs for SYN-ACK responses to verify connectivity
3. **Configurable Parameters**: Target IP, port, attack rate, thread count
4. **IP Spoofing Option**: Randomized source addresses for enhanced attack effectiveness
5. **Rate Control**: Precise packets per second control

## Attack Results Analysis

Based on the demonstration screenshots:

### Without IP Spoofing (`images/attacker_nospoof.jpg`)
- Attack uses real source IP address
- Network traffic shows consistent pattern from single source
- Easier for target to implement IP-based blocking
- Resource consumption is moderate

### With IP Spoofing (`images/attacker_spoof.jpg`) 
- Attack uses randomized source IP addresses
- Creates diverse traffic patterns that are harder to filter
- More effective at bypassing simple IP-based defenses
- Significantly increases attack effectiveness

### Victim Impact

#### Without Spoofing (`images/victim_ss_no_spoof.png`)
- Server experiences moderate resource consumption
- Connection attempts from single IP can be blocked
- Some legitimate traffic may still get through

#### With Spoofing (`images/victim_ss_spoof.png`)
- Server resources become severely strained
- Difficult to distinguish malicious from legitimate traffic
- Service becomes largely unavailable to legitimate users

## Technical Implementation

### Packet Structure

```python
# IP Header Fields
- Version: 4 (IPv4)
- Header Length: 5 (20 bytes)
- Type of Service: 0
- Total Length: 40 bytes (IP + TCP)
- Identification: Random
- Flags: Don't Fragment
- TTL: 64
- Protocol: TCP (6)
- Source/Destination IPs

# TCP Header Fields
- Source/Destination Ports
- Sequence Number: Random
- Acknowledgment: 0
- Header Length: 5 (20 bytes)
- Flags: SYN (0x02)
- Window Size: 5840
- Checksum: Calculated
```

### Attack Flow

1. **Initialization**: Setup raw sockets with IP header inclusion
2. **Target Validation**: Verify target IP address format
3. **Connectivity Test**: Send initial SYN packet to test reachability
4. **Thread Deployment**: Launch multiple worker threads
5. **Flood Execution**: Continuous SYN packet transmission
6. **Monitoring**: Track responses and adjust attack parameters

## Defense Mechanisms

### Network-Level Defenses
- **SYN Cookies**: Stateless connection handling
- **Connection Rate Limiting**: Limit new connections per IP
- **Firewall Rules**: Block suspicious traffic patterns
- **Load Balancing**: Distribute incoming connections

### System-Level Defenses
- **TCP Backlog Tuning**: Increase connection queue size
- **Timeout Reduction**: Faster cleanup of half-open connections
- **Resource Monitoring**: Track system resource usage
- **Intrusion Detection**: Automated attack pattern recognition

## Educational Value

This project demonstrates:
- Low-level network programming concepts
- TCP/IP protocol implementation details
- Socket programming and raw packet manipulation
- Multi-threaded application development
- Network security vulnerabilities and mitigation strategies


## Conclusion

The TCP SYN flood attack remains a significant network security threat. This implementation demonstrates both the simplicity of executing such attacks and the importance of implementing proper defensive measures. The comparison between spoofed and non-spoofed attacks clearly shows the enhanced effectiveness of IP spoofing in DOS scenarios.

Understanding these attack vectors is crucial for network administrators and security professionals to develop effective countermeasures and maintain robust network security postures.
