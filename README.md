# VPN Packet Parsing

## Test Pcaps

```shell
$ scp solana@192.168.10.211:/data/Solana_datasets/mn-data/external_datasets/vpn_data/open_vpn/openvpn_gitClone_vpnEstablished_29-11-2024.pcap .
```

## OpenVPN Opcodes

### Control Packets (with MSB)

```shell
P_CONTROL_HARD_RESET_CLIENT_V1
P_CONTROL_HARD_RESET_SERVER_V1
P_CONTROL_SOFT_RESET_V1
P_CONTROL_V1
P_ACK_V1
P_CONTROL_HARD_RESET_CLIENT_V2
P_CONTROL_SOFT_RESET_SERVER_V2
```

### Data Packets (without the control bit set)
```shell
P_DATA_V1
P_DATA_V2
```

### OpenVPN Opcode Mapping

- For UDP packet, check message type in the first byte of the payload
- For TCP packet, skip 2 bytes of packet_lenght, then check message type in the first byte of the payload
```shell
OPENVPN_OPCODES = {
        0x08: "P_CONTROL_HARD_RESET_CLIENT_V1",
        0x10: "P_CONTROL_HARD_RESET_SERVER_V1",
        0x18: "P_CONTROL_SOFT_RESET_V1",
        0x20: "P_CONTROL_V1",
        0x28: "P_ACK_V1",
        0x30: "P_DATA_V1",
        0x38: "P_CONTROL_HARD_RESET_CLIENT_V2",
        0x40: "P_CONTROL_SOFT_RESET_SERVER_V2",
        0x48: "P_DATA_V2"
    }
```

### Key Differences

1. **Payload Length Check**:
   - UDP: Requires minimum 1 byte
   - TCP: Requires minimum 3 bytes (2 for length + 1 for opcode)

2. **Opcode Location**:
   - UDP: First byte of payload
   - TCP: Third byte of payload (after 2-byte length field)

3. **Return Format**:
   - UDP: Returns (is_openvpn, packet_type, opcode_hex)
   - TCP: Returns (is_openvpn, packet_type, {opcode, length})


## IPSec VPN 
1. It often involve UDP ports 500 or 4500, and protocols AH (IP protocol 51) or ESP (IP protocol 50) for authentication or encryption.

### What is UDP Encapsulated of IPSec Packets field in Wireshark?

ref: [RFC 3948] - https://datatracker.ietf.org/doc/rfc3948/

In Wireshark, "UDP encapsulation of IPsec packets" refers to a feature where an IPsec packet (which normally doesn't have a Layer 4 protocol like UDP) is wrapped within a UDP header, allowing it to traverse networks that might have issues with raw IPsec packets, particularly when dealing with NAT devices; essentially, the IPsec payload is encapsulated inside a standard UDP packet to enable easier network traversal. 


Wireshark filter 

```
udpencap.non_esp_marker
```
**Note**: As mentioned below, there is a UDP header and a non-ESP marker field for port 4500.
When parsing the packet, we need to drop the first 12 bytes of the payload to get the actual IPsec packet.

```
2.  Packet Formats

2.1  UDP-encapsulated ESP Header Format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Source Port            |      Destination Port         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Length              |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      ESP header [RFC 2406]                    |
   ~                                                               ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The UDP header is a standard [RFC 768] header, where
   o  Source Port and Destination Port MUST be the same as used by IKE
      traffic.
   o  IPv4 UDP Checksum SHOULD be transmitted as a zero value.
   o  Receivers MUST NOT depend upon the UDP checksum being a zero
      value.

   The SPI field in the ESP header MUST NOT be zero.

2.2  IKE Header Format for Port 4500

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Source Port            |      Destination Port         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Length              |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Non-ESP Marker                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      IKE header [RFC 2409]                    |
   ~                                                               ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The UDP header is a standard [RFC 768] header, and is used as defined
   in [NAT-T-IKE]. This document does not set any new requirements for
   the checksum handling of an IKE packet.

   Non-ESP Marker is 4 bytes of zero aligning with the SPI field of an
   ESP packet.
```