#ifndef TSPU_TLS_PARSER_HPP
#define TSPU_TLS_PARSER_HPP

#pragma once
#include <string>
#include <cstdint>

// Minimal TLS ClientHello parser.
// We parse just enough of the handshake to find the SNI extension (type 0x0000).
// No state machine, no session tracking — first packet only.
//
// TLS record layout:
//   [0]     content type (0x16 = handshake)
//   [1-2]   version (0x03 0x01 or 0x03 0x03)
//   [3-4]   record length
//   [5]     handshake type (0x01 = ClientHello)
//   [6-8]   handshake length (3 bytes, big-endian)
//   [9-10]  client version
//   [11-42] random (32 bytes)
//   [43]    session id length
//   ...     session id
//   then 2-byte cipher suites length, cipher suites
//   then 1-byte compression methods length, compression methods
//   then 2-byte extensions total length
//   then extensions: each is [type 2B][len 2B][data]
//   SNI extension type = 0x0000
//     data: [list length 2B][name type 1B = 0x00][name length 2B][hostname]

namespace tls {

std::string extract_sni(const uint8_t* data, size_t len) {
    // Need at least a TLS record header + handshake header
    if (len < 43) return "";

    // Content type must be 0x16 (handshake)
    if (data[0] != 0x16) return "";

    // Major version must be 3
    if (data[1] != 0x03) return "";

    // Handshake type must be 0x01 (ClientHello)
    if (data[5] != 0x01) return "";

    // Skip past: record header(5) + handshake header(4) + client_version(2) + random(32) = 43
    size_t pos = 43;

    // Session ID
    if (pos >= len) return "";
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;

    // Cipher suites
    if (pos + 2 > len) return "";
    uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2 + cipher_suites_len;

    // Compression methods
    if (pos + 1 > len) return "";
    uint8_t comp_len = data[pos++];
    pos += comp_len;

    // Extensions total length
    if (pos + 2 > len) return "";
    uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;

    size_t ext_end = pos + extensions_len;
    if (ext_end > len) ext_end = len;

    // Walk extensions looking for type 0x0000 (SNI)
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
        uint16_t ext_len  = (static_cast<uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;

        if (ext_type == 0x0000) {
            // SNI extension found
            // Structure: [server_name_list_length 2B][name_type 1B][name_length 2B][name]
            if (pos + 5 > ext_end) return "";
            // skip list length
            pos += 2;
            uint8_t name_type = data[pos++];
            if (name_type != 0x00) return ""; // 0x00 = host_name

            uint16_t name_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
            pos += 2;

            if (pos + name_len > ext_end) return "";
            return std::string(reinterpret_cast<const char*>(data + pos), name_len);
        }

        pos += ext_len;
    }

    return "";
}

} // namespace tls

#endif // TSPU_TLS_PARSER_HPP