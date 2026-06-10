#ifndef TSPU_DNS_PARSER_HPP
#define TSPU_DNS_PARSER_HPP

#pragma once
#include <string>
#include <cstdint>
#include <vector>

// DNS wire format parser — extracts the queried domain name from a UDP payload.
// We only care about query sections (QR bit = 0), and only the QNAME of the first question.
// No full protocol compliance needed — just enough to get the domain string.

namespace dns {

// Returns the queried domain name from a raw DNS UDP payload.
// Returns empty string if the payload is not a recognisable DNS query.
std::string extract_query_domain(const uint8_t* data, size_t len) {
    // DNS header is 12 bytes minimum
    if (len < 12) return "";

    // Byte 2, bit 7: QR flag. 0 = query, 1 = response.
    // We want to capture both queries AND responses so we can log what was resolved.
    // For responses we still extract the original QNAME from the question section.

    uint16_t qdcount = (static_cast<uint16_t>(data[4]) << 8) | data[5];
    if (qdcount == 0) return "";

    // Walk the QNAME starting at byte 12
    size_t pos = 12;
    std::string domain;

    while (pos < len) {
        uint8_t label_len = data[pos];

        // 0x00 terminates the QNAME
        if (label_len == 0) {
            // Remove trailing dot if present
            if (!domain.empty() && domain.back() == '.') domain.pop_back();
            return domain;
        }

        // Pointer compression (0xC0 prefix) — not expected in question sections
        // of a fresh query but handle gracefully
        if ((label_len & 0xC0) == 0xC0) {
            // Can't follow pointers without the full packet context here;
            // just stop and return what we have so far
            if (!domain.empty() && domain.back() == '.') domain.pop_back();
            return domain;
        }

        pos++; // move past length byte
        if (pos + label_len > len) return ""; // truncated

        domain.append(reinterpret_cast<const char*>(data + pos), label_len);
        domain += '.';
        pos += label_len;
    }

    return "";
}

} // namespace dns

#endif // TSPU_DNS_PARSER_HPP