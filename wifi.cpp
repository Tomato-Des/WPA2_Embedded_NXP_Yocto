#include "wifi.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

// ==================== WiFiNetwork Implementation ====================
WiFiNetwork::WiFiNetwork() 
    : channel(0), signal_strength(0), last_seen(0), 
      has_msg1(false), has_msg2(false) {
    memset(bssid, 0, 6);
    memset(anonce, 0, 32);
    memset(snonce, 0, 32);
    memset(ap_mac, 0, 6);
    memset(client_mac, 0, 6);
    memset(mic, 0, 16);
}

std::string WiFiNetwork::get_display_ssid() const {
    if (is_printable_ssid(ssid)) {
        return ssid;
    } else {
        return bytes_to_hex((const uint8_t*)ssid.c_str(), ssid.length());
    }
}

// ==================== ClientDevice Implementation ====================
ClientDevice::ClientDevice() : last_seen(0), packet_count(0) {
    memset(mac, 0, 6);
}

// ==================== WiFiController Implementation ====================
WiFiController::WiFiController(const std::string& iface) 
    : interface(iface), handle(nullptr), monitor_mode_active(false) {
}

WiFiController::~WiFiController() {
    close_capture();
    if (monitor_mode_active) {
        restore_managed_mode();
    }
}

bool WiFiController::setup_monitor_mode() {
    std::cout << "[INFO] Setting up monitor mode on " << interface << std::endl;
    
    // Bring interface down
    std::string cmd = "ip link set " + interface + " down 2>&1";
    if (system(cmd.c_str()) != 0) {
        std::cerr << "[ERROR] Failed to bring interface down" << std::endl;
        return false;
    }
    
    // Set monitor mode
    cmd = "iw dev " + interface + " set type monitor 2>&1";
    if (system(cmd.c_str()) != 0) {
        std::cerr << "[ERROR] Failed to set monitor mode" << std::endl;
        return false;
    }
    
    // Bring interface up
    cmd = "ip link set " + interface + " up 2>&1";
    if (system(cmd.c_str()) != 0) {
        std::cerr << "[ERROR] Failed to bring interface up" << std::endl;
        return false;
    }
    
    monitor_mode_active = true;
    std::cout << "[INFO] Monitor mode enabled successfully" << std::endl;
    return true;
}

void WiFiController::restore_managed_mode() {
    if (!monitor_mode_active) return;
    
    std::cout << "[INFO] Restoring managed mode on " << interface << std::endl;
    std::string cmd = "ip link set " + interface + " down 2>&1";
    system(cmd.c_str());
    cmd = "iw dev " + interface + " set type managed 2>&1";
    system(cmd.c_str());
    cmd = "ip link set " + interface + " up 2>&1";
    system(cmd.c_str());
    
    monitor_mode_active = false;
}

bool WiFiController::set_channel(int channel) {
    std::string cmd = "iw dev " + interface + " set channel " +
                      std::to_string(channel) + " 2>&1";
    int result = system(cmd.c_str());
    bool success = (result == 0);

    if (success) {
        std::cout << "[INFO] Set channel to " << channel << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to set channel " << channel
                  << " (exit code: " << result << ")" << std::endl;
    }
    return success;
}

bool WiFiController::open_capture(const std::string& filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), 65535, 1, 1, errbuf);
    if (!handle) {
        std::cerr << "[ERROR] Failed to open pcap: " << errbuf << std::endl;
        return false;
    }
    
    if (!filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[ERROR] Failed to compile filter: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "[ERROR] Failed to set filter: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        pcap_freecode(&fp);
    }
    
    std::cout << "[INFO] Packet capture opened successfully" << std::endl;
    return true;
}

void WiFiController::close_capture() {
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
        std::cout << "[INFO] Packet capture closed" << std::endl;
    }
}

// ==================== PacketProcessor Implementation ====================
bool PacketProcessor::is_beacon_frame(const uint8_t* packet, int len) {
    if (len < 24) return false;
    uint8_t frame_type = packet[0];
    uint8_t frame_subtype = (frame_type >> 4) & 0x0F;
    // Management frame (type 00) and beacon subtype (1000)
    return (frame_type & 0x0C) == 0x00 && frame_subtype == 0x08;
}

bool PacketProcessor::parse_beacon(const uint8_t* packet, int len, WiFiNetwork& net) {
    if (len < 36) return false;
    
    // Extract BSSID (address 3 in beacon)
    memcpy(net.bssid, packet + 16, 6);
    
    // Skip fixed parameters (12 bytes after 802.11 header)
    const uint8_t* tags = packet + 36;
    int tags_len = len - 36;
    
    bool found_ssid = false;
    bool is_wpa2 = false;
    
    int offset = 0;
    while (offset + 2 <= tags_len) {
        uint8_t tag_num = tags[offset];
        uint8_t tag_len = tags[offset + 1];
        
        if (offset + 2 + tag_len > tags_len) break;
        
        if (tag_num == 0) { // SSID
            net.ssid = std::string((char*)(tags + offset + 2), tag_len);
            found_ssid = true;
        } else if (tag_num == 48) { // RSN Information (WPA2)
            const uint8_t* rsn = tags + offset + 2;
            if (tag_len >= 12) {
                // Look for AKM suite 00-0F-AC-02 (PSK)
                for (int i = 8; i < tag_len - 3; i++) {
                    if (rsn[i] == 0x00 && rsn[i+1] == 0x0F && 
                        rsn[i+2] == 0xAC && rsn[i+3] == 0x02) {
                        is_wpa2 = true;
                        break;
                    }
                }
            }
        }
        
        offset += 2 + tag_len;
    }
    
    return found_ssid && is_wpa2;
}

bool PacketProcessor::is_eapol_frame(const uint8_t* packet, int len) {
    if (len < 32) return false;

    // Check for Data frame (type bits 2-3 should be 10)
    uint8_t frame_type = packet[0];
    if ((frame_type & 0x0C) != 0x08) return false; // Not data frame

    // Determine 802.11 header size based on frame control flags
    uint8_t frame_ctrl_lo = packet[0];
    uint8_t frame_ctrl_hi = packet[1];

    bool to_ds = (frame_ctrl_hi & 0x01) != 0;
    bool from_ds = (frame_ctrl_hi & 0x02) != 0;
    bool is_qos = (frame_ctrl_lo & 0x80) != 0;  // Subtype bit 7

    int header_size = 24;  // Base 802.11 header

    // Add Address 4 if both ToDS and FromDS are set (WDS)
    if (to_ds && from_ds) {
        header_size += 6;
    }

    // Add QoS Control field if QoS data frame
    if (is_qos) {
        header_size += 2;
    }

    int llc_offset = header_size;
    if (len < llc_offset + 8) return false;

    // Check LLC/SNAP: AA-AA-03-00-00-00-88-8E
    bool is_eapol = packet[llc_offset] == 0xAA &&
                    packet[llc_offset + 1] == 0xAA &&
                    packet[llc_offset + 2] == 0x03 &&
                    packet[llc_offset + 6] == 0x88 &&
                    packet[llc_offset + 7] == 0x8E;

    if (is_eapol) {
        std::cout << "[DEBUG] EAPOL detected! FC=" << std::hex << (int)frame_ctrl_lo
                  << " " << (int)frame_ctrl_hi << std::dec
                  << " ToDS=" << to_ds << " FromDS=" << from_ds << " QoS=" << is_qos
                  << " HdrSize=" << header_size << " len=" << len << std::endl;
    }

    return is_eapol;
}

int PacketProcessor::get_eapol_message_type(const uint8_t* packet, int len) {
    if (len < 32) {
        std::cout << "[DEBUG] get_eapol_message_type: packet too short (" << len << " bytes)" << std::endl;
        return 0;
    }

    // Calculate 802.11 header size dynamically
    uint8_t frame_ctrl_lo = packet[0];
    uint8_t frame_ctrl_hi = packet[1];

    bool to_ds = (frame_ctrl_hi & 0x01) != 0;
    bool from_ds = (frame_ctrl_hi & 0x02) != 0;
    bool is_qos = (frame_ctrl_lo & 0x80) != 0;

    int header_size = 24;
    if (to_ds && from_ds) header_size += 6;  // WDS
    if (is_qos) header_size += 2;             // QoS Control

    // LLC/SNAP is 8 bytes
    int eapol_offset = header_size + 8;
    if (len < eapol_offset + 97) {
        std::cout << "[DEBUG] get_eapol_message_type: packet too short for MIC (need "
                  << (eapol_offset + 97) << ", have " << len << ")" << std::endl;
        return 0;
    }

    const uint8_t* eapol = packet + eapol_offset;

    // Verify EAPOL-Key frame
    if (eapol[1] != 0x03) {
        std::cout << "[DEBUG] get_eapol_message_type: not Key frame (type=" << (int)eapol[1] << ")" << std::endl;
        return 0;
    }
    if (eapol[4] != 0x02) {
        std::cout << "[DEBUG] get_eapol_message_type: not WPA Key descriptor (desc=" << (int)eapol[4] << ")" << std::endl;
        return 0;
    }

    // Parse Key Information field (big endian)
    uint16_t key_info = (eapol[5] << 8) | eapol[6];

    bool has_mic = (key_info & 0x0100) != 0;
    bool has_install = (key_info & 0x0040) != 0;
    bool is_pairwise = (key_info & 0x0008) != 0;

    std::cout << "[DEBUG] EAPOL Key Info: 0x" << std::hex << key_info << std::dec
              << " MIC=" << has_mic << " Install=" << has_install
              << " Pairwise=" << is_pairwise << std::endl;

    if (!is_pairwise) {
        std::cout << "[DEBUG] get_eapol_message_type: not pairwise key" << std::endl;
        return 0;
    }

    int msg_type = 0;
    if (!has_mic && !has_install) msg_type = 1; // Message 1
    else if (has_mic && !has_install) msg_type = 2;  // Message 2 (or 4, but we use 2)
    else if (has_mic && has_install) msg_type = 3;   // Message 3

    std::cout << "[DEBUG] Detected EAPOL Message Type: " << msg_type << std::endl;

    return msg_type;
}

bool PacketProcessor::parse_eapol_msg1(const uint8_t* packet, int len, WiFiNetwork& net) {
    std::cout << "[DEBUG] parse_eapol_msg1: parsing message 1 (len=" << len << ")" << std::endl;

    if (len < 32) {
        std::cout << "[DEBUG] parse_eapol_msg1: packet too short" << std::endl;
        return false;
    }

    // Calculate header size dynamically
    uint8_t frame_ctrl_lo = packet[0];
    uint8_t frame_ctrl_hi = packet[1];   
    bool to_ds = (frame_ctrl_hi & 0x01) != 0;
    bool from_ds = (frame_ctrl_hi & 0x02) != 0;
    bool is_qos = (frame_ctrl_lo & 0x80) != 0;

    int header_size = 24;
    if (to_ds && from_ds) header_size += 6;
    if (is_qos) header_size += 2;

    int eapol_offset = header_size + 8;
    if (len < eapol_offset + 49) {
        std::cout << "[DEBUG] parse_eapol_msg1: packet too short for ANonce (need "
                  << (eapol_offset + 49) << ", have " << len << ")" << std::endl;
        return false;
    }

    const uint8_t* eapol = packet + eapol_offset;

    // --- NEW: Use EAPOL header length to trim trailers (FCS, driver padding, etc.) ---
    // EAPOL header: [0]=version [1]=type [2..3]=length (big-endian)
    uint16_t eapol_body_len = (uint16_t(eapol[2]) << 8) | uint16_t(eapol[3]);
    size_t total_eapol = 4 + size_t(eapol_body_len);

    size_t available = size_t(len - eapol_offset);
    if (available < total_eapol) {
        std::cout << "[DEBUG] parse_eapol_msg1: packet too short for full EAPOL frame (need "
                  << total_eapol << ", have " << available << ")" << std::endl;
        return false;
    }

    // Extract ANonce (offset 17, length 32)
    memcpy(net.anonce, eapol + 17, 32);

    // Extract AP MAC (Address 3 - BSSID)
    memcpy(net.ap_mac, packet + 16, 6);

    // Extract Client MAC (Address 1 - Destination) - first handshake client
    memcpy(net.client_mac, packet + 4, 6);

    // Save full EAPOL frame
    net.eapol_msg1.assign(eapol, eapol + total_eapol);

    std::cout << "[DEBUG] parse_eapol_msg1: SUCCESS - AP=" << std::hex
              << (int)net.ap_mac[0] << ":" << (int)net.ap_mac[1] << ":" << (int)net.ap_mac[2] << ":"
              << (int)net.ap_mac[3] << ":" << (int)net.ap_mac[4] << ":" << (int)net.ap_mac[5]
              << " Client=" << (int)net.client_mac[0] << ":" << (int)net.client_mac[1] << ":"
              << (int)net.client_mac[2] << ":" << (int)net.client_mac[3] << ":"
              << (int)net.client_mac[4] << ":" << (int)net.client_mac[5] << std::dec
              << " ANonce[0-3]=" << std::hex << (int)net.anonce[0] << (int)net.anonce[1]
              << (int)net.anonce[2] << (int)net.anonce[3] << std::dec << std::endl;

    return true;
}

bool PacketProcessor::parse_eapol_msg2(const uint8_t* packet, int len, WiFiNetwork& net) {
    std::cout << "[DEBUG] parse_eapol_msg2: parsing message 2 (len=" << len << ")" << std::endl;

    if (len < 32) {
        std::cout << "[DEBUG] parse_eapol_msg2: packet too short" << std::endl;
        return false;
    }

    // Calculate header size dynamically
    uint8_t frame_ctrl_lo = packet[0];
    uint8_t frame_ctrl_hi = packet[1];                   // EAPOL hdr (4) + body length
    bool to_ds = (frame_ctrl_hi & 0x01) != 0;
    bool from_ds = (frame_ctrl_hi & 0x02) != 0;
    bool is_qos = (frame_ctrl_lo & 0x80) != 0;

    int header_size = 24;
    if (to_ds && from_ds) header_size += 6;
    if (is_qos) header_size += 2;

    int eapol_offset = header_size + 8;
    if (len < eapol_offset + 97) {
        std::cout << "[DEBUG] parse_eapol_msg2: packet too short for MIC (need "
                  << (eapol_offset + 97) << ", have " << len << ")" << std::endl;
        return false;
    }

    const uint8_t* eapol = packet + eapol_offset;

    uint16_t eapol_body_len = (uint16_t(eapol[2]) << 8) | uint16_t(eapol[3]);
    size_t total_eapol = 4 + size_t(eapol_body_len);

    size_t available = size_t(len - eapol_offset);
    if (available < total_eapol) {
        std::cout << "[DEBUG] parse_eapol_msg2: packet too short for full EAPOL frame" << std::endl;
        return false;
    }



    // Extract current packet's client MAC (Address 2 - Source)
    uint8_t current_client_mac[6];
    memcpy(current_client_mac, packet + 10, 6);

    // Check if we already have a client MAC stored (from msg1)
    bool client_mac_is_set = false;
    for (int i = 0; i < 6; i++) {
        if (net.client_mac[i] != 0) {
            client_mac_is_set = true;
            break;
        }
    }

    if (!client_mac_is_set) {
        std::cout << "[DEBUG] parse_eapol_msg2: REJECTED - no msg1 received yet (client_mac not set)" << std::endl;
        return false;
    }

    // Client MAC is set, verify this packet is from the same client
    if (memcmp(net.client_mac, current_client_mac, 6) != 0) {
        std::cout << "[DEBUG] parse_eapol_msg2: REJECTED - different client MAC" << std::endl;
        std::cout << "[DEBUG]   Expected: " << std::hex
                  << (int)net.client_mac[0] << ":" << (int)net.client_mac[1] << ":"
                  << (int)net.client_mac[2] << ":" << (int)net.client_mac[3] << ":"
                  << (int)net.client_mac[4] << ":" << (int)net.client_mac[5] << std::endl;
        std::cout << "[DEBUG]   Got:      " << std::hex
                  << (int)current_client_mac[0] << ":" << (int)current_client_mac[1] << ":"
                  << (int)current_client_mac[2] << ":" << (int)current_client_mac[3] << ":"
                  << (int)current_client_mac[4] << ":" << (int)current_client_mac[5] << std::dec << std::endl;
        return false;
    }

    // Extract AP MAC (Address 3 - BSSID)
    memcpy(net.ap_mac, packet + 16, 6);

    // Extract SNonce (offset 17, length 32)
    memcpy(net.snonce, eapol + 17, 32);

    // Extract MIC (offset 81, length 16)
    memcpy(net.mic, eapol + 81, 16);

    // Save full EAPOL frame
    net.eapol_msg2.assign(eapol, eapol + total_eapol);

    std::cout << "[DEBUG] parse_eapol_msg2: SUCCESS - Client=" << std::hex
              << (int)current_client_mac[0] << ":" << (int)current_client_mac[1] << ":"
              << (int)current_client_mac[2] << ":" << (int)current_client_mac[3] << ":"
              << (int)current_client_mac[4] << ":" << (int)current_client_mac[5] << std::dec
              << " SNonce[0-3]=" << std::hex << (int)net.snonce[0] << (int)net.snonce[1]
              << (int)net.snonce[2] << (int)net.snonce[3]
              << " MIC[0-3]=" << (int)net.mic[0] << (int)net.mic[1]
              << (int)net.mic[2] << (int)net.mic[3] << std::dec << std::endl;

    return true;
}

bool PacketProcessor::is_data_frame(const uint8_t* packet, int len) {
    if (len < 24) return false;
    uint8_t frame_type = packet[0];
    return (frame_type & 0x0C) == 0x08; // Data frame
}

void PacketProcessor::extract_addresses(const uint8_t* packet, int len, 
                                       uint8_t* ap_mac, uint8_t* client_mac) {
    if (len < 24) return;
    
    // For data frames:
    // ToDS=1, FromDS=0: Address 1=BSSID, Address 2=Source (client)
    // ToDS=0, FromDS=1: Address 1=Destination (client), Address 2=BSSID
    uint8_t frame_ctrl = packet[1];
    bool to_ds = (frame_ctrl & 0x01) != 0;
    bool from_ds = (frame_ctrl & 0x02) != 0;
    
    if (to_ds && !from_ds) {
        // Client to AP
        memcpy(ap_mac, packet + 4, 6);      // Address 1
        memcpy(client_mac, packet + 10, 6); // Address 2
    } else if (!to_ds && from_ds) {
        // AP to Client
        memcpy(client_mac, packet + 4, 6);  // Address 1
        memcpy(ap_mac, packet + 10, 6);     // Address 2
    } else {
        // Address 3 is usually BSSID
        memcpy(ap_mac, packet + 16, 6);
        memcpy(client_mac, packet + 10, 6);
    }
}

std::vector<uint8_t> PacketProcessor::craft_deauth_frame(const uint8_t* src_mac,
                                                         const uint8_t* dst_mac,
                                                         const uint8_t* bssid) {
    std::vector<uint8_t> frame(26);

    // Frame Control: Deauthentication (0xC0 0x00)
    frame[0] = 0xC0;
    frame[1] = 0x00;

    // Duration
    frame[2] = 0x3A;
    frame[3] = 0x01;

    // Address 1: Destination
    memcpy(&frame[4], dst_mac, 6);

    // Address 2: Source
    memcpy(&frame[10], src_mac, 6);

    // Address 3: BSSID (MUST always be AP's BSSID per 802.11 standard)
    memcpy(&frame[16], bssid, 6);

    // Sequence control (will be filled by driver)
    frame[22] = 0x00;
    frame[23] = 0x00;

    // Reason code: Class 3 frame from non-associated STA (0x07)
    frame[24] = 0x07;
    frame[25] = 0x00;

    return frame;
}

// ==================== Utility Functions ====================
std::string mac_to_string(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

bool is_printable_ssid(const std::string& ssid) {
    if (ssid.empty()) return false;
    for (char c : ssid) {
        if (c < 32 || c > 126) return false;
    }
    return true;
}

bool compare_mac(const uint8_t* mac1, const uint8_t* mac2) {
    return memcmp(mac1, mac2, 6) == 0;
}

bool normalize_80211_frame(pcap_t* handle,
                           const uint8_t* packet, int len,
                           const uint8_t*& out_pkt, int& out_len) {
    out_pkt = packet;
    out_len = len;

    if (!handle || !packet || len <= 0) return false;

    int dlt = pcap_datalink(handle);

    // Monitor mode on ath9k_htc (AR9271) → radiotap header
    if (dlt == DLT_IEEE802_11_RADIO) {
        if (len < 4) {
            std::cout << "[DEBUG] normalize: packet too short for radiotap header (len=" << len << ")\n";
            return false;
        }
        uint8_t ver = packet[0];
        if (ver != 0) {
            std::cout << "[DEBUG] normalize: bad radiotap version=" << (int)ver << "\n";
            return false;
        }

        // Radiotap header length is at bytes 2-3 (little endian)
        int rt_len = packet[2] | (packet[3] << 8);

        // FIXED: Allow rt_len == len (control frames with no payload)
        if (rt_len <= 0 || rt_len > len) {
            std::cout << "[DEBUG] normalize: invalid radiotap length (rt_len=" << rt_len
                      << ", packet_len=" << len << ")\n";
            return false;
        }

        // Skip radiotap header to get raw 802.11 frame
        out_pkt = packet + rt_len;
        out_len = len - rt_len;

        // Debug: Log what we're stripping
        if (out_len == 0) {
            std::cout << "[DEBUG] normalize: WARNING - no 802.11 data after radiotap (rt_len="
                      << rt_len << ", total=" << len << ")\n";
        }

        return true;
    }

    // Already raw 802.11
    if (dlt == DLT_IEEE802_11) {
        return true;
    }

    // Unknown data link type
    return false;
}
