#ifndef WIFI_H
#define WIFI_H

#include <string>
#include <vector>
#include <cstdint>
#include <pcap.h>

// ==================== Data Structures ====================
struct WiFiNetwork {
    uint8_t bssid[6];
    std::string ssid;
    int channel;
    int signal_strength;
    time_t last_seen;
    
    // Handshake data
    bool has_msg1;
    bool has_msg2;
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t ap_mac[6];
    uint8_t client_mac[6];
    uint8_t mic[16];
    std::vector<uint8_t> eapol_msg2;
    std::vector<uint8_t> eapol_msg1;
    
    WiFiNetwork();
    bool handshake_complete() const { return has_msg1 && has_msg2; }
    std::string get_display_ssid() const;  // Returns printable SSID or hex
};

struct ClientDevice {
    uint8_t mac[6];
    time_t last_seen;
    int packet_count;
    
    ClientDevice();
};

// ==================== WiFi Controller ====================
class WiFiController {
private:
    std::string interface;
    pcap_t* handle;
    bool monitor_mode_active;
    
public:
    WiFiController(const std::string& iface);
    ~WiFiController();
    
    bool setup_monitor_mode();
    void restore_managed_mode();
    bool set_channel(int channel);
    bool open_capture(const std::string& filter);
    void close_capture();
    
    pcap_t* get_handle() { return handle; }
    bool is_monitor_active() const { return monitor_mode_active; }
};

// ==================== Packet Processor ====================
class PacketProcessor {
public:
    // Beacon frame processing
    static bool is_beacon_frame(const uint8_t* packet, int len);
    static bool parse_beacon(const uint8_t* packet, int len, WiFiNetwork& net);
    
    // EAPOL frame processing
    static bool is_eapol_frame(const uint8_t* packet, int len);
    static int get_eapol_message_type(const uint8_t* packet, int len);
    static bool parse_eapol_msg1(const uint8_t* packet, int len, WiFiNetwork& net);
    static bool parse_eapol_msg2(const uint8_t* packet, int len, WiFiNetwork& net);
    
    // Data frame processing (for client detection)
    static bool is_data_frame(const uint8_t* packet, int len);
    static void extract_addresses(const uint8_t* packet, int len, 
                                  uint8_t* ap_mac, uint8_t* client_mac);
    
    // Deauth frame crafting
    static std::vector<uint8_t> craft_deauth_frame(const uint8_t* src_mac,
                                                   const uint8_t* dst_mac,
                                                   const uint8_t* bssid);
};

// ==================== Utility Functions ====================
std::string mac_to_string(const uint8_t* mac);
std::string bytes_to_hex(const uint8_t* data, size_t len);
bool is_printable_ssid(const std::string& ssid);
bool compare_mac(const uint8_t* mac1, const uint8_t* mac2);

// Radiotap header stripping for monitor mode
bool normalize_80211_frame(pcap_t* handle,
                           const uint8_t* packet, int len,
                           const uint8_t*& out_pkt, int& out_len);

#endif // WIFI_H