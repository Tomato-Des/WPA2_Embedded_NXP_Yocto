#ifndef CRACKER_H
#define CRACKER_H

#include "wifi.h"
#include <string>
#include <fstream>
#include <functional>

// ==================== WPA2 Cracker ====================
class WPA2Cracker {
private:
    std::ofstream log_file;
    
    // Crypto functions
    void pbkdf2_sha1(const std::string& password, const std::string& ssid, 
                     uint8_t* output);
    void generate_ptk(const uint8_t* pmk, const uint8_t* anonce, 
                      const uint8_t* snonce, const uint8_t* ap_mac,
                      const uint8_t* client_mac, uint8_t* ptk);
    bool verify_mic(const uint8_t* kck, const std::vector<uint8_t>& eapol_frame,
                    const uint8_t* expected_mic);
    
public:
    WPA2Cracker();
    ~WPA2Cracker();
    
    // Log handshake details to file
    void log_handshake_info(const WiFiNetwork& net);
    
    // Crack with progress callback
    // Callback params: (passwords_tried, current_password)
    std::string crack(const WiFiNetwork& net, const std::string& dict_file,
                     std::function<void(int, const std::string&)> progress_callback = nullptr);
};

#endif // CRACKER_H