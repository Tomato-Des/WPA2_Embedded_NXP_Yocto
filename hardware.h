#ifndef HARDWARE_H
#define HARDWARE_H

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>

// ==================== LED Controller ====================
class LEDController {
private:
    const char* led_paths[4] = {
        "/sys/class/leds/wpa2:red:status/brightness",
        "/sys/class/leds/wpa2:yellow:status/brightness",
        "/sys/class/leds/wpa2:green:status/brightness",
        "/sys/class/leds/wpa2:blue:status/brightness"
    };
    
    const char* led_trigger_paths[4] = {
        "/sys/class/leds/wpa2:red:status/trigger",
        "/sys/class/leds/wpa2:yellow:status/trigger",
        "/sys/class/leds/wpa2:green:status/trigger",
        "/sys/class/leds/wpa2:blue:status/trigger"
    };
    
    const char* led_delay_on_paths[4] = {
        "/sys/class/leds/wpa2:red:status/delay_on",
        "/sys/class/leds/wpa2:yellow:status/delay_on",
        "/sys/class/leds/wpa2:green:status/delay_on",
        "/sys/class/leds/wpa2:blue:status/delay_on"
    };
    
    const char* led_delay_off_paths[4] = {
        "/sys/class/leds/wpa2:red:status/delay_off",
        "/sys/class/leds/wpa2:yellow:status/delay_off",
        "/sys/class/leds/wpa2:green:status/delay_off",
        "/sys/class/leds/wpa2:blue:status/delay_off"
    };
    
public:
    enum LED { RED = 0, YELLOW = 1, GREEN = 2, BLUE = 3 };
    
    void set_solid(LED led, bool on);
    void set_blink(LED led, int delay_ms);
    void all_off();
};

// ==================== Button Controller ====================
class ButtonController {
private:
    int event_fd;
    time_t last_esc_press;
    int esc_press_count;
    
public:
    enum Button { NONE, UP, DOWN, SELECT, ESC };
    
    ButtonController();
    ~ButtonController();
    
    Button get_press();
    bool check_double_esc();  // Returns true if ESC pressed twice within 1 second
};

// ==================== OLED Display (Python wrapper) ====================
class OLEDDisplay {
private:
    std::string python_script;
    
    void call_python(const std::string& command);
    
public:
    OLEDDisplay();
    ~OLEDDisplay();
    
    void show_menu(const std::vector<std::string>& items, int selected_idx);
    void show_message(const std::string& title, const std::vector<std::string>& lines);
    void show_scanning(int network_count);
    void show_capturing(const std::string& mode, const std::string& ssid);
    void show_cracking(int progress_percent, int total_passwords);
    void show_success(const std::string& password);
    void show_failure();
    void clear();
};

#endif // HARDWARE_H