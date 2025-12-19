#include "hardware.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <linux/input.h>

// ==================== LED Controller Implementation ====================
void LEDController::set_solid(LED led, bool on) {
    // Set to none trigger first
    int fd = open(led_trigger_paths[led], O_WRONLY);
    if (fd >= 0) {
        write(fd, "none", 4);
        close(fd);
    }
    
    // Set brightness
    fd = open(led_paths[led], O_WRONLY);
    if (fd >= 0) {
        const char* value = on ? "255" : "0";
        write(fd, value, strlen(value));
        close(fd);
    }
}

void LEDController::set_blink(LED led, int delay_ms) {
    // Set to timer trigger
    int fd = open(led_trigger_paths[led], O_WRONLY);
    if (fd >= 0) {
        write(fd, "timer", 5);
        close(fd);
    }
    
    // Set delay_on and delay_off
    char delay_str[16];
    snprintf(delay_str, sizeof(delay_str), "%d", delay_ms);
    
    fd = open(led_delay_on_paths[led], O_WRONLY);
    if (fd >= 0) {
        write(fd, delay_str, strlen(delay_str));
        close(fd);
    }
    
    fd = open(led_delay_off_paths[led], O_WRONLY);
    if (fd >= 0) {
        write(fd, delay_str, strlen(delay_str));
        close(fd);
    }
}

void LEDController::all_off() {
    for (int i = 0; i < 4; i++) {
        set_solid((LED)i, false);
    }
}

// ==================== Button Controller Implementation ====================
ButtonController::ButtonController() : event_fd(-1), last_esc_press(0), esc_press_count(0) {
    event_fd = open("/dev/input/event1", O_RDONLY | O_NONBLOCK);
    if (event_fd < 0) {
        std::cerr << "[ERROR] Failed to open button input device /dev/input/event1" << std::endl;
        throw std::runtime_error("Button initialization failed");
    }
    std::cout << "[INFO] Button controller initialized" << std::endl;
}

ButtonController::~ButtonController() {
    if (event_fd >= 0) close(event_fd);
}

ButtonController::Button ButtonController::get_press() {
    struct input_event ev;
    while (read(event_fd, &ev, sizeof(ev)) == sizeof(ev)) {
        if (ev.type == EV_KEY && ev.value == 1) {  // Key press (not release)
            switch (ev.code) {
                case KEY_UP: return UP;
                case KEY_DOWN: return DOWN;
                case KEY_ENTER: return SELECT;
                case KEY_ESC: return ESC;
            }
        }
    }
    return NONE;
}

bool ButtonController::check_double_esc() {
    time_t now = time(NULL);
    
    // Reset if more than 1 second passed
    if (now - last_esc_press > 1) {
        esc_press_count = 1;
        last_esc_press = now;
        return false;
    }
    
    // Within 1 second
    esc_press_count++;
    if (esc_press_count >= 2) {
        esc_press_count = 0;
        last_esc_press = 0;
        return true;
    }
    
    last_esc_press = now;
    return false;
}

// ==================== OLED Display Implementation ====================
OLEDDisplay::OLEDDisplay() : python_script("./oled_display.py") {
    // Test if python script exists
    if (access(python_script.c_str(), X_OK) != 0) {
        std::cerr << "[ERROR] OLED display script not found or not executable: " 
                  << python_script << std::endl;
        throw std::runtime_error("OLED initialization failed");
    }
    clear();
    std::cout << "[INFO] OLED display initialized" << std::endl;
}

OLEDDisplay::~OLEDDisplay() {
    clear();
}

void OLEDDisplay::call_python(const std::string& command) {
    std::string cmd = python_script + " " + command + " 2>&1";
    std::cout << "[DEBUG] Calling Python: " << cmd << std::endl;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        // Read and print output
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            std::cout << "[PYTHON_OUTPUT] " << buffer;
        }
        int status = pclose(pipe);
        std::cout << "[DEBUG] Python exit status: " << status << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to popen: " << cmd << std::endl;
    }
}

void OLEDDisplay::show_menu(const std::vector<std::string>& items, int selected_idx) {
    std::stringstream ss;
    ss << "menu " << selected_idx;
    for (const auto& item : items) {
        ss << " \"" << item << "\"";
    }
    call_python(ss.str());
}

void OLEDDisplay::show_message(const std::string& title, const std::vector<std::string>& lines) {
    std::stringstream ss;
    ss << "message \"" << title << "\"";
    for (const auto& line : lines) {
        ss << " \"" << line << "\"";
    }
    call_python(ss.str());
}

void OLEDDisplay::show_scanning(int network_count) {
    std::stringstream ss;
    ss << "scanning " << network_count;
    call_python(ss.str());
}

void OLEDDisplay::show_capturing(const std::string& mode, const std::string& ssid) {
    std::stringstream ss;
    ss << "capturing \"" << mode << "\" \"" << ssid << "\"";
    call_python(ss.str());
}

void OLEDDisplay::show_cracking(int progress_percent, int total_passwords) {
    std::stringstream ss;
    ss << "cracking " << progress_percent << " " << total_passwords;
    call_python(ss.str());
}

void OLEDDisplay::show_success(const std::string& password) {
    std::stringstream ss;
    ss << "success \"" << password << "\"";
    call_python(ss.str());
}

void OLEDDisplay::show_failure() {
    call_python("failure");
}

void OLEDDisplay::clear() {
    call_python("clear");
}
