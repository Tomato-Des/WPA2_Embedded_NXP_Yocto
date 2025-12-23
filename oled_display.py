#!/usr/bin/env python3
"""
OLED Display Helper for WPA2 Auditor
Called by C++ application to update display
"""

import sys
from luma.core.interface.serial import i2c
from luma.core.render import canvas
from luma.oled.device import ssd1306
from PIL import Image, ImageDraw, ImageFont

# Configuration
I2C_BUS = 0
I2C_ADDR = 0x3C

class OLEDHelper:
    def __init__(self):
        print("[OLED_PY] Initializing OLED...", file=sys.stderr)
        try:
            serial = i2c(port=I2C_BUS, address=I2C_ADDR)
            self.device = ssd1306(serial)
            self.device.persist = True  # Keep display content after process exits
        except Exception as e:
            print(f"[OLED_PY] ERROR: Failed to initialize OLED: {e}", file=sys.stderr)
            sys.exit(1)
        print("[OLED_PY] OLED initialized successfully", file=sys.stderr)
    
    def clear(self):
        print("[OLED_PY] Clearing display", file=sys.stderr)
        self.device.clear()
    
    def _draw_and_display(self, draw_func):
        """Helper to draw and persist to display"""
        image = Image.new('1', (self.device.width, self.device.height))
        draw = ImageDraw.Draw(image)
        draw_func(draw)
        self.device.display(image)
    
    def show_menu(self, items, selected_idx):
        """Display menu with selection indicator and scrolling"""
        print(f"[OLED_PY] show_menu called: selected_idx={selected_idx}, items={items}", file=sys.stderr)

        def draw(draw):
            # Calculate visible window (6 items fit on screen with 10px height each)
            max_visible = 6
            total_items = len(items)

            # Calculate scroll offset to keep selected item visible
            # If selected is in first 3 items, show from start
            # If selected is in last 3 items, show last 6 items
            # Otherwise, keep selected item in middle (position 3)
            if total_items <= max_visible:
                # All items fit on screen
                start_idx = 0
                end_idx = total_items
            elif selected_idx < 3:
                # Near the top
                start_idx = 0
                end_idx = min(max_visible, total_items)
            elif selected_idx >= total_items - 3:
                # Near the bottom
                start_idx = max(0, total_items - max_visible)
                end_idx = total_items
            else:
                # In the middle - keep selected at position 3
                start_idx = selected_idx - 3
                end_idx = min(start_idx + max_visible, total_items)

            # Draw visible items
            y = 0
            for idx in range(start_idx, end_idx):
                prefix = "> " if idx == selected_idx else "  "
                text = prefix + items[idx]
                if len(text) > 21:
                    text = text[:20] + "..."
                draw.text((0, y), text, fill="white")
                y += 10

            # Draw scroll indicators if needed
            if total_items > max_visible:
                # Up arrow if there are items above
                if start_idx > 0:
                    draw.text((120, 0), "^", fill="white")
                # Down arrow if there are items below
                if end_idx < total_items:
                    draw.text((120, 54), "v", fill="white")

        self._draw_and_display(draw)
        print(f"[OLED_PY] show_menu completed (showing items {start_idx if 'start_idx' in locals() else 0}-{end_idx if 'end_idx' in locals() else len(items)})", file=sys.stderr)
    
    def show_message(self, title, lines):
        """Display title and message lines"""
        print(f"[OLED_PY] show_message called: title='{title}', lines={lines}", file=sys.stderr)
        
        def draw(draw):
            draw.rectangle((0, 0, 127, 10), outline="white", fill="white")
            draw.text((2, 0), title, fill="black")
            y = 14
            for line in lines:
                if len(line) > 21:
                    line = line[:20] + "..."
                draw.text((2, y), line, fill="white")
                y += 10
                if y > 54:
                    break
        
        self._draw_and_display(draw)
        print("[OLED_PY] show_message completed", file=sys.stderr)
    
    def show_scanning(self, network_count):
        """Display scanning status"""
        print(f"[OLED_PY] show_scanning called: network_count={network_count}", file=sys.stderr)
        
        def draw(draw):
            draw.text((10, 10), "Scanning for", fill="white")
            draw.text((10, 20), "beacon frames...", fill="white")
            draw.text((10, 40), f"Found: {network_count}", fill="white")
        
        self._draw_and_display(draw)
        print("[OLED_PY] show_scanning completed", file=sys.stderr)
    
    def show_capturing(self, mode, ssid):
        """Display handshake capture status"""
        print(f"[OLED_PY] show_capturing called: mode='{mode}', ssid='{ssid}'", file=sys.stderr)
        
        def draw(draw):
            draw.text((5, 5), mode, fill="white")
            draw.text((5, 20), "Target:", fill="white")
            ssid_display = ssid if len(ssid) <= 18 else ssid[:17] + "..."
            draw.text((5, 30), ssid_display, fill="white")
            draw.rectangle((5, 50, 122, 58), outline="white")
        
        self._draw_and_display(draw)
        print("[OLED_PY] show_capturing completed", file=sys.stderr)
    
    def show_cracking(self, progress_percent, total_passwords):
        """Display cracking progress"""
        print(f"[OLED_PY] show_cracking called: progress={progress_percent}%, total={total_passwords}", file=sys.stderr)
        
        def draw(draw):
            draw.text((15, 5), "Cracking...", fill="white")
            bar_width = int(118 * progress_percent / 100)
            draw.rectangle((5, 25, 122, 35), outline="white")
            if bar_width > 0:
                draw.rectangle((5, 25, 5 + bar_width, 35), fill="white")
            draw.text((50, 40), f"{progress_percent}%", fill="white")
            tried_text = f"{total_passwords} tried"
            draw.text((20, 52), tried_text, fill="white")
        
        self._draw_and_display(draw)
        print("[OLED_PY] show_cracking completed", file=sys.stderr)
    
    def show_success(self, password):
        """Display success message with password"""
        print(f"[OLED_PY] show_success called: password='{password}'", file=sys.stderr)
        
        def draw(draw):
            draw.text((25, 5), "SUCCESS!", fill="white")
            draw.text((10, 20), "Password found:", fill="white")
            pwd_display = password if len(password) <= 18 else password[:17] + "..."
            draw.text((10, 35), pwd_display, fill="white")
            draw.text((5, 52), "SELECT: Menu", fill="white")
        
        self._draw_and_display(draw)
        print("[OLED_PY] show_success completed", file=sys.stderr)
    
    def show_failure(self):
        """Display failure message"""
        print("[OLED_PY] show_failure called", file=sys.stderr)
        
        def draw(draw):
            draw.text((30, 15), "FAILED", fill="white")
            draw.text((5, 30), "Password not in", fill="white")
            draw.text((5, 40), "dictionary", fill="white")
            draw.text((5, 52), "SELECT: Menu", fill="white")
        
        self._draw_and_display(draw)
        print("[OLED_PY] show_failure completed", file=sys.stderr)

def main():
    print(f"[OLED_PY] main() called with args: {sys.argv}", file=sys.stderr)
    if len(sys.argv) < 2:
        print("[OLED_PY] ERROR: No command provided", file=sys.stderr)
        print("Usage: oled_display.py <command> [args...]", file=sys.stderr)
        sys.exit(1)
    
    display = OLEDHelper()
    command = sys.argv[1]
    print(f"[OLED_PY] Command: {command}", file=sys.stderr)
    
    try:
        if command == "clear":
            display.clear()
        
        elif command == "menu":
            if len(sys.argv) < 3:
                print("[OLED_PY] ERROR: menu command needs more args", file=sys.stderr)
                print("Usage: menu <selected_idx> <item1> <item2> ...", file=sys.stderr)
                sys.exit(1)
            selected_idx = int(sys.argv[2])
            items = sys.argv[3:]
            display.show_menu(items, selected_idx)
        
        elif command == "message":
            if len(sys.argv) < 3:
                print("[OLED_PY] ERROR: message command needs more args", file=sys.stderr)
                print("Usage: message <title> <line1> <line2> ...", file=sys.stderr)
                sys.exit(1)
            title = sys.argv[2]
            lines = sys.argv[3:] if len(sys.argv) > 3 else []
            display.show_message(title, lines)
        
        elif command == "scanning":
            network_count = int(sys.argv[2]) if len(sys.argv) > 2 else 0
            display.show_scanning(network_count)
        
        elif command == "capturing":
            if len(sys.argv) < 4:
                print("[OLED_PY] ERROR: capturing command needs more args", file=sys.stderr)
                print("Usage: capturing <mode> <ssid>", file=sys.stderr)
                sys.exit(1)
            mode = sys.argv[2]
            ssid = sys.argv[3]
            display.show_capturing(mode, ssid)
        
        elif command == "cracking":
            if len(sys.argv) < 4:
                print("[OLED_PY] ERROR: cracking command needs more args", file=sys.stderr)
                print("Usage: cracking <progress_percent> <total_passwords>", file=sys.stderr)
                sys.exit(1)
            progress = int(sys.argv[2])
            total = int(sys.argv[3])
            display.show_cracking(progress, total)
        
        elif command == "success":
            if len(sys.argv) < 3:
                print("[OLED_PY] ERROR: success command needs more args", file=sys.stderr)
                print("Usage: success <password>", file=sys.stderr)
                sys.exit(1)
            password = sys.argv[2]
            display.show_success(password)
        
        elif command == "failure":
            display.show_failure()
        
        else:
            print(f"[OLED_PY] ERROR: Unknown command: {command}", file=sys.stderr)
            sys.exit(1)
        
        print(f"[OLED_PY] Command '{command}' executed successfully", file=sys.stderr)
    
    except Exception as e:
        print(f"[OLED_PY] EXCEPTION: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    
    print("[OLED_PY] main() exiting", file=sys.stderr)

if __name__ == "__main__":
    main()
