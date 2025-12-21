# Makefile for WPA2 Security Auditor
# Compatible with Yocto cross-compilation

CXX ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -O2
LDFLAGS ?=
LDLIBS ?= -lpcap -lssl -lcrypto

TARGET = wpa2_auditor
OBJS = ignore.o hardware.o wifi.o cracker.o

# Python helper script
PYTHON_SCRIPT = oled_display.py

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LDLIBS)
	@echo "Linking complete: $(TARGET)"

ignore.o: ignore.cpp hardware.h wifi.h cracker.h
	$(CXX) $(CXXFLAGS) -c ignore.cpp

hardware.o: hardware.cpp hardware.h
	$(CXX) $(CXXFLAGS) -c hardware.cpp

wifi.o: wifi.cpp wifi.h
	$(CXX) $(CXXFLAGS) -c wifi.cpp

cracker.o: cracker.cpp cracker.h wifi.h
	$(CXX) $(CXXFLAGS) -c cracker.cpp

clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Clean complete"

.PHONY: all clean
