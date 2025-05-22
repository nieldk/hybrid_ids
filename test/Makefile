# Makefile for hybrid_ids project

CXX := g++
TARGET := hybrid_ids
SRC := hybrid_ids.cpp

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

# Compiler flags
CXXFLAGS := -std=c++17 -Wall -Wextra -Werror
LDFLAGS := -lpcap

# Debug and Release configurations
DEBUG_FLAGS := -O0 -g
RELEASE_FLAGS := -O2

all: release

release: CXXFLAGS += $(RELEASE_FLAGS)
release: $(TARGET)

debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

install: $(TARGET)
	install -Dm755 $(TARGET) $(BINDIR)/$(TARGET)
	@echo "Installed $(TARGET) to $(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	@echo "Uninstalled $(TARGET) from $(BINDIR)"

clean:
	rm -f $(TARGET)

.PHONY: all release debug clean

