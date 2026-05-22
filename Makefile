# Deadlight Proxy - Makefile
# Build system for the modular proxy server

#=============================================================================
# Project Configuration
#=============================================================================
PROJECT  = deadlight
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
PREFIX   = /usr/local

#=============================================================================
# Compiler Configuration
#=============================================================================
CC       = gcc
CFLAGS   = -std=gnu11 -Wall -Wextra -pedantic -O2 -g
CFLAGS  += -DDEADLIGHT_VERSION=\"$(VERSION)\"
DEPFLAGS = -MMD -MP
LDFLAGS  = -Wl,--as-needed
LIBS     = -lssl -lcrypto -lpthread -lresolv

# Package config for GLib/GIO
GLIB_CFLAGS := $(shell pkg-config --cflags glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)
GLIB_LIBS   := $(shell pkg-config --libs   glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)

# Combined flags
ALL_CFLAGS = $(CFLAGS) $(DEPFLAGS) $(GLIB_CFLAGS) -Isrc
ALL_LIBS   = $(LIBS) $(GLIB_LIBS)

#=============================================================================
# Directory Structure
#=============================================================================
SRCDIR         = src
OBJDIR         = obj
BINDIR         = bin
PLUGINDIR      = $(SRCDIR)/plugins
PLUGIN_BINDIR  = $(BINDIR)/plugins

# Installation directories
LIBDIR   = $(PREFIX)/lib
CONFDIR  = /etc/deadlight
LOGDIR   = /var/log/deadlight
CACHEDIR = /var/cache/deadlight

#=============================================================================
# Source Files 
#=============================================================================
CORE_SOURCES = \
	$(SRCDIR)/core/main.c \
	$(SRCDIR)/core/config.c \
	$(SRCDIR)/core/context.c \
	$(SRCDIR)/core/logging.c \
	$(SRCDIR)/core/network.c \
	$(SRCDIR)/core/ssl.c \
	$(SRCDIR)/core/protocols.c \
	$(SRCDIR)/core/protocol_detection.c \
	$(SRCDIR)/core/plugins.c \
	$(SRCDIR)/core/request.c \
	$(SRCDIR)/core/utils.c \
	$(SRCDIR)/core/ssl_tunnel.c \
	$(SRCDIR)/core/connection_pool.c

PROTOCOL_SOURCES = \
	$(SRCDIR)/protocols/http.c \
	$(SRCDIR)/protocols/imap.c \
	$(SRCDIR)/protocols/imaps.c \
	$(SRCDIR)/protocols/socks.c \
	$(SRCDIR)/protocols/smtp.c \
	$(SRCDIR)/protocols/websocket.c \
	$(SRCDIR)/protocols/ftp.c \
	$(SRCDIR)/protocols/api.c \
	$(SRCDIR)/protocols/federation.c

# Plugins that are statically linked because core code depends on them
PLUGIN_STATIC_SOURCES = \
	$(SRCDIR)/plugins/ratelimiter.c

VPN_SOURCES = \
	$(SRCDIR)/vpn/vpn_gateway.c

ALL_SOURCES = $(CORE_SOURCES) $(PROTOCOL_SOURCES) $(PLUGIN_STATIC_SOURCES) $(VPN_SOURCES)

#=============================================================================
# UI Configuration (set UI=1 to enable)
#=============================================================================
UI ?= 0
ifeq ($(UI),1)
  MHD_CFLAGS := $(shell pkg-config --cflags libmicrohttpd)
  MHD_LIBS   := $(shell pkg-config --libs   libmicrohttpd)

  ALL_CFLAGS += -DENABLE_UI $(MHD_CFLAGS)
  ALL_LIBS   += $(MHD_LIBS)
  ALL_SOURCES += \
	$(SRCDIR)/ui/ui.c \
	$(SRCDIR)/ui/assets.c
endif

#=============================================================================
# Object / Dependency Files
#=============================================================================
ALL_OBJECTS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(ALL_SOURCES))
ALL_DEPS    = $(ALL_OBJECTS:.o=.d)

#=============================================================================
# Plugin Configuration
#
#   Plugins are built ONLY as shared objects (.so).  They are not linked
#   into the main binary — the plugin loader discovers them at runtime.
#=============================================================================
PLUGIN_CFLAGS = $(CFLAGS) $(GLIB_CFLAGS) -Isrc -fPIC
PLUGIN_LIBS   = $(GLIB_LIBS)

PLUGIN_TARGETS = \
	$(PLUGIN_BINDIR)/adblocker.so \

#=============================================================================
# Top-level Targets
#=============================================================================
MAIN_TARGET = $(BINDIR)/$(PROJECT)

.PHONY: all dirs clean run run-vpn dev plugins plugins-only install uninstall help

# Default target
all: dirs $(MAIN_TARGET) plugins

#=============================================================================
# Directory Creation
#=============================================================================
dirs:
	@mkdir -p $(OBJDIR) $(BINDIR) $(PLUGIN_BINDIR)

#=============================================================================
# Main Executable
#=============================================================================
$(MAIN_TARGET): $(ALL_OBJECTS) | $(BINDIR)
	@echo "Linking $(PROJECT)..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(ALL_LIBS)
	@echo "Built $(PROJECT) $(VERSION)"

#=============================================================================
# Pattern Rule — compiles any src/**/*.c → obj/**/*.o
#=============================================================================
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	@$(CC) $(ALL_CFLAGS) -c $< -o $@

#=============================================================================
# Generated UI Assets
#=============================================================================
ifeq ($(UI),1)
# Assets to embed (HTML + favicons)
UI_ASSETS = \
	$(SRCDIR)/ui/index.html \
	$(SRCDIR)/ui/favicon.ico \
	$(SRCDIR)/ui/favicon.png

# Generate single assets.c file from all UI assets
$(SRCDIR)/ui/assets.c: $(UI_ASSETS)
	@echo "Generating UI assets..."
	@echo "/* Auto-generated UI assets */" > $@
	@echo "" >> $@
	@for asset in $(UI_ASSETS); do \
		echo "Embedding $$asset..."; \
		xxd -i $$asset >> $@; \
		echo "" >> $@; \
	done

# Make sure the generated file exists before we try to compile it
$(OBJDIR)/ui/assets.o: $(SRCDIR)/ui/assets.c
endif

#=============================================================================
# Automatic Header Dependencies
#
#   The -MMD -MP flags cause gcc to emit .d files alongside every .o file.
#   Including them here means "if deadlight.h changes, everything that
#   includes it gets recompiled automatically."
#=============================================================================
-include $(ALL_DEPS)

#=============================================================================
# Shared Plugins
#=============================================================================
plugins: $(PLUGIN_TARGETS)

$(PLUGIN_BINDIR)/adblocker.so: $(PLUGINDIR)/adblocker.c $(PLUGINDIR)/adblocker.h | $(PLUGIN_BINDIR)
	@echo "Building AdBlocker plugin..."
	@$(CC) $(PLUGIN_CFLAGS) -shared -o $@ $< $(PLUGIN_LIBS)

$(PLUGIN_BINDIR)/ratelimiter.so: $(PLUGINDIR)/ratelimiter.c $(PLUGINDIR)/ratelimiter.h | $(PLUGIN_BINDIR)
	@echo "Building RateLimiter plugin..."
	@$(CC) $(PLUGIN_CFLAGS) -shared -o $@ $< $(PLUGIN_LIBS)

#=============================================================================
# Utility Targets
#=============================================================================

clean:
	@echo "Cleaning build files..."
	@rm -rf $(OBJDIR) $(BINDIR)
	@rm -f $(SRCDIR)/ui/assets.c
	@echo "Clean complete"

run: $(MAIN_TARGET)
	@echo "Running $(PROJECT)..."
	@./$(MAIN_TARGET) -v

run-vpn: $(MAIN_TARGET)
	@echo "Running $(PROJECT) with VPN gateway (requires root)..."
	@sudo ./$(MAIN_TARGET) -v

# Debug / development build — override optimisation cleanly so there is
# no -O2 -O0 conflict, then rebuild from scratch and launch.
dev: CFLAGS := -std=gnu11 -Wall -Wextra -pedantic -DDEBUG -g3 -O0 \
               -DDEADLIGHT_VERSION=\"$(VERSION)\"
dev: clean all
	@echo "Starting development server..."
	@./$(MAIN_TARGET) -v

plugins-only: dirs $(PLUGIN_TARGETS)
	@echo "Plugins built"

#=============================================================================
# Install / Uninstall
#=============================================================================

install: all
	@echo "Installing $(PROJECT)..."
	@install -d $(DESTDIR)$(PREFIX)/bin
	@install -d $(DESTDIR)$(LIBDIR)/$(PROJECT)/plugins
	@install -d $(DESTDIR)$(CONFDIR)
	@install -d $(DESTDIR)$(LOGDIR)
	@install -d $(DESTDIR)$(CACHEDIR)
	@install -m 755 $(MAIN_TARGET) $(DESTDIR)$(PREFIX)/bin/
	@install -m 644 $(PLUGIN_TARGETS) $(DESTDIR)$(LIBDIR)/$(PROJECT)/plugins/
	@echo "Installation complete"
	@echo ""
	@echo "Note: VPN gateway requires root/CAP_NET_ADMIN capabilities"
	@echo "To enable VPN, set vpn.enabled=true in $(CONFDIR)/deadlight.conf"

uninstall:
	@echo "Uninstalling $(PROJECT)..."
	@rm -f  $(DESTDIR)$(PREFIX)/bin/$(PROJECT)
	@rm -rf $(DESTDIR)$(LIBDIR)/$(PROJECT)
	@echo "Uninstall complete"

#=============================================================================
# Help
#=============================================================================

help:
	@echo "Deadlight Proxy v$(VERSION) — Available targets:"
	@echo ""
	@echo "  all            Build everything (default)"
	@echo "  clean          Remove build artifacts"
	@echo "  run            Build and run the proxy"
	@echo "  run-vpn        Build and run with VPN (requires sudo)"
	@echo "  dev            Debug build (-O0, -DDEBUG) and run"
	@echo "  plugins        Build all shared plugins"
	@echo "  plugins-only   Build only plugins (no main executable)"
	@echo "  install        Install to system directories"
	@echo "  uninstall      Remove from system directories"
	@echo "  help           Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  UI=1           Enable embedded web UI (requires libmicrohttpd)"
	@echo "  VERSION=x.y.z  Set version string (default: dev)"
	@echo "  PREFIX=/path   Installation prefix (default: /usr/local)"
	@echo ""
	@echo "Examples:"
	@echo "  make                          # standard build"
	@echo "  make UI=1                     # build with web UI"
	@echo "  make dev UI=1                 # debug build with web UI"
	@echo "  make VERSION=1.0.0 install    # versioned install"
	@echo ""
	@echo "VPN Gateway:"
	@echo "  Automatically included in build."
	@echo "  Requires root to run: sudo ./bin/deadlight"
	@echo "  Enable in config:    [vpn] enabled=true"