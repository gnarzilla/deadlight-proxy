/**
 * Deadlight Proxy v1.0 - Main Entry Point
 *
 * A modular, extensible HTTP/HTTPS proxy with SSL interception
 * Built with GNU/GLib ecosystem for robustness and performance
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <pwd.h>
#include <getopt.h>
#include <glib-unix.h>
#include <glib.h>
#include <gio/gio.h>
#include <locale.h>
#include <fcntl.h>

#include "deadlight.h"

#ifdef ENABLE_UI
#include "ui/ui.h"
#endif

#include "vpn/vpn_gateway.h"

GQuark deadlight_error_quark(void) {
    return g_quark_from_static_string("deadlight-error");
}

static DeadlightContext *g_context = NULL;

// Command line options
static gboolean opt_daemon = FALSE;
static gboolean opt_verbose = FALSE;
static gboolean opt_test_mode = FALSE;
static gchar *opt_config_file = NULL;
static gchar *opt_test_module = NULL;
static gchar *opt_pid_file = NULL;
static gint opt_port = 0;

static GOptionEntry entries[] = {
    {"daemon", 'd', 0, G_OPTION_ARG_NONE, &opt_daemon,
     "Run as daemon", NULL},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose,
     "Verbose output", NULL},
    {"config", 'c', 0, G_OPTION_ARG_STRING, &opt_config_file,
     "Configuration file", "FILE"},
    {"port", 'p', 0, G_OPTION_ARG_INT, &opt_port,
     "Listen port (overrides config)", "PORT"},
    {"pid-file", 0, 0, G_OPTION_ARG_STRING, &opt_pid_file,
     "PID file for daemon mode", "FILE"},
    {"test", 't', 0, G_OPTION_ARG_STRING, &opt_test_module,
     "Test specific module", "MODULE"},
    {"test-mode", 0, 0, G_OPTION_ARG_NONE, &opt_test_mode,
     "Enable test mode", NULL},
    {NULL}
};

#ifndef DEADLIGHT_VERSION
#define DEADLIGHT_VERSION "dev"
#endif

#define VERSION DEADLIGHT_VERSION

static const char *BUILD_DATE = __DATE__ " " __TIME__;

// Forward declarations
static gboolean signal_handler(gpointer user_data);
static void cleanup_resources(void);
static void cleanup_and_exit(int exit_code);
static int run_tests(const gchar *module);
static int run_daemon_mode(void);
static int run_interactive_mode(void);
static void print_banner(void);
static void print_test_commands(gint port, gboolean vpn_enabled);
static void print_usage(void);
static gboolean write_pid_file_atomic(const gchar *pid_file);
static void setup_resource_limits(void);
static void drop_privileges(void);
static gboolean validate_configuration(DeadlightContext *ctx, GError **error);

/**
 * GLib signal callback for graceful shutdown
 */
static gboolean signal_handler(gpointer user_data) {
    // Use write() for signal safety
    const char *msg = "Received shutdown signal\n";
    ssize_t ignored = write(STDERR_FILENO, msg, strlen(msg));
    (void)ignored; // Ignore the return value
    
    DeadlightContext *ctx = (DeadlightContext *)user_data;
    if (ctx && ctx->main_loop) {
        g_main_loop_quit(ctx->main_loop);
    }
    
    return G_SOURCE_REMOVE;
}

/**
 * Cleanup all resources
 */
static void cleanup_resources(void) {
    if (g_context) {
        deadlight_context_free(g_context);
        g_context = NULL;
    }
    
    // Free all command line option strings
    if (opt_config_file) {
        g_free(opt_config_file);
        opt_config_file = NULL;
    }
    
    if (opt_test_module) {
        g_free(opt_test_module);
        opt_test_module = NULL;
    }
    
    if (opt_pid_file) {
        g_free(opt_pid_file);
        opt_pid_file = NULL;
    }
}

/**
 * Cleanup and exit with code
 */
static void cleanup_and_exit(int exit_code) {
    cleanup_resources();
    exit(exit_code);
}

/**
 * Validate configuration after loading
 */
static gboolean validate_configuration(DeadlightContext *ctx, GError **error) {
    if (!ctx || !ctx->config) {
        g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                   "Configuration not loaded");
        return FALSE;
    }

    // Check required sections
    const gchar *required_sections[] = {"core", "ssl", NULL};
    for (int i = 0; required_sections[i]; i++) {
        if (!deadlight_config_has_section(ctx, required_sections[i])) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                       "Missing required section: %s", required_sections[i]);
            return FALSE;
        }
    }
    
    // Validate core settings
    gint port = deadlight_config_get_int(ctx, "core", "port", -1);
    if (port <= 0 || port > 65535) {
        g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                   "Invalid port number: %d", port);
        return FALSE;
    }
    
    // Validate SSL settings if enabled
    gboolean ssl_enabled = deadlight_config_get_bool(ctx, "ssl", "enabled", FALSE);
    if (ssl_enabled) {
        const gchar *ca_cert = deadlight_config_get_string(ctx, "ssl", "ca_cert_file", NULL);
        const gchar *ca_key = deadlight_config_get_string(ctx, "ssl", "ca_key_file", NULL);
        
        if (!ca_cert || !ca_key) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                       "SSL enabled but CA cert/key files not specified");
            return FALSE;
        }
        
        // Check if files exist and are readable
        if (access(ca_cert, R_OK) != 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                       "Cannot read CA cert file: %s", ca_cert);
            return FALSE;
        }
        
        if (access(ca_key, R_OK) != 0) {
            g_set_error(error, DEADLIGHT_ERROR, DEADLIGHT_ERROR_CONFIG,
                       "Cannot read CA key file: %s", ca_key);
            return FALSE;
        }
    }
    
    return TRUE;
}

/**
 * Test mode - run specific module tests
 */
static int run_tests(const gchar *module) {
    g_print("Deadlight Proxy Test Mode\n");
    g_print("Version: %s\n", VERSION);
    g_print("Build: %s\n\n", BUILD_DATE);
    g_print("Testing module: %s\n\n", module);
    
    if (g_strcmp0(module, "all") == 0) {
        g_print("Running all tests...\n");
        
        // Test each module
        const gchar *modules[] = {
            "config", "logging", "network", "protocols",
            "ssl", "plugins", "api", NULL
        };
        
        gboolean all_passed = TRUE;
        for (int i = 0; modules[i]; i++) {
            g_print("Testing %s... ", modules[i]);
            
            // Call module-specific test function
            gboolean result = deadlight_test_module(modules[i]);
            
            if (result) {
                g_print("PASS\n");
            } else {
                g_print("FAIL\n");
                all_passed = FALSE;
            }
        }
        
        g_print("\n%s\n", all_passed ? "All tests passed!" : "Some tests failed!");
        return all_passed ? 0 : 1;
    }
    
    // Test specific module
    g_print("Testing %s... ", module);
    gboolean result = deadlight_test_module(module);
    g_print("%s\n", result ? "PASS" : "FAIL");
    
    return result ? 0 : 1;
}

const gchar *deadlight_get_version(void) {
    return DEADLIGHT_VERSION_STRING;
}

const gchar *deadlight_get_build_date(void) {
    return __DATE__ " " __TIME__;
}

/**
 * Atomic PID file creation with race condition protection
 */
static gboolean write_pid_file_atomic(const gchar *pid_file) {
    if (!pid_file) return TRUE;
    
    // First check if file exists and process is still running
    if (g_file_test(pid_file, G_FILE_TEST_EXISTS)) {
        FILE *old = fopen(pid_file, "r");
        if (old) {
            pid_t old_pid;
            if (fscanf(old, "%d", &old_pid) == 1) {
                fclose(old);
                
                // Check if process is still alive
                if (kill(old_pid, 0) == 0) {
                    g_critical("Process %d is already running (PID file: %s)", 
                              old_pid, pid_file);
                    return FALSE;
                } else {
                    g_warning("Removing stale PID file for process %d", old_pid);
                    unlink(pid_file);
                }
            } else {
                fclose(old);
            }
        }
    }
    
    // Create PID file atomically
    FILE *fp = fopen(pid_file, "wx");
    if (!fp) {
        if (errno == EEXIST) {
            // Race condition - try again
            return write_pid_file_atomic(pid_file);
        }
        g_critical("Failed to create PID file %s: %s", pid_file, strerror(errno));
        return FALSE;
    }
    
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    
    g_info("PID file written to %s", pid_file);
    return TRUE;
}

/**
 * Remove PID file on exit
 */
static void remove_pid_file(void) {
    if (opt_pid_file && g_file_test(opt_pid_file, G_FILE_TEST_EXISTS)) {
        if (unlink(opt_pid_file) == 0) {
            g_info("PID file removed");
        } else {
            g_warning("Failed to remove PID file: %s", strerror(errno));
        }
    }
}

/**
 * Set system resource limits
 */
static void setup_resource_limits(void) {
    struct rlimit rl;
    
    // Get current limits
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < 4096) {
            rl.rlim_cur = 4096;
            if (rl.rlim_max < 4096) {
                rl.rlim_max = 4096;
            }
            if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
                g_warning("Failed to increase file descriptor limit: %s", 
                         strerror(errno));
            } else {
                g_debug("File descriptor limit increased to %lu", 
                       (unsigned long)rl.rlim_cur);
            }
        }
    }
    
    // Enable core dumps for debugging
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &rl) < 0) {
        g_debug("Failed to enable core dumps: %s", strerror(errno));
    }
}

/**
 * Drop privileges to non-root user
 */
static void drop_privileges(void) {
    if (getuid() != 0) {
        g_debug("Running as non-root, skipping privilege drop");
        return;
    }
    
    struct passwd *pw = getpwnam("nobody");
    if (!pw) {
        pw = getpwnam("daemon");
    }
    
    if (pw) {
        if (setgid(pw->pw_gid) != 0) {
            g_warning("Failed to setgid to %d: %s", pw->pw_gid, strerror(errno));
        }
        if (setuid(pw->pw_uid) != 0) {
            g_warning("Failed to setuid to %d: %s", pw->pw_uid, strerror(errno));
        }
        
        g_info("Dropped privileges to user %s (uid=%d, gid=%d)", 
               pw->pw_name, pw->pw_uid, pw->pw_gid);
    } else {
        g_warning("Could not find non-root user to drop privileges");
    }
}

/**
 * Daemon mode - detach from terminal
 */
static int run_daemon_mode(void) {
    g_info("Starting daemon mode...");
    
    // Fork to background
    pid_t pid = fork();
    if (pid < 0) {
        g_critical("Failed to fork: %s", strerror(errno));
        return 1;
    }
    
    if (pid > 0) {
        // Parent process exits
        g_info("Daemon started with PID %d", pid);
        exit(0);
    }
    
    // Child process continues
    setsid();  // Create new session
    
    // Change working directory
    if (chdir("/") < 0) {
        g_critical("Failed to change directory: %s", strerror(errno));
        return 1;
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Reopen stdin/out/err to /dev/null
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > STDERR_FILENO) {
            close(null_fd);
        }
    }
    
    // Write PID file atomically
    if (!write_pid_file_atomic(opt_pid_file)) {
        return 1;
    }
    
    // Register cleanup for PID file
    atexit(remove_pid_file);
    
    // Drop privileges
    drop_privileges();
    
    // Run main program
    return run_interactive_mode();
}

/**
 * Interactive mode - main proxy operation
 */
static int run_interactive_mode(void) {
    GError *error = NULL;
    int ret = 0;
    
    // Set up resource limits
    setup_resource_limits();
    
    // Initialize context
    g_context = deadlight_context_new();
    if (!g_context) {
        g_critical("Failed to create Deadlight context");
        return 1;
    }
    
    // Load configuration
    if (!deadlight_config_load(g_context, opt_config_file, &error)) {
        g_critical("Failed to load configuration: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup;
    }
    
    // Override port if specified
    if (opt_port > 0) {
        deadlight_config_set_int(g_context, "core", "port", opt_port);
        g_info("Command-line port override applied: %d", opt_port);
    }

    gboolean vpn_enabled = deadlight_config_get_bool(g_context, "vpn", "enabled", FALSE);

    // Validate configuration
    if (!validate_configuration(g_context, &error)) {
        g_critical("Configuration validation failed: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup;
    }

    if (vpn_enabled && opt_daemon) {
        g_warning("VPN may require CAP_NET_ADMIN; daemon privilege drop can prevent VPN startup");
    }
    
    // Set log level
    if (opt_verbose) {
        deadlight_config_set_string(g_context, "core", "log_level", "debug");
    }
    
    // Initialize logging
    if (!deadlight_logging_init(g_context, &error)) {
        g_critical("Failed to initialize logging: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup;
    }
    
    // Print startup banner
    if (!opt_daemon) {
        print_banner();
    }
    
    // Initialize subsystems
    g_info("Initializing Deadlight systems...");
    
    deadlight_protocols_init(g_context);
    
    if (!deadlight_network_init(g_context, &error)) {
        g_critical("Failed to initialize network: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_network;
    }
    
    if (!deadlight_ssl_init(g_context, &error)) {
        g_critical("Failed to initialize SSL: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_ssl;
    }
    
    if (!deadlight_plugins_init(g_context, &error)) {
        g_critical("Failed to initialize plugins: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_plugins;
    }
    
    // Initialize VPN if enabled
    if (vpn_enabled) {
        g_info("VPN gateway is enabled in configuration");
        
        g_context->vpn = g_new0(DeadlightVPNManager, 1);
        g_context->vpn->context = g_context;
        g_context->vpn->tun_fd = -1;
        g_context->vpn->total_connections = 0;
        g_context->vpn->active_connections = 0;
        g_context->vpn->bytes_sent = 0;
        g_context->vpn->bytes_received = 0;
        
        if (!deadlight_vpn_gateway_init(g_context, &error)) {
            g_warning("Failed to initialize VPN gateway: %s", error->message);
            g_warning("Continuing without VPN functionality");
            g_clear_error(&error);
            
            g_free(g_context->vpn);
            g_context->vpn = NULL;
        } else {
            g_info("VPN initialized successfully");
        }
    } else {
        g_debug("VPN gateway is disabled (set vpn.enabled=true to enable)");
    }
    
#ifdef ENABLE_UI
    g_info("Starting UI server...");
    start_ui_server(g_context);
#endif
    
    // Set up signal handlers
    g_unix_signal_add(SIGINT, signal_handler, g_context);
    g_unix_signal_add(SIGTERM, signal_handler, g_context);
    g_unix_signal_add(SIGHUP, signal_handler, g_context);
    
    // Start listening
    gint port = deadlight_config_get_int(g_context, "core", "port", 8080);
    g_info("Starting proxy on port %d", port);
    
    if (!deadlight_network_start_listener(g_context, port, &error)) {
        g_critical("Failed to start listener: %s", error->message);
        g_error_free(error);
        ret = 1;
        goto cleanup_listener;
    }
    
    // Print configuration info
    if (!opt_daemon) {
        g_print("\nDeadlight Proxy %s is ready!\n", VERSION);
        g_print("Build: %s\n", BUILD_DATE);
        g_print("Listening on port %d\n", port);
        g_print("Configuration file: %s\n",
                opt_config_file ? opt_config_file : "default");
        g_print("Plugins loaded: %d\n",
                deadlight_plugins_count(g_context));
        
        // Test commands (only show if not daemon)
        if (opt_verbose) {
            print_test_commands(port, g_context->vpn != NULL);
        }
        
        g_print("\nPress Ctrl+C to stop\n\n");
    }
    
    // Run main loop
    g_context->main_loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(g_context->main_loop);
    
    // Cleanup (fall through to labels)
    
cleanup_listener:
    g_info("Stopping network listener...");
    deadlight_network_stop(g_context);
    
cleanup_plugins:
    g_info("Cleaning up plugins...");
    deadlight_plugins_cleanup(g_context);
    
cleanup_ssl:
    g_info("Cleaning up SSL...");
    deadlight_ssl_cleanup(g_context);
    
cleanup_network:
    g_info("Cleaning up network...");
    deadlight_network_cleanup(g_context);
    
    // Cleanup VPN if active
    if (g_context->vpn) {
        g_info("Cleaning up VPN...");
        deadlight_vpn_gateway_cleanup(g_context);
    }
    
#ifdef ENABLE_UI
    g_info("Stopping UI server...");
    stop_ui_server();
#endif
    
cleanup:
    if (g_context) {
        if (g_context->main_loop) {
            g_main_loop_unref(g_context->main_loop);
            g_context->main_loop = NULL;
        }
    }
    
    g_info("Deadlight proxy stopped");
    return ret;
}

/**
 * Print test commands for all protocols
 */
static void print_test_commands(gint port, gboolean vpn_enabled) {
    g_print("\nTest commands:\n\n");

    g_print("  # Basic HTTP smoke test\n");
    g_print("  curl -x http://localhost:%d http://example.com\n", port);

    g_print("\n  # Inspect proxy-visible request details\n");
    g_print("  curl -x http://localhost:%d http://httpbin.org/headers\n", port);
    g_print("  curl -x http://localhost:%d http://httpbin.org/ip\n", port);

    g_print("\n  # Plain HTTP\n");
    g_print("  curl -x http://localhost:%d http://neverssl.com/\n", port);

    g_print("\n  # HTTPS using Deadlight's local CA\n");
    g_print("  curl --cacert ~/.deadlight/ca.crt -x http://localhost:%d https://httpbin.org/headers\n", port);

    g_print("\n  # SOCKS4\n");
    g_print("  curl --socks4 localhost:%d http://httpbin.org/ip\n", port);

    g_print("\n  # SOCKS5\n");
    g_print("  curl --socks5 localhost:%d http://httpbin.org/ip\n", port);
    
    g_print("\n  # SMTP\n");
    g_print("  printf \"HELO test.com\\r\\n\" | nc localhost %d\n", port);
    
    g_print("\n  # IMAP (NOOP)\n");
    g_print("  printf \"A001 NOOP\\r\\n\" | nc localhost %d\n", port);
    
    g_print("\n  # IMAP STARTTLS\n");
    g_print("  openssl s_client -connect localhost:%d -starttls imap -crlf\n", port);
    
    g_print("\n  # IMAPS tunnel using telnet\n");
    g_print("  telnet localhost %d\n", port);
    g_print("\n  # Once connected, type the following and press Enter:\n");
    g_print("  A001 NOOP\n");
    
    g_print("\n  # WebSocket\n");
    g_print("  websocat -p http://localhost:%d wss://echo.websocket.org\n\n", port);
    

    g_print("  # FTP with netcat:\n");
    g_print("  printf \"USER anonymous\\r\\n\" | nc localhost %d\n\n", port);
    
    // VPN
    if (vpn_enabled) {
        g_print("  # VPN Gateway (requires root/CAP_NET_ADMIN):\n");
        g_print("  # Configure client to use 10.8.0.1 as gateway\n");
        g_print("  sudo ip route add default via 10.8.0.1 dev tun0\n");
        g_print("  curl https://httpbin.org/headers  # Traffic goes through proxy!\n\n");
    }
}

/**
 * Print startup banner
 */
static void print_banner(void) {
    g_print("\n");
    g_print("═══════════════════════════════════════════════════════════\n");
    g_print("                     Deadlight Proxy                      \n");
    g_print("                     Version: %s                       \n", VERSION);
    g_print("                     Build: %s                    \n", BUILD_DATE);
    g_print("═══════════════════════════════════════════════════════════\n");
    g_print("\n");
}

/**
 * Print usage information
 */
static void print_usage(void) {
    g_print("Deadlight Proxy %s - Modular HTTP(S)/SOCKS Proxy\n", VERSION);
    g_print("Build: %s\n\n", BUILD_DATE);
    g_print("Usage: deadlight [OPTIONS]\n\n");
    g_print("Options:\n");
    g_print("  -d, --daemon           Run as daemon\n");
    g_print("  -v, --verbose          Verbose output\n");
    g_print("  -c, --config FILE      Configuration file\n");
    g_print("  -p, --port PORT        Listen port (overrides config)\n");
    g_print("      --pid-file FILE    PID file for daemon mode\n");
    g_print("  -t, --test MODULE      Test specific module\n");
    g_print("      --test-mode        Enable test mode\n");
    g_print("  -h, --help             Show this help\n\n");
    g_print("Test modules:\n");
    g_print("  all, config, logging, network, protocols, ssl, plugins, api\n\n");
    g_print("Examples:\n");
    g_print("  deadlight -p 8787                    # Start on port 8787\n");
    g_print("  deadlight -d --pid-file /tmp/dl.pid # Run as daemon\n");
    g_print("  deadlight -t all                     # Run all tests\n");
    g_print("  deadlight -t network                 # Test network module\n");
    g_print("  deadlight -c custom.conf -v          # Use custom config with debug\n");
    g_print("\n");
}

/**
 * Main entry point
 */
int main(int argc, char *argv[]) {
    /* enable Unicode output if LANG is UTF-8 capable */
    setlocale(LC_ALL, "");
    
    GError *error = NULL;
    GOptionContext *context;
    
    // Initialize GLib
    g_log_set_default_handler(deadlight_log_handler, NULL);
    
    // Parse command line arguments
    context = g_option_context_new("- HTTP(S)/SOCKS Proxy");
    
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_set_description(context,
        "Deadlight Proxy v1.0 - A modular, extensible proxy server\n"
        "Built with GNU/GLib for robustness and performance");
    
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr("Option parsing failed: %s\n", error->message);
        g_error_free(error);
        g_option_context_free(context);
        return 1;
    }
    
    g_option_context_free(context);
    
    // Handle help separately
    if (argc > 1 && (g_strcmp0(argv[1], "-h") == 0 ||
                     g_strcmp0(argv[1], "--help") == 0)) {
        print_usage();
        return 0;
    }
    
    // Test mode
    if (opt_test_module) {
        int result = run_tests(opt_test_module);
        cleanup_and_exit(result);
    }
    
    // Daemon mode
    if (opt_daemon) {
        return run_daemon_mode();
    }
    
    // Interactive mode
    int ret = run_interactive_mode();
    cleanup_and_exit(ret);
}