#pragma once

/**
 * @brief Forward declaration for a platform-specific mutex implementation.
 */
struct mutex_impl;

namespace proxy
{
    /**
     * @brief Forward declaration for the SOCKS local router class.
     */
    class socks_local_router;
}

/**
 * @brief Manages the lifecycle and configuration of the unmanaged SOCKS proxy gateway.
 *
 * This class provides a singleton interface for starting/stopping the proxy gateway,
 * adding SOCKS5 proxies, associating processes to proxies, and managing logging.
 * It wraps the core proxy logic and exposes thread-safe methods for integration
 * with managed and unmanaged code.
 */
class socksify_unmanaged  // NOLINT(clang-diagnostic-padded)
{
    explicit socksify_unmanaged(log_level_mx log_level);

public:
    ~socksify_unmanaged();

    socksify_unmanaged(const socksify_unmanaged& other) = delete;
    socksify_unmanaged(socksify_unmanaged&& other) = delete;
    socksify_unmanaged& operator=(const socksify_unmanaged& other) = delete;
    socksify_unmanaged& operator=(socksify_unmanaged&& other) = delete;

    static socksify_unmanaged* get_instance(log_level_mx log_level = log_level_mx::all);

    [[nodiscard]] bool start() const;
    [[nodiscard]] bool stop() const;

    /**
     * @brief Enables bypass of the SOCKS proxy for local/LAN traffic.
     *
     * When enabled, connections destined for local network addresses are routed
     * directly (bypassing the SOCKS proxy), while non-LAN traffic continues to be
     * processed by the configured SOCKS5 proxies.
     *
     * @note This option must be configured before calling start() to take effect.
     *       Changing this after the gateway has been started will not affect the
     *       currently running instance.
     */
    void set_bypass_lan() const;

    /**
     * @brief Adds a SOCKS5 proxy to the gateway.
     * @param endpoint The proxy endpoint in "IP:Port" format.
     * @param protocol The supported protocol(s) for the proxy.
     * @param start Whether to start the proxy immediately.
     * @param login Optional username for authentication.
     * @param password Optional password for authentication.
     * @return A handle (LONG_PTR) to the proxy instance, or 0 on failure.
     */
    [[nodiscard]] LONG_PTR add_socks5_proxy(
        const std::string& endpoint,
        supported_protocols_mx protocol,
        bool start = false,
        const std::string& login = "",
        const std::string& password = ""
    ) const;

    [[nodiscard]] bool associate_process_name_to_proxy(
        const std::wstring& process_name,
        LONG_PTR proxy_id) const;
    [[nodiscard]] bool exclude_process_name(const std::wstring& process_name) const;

    void set_log_limit(uint32_t log_limit);
    [[nodiscard]] uint32_t get_log_limit();
    void set_log_event(HANDLE log_event);
    log_storage_mx_t read_log();

    // --- NEW: wrappers for per-process destination CIDR management -----------
    [[nodiscard]] bool include_process_dst_cidr(const std::wstring& process_name,
                                                const std::string& cidr) const;
    [[nodiscard]] bool remove_process_dst_cidr(const std::wstring& process_name,
                                               const std::string& cidr) const;
    // -------------------------------------------------------------------------

private:
    static void log_printer(const char* log);
    static void log_event(event_mx log);
    void print_log(log_level_mx level, const std::string& message) const;

    std::string address_; ///< The address for the proxy (if applicable).
    std::unique_ptr<proxy::socks_local_router> proxy_; ///< The core proxy router instance.
    std::unique_ptr<mutex_impl> lock_; ///< Mutex for thread safety.
    /// <summary>
    /// Optional output file stream for logging pcap data.
    /// </summary>
    std::optional<std::ofstream> pcap_log_file_;
    log_level_mx log_level_{ log_level_mx::error }; ///< The current log level.
};