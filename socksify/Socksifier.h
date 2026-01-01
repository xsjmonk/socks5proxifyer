// ReSharper disable CppInconsistentNaming
#pragma once

using namespace System;

/// <summary>
/// Forward declaration for the unmanaged implementation of the Socksifier logic.
/// </summary>
class socksify_unmanaged;

namespace Socksifier
{
    /// <summary>
    /// Specifies the logging level for the Socksifier component.
    /// </summary>
    /// <remarks>
    /// The log levels are bitmask values. Higher values include all lower levels.
    /// </remarks>
    public enum class LogLevel
    {
        /// <summary>
        /// Error messages only.
        /// </summary>
        Error = 0,
        /// <summary>
        /// Warning and error messages.
        /// </summary>
        Warning = 1,
        /// <summary>
        /// Informational, warning, and error messages.
        /// </summary>
        Info = 2,
        /// <summary>
        /// Debug, informational, warning, and error messages.
        /// </summary>
        Debug = 4,
        /// <summary>
        /// All log messages.
        /// </summary>
        All = 255,
    };

    /// <summary>
    /// Represents the status of the proxy gateway.
    /// </summary>
    public enum class ProxyGatewayStatus
    {
        /// <summary>The gateway is stopped.</summary>
        Stopped,
        /// <summary>The gateway is connected.</summary>
        Connected,
        /// <summary>The gateway is disconnected.</summary>
        Disconnected,
        /// <summary>An error has occurred in the gateway.</summary>
        Error
    };

    /// <summary>
    /// Enumerates the types of events that can occur in the proxy gateway.
    /// </summary>
    public enum class ProxyGatewayEvent
    {
        /// <summary>The gateway has connected.</summary>
        Connected,
        /// <summary>The gateway has disconnected.</summary>
        Disconnected,
        /// <summary>A message event.</summary>
        Message,
        /// <summary>An address error event.</summary>
        AddressError,
        /// <summary>An NDIS error event.</summary>
        NdisError
    };

    /// <summary>
    /// Specifies the supported protocols for proxying.
    /// </summary>
    public enum class SupportedProtocolsEnum
    {
        /// <summary>TCP protocol only.</summary>
        TCP,
        /// <summary>UDP protocol only.</summary>
        UDP,
        /// <summary>Both TCP and UDP protocols.</summary>
        BOTH
    };

    /// <summary>
    /// Represents a single log entry for Socksifier events.
    /// </summary>
    public ref class LogEntry sealed
    {
        long long time_stamp_;
        ProxyGatewayEvent tunnel_event_;
        String^ description_;
        UInt64 data_;

    public:
        LogEntry(const long long time_stamp, const ProxyGatewayEvent event, String^ description)
            : time_stamp_(time_stamp),
              tunnel_event_(event),
              description_(description)
        {
        }

        LogEntry(const long long time_stamp, const ProxyGatewayEvent event, const UInt64 data)
            : time_stamp_(time_stamp),
              tunnel_event_(event),
              data_(data)
        {
        }

        property long long TimeStamp { long long get() { return time_stamp_; } }
        property ProxyGatewayEvent Event { ProxyGatewayEvent get() { return tunnel_event_; } }
        property String^ Description { String^ get() { return description_; } }
        property UInt64 Data { UInt64 get() { return data_; } }
    };

    /// <summary>
    /// Provides data for log event notifications.
    /// </summary>
    public ref class LogEventArgs sealed : public EventArgs
    {
        Collections::Generic::List<LogEntry^>^ log_;

    public:
        explicit LogEventArgs(Collections::Generic::List<LogEntry^>^ log)
            : log_(log)
        {
        }

        property Collections::Generic::List<LogEntry^>^ Log
        {
            Collections::Generic::List<LogEntry^> ^ get() { return log_; }
        }
    };

    /// <summary>
    /// Main entry point for managing SOCKS proxying and process association.
    /// </summary>
    public ref class Socksifier sealed
    {
        Socksifier(LogLevel log_level);

    public:
        !Socksifier();
        ~Socksifier();

        static Socksifier^ Socksifier::GetInstance(LogLevel log_level);
        static Socksifier^ Socksifier::GetInstance();

        event EventHandler<LogEventArgs^>^ LogEvent;

        bool Start();
        bool Stop();

        /// <summary>
        /// Enables LAN traffic bypass.
        /// When enabled, traffic to/from local network ranges will pass through without being proxied.
        /// </summary>
        /// <remarks>
        /// This must be called before Start() to take effect.
        /// 
        /// Bypassed ranges:
        /// - 10.0.0.0/8 (Private Class A)
        /// - 172.16.0.0/12 (Private Class B: 172.16.x.x - 172.31.x.x)
        /// - 192.168.0.0/16 (Private Class C)
        /// - 224.0.0.0/4 (Multicast: 224.x.x.x - 239.x.x.x)
        /// - 169.254.0.0/16 (Link-local / APIPA)
        /// </remarks>
        void SetBypassLan();

        /// <summary>
        /// Adds a SOCKS5 proxy to the gateway.
        /// </summary>
        /// <param name="endpoint">The proxy endpoint (IP:Port).</param>
        /// <param name="username">The username for authentication.</param>
        /// <param name="password">The password for authentication.</param>
        /// <param name="protocols">The supported protocols.</param>
        /// <param name="start">Whether to start the proxy immediately.</param>
        /// <returns>A handle to the proxy instance.</returns>
        IntPtr AddSocks5Proxy(String^ endpoint, String^ username, String^ password, SupportedProtocolsEnum protocols,
            bool start);

        /// <summary>
        /// Associates a process name with a specific proxy.
        /// </summary>
        /// <param name="processName">The process name to associate.</param>
        /// <param name="proxy">The proxy handle.</param>
        /// <returns>True if association was successful, otherwise false.</returns>
        bool AssociateProcessNameToProxy(String^ processName, IntPtr proxy);
        bool ExcludeProcessName(String^ excludedEntry);

        // --- NEW: per-process destination CIDR include helpers (used by Program.cs) ---
        bool IncludeProcessDestinationCidr(String^ processName, String^ cidr);
        bool RemoveProcessDestinationCidr(String^ processName, String^ cidr);
        // ------------------------------------------------------------------------------

        property Int32 LogEventInterval
        {
            Int32 get() { return log_event_interval_; }
            void set(const Int32 value) { log_event_interval_ = value; }
        }

        property UInt32 LogLimit
        {
            UInt32 get() { return GetLogLimit(); }
            void set(const UInt32 value) { SetLogLimit(value); };
        }

    private:
        void log_thread();
        UInt32 GetLogLimit();
        void SetLogLimit(UInt32 value);

        static Socksifier^ instance_;
        socksify_unmanaged* unmanaged_ptr_{ nullptr };
        Threading::AutoResetEvent^ log_event_;
        Threading::Thread^ logging_thread_;
        volatile bool logger_thread_active_ = true;
        Int32 log_event_interval_;
    };
}
