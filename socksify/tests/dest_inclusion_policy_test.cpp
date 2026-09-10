#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include "policy/dest_inclusion_policy.h"
#include "policy/process_key.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>

namespace {

int g_failures = 0;

void expect_true(bool condition, const char* message) {
    if (!condition) {
        ++g_failures;
        std::fprintf(stderr, "FAIL: %s\n", message);
    }
}

void expect_false(bool condition, const char* message) {
    expect_true(!condition, message);
}

void expect_equal(int actual, int expected, const char* message) {
    if (actual != expected) {
        ++g_failures;
        std::fprintf(stderr, "FAIL: %s (expected %d, got %d)\n", message, expected, actual);
    }
}

void expect_key(const wchar_t* input, const wchar_t* expected, const char* message) {
    const auto actual = dip_policy::normalize_process_key(input);
    if (actual != expected) {
        ++g_failures;
        std::fwprintf(stderr, L"FAIL: %hs (expected '%s', got '%s')\n", message, expected, actual.c_str());
    }
}

sockaddr_in make_ipv4_destination(const char* dotted_quad) {
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(443);
    if (InetPtonA(AF_INET, dotted_quad, &destination.sin_addr) != 1) {
        std::fprintf(stderr, "FAIL: invalid test address %s\n", dotted_quad);
        ++g_failures;
    }
    return destination;
}

int redirect_decision(const wchar_t* process_name, const char* destination_ip) {
    const auto destination = make_ipv4_destination(destination_ip);
    return dip_should_redirect_for(
        process_name,
        reinterpret_cast<const sockaddr*>(&destination),
        sizeof(destination));
}

using redirect_decider_fn = std::function<bool(const std::wstring&, const sockaddr*, int)>;

bool invoke_decider(const redirect_decider_fn& decider,
                    const wchar_t* process_name,
                    const char* destination_ip) {
    const auto destination = make_ipv4_destination(destination_ip);
    return decider(
        process_name,
        reinterpret_cast<const sockaddr*>(&destination),
        sizeof(destination));
}

void test_process_key_normalization() {
    expect_key(L"rdcman", L"rdcman", "rdcman stays canonical");
    expect_key(L"rdcman.exe", L"rdcman", "rdcman.exe strips extension");
    expect_key(L"RDCMAN", L"rdcman", "RDCMAN lower-cases");
    expect_key(L"RDCMAN.EXE", L"rdcman", "RDCMAN.EXE normalizes fully");
    expect_key(L"C:\\Windows\\System32\\mstsc.exe", L"mstsc", "full path normalizes to mstsc");
    expect_key(L"SomeService", L"someservice", "extensionless service name is preserved");
}

void test_malformed_cidr_is_rejected() {
    expect_equal(dip_add_process(L"rdcman", "not-a-cidr"), 0, "malformed CIDR rejected on add");
    expect_equal(dip_remove_process(L"rdcman", "192.168.100.0"), 0, "missing prefix rejected on remove");
}

void test_add_remove_use_identical_canonical_keys() {
    expect_equal(dip_add_process(L"rdcman.exe", "192.168.100.0/24"), 1, "add with .exe succeeds");
    expect_equal(dip_remove_process(L"RDCMAN", "192.168.100.0/24"), 1, "remove with alternate casing succeeds");
    expect_equal(
        redirect_decision(L"rdcman.exe", "192.168.100.1"),
        1,
        "removed process falls back to default redirect behavior");
}

void test_configured_process_range_enforcement() {
    expect_equal(dip_add_process(L"rdcman", "192.168.100.0/24"), 1, "add rdcman range succeeds");

    expect_equal(
        redirect_decision(L"rdcman.exe", "192.168.100.1"),
        1,
        "inside-range destination redirects for lookup key rdcman.exe");
    expect_equal(
        redirect_decision(L"RDCMAN", "192.168.100.1"),
        1,
        "inside-range destination redirects for lookup key RDCMAN");
    expect_equal(
        redirect_decision(L"C:\\Windows\\System32\\mstsc.exe", "192.168.100.50"),
        1,
        "stored rdcman policy does not apply to mstsc path lookup");

    expect_equal(
        redirect_decision(L"rdcman", "8.8.8.8"),
        0,
        "outside-range destination passes for configured process");
    expect_equal(
        redirect_decision(L"rdcman.exe", "203.0.113.10"),
        0,
        "outside-range destination passes for lookup key with .exe");

    expect_equal(dip_remove_process(L"rdcman.exe", "192.168.100.0/24"), 1, "cleanup rdcman range");
}

void test_unconfigured_process_default_redirect() {
    expect_equal(
        redirect_decision(L"unconfigured-process-test", "8.8.8.8"),
        1,
        "unconfigured process keeps default redirect behavior");
}

void test_tcp_and_udp_decider_paths_share_policy() {
    expect_equal(dip_add_process(L"rdcman", "192.168.100.0/24"), 1, "add rdcman range for decider test");

    const redirect_decider_fn tcp_decider = [](const std::wstring& process_name,
                                               const sockaddr* destination,
                                               const int destination_length) {
        return dip_should_redirect_for(process_name.c_str(), destination, destination_length) == 1;
    };
    const redirect_decider_fn udp_decider = tcp_decider;

    expect_true(
        invoke_decider(tcp_decider, L"rdcman.exe", "192.168.100.1"),
        "TCP decider path redirects inside configured range");
    expect_false(
        invoke_decider(tcp_decider, L"rdcman.exe", "203.0.113.10"),
        "TCP decider path passes outside configured range");
    expect_true(
        invoke_decider(udp_decider, L"rdcman.exe", "192.168.100.1"),
        "UDP decider path redirects inside configured range");
    expect_false(
        invoke_decider(udp_decider, L"rdcman.exe", "203.0.113.10"),
        "UDP decider path passes outside configured range");

    expect_equal(dip_remove_process(L"rdcman", "192.168.100.0/24"), 1, "cleanup rdcman range after decider test");
}

}  // namespace

int main() {
    WSADATA wsa_data{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    test_process_key_normalization();
    test_malformed_cidr_is_rejected();
    test_add_remove_use_identical_canonical_keys();
    test_configured_process_range_enforcement();
    test_unconfigured_process_default_redirect();
    test_tcp_and_udp_decider_paths_share_policy();

    WSACleanup();

    if (g_failures == 0) {
        std::printf("dest_inclusion_policy_test: all tests passed\n");
        return 0;
    }

    std::fprintf(stderr, "dest_inclusion_policy_test: %d failure(s)\n", g_failures);
    return 1;
}
