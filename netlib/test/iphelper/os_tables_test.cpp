// Deterministic tests for the test-side OS table capture (os_tables.h) and the isolation
// decisions built on it. Fake table-query functions replace GetExtendedTcpTable /
// GetExtendedUdpTable through os_tables::table_api; no production code is involved.
//
// They prove that a failed query, a successful empty table, and a buffer-growth retry followed
// by success are distinct outcomes, and that a failed query of either address family yields
// isolation::query_failed rather than an absence-based decision.

#include "pch.h"
#include "test_support.h"
#include "os_tables.h"

namespace
{
    namespace tables = netlib_test::os_tables;

    // ------------------------------------------------------------------------------------
    // Fake table API
    // ------------------------------------------------------------------------------------

    enum class fake_mode { rows, fail, grow_once_then_rows, always_grow };

    struct fake_slot
    {
        fake_mode mode{ fake_mode::rows };
        DWORD error{ NO_ERROR };
        std::function<DWORD(PVOID, PDWORD)> write;   // writes the table or requests a size
        unsigned calls{ 0 };
        std::vector<DWORD> sizes_seen;
    };

    // [0] TCP AF_INET, [1] TCP AF_INET6, [2] UDP AF_INET, [3] UDP AF_INET6
    std::array<fake_slot, 4> g_slots;

    size_t slot_index(const tables::protocol proto, const ULONG family)
    {
        return (proto == tables::protocol::tcp ? 0 : 2) + (family == AF_INET ? 0 : 1);
    }

    template <typename Table, typename Row>
    std::function<DWORD(PVOID, PDWORD)> table_writer(std::vector<Row> rows)
    {
        return [rows = std::move(rows)](const PVOID buffer, const PDWORD size) -> DWORD {
            const auto needed = static_cast<DWORD>((std::max<size_t>)(
                offsetof(Table, table) + rows.size() * sizeof(Row), sizeof(Table)));
            if (*size < needed)
            {
                *size = needed;
                return ERROR_INSUFFICIENT_BUFFER;
            }
            auto* table = static_cast<Table*>(buffer);
            table->dwNumEntries = static_cast<DWORD>(rows.size());
            if (!rows.empty())
                std::memcpy(table->table, rows.data(), rows.size() * sizeof(Row));
            return NO_ERROR;
        };
    }

    DWORD dispatch(const tables::protocol proto, const PVOID buffer, const PDWORD size, const ULONG family)
    {
        auto& slot = g_slots[slot_index(proto, family)];
        ++slot.calls;
        slot.sizes_seen.push_back(*size);
        switch (slot.mode)
        {
        case fake_mode::fail:
            return slot.error;
        case fake_mode::always_grow:
            *size += 64;
            return ERROR_INSUFFICIENT_BUFFER;
        case fake_mode::grow_once_then_rows:
            if (slot.calls == 1)
            {
                *size += 4096;   // larger than any table these tests write
                return ERROR_INSUFFICIENT_BUFFER;
            }
            return slot.write(buffer, size);
        case fake_mode::rows:
            return slot.write(buffer, size);
        }
        return ERROR_INVALID_FUNCTION;
    }

    DWORD WINAPI fake_tcp(const PVOID buffer, const PDWORD size, BOOL, const ULONG family, TCP_TABLE_CLASS, ULONG)
    {
        return dispatch(tables::protocol::tcp, buffer, size, family);
    }

    DWORD WINAPI fake_udp(const PVOID buffer, const PDWORD size, BOOL, const ULONG family, UDP_TABLE_CLASS, ULONG)
    {
        return dispatch(tables::protocol::udp, buffer, size, family);
    }

    constexpr tables::table_api fake_api{ &fake_tcp, &fake_udp };

    // ------------------------------------------------------------------------------------
    // Row builders
    // ------------------------------------------------------------------------------------

    constexpr DWORD owner_pid = 4242;
    constexpr uint16_t port_a = 50001;
    constexpr uint16_t port_b = 50002;

    DWORD net_port(const uint16_t port) { return htons(port); }

    MIB_TCPROW_OWNER_PID tcp4_row(const uint16_t local, const uint16_t remote, const DWORD pid)
    {
        MIB_TCPROW_OWNER_PID row{};
        row.dwState = MIB_TCP_STATE_ESTAB;
        ::inet_pton(AF_INET, "127.0.0.1", &row.dwLocalAddr);
        ::inet_pton(AF_INET, "127.0.0.1", &row.dwRemoteAddr);
        row.dwLocalPort = net_port(local);
        row.dwRemotePort = net_port(remote);
        row.dwOwningPid = pid;
        return row;
    }

    MIB_TCP6ROW_OWNER_PID tcp6_mapped_row(const uint16_t local, const uint16_t remote, const DWORD pid)
    {
        MIB_TCP6ROW_OWNER_PID row{};
        row.dwState = MIB_TCP_STATE_ESTAB;
        std::memcpy(row.ucLocalAddr, tables::v4_mapped_loopback.data(), 16);
        std::memcpy(row.ucRemoteAddr, tables::v4_mapped_loopback.data(), 16);
        row.dwLocalPort = net_port(local);
        row.dwRemotePort = net_port(remote);
        row.dwOwningPid = pid;
        return row;
    }

    MIB_UDPROW_OWNER_PID udp4_row(const char* address, const uint16_t port, const DWORD pid)
    {
        MIB_UDPROW_OWNER_PID row{};
        ::inet_pton(AF_INET, address, &row.dwLocalAddr);
        row.dwLocalPort = net_port(port);
        row.dwOwningPid = pid;
        return row;
    }

    MIB_UDP6ROW_OWNER_PID udp6_row(const std::array<uint8_t, 16>& address, const uint16_t port, const DWORD pid)
    {
        MIB_UDP6ROW_OWNER_PID row{};
        std::memcpy(row.ucLocalAddr, address.data(), 16);
        row.dwLocalPort = net_port(port);
        row.dwOwningPid = pid;
        return row;
    }

    class OsTableCaptureTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            g_slots = {};
            // Default: every table succeeds and is empty.
            set_tcp4({});
            set_tcp6({});
            set_udp4({});
            set_udp6({});
        }

        static fake_slot& slot(const tables::protocol proto, const int family) { return g_slots[slot_index(proto, family)]; }

        static void set_tcp4(std::vector<MIB_TCPROW_OWNER_PID> rows, const fake_mode mode = fake_mode::rows)
        {
            slot(tables::protocol::tcp, AF_INET) = { mode, NO_ERROR, table_writer<MIB_TCPTABLE_OWNER_PID>(std::move(rows)) };
        }
        static void set_tcp6(std::vector<MIB_TCP6ROW_OWNER_PID> rows, const fake_mode mode = fake_mode::rows)
        {
            slot(tables::protocol::tcp, AF_INET6) = { mode, NO_ERROR, table_writer<MIB_TCP6TABLE_OWNER_PID>(std::move(rows)) };
        }
        static void set_udp4(std::vector<MIB_UDPROW_OWNER_PID> rows, const fake_mode mode = fake_mode::rows)
        {
            slot(tables::protocol::udp, AF_INET) = { mode, NO_ERROR, table_writer<MIB_UDPTABLE_OWNER_PID>(std::move(rows)) };
        }
        static void set_udp6(std::vector<MIB_UDP6ROW_OWNER_PID> rows, const fake_mode mode = fake_mode::rows)
        {
            slot(tables::protocol::udp, AF_INET6) = { mode, NO_ERROR, table_writer<MIB_UDP6TABLE_OWNER_PID>(std::move(rows)) };
        }
        static void set_failure(const tables::protocol proto, const int family, const DWORD error)
        {
            auto& s = slot(proto, family);
            s.mode = fake_mode::fail;
            s.error = error;
        }
    };

    // ------------------------------------------------------------------------------------
    // Capture outcomes
    // ------------------------------------------------------------------------------------

    TEST_F(OsTableCaptureTest, FailedQueryIsReportedWithProtocolFamilyAndError)
    {
        set_failure(tables::protocol::udp, AF_INET6, ERROR_INVALID_PARAMETER);

        const auto c = tables::capture_table(tables::protocol::udp, AF_INET6, fake_api);
        EXPECT_FALSE(c.ok);
        EXPECT_EQ(c.api_error, static_cast<DWORD>(ERROR_INVALID_PARAMETER));
        EXPECT_EQ(c.attempts, 1u);
        EXPECT_TRUE(c.rows.empty());
        const auto text = c.describe_failure();
        EXPECT_NE(text.find("UDP AF_INET6"), std::string::npos) << text;
        EXPECT_NE(text.find("GetExtendedUdpTable"), std::string::npos) << text;
        EXPECT_NE(text.find("error 87"), std::string::npos) << text;
    }

    TEST_F(OsTableCaptureTest, SuccessfulEmptyTableIsDistinctFromFailure)
    {
        const auto c = tables::capture_table(tables::protocol::tcp, AF_INET, fake_api);
        EXPECT_TRUE(c.ok);
        EXPECT_EQ(c.api_error, static_cast<DWORD>(NO_ERROR));
        EXPECT_EQ(c.attempts, 1u);
        EXPECT_TRUE(c.rows.empty());
    }

    TEST_F(OsTableCaptureTest, BufferGrowthRetryThenSuccessReturnsRows)
    {
        set_tcp6({ tcp6_mapped_row(port_a, port_b, owner_pid) }, fake_mode::grow_once_then_rows);

        const auto c = tables::capture_table(tables::protocol::tcp, AF_INET6, fake_api);
        ASSERT_TRUE(c.ok);
        EXPECT_EQ(c.attempts, 2u);
        ASSERT_EQ(c.rows.size(), 1u);
        EXPECT_EQ(c.rows[0].local_port, port_a);
        EXPECT_EQ(c.rows[0].remote_port, port_b);
        EXPECT_EQ(c.rows[0].pid, owner_pid);

        // The retry used the size requested by the first call.
        const auto& s = slot(tables::protocol::tcp, AF_INET6);
        ASSERT_EQ(s.sizes_seen.size(), 2u);
        EXPECT_EQ(s.sizes_seen[1], s.sizes_seen[0] + 4096);
    }

    TEST_F(OsTableCaptureTest, PersistentInsufficientBufferIsBoundedFailure)
    {
        set_udp4({}, fake_mode::always_grow);

        const auto c = tables::capture_table(tables::protocol::udp, AF_INET, fake_api);
        EXPECT_FALSE(c.ok);
        EXPECT_EQ(c.api_error, static_cast<DWORD>(ERROR_INSUFFICIENT_BUFFER));
        EXPECT_EQ(c.attempts, tables::max_query_attempts);
    }

    // ------------------------------------------------------------------------------------
    // Isolation decisions
    // ------------------------------------------------------------------------------------

    TEST_F(OsTableCaptureTest, TcpMappedRowsOnlyAreIsolated)
    {
        set_tcp6({ tcp6_mapped_row(port_a, port_b, owner_pid), tcp6_mapped_row(port_b, port_a, owner_pid) });

        const auto r = tables::mapped_tcp_isolation(tables::capture_protocol(tables::protocol::tcp, fake_api), owner_pid, port_a, port_b);
        EXPECT_EQ(r.state, tables::isolation::isolated) << r.detail;
    }

    TEST_F(OsTableCaptureTest, TcpNativeRowsPreventIsolation)
    {
        set_tcp6({ tcp6_mapped_row(port_a, port_b, owner_pid), tcp6_mapped_row(port_b, port_a, owner_pid) });
        set_tcp4({ tcp4_row(port_b, port_a, owner_pid) });

        const auto r = tables::mapped_tcp_isolation(tables::capture_protocol(tables::protocol::tcp, fake_api), owner_pid, port_a, port_b);
        EXPECT_EQ(r.state, tables::isolation::not_isolated) << r.detail;
    }

    TEST_F(OsTableCaptureTest, TcpEmptyTablesAreNotIsolatedRatherThanFailed)
    {
        const auto r = tables::mapped_tcp_isolation(tables::capture_protocol(tables::protocol::tcp, fake_api), owner_pid, port_a, port_b);
        EXPECT_EQ(r.state, tables::isolation::not_isolated) << r.detail;
    }

    // A failed AF_INET query must not be read as "no native row", which would falsely claim
    // isolation when the mapped rows are present.
    TEST_F(OsTableCaptureTest, FailedIpv4TcpQueryIsQueryFailureNotIsolation)
    {
        set_tcp6({ tcp6_mapped_row(port_a, port_b, owner_pid), tcp6_mapped_row(port_b, port_a, owner_pid) });
        set_failure(tables::protocol::tcp, AF_INET, ERROR_NOT_SUPPORTED);

        const auto r = tables::mapped_tcp_isolation(tables::capture_protocol(tables::protocol::tcp, fake_api), owner_pid, port_a, port_b);
        EXPECT_EQ(r.state, tables::isolation::query_failed) << r.detail;
        EXPECT_NE(r.detail.find("TCP AF_INET table"), std::string::npos) << r.detail;
        EXPECT_NE(r.detail.find("error 50"), std::string::npos) << r.detail;
    }

    // A failed AF_INET6 query must not be read as "no mapped row" (not isolated / unsupported).
    TEST_F(OsTableCaptureTest, FailedIpv6TcpQueryIsQueryFailureNotAbsence)
    {
        set_failure(tables::protocol::tcp, AF_INET6, ERROR_NOT_SUPPORTED);

        const auto r = tables::mapped_tcp_isolation(tables::capture_protocol(tables::protocol::tcp, fake_api), owner_pid, port_a, port_b);
        EXPECT_EQ(r.state, tables::isolation::query_failed) << r.detail;
        EXPECT_NE(r.detail.find("TCP AF_INET6 table"), std::string::npos) << r.detail;
    }

    TEST_F(OsTableCaptureTest, UdpUnspecifiedRowOnlyIsIsolated)
    {
        set_udp6({ udp6_row(tables::v6_unspecified, port_a, owner_pid) });

        const auto r = tables::mapped_udp_isolation(tables::capture_protocol(tables::protocol::udp, fake_api),
            tables::v6_unspecified, owner_pid, port_a);
        EXPECT_EQ(r.state, tables::isolation::isolated) << r.detail;
    }

    TEST_F(OsTableCaptureTest, UdpNativeRowPreventsIsolation)
    {
        set_udp6({ udp6_row(tables::v6_unspecified, port_a, owner_pid) });
        set_udp4({ udp4_row("0.0.0.0", port_a, owner_pid) });

        const auto r = tables::mapped_udp_isolation(tables::capture_protocol(tables::protocol::udp, fake_api),
            tables::v6_unspecified, owner_pid, port_a);
        EXPECT_EQ(r.state, tables::isolation::not_isolated) << r.detail;
    }

    TEST_F(OsTableCaptureTest, UdpRowOfAnotherOwnerIsNotIsolation)
    {
        set_udp6({ udp6_row(tables::v4_mapped_loopback, port_a, owner_pid + 1) });

        const auto r = tables::mapped_udp_isolation(tables::capture_protocol(tables::protocol::udp, fake_api),
            tables::v4_mapped_loopback, owner_pid, port_a);
        EXPECT_EQ(r.state, tables::isolation::not_isolated) << r.detail;
    }

    TEST_F(OsTableCaptureTest, FailedIpv4UdpQueryIsQueryFailureNotIsolation)
    {
        set_udp6({ udp6_row(tables::v6_unspecified, port_a, owner_pid) });
        set_failure(tables::protocol::udp, AF_INET, ERROR_NOT_SUPPORTED);

        const auto r = tables::mapped_udp_isolation(tables::capture_protocol(tables::protocol::udp, fake_api),
            tables::v6_unspecified, owner_pid, port_a);
        EXPECT_EQ(r.state, tables::isolation::query_failed) << r.detail;
        EXPECT_NE(r.detail.find("UDP AF_INET table"), std::string::npos) << r.detail;
    }

    TEST_F(OsTableCaptureTest, FailedIpv6UdpQueryIsQueryFailureNotAbsence)
    {
        set_failure(tables::protocol::udp, AF_INET6, ERROR_NOT_SUPPORTED);

        const auto r = tables::mapped_udp_isolation(tables::capture_protocol(tables::protocol::udp, fake_api),
            tables::v6_unspecified, owner_pid, port_a);
        EXPECT_EQ(r.state, tables::isolation::query_failed) << r.detail;
        EXPECT_NE(r.detail.find("UDP AF_INET6 table"), std::string::npos) << r.detail;
    }

    TEST_F(OsTableCaptureTest, GrowthRetryOnBothFamiliesStillDecidesIsolation)
    {
        set_udp4({}, fake_mode::grow_once_then_rows);
        set_udp6({ udp6_row(tables::v4_mapped_loopback, port_a, owner_pid) }, fake_mode::grow_once_then_rows);

        const auto view = tables::capture_protocol(tables::protocol::udp, fake_api);
        EXPECT_EQ(view.v4.attempts, 2u);
        EXPECT_EQ(view.v6.attempts, 2u);
        const auto r = tables::mapped_udp_isolation(view, tables::v4_mapped_loopback, owner_pid, port_a);
        EXPECT_EQ(r.state, tables::isolation::isolated) << r.detail;
    }
}
