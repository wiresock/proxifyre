// ReSharper disable CppInconsistentNaming
#pragma once

namespace pcap
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// Link layer types
    /// </summary>
    // --------------------------------------------------------------------------------
    enum link_layer_type : uint32_t
    {
        /// <summary>BSD loopback encapsulation</summary>
        LINKTYPE_NULL = 0,
        /// <summary>IEEE 802.3 Ethernet</summary>
        LINKTYPE_ETHERNET = 1,
        /// <summary>AX.25 packet</summary>
        LINKTYPE_AX25 = 3,
        /// <summary>IEEE 802.5 Token Ring</summary>
        LINKTYPE_IEEE802_5 = 6,
        /// <summary>ARCNET Data Packets</summary>
        LINKTYPE_ARCNET_BSD = 7,
        /// <summary>SLIP, encapsulated with a LINKTYPE_SLIP header</summary>
        LINKTYPE_SLIP = 8,
        /// <summary>PPP, as per RFC 1661 and RFC 1662</summary>
        LINKTYPE_PPP = 9,
        /// <summary>FDDI, as specified by ANSI INCITS 239-1994</summary>
        LINKTYPE_FDDI = 10,
        /// <summary>Raw IP</summary>
        LINKTYPE_DLT_RAW1 = 12,
        /// <summary>Raw IP (OpenBSD)</summary>
        LINKTYPE_DLT_RAW2 = 14,
        /// <summary>PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC
        /// framing, as per section 4.3.1 of RFC 1547</summary>
        LINKTYPE_PPP_HDLC = 50,
        /// <summary>PPPoE</summary>
        LINKTYPE_PPP_ETHER = 51,
        /// <summary>RFC 1483 LLC/SNAP-encapsulated ATM</summary>
        LINKTYPE_ATM_RFC1483 = 100,
        /// <summary>Raw IP</summary>
        LINKTYPE_RAW = 101,
        /// <summary>Cisco PPP with HDLC framing</summary>
        LINKTYPE_C_HDLC = 104,
        /// <summary>IEEE 802.11 wireless LAN</summary>
        LINKTYPE_IEEE802_11 = 105,
        /// <summary>Frame Relay</summary>
        LINKTYPE_FRELAY = 107,
        /// <summary>OpenBSD loopback encapsulation</summary>
        LINKTYPE_LOOP = 108,
        /// <summary>Linux "cooked" capture encapsulation</summary>
        LINKTYPE_LINUX_SLL = 113,
        /// <summary>Apple LocalTalk</summary>
        LINKTYPE_LTALK = 114,
        /// <summary>OpenBSD pflog</summary>
        LINKTYPE_PFLOG = 117,
        /// <summary>Prism monitor mode information followed by an 802.11 header</summary>
        LINKTYPE_IEEE802_11_PRISM = 119,
        /// <summary>RFC 2625 IP-over-Fibre Channel</summary>
        LINKTYPE_IP_OVER_FC = 122,
        /// <summary>ATM traffic, encapsulated as per the scheme used by SunATM devices</summary>
        LINKTYPE_SUNATM = 123,
        /// <summary>Radiotap link-layer information followed by an 802.11 header</summary>
        LINKTYPE_IEEE802_11_RADIOTAP = 127,
        /// <summary>ARCNET Data Packets, as described by the ARCNET Trade Association
        /// standard ATA 878.1-1999</summary>
        LINKTYPE_ARCNET_LINUX = 129,
        /// <summary>Apple IP-over-IEEE 1394 cooked header</summary>
        LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138,
        /// <summary>Signaling System 7 Message Transfer Part Level 2</summary>
        LINKTYPE_MTP2_WITH_PHDR = 139,
        /// <summary>Signaling System 7 Message Transfer Part Level 2</summary>
        LINKTYPE_MTP2 = 140,
        /// <summary>Signaling System 7 Message Transfer Part Level 3</summary>
        LINKTYPE_MTP3 = 141,
        /// <summary>Signaling System 7 Signalling Connection Control Part</summary>
        LINKTYPE_SCCP = 142,
        /// <summary>Signaling System 7 Signalling Connection Control Part</summary>
        LINKTYPE_DOCSIS = 143,
        /// <summary>Linux-IrDA packets</summary>
        LINKTYPE_LINUX_IRDA = 144,
        /// <summary>AVS monitor mode information followed by an 802.11 header</summary>
        LINKTYPE_IEEE802_11_AVS = 163,
        /// <summary>BACnet MS/TP frames</summary>
        LINKTYPE_BACNET_MS_TP = 165,
        /// <summary>PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the
        /// 0xff address byte replaced by a direction indication - 0x00 for incoming and 0x01 for outgoing</summary>
        LINKTYPE_PPP_PPPD = 166,
        /// <summary>General Packet Radio Service Logical Link Control</summary>
        LINKTYPE_GPRS_LLC = 169,
        /// <summary>Transparent-mapped generic framing procedure</summary>
        LINKTYPE_GPF_T = 170,
        /// <summary>Frame-mapped generic framing procedure</summary>
        LINKTYPE_GPF_F = 171,
        /// <summary>Link Access Procedures on the D Channel (LAPD) frames</summary>
        LINKTYPE_LINUX_LAPD = 177,
        /// <summary>Bluetooth HCI UART transport layer</summary>
        LINKTYPE_BLUETOOTH_HCI_H4 = 187,
        /// <summary>USB packets, beginning with a Linux USB header</summary>
        LINKTYPE_USB_LINUX = 189,
        /// <summary>Per-Packet Information information</summary>
        LINKTYPE_PPI = 192,
        /// <summary>IEEE 802.15.4 wireless Personal Area Network</summary>
        LINKTYPE_IEEE802_15_4 = 195,
        /// <summary>Various link-layer types, with a pseudo-header, for SITA</summary>
        LINKTYPE_SITA = 196,
        /// <summary>Various link-layer types, with a pseudo-header, for Endace DAG cards;
        /// encapsulates Endace ERF record</summary>
        LINKTYPE_ERF = 197,
        /// <summary>Bluetooth HCI UART transport layer</summary>
        LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201,
        /// <summary>AX.25 packet, with a 1-byte KISS header containing a type indicator</summary>
        LINKTYPE_AX25_KISS = 202,
        /// <summary>Link Access Procedures on the D Channel (LAPD) frames</summary>
        LINKTYPE_LAPD = 203,
        /// <summary>PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header
        /// with a zero value meaning "received by this host" and a non-zero value meaning
        /// "sent by this host" </summary>
        LINKTYPE_PPP_WITH_DIR = 204,
        /// <summary>Cisco PPP with HDLC framing</summary>
        LINKTYPE_C_HDLC_WITH_DIR = 205,
        /// <summary>Frame Relay</summary>
        LINKTYPE_FRELAY_WITH_DIR = 206,
        /// <summary>IPMB over an I2C circuit</summary>
        LINKTYPE_IPMB_LINUX = 209,
        /// <summary>IEEE 802.15.4 wireless Personal Area Network</summary>
        LINKTYPE_IEEE802_15_4_NONASK_PHY = 215,
        /// <summary>USB packets, beginning with a Linux USB header</summary>
        LINKTYPE_USB_LINUX_MMAPPED = 220,
        /// <summary>Fibre Channel FC-2 frames, beginning with a Frame_Header</summary>
        LINKTYPE_FC_2 = 224,
        /// <summary>Fibre Channel FC-2 frames</summary>
        LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225,
        /// <summary>Solaris ipnet pseudo-header</summary>
        LINKTYPE_IPNET = 226,
        /// <summary>CAN (Controller Area Network) frames, with a pseudo-header as supplied
        /// by Linux SocketCAN</summary>
        LINKTYPE_CAN_SOCKETCAN = 227,
        /// <summary>Raw IPv4; the packet begins with an IPv4 header</summary>
        LINKTYPE_IPV4 = 228,
        /// <summary>Raw IPv6; the packet begins with an IPv6 header</summary>
        LINKTYPE_IPV6 = 229,
        /// <summary>IEEE 802.15.4 wireless Personal Area Network, without the FCS at the
        /// end of the frame</summary>
        LINKTYPE_IEEE802_15_4_NOFCS = 230,
        /// <summary>Raw D-Bus messages, starting with the endianness flag, followed by the
        /// message type, etc., but without the authentication handshake before the message
        /// sequence</summary>
        LINKTYPE_DBUS = 231,
        /// <summary>DVB-CI (DVB Common Interface for communication between a PC Card module
        /// and a DVB receiver), with the message format specified by the PCAP format for DVB-CI
        /// specification</summary>
        LINKTYPE_DVB_CI = 235,
        /// <summary>Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the
        /// same as, 27.010)</summary>
        LINKTYPE_MUX27010 = 236,
        /// <summary>D_PDUs as described by NATO standard STANAG 5066, starting with the
        /// synchronization sequence, and including both header and data CRCs</summary>
        LINKTYPE_STANAG_5066_D_PDU = 237,
        /// <summary>Linux netlink NETLINK NFLOG socket log messages</summary>
        LINKTYPE_NFLOG = 239,
        /// <summary>Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices,
        /// followed by an Ethernet frame, beginning with the MAC header and ending with the FCS</summary>
        LINKTYPE_NETANALYZER = 240,
        /// <summary>Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices,
        /// followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending
        /// with the FCS</summary>
        LINKTYPE_NETANALYZER_TRANSPARENT = 241,
        /// <summary>IP-over-InfiniBand, as specified by RFC 4391 section 6</summary>
        LINKTYPE_IPOIB = 242,
        /// <summary>MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ITU-T
        /// Recommendation H.222.0</summary>
        LINKTYPE_MPEG_2_TS = 243,
        /// <summary>Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format
        /// as used by their ng40 protocol tester</summary>
        LINKTYPE_NG40 = 244,
        /// <summary>Pseudo-header for NFC LLCP packet captures, followed by frame data for the LLCP
        /// Protocol as specified by NFCForum-TS-LLCP_1.1</summary>
        LINKTYPE_NFC_LLCP = 245,
        /// <summary>Raw InfiniBand frames, starting with the Local Routing Header</summary>
        LINKTYPE_INFINIBAND = 247,
        /// <summary>SCTP packets, as defined by RFC 4960, with no lower-level protocols such
        /// as IPv4 or IPv6</summary>
        LINKTYPE_SCTP = 248,
        /// <summary>USB packets, beginning with a USBPcap header</summary>
        LINKTYPE_USBPCAP = 249,
        /// <summary>Serial-line packet header for the Schweitzer Engineering Laboratories
        /// "RTAC" product</summary>
        LINKTYPE_RTAC_SERIAL = 250,
        /// <summary>Bluetooth Low Energy air interface Link Layer packets</summary>
        LINKTYPE_BLUETOOTH_LE_LL = 251,
        /// <summary>Linux Netlink capture encapsulation</summary>
        LINKTYPE_NETLINK = 253,
        /// <summary>Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack</summary>
        LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254,
        /// <summary>Bluetooth Basic Rate and Enhanced Data Rate baseband packets</summary>
        LINKTYPE_BLUETOOTH_BREDR_BB = 255,
        /// <summary>Bluetooth Low Energy link-layer packets</summary>
        LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256,
        /// <summary>PROFIBUS data link layer packets, as specified by IEC standard 61158-6-3</summary>
        LINKTYPE_PROFIBUS_DL = 257,
        /// <summary>Apple PKTAP capture encapsulation</summary>
        LINKTYPE_PKTAP = 258,
        /// <summary>Ethernet-over-passive-optical-network packets</summary>
        LINKTYPE_EPON = 259,
        /// <summary>IPMI trace packets, as specified by Table 3-20 "Trace Data Block Format" in
        /// the PICMG HPM.2 specification</summary>
        LINKTYPE_IPMI_HPM_2 = 260,
        /// <summary>Per Joshua Wright, formats for Z-Wave RF profiles
        /// R1 and R2 captures</summary>
        LINKTYPE_ZWAVE_R1_R2 = 261,
        /// <summary>Per Joshua Wright, formats for Z-Wave RF profile
        /// R3 captures</summary>
        LINKTYPE_ZWAVE_R3 = 262,
        /// <summary>Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo
        /// Open protocol common packet structure captures</summary>
        LINKTYPE_WATTSTOPPER_DLM = 263,
        /// <summary>Messages between ISO 14443 contactless smartcards (Proximity Integrated
        /// Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message
        /// format specified by the PCAP format for ISO14443 specification</summary>
        LINKTYPE_ISO_14443 = 264
    };

    /// <summary>
    /// PCAP file header representation
    /// </summary>
    using pcap_hdr_t = struct pcap_hdr_s
    {
        /// <summary>magic number</summary>
        uint32_t magic_number;
        /// <summary>major version number</summary>
        uint16_t version_major;
        /// <summary>minor version number</summary>
        uint16_t version_minor;
        /// <summary>GMT to local correction</summary>
        int32_t thiszone;
        /// <summary>accuracy of timestamps</summary>
        uint32_t sigfigs;
        /// <summary>max length of captured packets, in octets</summary>
        uint32_t snaplen;
        /// <summary>data link type</summary>
        uint32_t network;
    };

    /// <summary>
    /// PCAP record header
    /// </summary>
    using pcaprec_hdr_t = struct pcaprec_hdr_s
    {
        /// <summary>timestamp seconds</summary>
        uint32_t ts_sec;
        /// <summary>timestamp microseconds</summary>
        uint32_t ts_usec;
        /// <summary>number of octets of packet saved in file</summary>
        uint32_t incl_len;
        /// <summary>actual length of packet</summary>
        uint32_t orig_len;
    };

    /// <summary>
    /// Class wrapper for the pcap_hdr_t
    /// </summary>
    class pcap_file_header
    {
    public:
        /// <summary>
        /// Constructs PCAP header object instance
        /// </summary>
        /// <param name="version_major">major version number</param>
        /// <param name="version_minor">minor version number</param>
        /// <param name="this_zone">GMT to local correction</param>
        /// <param name="sig_figs">accuracy of timestamps</param>
        /// <param name="snap_len">max length of captured packets, in octets</param>
        /// <param name="network">data link type</param>
        pcap_file_header(const uint16_t version_major, const uint16_t version_minor, const int32_t this_zone,
            const uint32_t sig_figs,
            const uint32_t snap_len, const link_layer_type network) noexcept
            : header_{ 0xa1b2c3d4, version_major, version_minor, this_zone, sig_figs, snap_len, network }
        {
        }

        /// <summary>
        /// Writes pcap_file_header into the specified stream
        /// </summary>
        /// <param name="os">std::ostream instance reference</param>
        /// <param name="obj">pcap_file_header object instance</param>
        /// <returns>std::ostream instance reference</returns>
        friend std::ostream& operator<<(std::ostream& os, const pcap_file_header& obj)
        {
            return os.write(reinterpret_cast<const char*>(&obj.header_), sizeof(pcap_hdr_t));
        }

    private:
        /// <summary>
        /// PCAP header structure
        /// </summary>
        pcap_hdr_t header_;
    };

    /// <summary>
    /// Class wrapper for the PCAP record
    /// </summary>
    class pcap_record_header
    {
    public:
        /// <summary>
        /// Constructs PCAP file record
        /// </summary>
        /// <param name="timestamp_sec">timestamp seconds</param>
        /// <param name="timestamp_usec">timestamp microseconds</param>
        /// <param name="incl_len">number of octets of packet saved in file</param>
        /// <param name="orig_len">actual length of packet</param>
        /// <param name="data">packet content pointer</param>
        pcap_record_header(const uint32_t timestamp_sec, const uint32_t timestamp_usec, const uint32_t incl_len,
            const uint32_t orig_len, const char* data) noexcept
            : header_{ timestamp_sec, timestamp_usec, incl_len, orig_len }, data_{ data }
        {
        }

        /// <summary>
        /// Writes PCAP record into the specified stream
        /// </summary>
        /// <param name="os">std::ostream instance reference</param>
        /// <param name="obj">pcap_record_header object instance</param>
        /// <returns>std::ostream instance reference</returns>
        friend std::ostream& operator<<(std::ostream& os, const pcap_record_header& obj)
        {
            return os.write(reinterpret_cast<const char*>(&obj.header_), sizeof(pcaprec_hdr_t)).write(
                obj.data_, obj.header_.incl_len);
        }

    private:
        /// <summary>
        /// PCAP record header structure
        /// </summary>
        pcaprec_hdr_t header_;
        /// <summary>
        /// PCAP network packet data pointer
        /// </summary>
        const char* data_;
    };
}
