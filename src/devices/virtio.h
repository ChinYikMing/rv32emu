/*
 * rv32emu is freely redistributable under the MIT License. See the file
 * "LICENSE" for information on usage and redistribution of this file.
 */

#pragma once

/*
 * The linux/vm_sockets.h must after sys/socket.h
 * to pevent incomplete type ‘struct sockaddr’.
 */
/* clang-format off */
#include <sys/socket.h>
#include <linux/vm_sockets.h>
/* clang-format on */

#define VIRTIO_VENDOR_ID 0x12345678
#define VIRTIO_MAGIC_NUMBER 0x74726976
#define VIRTIO_VERSION 2
#define VIRTIO_CONFIG_GENERATION 0

#define VIRTIO_STATUS_DRIVER_OK 4
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64

#define VIRTIO_INT_USED_RING 1
#define VIRTIO_INT_CONF_CHANGE 2

#define VIRTIO_DESC_F_NEXT 1
#define VIRTIO_DESC_F_WRITE 2

#define VIRTIO_BLK_DEV_ID 2
#define VIRTIO_BLK_T_IN 0
#define VIRTIO_BLK_T_OUT 1
#define VIRTIO_BLK_T_FLUSH 4
#define VIRTIO_BLK_T_GET_ID 8
#define VIRTIO_BLK_T_GET_LIFETIME 10
#define VIRTIO_BLK_T_DISCARD 11
#define VIRTIO_BLK_T_WRITE_ZEROES 13
#define VIRTIO_BLK_T_SECURE_ERASE 14

#define VIRTIO_BLK_S_OK 0
#define VIRTIO_BLK_S_IOERR 1
#define VIRTIO_BLK_S_UNSUPP 2

/* TODO: support more features */
#define VIRTIO_BLK_F_RO (1 << 5)

/* VirtIO MMIO registers */
#define VIRTIO_REG_LIST                  \
    _(MagicValue, 0x000)        /* R */  \
    _(Version, 0x004)           /* R */  \
    _(DeviceID, 0x008)          /* R */  \
    _(VendorID, 0x00c)          /* R */  \
    _(DeviceFeatures, 0x010)    /* R */  \
    _(DeviceFeaturesSel, 0x014) /* W */  \
    _(DriverFeatures, 0x020)    /* W */  \
    _(DriverFeaturesSel, 0x024) /* W */  \
    _(QueueSel, 0x030)          /* W */  \
    _(QueueNumMax, 0x034)       /* R */  \
    _(QueueNum, 0x038)          /* W */  \
    _(QueueReady, 0x044)        /* RW */ \
    _(QueueNotify, 0x050)       /* W */  \
    _(InterruptStatus, 0x60)    /* R */  \
    _(InterruptACK, 0x064)      /* W */  \
    _(Status, 0x070)            /* RW */ \
    _(QueueDescLow, 0x080)      /* W */  \
    _(QueueDescHigh, 0x084)     /* W */  \
    _(QueueDriverLow, 0x090)    /* W */  \
    _(QueueDriverHigh, 0x094)   /* W */  \
    _(QueueDeviceLow, 0x0a0)    /* W */  \
    _(QueueDeviceHigh, 0x0a4)   /* W */  \
    _(ConfigGeneration, 0x0fc)  /* R */  \
    _(Config, 0x100)            /* RW */

enum {
#define _(reg, addr) VIRTIO_##reg = addr >> 2,
    VIRTIO_REG_LIST
#undef _
};

struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

#define IRQ_VBLK_SHIFT 3
#define IRQ_VBLK_BIT (1 << IRQ_VBLK_SHIFT)

typedef struct {
    uint32_t queue_num;
    uint32_t queue_desc;
    uint32_t queue_avail;
    uint32_t queue_used;
    uint16_t last_avail;
    bool ready;
} virtio_queue_t;

typedef struct {
    /* feature negotiation */
    uint32_t device_features;
    uint32_t device_features_sel;
    uint32_t driver_features;
    uint32_t driver_features_sel;
    /* queue config */
    uint32_t queue_sel;
    virtio_queue_t queues[2];
    /* status */
    uint32_t status;
    uint32_t interrupt_status;
    /* supplied by environment */
    uint32_t *ram;
    uint32_t *disk;
    uint64_t disk_size;
    int disk_fd;
    /* implementation-specific */
    void *priv;
} virtio_blk_state_t;

uint32_t virtio_blk_read(virtio_blk_state_t *vblk, uint32_t addr);

void virtio_blk_write(virtio_blk_state_t *vblk, uint32_t addr, uint32_t value);

uint32_t *virtio_blk_init(virtio_blk_state_t *vblk,
                          char *disk_file,
                          bool readonly);

virtio_blk_state_t *vblk_new();

void vblk_delete(virtio_blk_state_t *vblk);

/*--------------------------------- VirtIO vsock ----------------------------*/

#define BUF_ALLOC 64 * 4096 /* 64 pages */

#define VIRTIO_VSOCK_DEV_ID 19

typedef struct {
    /* feature negotiation */
    uint32_t device_features;
    uint32_t device_features_sel;
    uint32_t driver_features;
    uint32_t driver_features_sel;
    /* queue config */
    uint32_t queue_sel;
    /* RX, TX, Event */
    virtio_queue_t queues[3];
    /* status */
    uint32_t status;
    uint32_t interrupt_status;
    /* supplied by environment */
    uint32_t *ram;
    uint64_t cid; /* context ID */
    int port;
    int peer_port;
    int socket;    /* listening socket */
    int client_fd; /* FIXME: use better naming */
    /* buffer management */
    uint8_t recv_buf[BUF_ALLOC]; /* preallocated recv buffer */
    uint32_t pending_bytes;
    uint32_t peer_free; /* peer available buffer */
    uint32_t tx_cnt;    /* bytes sent from host to guest/peer (monolithic increasing) */
    /* implementation-specific */
    void *priv;
} virtio_vsock_state_t;

#define IRQ_VSOCK_SHIFT 4
#define IRQ_VSOCK_BIT (1 << IRQ_VSOCK_SHIFT)

#define VIRTIO_VSOCK_F_STREAM 1
#define VIRTIO_VSOCK_F_SEQPACKET (1 << 1)
#define VIRTIO_VSOCK_F_NO_IMPLIED_STREAM (1 << 2)

#define VIRTIO_VSOCK_OP_INVALID 0
/* Connect operations */
#define VIRTIO_VSOCK_OP_REQUEST 1
#define VIRTIO_VSOCK_OP_RESPONSE 2
#define VIRTIO_VSOCK_OP_RST 3
#define VIRTIO_VSOCK_OP_SHUTDOWN 4
/* To send payload */
#define VIRTIO_VSOCK_OP_RW 5
/* Tell the peer our credit info */
#define VIRTIO_VSOCK_OP_CREDIT_UPDATE 6
/* Request the peer to send the credit info to us */
#define VIRTIO_VSOCK_OP_CREDIT_REQUEST 7

#define VIRTIO_VSOCK_TYPE_STREAM 1
#define VIRTIO_VSOCK_TYPE_SEQPACKET 2

/*
 * For VIRTIO_VSOCK_OP_SHUTDOWN operation, these hints are stored in field
 * 'flags' in virtio_vsock_hdr. These hints are permanent once sent and
 * successive packets with bits clear do not reset them.
 */
#define VIRTIO_VSOCK_SHUTDOWN_F_RECEIVE 0
#define VIRTIO_VSOCK_SHUTDOWN_F_SEND 1

void virtio_vsock_recv(virtio_vsock_state_t *vsock);

void virtio_vsock_inject(virtio_vsock_state_t *vsock,
                         int op,
                         void *pkt,
                         struct sockaddr_vm *client_sa);

uint32_t virtio_vsock_read(virtio_vsock_state_t *vsock, uint32_t addr);

void virtio_vsock_write(virtio_vsock_state_t *vsock,
                        uint32_t addr,
                        uint32_t value);

void virtio_vsock_init(virtio_vsock_state_t *vsock, uint64_t cid);

virtio_vsock_state_t *vsock_new();

void vsock_delete(virtio_vsock_state_t *vsock);
