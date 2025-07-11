/*
 * rv32emu is freely redistributable under the MIT License. See the file *
 * "LICENSE" for information on usage and redistribution of this file.
 */

#if !defined(__linux__)
#error "Do not manage to build this file unless you are on Linux platform."
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
/*
 * The linux/vm_sockets.h must after sys/socket.h
 * to pevent incomplete type ‘struct sockaddr’.
 */
/* clang-format off */
#include <sys/socket.h>
#include <linux/vm_sockets.h>
/* clang-format on */

#include "virtio.h"

#define VSOCK_FEATURES_0 0
#define VSOCK_FEATURES_1 1 /* VIRTIO_F_VERSION_1 */
#define VSOCK_QUEUE_NUM_MAX 1024
#define VSOCK_QUEUE (vsock->queues[vsock->queue_sel])

#define VSOCK_PRIV(x) ((struct virtio_vsock_config *) x->priv)

#define VSOCK_PKT(vsock, vq_desc)                             \
    ((struct virtio_vsock_packet *) ((uintptr_t) vsock->ram + \
                                     (uintptr_t) vq_desc->addr))

#define VSOCK_PKT_HDR(vsock, vq_desc) VSOCK_PKT(vsock, vq_desc)->hdr

PACKED(struct virtio_vsock_config { uint64_t guest_cid; });

PACKED(struct virtio_vsock_hdr {
    /* Addressing */
    uint64_t src_cid;
    uint64_t dst_cid;
    uint32_t src_port;
    uint32_t dst_port;
    /* Payload size excludes header */
    uint32_t len;
    /* Socket type (stream or seqpacket) */
    uint16_t type;
    /* Operation */
    uint16_t op;
    /* Flags depends on operations */
    uint32_t flags;
    /* Buffer space management of stream sockets */
    uint32_t buf_alloc;
    uint32_t fwd_cnt;
});

PACKED(struct virtio_vsock_packet {
    struct virtio_vsock_hdr hdr;
    uint8_t data[];
});

/*
 * Event indicates that communication has been interrupted.
 */
#define VIRTIO_VSOCK_EVENT_TRANSPORT_RESET 0
struct virtio_vsock_event {
    uint32_t id;
};

static struct virtio_vsock_config vsock_configs[1];
static int vsock_dev_cnt = 0;

static void virtio_vsock_set_fail(virtio_vsock_state_t *vsock)
{
    vsock->status |= VIRTIO_STATUS_DEVICE_NEEDS_RESET;
    if (vsock->status & VIRTIO_STATUS_DRIVER_OK)
        vsock->interrupt_status |= VIRTIO_INT_CONF_CHANGE;
}

static inline uint32_t vsock_preprocess(virtio_vsock_state_t *vsock UNUSED,
                                        uint32_t addr)
{
    if ((addr >= MEM_SIZE) || (addr & 0b11)) {
        virtio_vsock_set_fail(vsock);
        return 0;
    }

    return addr >> 2;
}

static void virtio_vsock_update_status(virtio_vsock_state_t *vsock,
                                       uint32_t status)
{
    //rv_log_error("update status: %u", status);
    vsock->status |= status;
    if (status)
        return;

    // rv_log_info("device reset");

    /* Reset */
    uint32_t device_features = vsock->device_features;
    uint32_t *ram = vsock->ram;
    uint64_t cid = vsock->cid;
    int port = vsock->port;
    int peer_port = vsock->peer_port;
    uint8_t recv_buf[1024];
    memcpy(recv_buf, vsock->recv_buf, ARRAY_SIZE(recv_buf));
    uint32_t peer_free = vsock->peer_free;
    uint32_t tx_cnt = vsock->tx_cnt;
    uint32_t pending_cnt = vsock->pending_cnt;
    uint64_t socket = vsock->socket;
    void *priv = vsock->priv;
    memset(vsock, 0, sizeof(*vsock));
    vsock->device_features = device_features;
    vsock->ram = ram;
    vsock->cid = cid;
    vsock->port = port;
    vsock->peer_port = peer_port;
    memcpy(vsock->recv_buf, recv_buf, ARRAY_SIZE(recv_buf));
    vsock->peer_free = peer_free;
    vsock->tx_cnt = tx_cnt;
    vsock->pending_cnt = pending_cnt;
    vsock->socket = socket;
    vsock->priv = priv;
}

static void virtio_vsock_write_handler(virtio_vsock_state_t *vsock,
                                       uint64_t sector,
                                       uint64_t desc_addr,
                                       uint32_t len)
{
    // void *dest = (void *) ((uintptr_t) vsock->disk + sector * DISK_BLK_SIZE);
    // const void *src = (void *) ((uintptr_t) vsock->ram + desc_addr);
    // memcpy(dest, src, len);
}

static void virtio_vsock_read_handler(virtio_vsock_state_t *vsock,
                                      uint64_t sector,
                                      uint64_t desc_addr,
                                      uint32_t len)
{
    // void *dest = (void *) ((uintptr_t) vsock->ram + desc_addr);
    // const void *src =
    //     (void *) ((uintptr_t) vsock->disk + sector * DISK_BLK_SIZE);
    // memcpy(dest, src, len);
}

static int virtio_vsock_desc_handler(virtio_vsock_state_t *vsock,
                                     const virtio_queue_t *queue,
                                     uint16_t desc_idx,
                                     uint32_t *plen)
{
    /* A full virtio_vsock_req is represented by 3 descriptors, where
     * the first descriptor contains:
     *   le32 type
     *   le32 reserved
     *   le64 sector
     * the second descriptor contains:
     *   u8 data[][512]
     * the third descriptor contains:
     *   u8 status
     */
    // struct virtq_desc vq_desc[3];

    ///* Collect the descriptors */
    // for (int i = 0; i < 3; i++) {
    //     /* The size of the `struct virtq_desc` is 4 words */
    //     const struct virtq_desc *desc =
    //         (struct virtq_desc *) &vsock->ram[queue->queue_desc + desc_idx *
    //         4];

    //    /* Retrieve the fields of current descriptor */
    //    vq_desc[i].addr = desc->addr;
    //    vq_desc[i].len = desc->len;
    //    vq_desc[i].flags = desc->flags;
    //    desc_idx = desc->next;
    //}

    ///* The next flag for the first and second descriptors should be set,
    // * whereas for the third descriptor is should not be set
    // */
    // if (!(vq_desc[0].flags & VIRTIO_DESC_F_NEXT) ||
    //    !(vq_desc[1].flags & VIRTIO_DESC_F_NEXT) ||
    //    (vq_desc[2].flags & VIRTIO_DESC_F_NEXT)) {
    //    /* since the descriptor list is abnormal, we don't write the status
    //     * back here */
    //    virtio_vsock_set_fail(vsock);
    //    return -1;
    //}

    ///* Process the header */
    // const struct vsock_req_header *header =
    //     (struct vsock_req_header *) ((uintptr_t) vsock->ram +
    //     vq_desc[0].addr);
    // uint32_t type = header->type;
    // uint64_t sector = header->sector;
    // uint8_t *status = (uint8_t *) ((uintptr_t) vsock->ram + vq_desc[2].addr);

    ///* Check sector index is valid */
    // if (sector > (VSOCK_PRIV(vsock)->capacity - 1)) {
    //     *status = VIRTIO_VSOCK_S_IOERR;
    //     return -1;
    // }

    ///* Process the data */
    // switch (type) {
    // case VIRTIO_VSOCK_T_IN:
    //     virtio_vsock_read_handler(vsock, sector, vq_desc[1].addr,
    //     vq_desc[1].len); break;
    // case VIRTIO_VSOCK_T_OUT:
    //     if (vsock->device_features & VIRTIO_VSOCK_F_RO) { /* readonly */
    //         rv_log_error("Fail to write on a read only block device");
    //         *status = VIRTIO_VSOCK_S_IOERR;
    //         return -1;
    //     }
    //     virtio_vsock_write_handler(vsock, sector, vq_desc[1].addr,
    //     vq_desc[1].len); break;
    // default:
    //     rv_log_error("Unsupported virtio-blk operation");
    //     *status = VIRTIO_VSOCK_S_UNSUPP;
    //     return -1;
    // }

    ///* Return the device status */
    //*status = VIRTIO_VSOCK_S_OK;
    //*plen = vq_desc[1].len;

    return 0;
}

static void virtio_queue_response_handler(virtio_vsock_state_t *vsock,
                                          struct virtio_vsock_packet *resp)
{
    /* response should be put into RX virtqueue */
    uint32_t *ram = vsock->ram;
    virtio_queue_t *queue = &vsock->queues[0]; /* RX */

    uint16_t queue_idx = queue->last_avail % queue->queue_num;
    uint16_t buffer_idx =
        ram[queue->queue_avail + 1 + queue_idx / 2] >> (16 * (queue_idx % 2));

    /* Read descriptor */
    struct virtq_desc *vq_desc =
        (struct virtq_desc *) &vsock->ram[queue->queue_desc + buffer_idx * 4];

    queue->last_avail++;

    /* Store response */
    memcpy(&vsock->ram[vq_desc->addr >> 2], resp,
           sizeof(*resp) + resp->hdr.len);

    /* Update used ring information */
    uint16_t used = ram[queue->queue_used] >> 16;
    uint32_t vq_used_addr =
        queue->queue_used + 1 + (used % queue->queue_num) * 2;
    ram[vq_used_addr] = buffer_idx;
    ram[vq_used_addr + 1] = sizeof(*resp) + resp->hdr.len;
    used++;

    //rv_log_trace("response len: %lu, buffer_idx: %u", sizeof(*resp) + resp->hdr.len, buffer_idx);

    /* Reset used ring flag to zero (virtq_used.flags) */
    ram[queue->queue_used] &= MASK(16);

    /* Update the used ring pointer (virtq_used.idx) */
    ram[queue->queue_used] |= ((uint32_t) used) << 16;

    /* Kick the driver for the response, unless VIRTQ_AVAIL_F_NO_INTERRUPT is
     * set */
    if (!(ram[queue->queue_avail] & 1))
        vsock->interrupt_status |= VIRTIO_INT_USED_RING;
}

void virtio_vsock_recv(virtio_vsock_state_t *vsock)
{
    //if (vsock->pending_cnt) {
    //    if (vsock->peer_free < vsock->pending_cnt) {
    //        //rv_log_trace("peer_free is not enough to resend, peer_free: %u, pending_cnt: %u", vsock->peer_free, vsock->pending_cnt);
    //        return;
    //    }

    //    rv_log_trace("Resend pending data");

    //    struct virtio_vsock_packet *rx_pkt =
    //        malloc(sizeof(struct virtio_vsock_packet) + vsock->pending_cnt);
    //    assert(rx_pkt);

    //    rx_pkt->hdr.op = VIRTIO_VSOCK_OP_RW;
    //    rx_pkt->hdr.type = VIRTIO_VSOCK_TYPE_STREAM;
    //    rx_pkt->hdr.src_cid = VMADDR_CID_HOST;
    //    rx_pkt->hdr.src_port = vsock->peer_port;
    //    rx_pkt->hdr.dst_cid = vsock->cid;
    //    rx_pkt->hdr.dst_port = vsock->port;
    //    rx_pkt->hdr.len = vsock->pending_cnt;
    //    rx_pkt->hdr.flags = 0;
    //    rx_pkt->hdr.buf_alloc = 1024;
    //    rx_pkt->hdr.fwd_cnt = 0;
    //    memcpy(rx_pkt->data, vsock->recv_buf, vsock->pending_cnt);

    //    virtio_queue_response_handler(vsock, rx_pkt);

    //    vsock->pending_cnt = 0;

    //    free(rx_pkt);
    //}

    ssize_t recv_cnt = recv(vsock->socket, vsock->recv_buf,
                            ARRAY_SIZE(vsock->recv_buf), MSG_DONTWAIT);

    //if (vsock->peer_free < recv_cnt) {
    //    vsock->pending_cnt = recv_cnt;
    //    return;
    //}

    if (recv_cnt > 0) {
        // rv_log_trace("Received %zd bytes from host\n", n);
        /* Push received vsock packet into the RX virtqueue */
        struct virtio_vsock_packet *rx_pkt =
            malloc(sizeof(struct virtio_vsock_packet) + recv_cnt);
        assert(rx_pkt);

        rx_pkt->hdr.op = VIRTIO_VSOCK_OP_RW;
        rx_pkt->hdr.type = VIRTIO_VSOCK_TYPE_STREAM;
        rx_pkt->hdr.src_cid = VMADDR_CID_HOST;
        rx_pkt->hdr.src_port = vsock->peer_port;
        rx_pkt->hdr.dst_cid = vsock->cid;
        rx_pkt->hdr.dst_port = vsock->port;
        rx_pkt->hdr.len = recv_cnt;
        rx_pkt->hdr.flags = 0;
        rx_pkt->hdr.buf_alloc = 1024;
        rx_pkt->hdr.fwd_cnt = 0;
        memcpy(rx_pkt->data, vsock->recv_buf, recv_cnt);

	vsock->recv_buf[recv_cnt] = 0;
        //rv_log_trace("from recv push buffer: %s", vsock->recv_buf);
        virtio_queue_response_handler(vsock, rx_pkt);

        vsock->tx_cnt += recv_cnt;
        vsock->pending_cnt = 0;

        free(rx_pkt);

        // vsock->recv_buf[recv_cnt] = 0;
        // rv_log_trace("data: %s", (char *) vsock->recv_buf);
    } else if (recv_cnt == 0) {
        // FIXME:
        // Host disconnected
        // printf("Host disconnected\n");
        // close(vsock->socket);
        // vsock->socket = -1;
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* No data to read (if non-blocking) */
            return;
        }
        //rv_log_error("recv() failed: %s", strerror(errno));
        close(vsock->socket);
        vsock->socket = -1;
    }
}

int x = 0;

static void virtio_queue_notify_handler(virtio_vsock_state_t *vsock, int index)
{
    assert(index >= 0 && index <= 2);

    uint32_t *ram = vsock->ram;
    virtio_queue_t *queue = &vsock->queues[index];

    x++;
    // rv_log_trace("notify here, index: %d\n", index);
    uint16_t queue_idx = queue->last_avail % queue->queue_num;
    uint16_t buffer_idx =
        ram[queue->queue_avail + 1 + queue_idx / 2] >> (16 * (queue_idx % 2));
    queue->last_avail++;

    /* Read descriptor */
    struct virtq_desc *vq_desc =
        (struct virtq_desc *) &vsock->ram[queue->queue_desc + buffer_idx * 4];

    //rv_log_trace("len: %u", vq_desc->len);

    // PACKED(struct virtio_vsock_hdr {
    //     /* Addressing */
    //     uint64_t src_cid;
    //     uint64_t dst_cid;
    //     uint32_t src_port;
    //     uint32_t dst_port;
    //     /* Payload size excludes header */
    //     uint32_t len;
    //     /* Socket type (stream or seqpacket) */
    //     uint16_t type;
    //     /* Operation */
    //     uint16_t op;
    //     /* Flags depends on operations */
    //     uint32_t flags;
    //     /* Buffer space management of stream sockets */
    //     uint32_t buf_alloc;
    //     uint32_t fwd_cnt;
    // });

    // PACKED(struct virtio_vsock_packet {
    //     struct virtio_vsock_hdr hdr;
    //     uint8_t data[];
    // });

    struct virtio_vsock_packet *vsock_pkt = VSOCK_PKT(vsock, vq_desc);

    /* TODO: support seqpacket */
    if (vsock_pkt->hdr.type == VIRTIO_VSOCK_TYPE_SEQPACKET) {
        rv_log_error("Seqpacket is not supported");
        return;
    }

    //rv_log_trace(
    //    "src_cid: %lu, src_port: %lu, dst_cid: %lu, dst_port: %lu, op: %u",
    //    vsock_pkt->hdr.src_cid, vsock_pkt->hdr.src_port, vsock_pkt->hdr.dst_cid,
    //    vsock_pkt->hdr.dst_port, vsock_pkt->hdr.op);

    ssize_t ret;
    int shutdown_how = 0;
    if (index == 0) { /* RX */
        //rv_log_info("----------------rx---------------");
        switch (vsock_pkt->hdr.op) {
        case VIRTIO_VSOCK_OP_REQUEST:
            //rv_log_trace("rx request\n");
            break;
        case VIRTIO_VSOCK_OP_RESPONSE:
            //rv_log_trace("rx response\n");
            break;
        case VIRTIO_VSOCK_OP_RST:
            //rv_log_trace("rx reset\n");
            break;
        case VIRTIO_VSOCK_OP_SHUTDOWN:
            //rv_log_trace("rx shutdown\n");
            break;
        case VIRTIO_VSOCK_OP_RW:
            //rv_log_trace("rx rw\n");
            break;
        case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
            //rv_log_trace("rx credit_update...");
            break;
        case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
            //rv_log_trace("rx creadit_request...");
            break;
        default:
            //rv_log_error("rx Unknown vsock operation");
            break;
        }
    } else if (index == 1) { /* TX */
        //rv_log_info("tx");
        //uint32_t data_len = vq_desc->len - sizeof(struct virtio_vsock_hdr);
        //rv_log_info("len: %u", vq_desc->len);
        //rv_log_info("hdr_len: %u", sizeof(struct virtio_vsock_hdr));
        //rv_log_info("data_len: %u", data_len);
        //for (int i = 0; i < data_len; i++) {
        //    printf("%c", vsock_pkt->data[i]);
        //}

        switch (vsock_pkt->hdr.op) {
        case VIRTIO_VSOCK_OP_REQUEST:
            rv_log_trace("connecting..., dst_port: %u",
                         vsock_pkt->hdr.dst_port);
            struct sockaddr_vm svm = {
                .svm_family = AF_VSOCK,
                .svm_port = vsock_pkt->hdr.dst_port,
                .svm_cid = vsock_pkt->hdr.dst_cid,
            };
            struct virtio_vsock_packet resp = {
                .hdr = {
                    .op = VIRTIO_VSOCK_OP_RESPONSE,
                    .type = VIRTIO_VSOCK_TYPE_STREAM,
                    .src_cid = vsock_pkt->hdr.dst_cid,
                    .src_port = vsock_pkt->hdr.dst_port,
                    .dst_cid = vsock_pkt->hdr.src_cid,
                    .dst_port = vsock_pkt->hdr.src_port,
                    .len = 0,
                    .flags = 0,
                    .buf_alloc = 64 * 1024,
                    .fwd_cnt = 0,
                }};

            /* socket might shutdown, so creating a new one is required */
            int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
            if (socket < 0) {
                //rv_log_error("socket() failed: %s", strerror(errno));
                return;
            }
            vsock->socket = sock;

            if (connect(vsock->socket, (struct sockaddr *) &svm, sizeof(svm)) <
                0) {
                //rv_log_error("connect() failed: %s", strerror(errno));

                /* Send VIRTIO_VSOCK_OP_RST if connecting fails  */
                resp.hdr.op = VIRTIO_VSOCK_OP_RST;
                virtio_queue_response_handler(vsock, &resp);
                return 1;
            }
            /* store the connected port for virtio_vsock_recv() */
            vsock->peer_port = vsock_pkt->hdr.dst_port;
            vsock->port = vsock_pkt->hdr.src_port;
            /* Send VIRTIO_VSOCK_OP_RESPONSE if connecting OK */
            virtio_queue_response_handler(vsock, &resp);
            //rv_log_trace("Connect success\n");
            break;
        case VIRTIO_VSOCK_OP_RESPONSE:
            //rv_log_trace("response...");
            break;
        case VIRTIO_VSOCK_OP_RST:
            //rv_log_trace("reseting...");
            break;
        case VIRTIO_VSOCK_OP_SHUTDOWN:
            shutdown_how = SHUT_RD;
            if (VSOCK_PKT_HDR(vsock, vq_desc).flags &
                VIRTIO_VSOCK_SHUTDOWN_F_SEND) {
                shutdown_how |= SHUT_WR;
            }
            if (shutdown(vsock->socket, shutdown_how) < 0) {
                //rv_log_error("shutdown() failed: %s", strerror(errno));
            }
            //rv_log_trace("shutdown...");
            close(vsock->socket);
            vsock->socket = -1;
            break;
        case VIRTIO_VSOCK_OP_RW:
            /* Send payload if any */
            // char buf[1024] = {0};
            // recv(vsock->socket, buf, 1024, 0);
            // rv_log_trace("recv() buf: %s", buf);
            //if (VSOCK_PKT_HDR(vsock, vq_desc).src_cid == 3) {
            //    rv_log_fatal("rw operation from guest");
            //} else {
            //    rv_log_fatal("rw operation from host");
            //}
            while (vq_desc->flags & VIRTIO_DESC_F_NEXT) {
                vq_desc = (struct virtq_desc *) &vsock
                              ->ram[queue->queue_desc + vq_desc->next * 4];

                if ((ret = send(vsock->socket,
                                (uintptr_t) vsock->ram +
                                    (uintptr_t) vq_desc->addr,
                                vq_desc->len, 0) < 0)) {
                    //rv_log_error("send() failed: %s", strerror(errno));
                    break;
                };
                if (ret != vq_desc->len) {
                    //rv_log_trace("ret: %zu, len: %u", ret, vq_desc->len);
                }
                // assert(ret == vq_desc->len);

                // uint32_t data_len = vq_desc->len;
                // rv_log_info("len: %u", vq_desc->len);
                // rv_log_info("hdr_len: %u", sizeof(struct virtio_vsock_hdr));
                // rv_log_info("data_len: %u", data_len);
                // rv_log_fatal("vq_desc has next!");
            }
            //rv_log_trace("payload sending...");
            break;
        case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
            vsock->peer_free =
                VSOCK_PKT_HDR(vsock, vq_desc).buf_alloc -
                (vsock->tx_cnt - VSOCK_PKT_HDR(vsock, vq_desc).fwd_cnt);
            //rv_log_error("peer_free: %u", vsock->peer_free);
            //rv_log_error("credit update, tx_cnt: %u", vsock->tx_cnt);
            //rv_log_error("credit update, buf_alloc: %u",
            //             VSOCK_PKT_HDR(vsock, vq_desc).buf_alloc);
            //rv_log_error("credit update, fwd_cnt: %u",
            //             VSOCK_PKT_HDR(vsock, vq_desc).fwd_cnt);
            //rv_log_trace("credit_update...");
            break;
        case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
            //rv_log_trace("creadit_request...");
            break;
        default:
            //rv_log_error("Unknown vsock operation");
            break;
        }
    } else { /* index == 2, Event */
        //rv_log_info("-------------event------------");
    }

    // const char *msg = "Hello via VSOCK!\n";
    // write(vsock->socket, msg, strlen(msg));

    ///* Check for new buffers */
    // uint16_t new_avail = ram[queue->queue_avail] >> 16;
    // if (new_avail - queue->last_avail > (uint16_t) queue->queue_num) {
    //     rv_log_error("Size check fail");
    //     return virtio_vsock_set_fail(vsock);
    // }

    // if (queue->last_avail == new_avail)
    //     return;

    ///* Process them */
    // uint16_t new_used =
    //     ram[queue->queue_used] >> 16; /* virtq_used.idx (le16) */
    // while (queue->last_avail != new_avail) {
    //     /* Obtain the index in the ring buffer */
    //     uint16_t queue_idx = queue->last_avail % queue->queue_num;

    //    /* Since each buffer index occupies 2 bytes but the memory is aligned
    //     * with 4 bytes, and the first element of the available queue is
    //     stored
    //     * at ram[queue->queue_avail + 1], to acquire the buffer index, it
    //     * requires the following array index calculation and bit shifting.
    //     * Check also the `struct virtq_avail` on the spec.
    //     */
    //    uint16_t buffer_idx = ram[queue->queue_avail + 1 + queue_idx / 2] >>
    //                          (16 * (queue_idx % 2));

    //    /* Consume request from the available queue and process the data in
    //    the
    //     * descriptor list.
    //     */
    //    uint32_t len = 0;
    //    int result = virtio_vsock_desc_handler(vsock, queue, buffer_idx,
    //    &len); if (result != 0)
    //        return virtio_vsock_set_fail(vsock);

    //    /* Write used element information (`struct virtq_used_elem`) to the
    //    used
    //     * queue */
    //    uint32_t vq_used_addr =
    //        queue->queue_used + 1 + (new_used % queue->queue_num) * 2;
    //    ram[vq_used_addr] = buffer_idx; /* virtq_used_elem.id  (le32) */
    //    ram[vq_used_addr + 1] = len;    /* virtq_used_elem.len (le32) */
    //    queue->last_avail++;
    //    new_used++;
    //}

    ///* Check le32 len field of `struct virtq_used_elem` on the spec  */
    // vsock->ram[queue->queue_used] &= MASK(16); /* Reset low 16 bits to zero
    // */ vsock->ram[queue->queue_used] |= ((uint32_t) new_used) << 16; /* len
    // */

    ///* Send interrupt, unless VIRTQ_AVAIL_F_NO_INTERRUPT is set */
    // if (!(ram[queue->queue_avail] & 1))
    //     vsock->interrupt_status |= VIRTIO_INT_USED_RING;
}

uint32_t virtio_vsock_read(virtio_vsock_state_t *vsock, uint32_t addr)
{
    addr = addr >> 2;
#define _(reg) VIRTIO_##reg
    switch (addr) {
    case _(MagicValue):
        // rv_log_trace("magic");
        return VIRTIO_MAGIC_NUMBER;
    case _(Version):
        // rv_log_trace("version");
        return VIRTIO_VERSION;
    case _(DeviceID):
        // rv_log_trace("ID");
        return VIRTIO_VSOCK_DEV_ID;
    case _(VendorID):
        // rv_log_trace("vendor");
        return VIRTIO_VENDOR_ID;
    case _(DeviceFeatures):
        // rv_log_trace("devfeature");
        return vsock->device_features_sel == 0
                   ? VSOCK_FEATURES_0 | vsock->device_features
                   : (vsock->device_features_sel == 1 ? VSOCK_FEATURES_1 : 0);
    case _(QueueNumMax):
        // rv_log_trace("QueueNumMax");
        return VSOCK_QUEUE_NUM_MAX;
    case _(QueueReady):
        // rv_log_trace("QueueReady");
        return (uint32_t) VSOCK_QUEUE.ready;
    case _(InterruptStatus):
        // rv_log_trace("InterruptStatus");
        return vsock->interrupt_status;
    case _(Status):
        // rv_log_trace("Status");
        return vsock->status;
    case _(ConfigGeneration):
        // rv_log_trace("ConfigGeneration");
        return VIRTIO_CONFIG_GENERATION;
    default:
        // rv_log_trace("read configuration");
        /* Read configuration from the corresponding register */
        return ((uint32_t *) VSOCK_PRIV(vsock))[addr - _(Config)];
    }
#undef _
}

void virtio_vsock_write(virtio_vsock_state_t *vsock,
                        uint32_t addr,
                        uint32_t value)
{
    addr = addr >> 2;
#define _(reg) VIRTIO_##reg
    switch (addr) {
    case _(DeviceFeaturesSel):
        // rv_log_trace("W DeviceFeaturesSel");
        vsock->device_features_sel = value;
        break;
    case _(DriverFeatures):
        // rv_log_trace("W DriverFeatures");
        vsock->driver_features_sel == 0 ? (vsock->driver_features = value) : 0;
        break;
    case _(DriverFeaturesSel):
        // rv_log_trace("W DriverFeaturesSel");
        vsock->driver_features_sel = value;
        break;
    case _(QueueSel):
        // rv_log_trace("W QueueSel index: %d ---------", value);
        if (value < ARRAY_SIZE(vsock->queues))
            vsock->queue_sel = value;
        else
            virtio_vsock_set_fail(vsock);
        break;
    case _(QueueNum):
        // rv_log_trace("W QueueNum");
        if (value > 0 && value <= VSOCK_QUEUE_NUM_MAX)
            VSOCK_QUEUE.queue_num = value;
        else
            virtio_vsock_set_fail(vsock);
        break;
    case _(QueueReady):
        // rv_log_trace("W QueueReady");
        VSOCK_QUEUE.ready = value & 1;
        if (value & 1)
            VSOCK_QUEUE.last_avail = vsock->ram[VSOCK_QUEUE.queue_avail] >> 16;
        break;
    case _(QueueDescLow):
        // rv_log_trace("W QueueDescLow");
        VSOCK_QUEUE.queue_desc = vsock_preprocess(vsock, value);
        break;
    case _(QueueDescHigh):
        // rv_log_trace("W QueueDescHigh, value: %u", value);
        if (value)
            virtio_vsock_set_fail(vsock);
        break;
    case _(QueueDriverLow):
        // rv_log_trace("W QueueDriverLow");
        VSOCK_QUEUE.queue_avail = vsock_preprocess(vsock, value);
        break;
    case _(QueueDriverHigh):
        // rv_log_trace("W QueueDriverHigh, value: %u", value);
        if (value)
            virtio_vsock_set_fail(vsock);
        break;
    case _(QueueDeviceLow):
        // rv_log_trace("W QueueDeviceLow");
        VSOCK_QUEUE.queue_used = vsock_preprocess(vsock, value);
        break;
    case _(QueueDeviceHigh):
        // rv_log_trace("W QueueDeviceHigh, value: %u", value);
        if (value)
            virtio_vsock_set_fail(vsock);
        break;
    case _(QueueNotify):
        // rv_log_trace("W QueueNotify, value: %u", value);
        if (value < ARRAY_SIZE(vsock->queues))
            virtio_queue_notify_handler(vsock, value);
        else
            virtio_vsock_set_fail(vsock);
        break;
    case _(InterruptACK):
        // rv_log_trace("W InterruptACK, value: %u", value);
        vsock->interrupt_status &= ~value;
        break;
    case _(Status):
        // rv_log_trace("W Status, value: %u", value);
        virtio_vsock_update_status(vsock, value);
        break;
    default:
        // rv_log_trace("W Config");
        /* Write configuration to the corresponding register */
        ((uint32_t *) VSOCK_PRIV(vsock))[addr - _(Config)] = value;
        break;
    }
#undef _
}

void virtio_vsock_init(virtio_vsock_state_t *vsock, uint64_t cid)
{
    if (cid <= 0x2 || cid >= 0xffffffff) {
        rv_log_error("Invalid cid: %lu\n", cid);
        return;
    }

    /* The upper 32 bits of the CID are reserved and zeroed */
    vsock->cid = cid;
    vsock->priv = &vsock_configs[0];
    VSOCK_PRIV(vsock)->guest_cid = cid;

    // TODO: support VIRTIO_VSOCK_F_SEQPACKET
    vsock->device_features =
        VIRTIO_VSOCK_F_STREAM | VIRTIO_VSOCK_F_NO_IMPLIED_STREAM;
}

virtio_vsock_state_t *vsock_new()
{
    virtio_vsock_state_t *vsock = calloc(1, sizeof(virtio_vsock_state_t));
    assert(vsock);
    return vsock;
}

void vsock_delete(virtio_vsock_state_t *vsock)
{
    close(vsock->socket);
    free(vsock);
}
