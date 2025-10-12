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
    // rv_log_error("update status: %u", status);
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

    /* Reset used ring flag to zero (virtq_used.flags) */
    ram[queue->queue_used] &= MASK(16);

    /* Update the used ring pointer (virtq_used.idx) */
    ram[queue->queue_used] |= ((uint32_t) used) << 16;

    /* Kick the driver for the response, unless VIRTQ_AVAIL_F_NO_INTERRUPT is
     * set */
    if (!(ram[queue->queue_avail] & 1))
        vsock->interrupt_status |= VIRTIO_INT_USED_RING;
}

void virtio_vsock_inject(virtio_vsock_state_t *vsock,
                         int op,
                         void *pkt,
                         struct sockaddr_vm *client_sa)
{
    /* Some operations(e.g., VIRTIO_VSOCK_OP_RESPONSE)
     * might fail before notifying the driver via RX,
     * thus,
     */
    struct virtio_vsock_packet _pkt;
    struct virtio_vsock_packet *rx_pkt =
        pkt ? pkt : &_pkt;

    switch (op) {
    case VIRTIO_VSOCK_OP_REQUEST:
        rx_pkt->hdr.op = VIRTIO_VSOCK_OP_REQUEST;
        rx_pkt->hdr.type = VIRTIO_VSOCK_TYPE_STREAM;
        rx_pkt->hdr.src_cid = VMADDR_CID_HOST;
        rx_pkt->hdr.src_port = client_sa->svm_port;
        rx_pkt->hdr.dst_cid = vsock->cid;
        rx_pkt->hdr.dst_port = 2222;  // guest listen port, FIXME: dynamic
        rx_pkt->hdr.len = 0;
        rx_pkt->hdr.flags = 0;
        rx_pkt->hdr.buf_alloc = 1024;
        rx_pkt->hdr.fwd_cnt = 0;

        vsock->peer_port = 2222;  // guest listen port, FIXME: dynamic
        vsock->port = client_sa->svm_port;

        virtio_queue_response_handler(vsock, rx_pkt);
        break;
    case VIRTIO_VSOCK_OP_RESPONSE:
        /* Pair with TX's VIRTIO_VSOCK_OP_REQUEST
         *
         * Driver connects to the device via VIRTIO_VSOCK_OP_REQUEST on TX,
         * device response this(VIRTIO_VSOCK_OP_RESPONSE) on RX
         */
        rv_log_trace("Connection establised...");
        virtio_queue_response_handler(vsock, rx_pkt);
        break;
    case VIRTIO_VSOCK_OP_RW:
        ssize_t recv_cnt = recv(vsock->client_fd, vsock->recv_buf,
                                ARRAY_SIZE(vsock->recv_buf), MSG_DONTWAIT);

        if (recv_cnt > 0) {
            /* Push received vsock data into the RX */
            rx_pkt =
                malloc(sizeof(struct virtio_vsock_packet) + recv_cnt);
            assert(rx_pkt);

            rx_pkt->hdr.op = VIRTIO_VSOCK_OP_RW;
            rx_pkt->hdr.type = VIRTIO_VSOCK_TYPE_STREAM;
            rx_pkt->hdr.src_cid = VMADDR_CID_HOST;
            rx_pkt->hdr.src_port = vsock->port;
            rx_pkt->hdr.dst_cid = vsock->cid;
            rx_pkt->hdr.dst_port = vsock->peer_port;
            rx_pkt->hdr.len = recv_cnt;
            rx_pkt->hdr.flags = 0;
            rx_pkt->hdr.buf_alloc = 1024;
            rx_pkt->hdr.fwd_cnt = 0;
            memcpy(rx_pkt->data, vsock->recv_buf, recv_cnt);

            vsock->recv_buf[recv_cnt] = 0;
            rv_log_trace("from recv push buffer: %s", vsock->recv_buf);
            virtio_queue_response_handler(vsock, rx_pkt);

            vsock->tx_cnt += recv_cnt;
            vsock->pending_cnt = 0;

            free(rx_pkt);
        } else if (recv_cnt == 0) {
            // TODO:
            // Host disconnected
            // printf("Host disconnected\n");
            // close(vsock->socket);
            // vsock->socket = -1;
        }
        break;
    default:
        rv_log_error("Unknown vsock operation on RX");
        break;
    }
}

static void virtio_queue_notify_handler(virtio_vsock_state_t *vsock, int index)
{
    /* RX(index = 0) and Event(index = 2) data are flowed from device to driver.
     * Queue notification is only triggered by TX(index = 1) that the data
     * is flowed from driver to device. Thus, index should be = 1.
     */
    // FIXME: 0 and 2 should not be here
    // if(index != 1){
    //	rv_log_info("index: %d", index);
    //}
    // assert(index == 1);

    uint32_t *ram = vsock->ram;
    virtio_queue_t *queue = &vsock->queues[index];

    // rv_log_trace("notify here, index: %d\n", index);
    uint16_t queue_idx = queue->last_avail % queue->queue_num;
    uint16_t buffer_idx =
        ram[queue->queue_avail + 1 + queue_idx / 2] >> (16 * (queue_idx % 2));
    queue->last_avail++;

    /* Read descriptor */
    struct virtq_desc *vq_desc =
        (struct virtq_desc *) &vsock->ram[queue->queue_desc + buffer_idx * 4];

    struct virtio_vsock_packet *vsock_pkt = VSOCK_PKT(vsock, vq_desc);

    /* TODO: support seqpacket */
    if (vsock_pkt->hdr.type == VIRTIO_VSOCK_TYPE_SEQPACKET) {
        rv_log_error("Seqpacket is not supported");
        return;
    }

    ssize_t ret;
    int shutdown_how = 0;
    if (index == 1) { /* TX */
        switch (vsock_pkt->hdr.op) {
        case VIRTIO_VSOCK_OP_REQUEST:
            /* Pair with RX's VIRTIO_VSOCK_OP_RESPONSE
             *
             * Driver connects to the device via VIRTIO_VSOCK_OP_REQUEST on TX,
             * device response with VIRTIO_VSOCK_OP_RESPONSE on RX
             */

            // rv_log_trace("connecting..., dst_port: %u",
            //              vsock_pkt->hdr.dst_port);
            // rv_log_trace("connecting..., dst_cid: %u",
            //              vsock_pkt->hdr.dst_cid);
            // rv_log_trace("connecting..., src_port: %u",
            //              vsock_pkt->hdr.src_port);
            // rv_log_trace("connecting..., src_cid: %u",
            //              vsock_pkt->hdr.src_cid);
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

            /* socket might shutdown, so creating a new one for every connection
             */
            int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
            if (sock < 0) {
                rv_log_error("socket() failed: %s", strerror(errno));
                return 1;
            }
            vsock->client_fd = sock;

            struct sockaddr_vm client_sa = {0};
            socklen_t client_len = sizeof(client_sa);
            if (getsockname(vsock->client_fd, (struct sockaddr *) &client_sa,
                            &client_len) == -1) {
                rv_log_error("getsockname() failed: %s", strerror(errno));
                return 1;
            }

            if (connect(vsock->client_fd, (struct sockaddr *) &svm,
                        sizeof(svm)) < 0) {
                rv_log_error("connect() failed: %s", strerror(errno));

                /* Send VIRTIO_VSOCK_OP_RST if connecting fails  */
                resp.hdr.op = VIRTIO_VSOCK_OP_RST;
                virtio_vsock_inject(vsock, VIRTIO_VSOCK_OP_RESPONSE, &resp,
                                    &client_sa);
                return 1;
            }

            /* store the connected port for virtio_vsock_recv() */
            vsock->peer_port = vsock_pkt->hdr.src_port;
            vsock->port = vsock_pkt->hdr.dst_port;

            /* Send VIRTIO_VSOCK_OP_RESPONSE if connecting OK */
            virtio_vsock_inject(vsock, VIRTIO_VSOCK_OP_RESPONSE, &resp,
                                &client_sa);
            break;
        case VIRTIO_VSOCK_OP_RESPONSE:
            /* Pair with RX's VIRTIO_VSOCK_OP_REQUEST
             *
             * Device connects to the driver via VIRTIO_VSOCK_OP_REQUEST on RX,
             * driver response this(VIRTIO_VSOCK_OP_RESPONSE) on TX
             */
            rv_log_trace("Connection establised...");
            break;
        case VIRTIO_VSOCK_OP_RST:
            // FIXME: cannot send RST packet to socat, so socat does not show
            // error: Connection reset by peer The close() is shutdown the socat
            // gracefully, so no RST packet as well..

            // FIXME: this need to be fixed?
            /* RST(reset) packet comes after FIN(shutdown) packet,
             * thus the close() should be careful to not close newly created
             * client
             */
            rv_log_trace("Resetting...");

            close(vsock->client_fd);
            vsock->client_fd = -1;
            break;
        case VIRTIO_VSOCK_OP_SHUTDOWN:
            rv_log_trace("shutdown...");
            shutdown_how = SHUT_RD;
            if (VSOCK_PKT_HDR(vsock, vq_desc).flags &
                VIRTIO_VSOCK_SHUTDOWN_F_SEND) {
                shutdown_how |= SHUT_WR;
            }
            if (shutdown(vsock->client_fd, shutdown_how) < 0) {
                rv_log_error("shutdown() failed: %s", strerror(errno));
                return 1;
            }
            break;
        case VIRTIO_VSOCK_OP_RW:
            while (vq_desc->flags & VIRTIO_DESC_F_NEXT) {
                vq_desc = (struct virtq_desc *) &vsock
                              ->ram[queue->queue_desc + vq_desc->next * 4];

                if ((ret = send(vsock->client_fd,
                                (uintptr_t) vsock->ram +
                                    (uintptr_t) vq_desc->addr,
                                vq_desc->len, 0) < 0)) {
                    rv_log_error("send() failed: %s", strerror(errno));
                    break;
                };
                if (ret != vq_desc->len) {
                    // rv_log_trace("ret: %zu, len: %u", ret, vq_desc->len);
                }
                // FIXME: this assertion does not true
                // assert(ret == vq_desc->len);

                // uint32_t data_len = vq_desc->len;
                // rv_log_info("len: %u", vq_desc->len);
                // rv_log_info("hdr_len: %u", sizeof(struct virtio_vsock_hdr));
                // rv_log_info("data_len: %u", data_len);
                // rv_log_fatal("vq_desc has next!");
            }
            break;
        case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
            vsock->peer_free =
                VSOCK_PKT_HDR(vsock, vq_desc).buf_alloc -
                (vsock->tx_cnt - VSOCK_PKT_HDR(vsock, vq_desc).fwd_cnt);
            // rv_log_error("peer_free: %u", vsock->peer_free);
            // rv_log_error("credit update, tx_cnt: %u", vsock->tx_cnt);
            // rv_log_error("credit update, buf_alloc: %u",
            //              VSOCK_PKT_HDR(vsock, vq_desc).buf_alloc);
            // rv_log_error("credit update, fwd_cnt: %u",
            //              VSOCK_PKT_HDR(vsock, vq_desc).fwd_cnt);
            // rv_log_trace("credit_update...");
            break;
        case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
            // rv_log_trace("creadit_request...");
            break;
        default:
            rv_log_error("Unknown vsock operation on TX");
            break;
        }
    }
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
