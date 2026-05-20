/*
 * vhost-vdpa.c
 *
 * Copyright(c) 2017-2018 Intel Corporation.
 * Copyright(c) 2020 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "clients.h"
#include "hw/virtio/virtio-net.h"
#include "net/vhost_net.h"
#include "net/vhost-vdpa.h"
#include "hw/virtio/vhost-vdpa.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/memalign.h"
#include "qemu/option.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include <linux/vhost.h>
#include <sys/ioctl.h>
#include <err.h>
#include "standard-headers/linux/virtio_net.h"
#include "monitor/monitor.h"
#include "migration/misc.h"
#include "hw/virtio/vhost.h"
#include "trace.h"
#include <linux/genetlink.h>
#include <linux/netlink.h>
#if __has_include(<linux/vdpa.h>)
#include <linux/vdpa.h>
#else
#define VDPA_GENL_NAME "vdpa"
#define VDPA_GENL_VERSION 0x1
enum {
    VDPA_CMD_DEV_VSTATS_GET = 7,
};
enum {
    VDPA_ATTR_DEV_NAME = 4,
    VDPA_ATTR_DEV_QUEUE_INDEX = 17,
    VDPA_ATTR_DEV_VENDOR_ATTR_NAME = 18,
    VDPA_ATTR_DEV_VENDOR_ATTR_VALUE = 19,
};
#endif

/* Todo:need to add the multiqueue support here */
typedef struct VhostVDPAState {
    NetClientState nc;
    struct vhost_vdpa vhost_vdpa;
    NotifierWithReturn migration_state;
    VHostNetState *vhost_net;

    /* Control commands shadow buffers */
    void *cvq_cmd_out_buffer;
    virtio_net_ctrl_ack *status;

    /* The device always have SVQ enabled */
    bool always_svq;

    /* The device can isolate CVQ in its own ASID */
    bool cvq_isolated;

    bool started;
} VhostVDPAState;

/*
 * The array is sorted alphabetically in ascending order,
 * with the exception of VHOST_INVALID_FEATURE_BIT,
 * which should always be the last entry.
 */
static const int vdpa_feature_bits[] = {
    VIRTIO_F_ANY_LAYOUT,
    VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_F_RING_PACKED,
    VIRTIO_F_RING_RESET,
    VIRTIO_F_VERSION_1,
    VIRTIO_F_IN_ORDER,
    VIRTIO_F_NOTIFICATION_DATA,
    VIRTIO_NET_F_CSUM,
    VIRTIO_NET_F_CTRL_GUEST_OFFLOADS,
    VIRTIO_NET_F_CTRL_MAC_ADDR,
    VIRTIO_NET_F_CTRL_RX,
    VIRTIO_NET_F_CTRL_RX_EXTRA,
    VIRTIO_NET_F_CTRL_VLAN,
    VIRTIO_NET_F_CTRL_VQ,
    VIRTIO_NET_F_GSO,
    VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_GUEST_USO4,
    VIRTIO_NET_F_GUEST_USO6,
    VIRTIO_NET_F_HASH_REPORT,
    VIRTIO_NET_F_HOST_ECN,
    VIRTIO_NET_F_HOST_TSO4,
    VIRTIO_NET_F_HOST_TSO6,
    VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_HOST_USO,
    VIRTIO_NET_F_MQ,
    VIRTIO_NET_F_MRG_RXBUF,
    VIRTIO_NET_F_MTU,
    VIRTIO_NET_F_RSC_EXT,
    VIRTIO_NET_F_RSS,
    VIRTIO_NET_F_STATUS,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_RING_F_INDIRECT_DESC,

    /* VHOST_INVALID_FEATURE_BIT should always be the last entry */
    VHOST_INVALID_FEATURE_BIT
};

/** Supported device specific feature bits with SVQ */
static const uint64_t vdpa_svq_device_features =
    BIT_ULL(VIRTIO_NET_F_CSUM) |
    BIT_ULL(VIRTIO_NET_F_GUEST_CSUM) |
    BIT_ULL(VIRTIO_NET_F_CTRL_GUEST_OFFLOADS) |
    BIT_ULL(VIRTIO_NET_F_MTU) |
    BIT_ULL(VIRTIO_NET_F_MAC) |
    BIT_ULL(VIRTIO_NET_F_GUEST_TSO4) |
    BIT_ULL(VIRTIO_NET_F_GUEST_TSO6) |
    BIT_ULL(VIRTIO_NET_F_GUEST_ECN) |
    BIT_ULL(VIRTIO_NET_F_GUEST_UFO) |
    BIT_ULL(VIRTIO_NET_F_HOST_TSO4) |
    BIT_ULL(VIRTIO_NET_F_HOST_TSO6) |
    BIT_ULL(VIRTIO_NET_F_HOST_ECN) |
    BIT_ULL(VIRTIO_NET_F_HOST_UFO) |
    BIT_ULL(VIRTIO_NET_F_MRG_RXBUF) |
    BIT_ULL(VIRTIO_NET_F_STATUS) |
    BIT_ULL(VIRTIO_NET_F_CTRL_VQ) |
    BIT_ULL(VIRTIO_NET_F_CTRL_RX) |
    BIT_ULL(VIRTIO_NET_F_CTRL_VLAN) |
    BIT_ULL(VIRTIO_NET_F_CTRL_RX_EXTRA) |
    BIT_ULL(VIRTIO_NET_F_MQ) |
    BIT_ULL(VIRTIO_F_ANY_LAYOUT) |
    BIT_ULL(VIRTIO_NET_F_CTRL_MAC_ADDR) |
    /* VHOST_F_LOG_ALL is exposed by SVQ */
    BIT_ULL(VHOST_F_LOG_ALL) |
    BIT_ULL(VIRTIO_NET_F_HASH_REPORT) |
    BIT_ULL(VIRTIO_NET_F_RSS) |
    BIT_ULL(VIRTIO_NET_F_RSC_EXT) |
    BIT_ULL(VIRTIO_NET_F_STANDBY) |
    BIT_ULL(VIRTIO_NET_F_SPEED_DUPLEX);

#define VHOST_VDPA_NET_CVQ_ASID 1
#define VIO_VDPA_DEFAULT_HIGH_IOPS      95000ULL
#define VIO_VDPA_DEFAULT_LOW_IOPS       85000ULL
#define VIO_VDPA_DEFAULT_WINDOW_NS      1000000000LL
#define VIO_VDPA_DEFAULT_COOLDOWN_NS    3000000000LL
#define VIO_VDPA_DEFAULT_PASSTHROUGH_MIN_NS 10000000000LL
#define VIO_VDPA_DEFAULT_WARMUP_WINDOWS 2
#define VIO_VDPA_DEFAULT_LOW_WINDOWS    3
#define VIO_VDPA_DEFAULT_STATS_STABILIZE_WINDOWS 2
#define VIO_VDPA_MAX_SAMPLE_FAILURES    3
#define VIO_VDPA_STATS_ERR_LOG_LIMIT    8

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int) NLA_ALIGN(sizeof(struct nlattr)))
#endif

static void vhost_vdpa_net_vio_timer_cb(void *opaque);
static void vhost_vdpa_net_schedule_vio_switch(VhostVDPAState *s);

static uint64_t vio_vdpa_getenv_u64(const char *name, uint64_t defval)
{
    const char *value = g_getenv(name);
    char *endptr = NULL;
    uint64_t parsed;

    if (!value || !*value) {
        return defval;
    }

    parsed = g_ascii_strtoull(value, &endptr, 10);
    if (endptr == value || *endptr != '\0') {
        error_report("VIO-VDPA: ignoring invalid %s=%s", name, value);
        return defval;
    }

    return parsed;
}

static bool vio_vdpa_getenv_bool(const char *name, bool defval)
{
    const char *value = g_getenv(name);

    if (!value || !*value) {
        return defval;
    }

    if (!g_ascii_strcasecmp(value, "1") ||
        !g_ascii_strcasecmp(value, "on") ||
        !g_ascii_strcasecmp(value, "true") ||
        !g_ascii_strcasecmp(value, "yes")) {
        return true;
    }

    if (!g_ascii_strcasecmp(value, "0") ||
        !g_ascii_strcasecmp(value, "off") ||
        !g_ascii_strcasecmp(value, "false") ||
        !g_ascii_strcasecmp(value, "no")) {
        return false;
    }

    error_report("VIO-VDPA: ignoring invalid %s=%s", name, value);
    return defval;
}

static bool vio_vdpa_threshold_env_present(void)
{
    return g_getenv("VIO_VDPA_THRESHOLD") ||
           g_getenv("VIO_HIGH_IOPS") ||
           g_getenv("VIO_LOW_IOPS") ||
           g_getenv("VIO_WINDOW_NS") ||
           g_getenv("VIO_COOLDOWN_NS") ||
           g_getenv("VIO_PASSTHROUGH_MIN_NS") ||
           g_getenv("VIO_PASSTHROUGH_WARMUP_WINDOWS") ||
           g_getenv("VIO_LOW_WINDOWS") ||
           g_getenv("VIO_STATS_STABILIZE_WINDOWS") ||
           g_getenv("VIO_BACKEND_SWITCH") ||
           g_getenv("VIO_VDPA_DEV");
}

static bool vio_vdpa_debug_enabled(void)
{
    return vio_vdpa_getenv_bool("VIO_DEBUG_STATS", false);
}

static int vio_nl_add_attr(char *buf, size_t buflen, size_t *offset,
                           int type, const void *data, size_t len)
{
    struct nlattr *attr;
    size_t attr_len = NLA_HDRLEN + len;
    size_t aligned_len = NLA_ALIGN(attr_len);

    if (*offset + aligned_len > buflen) {
        return -EMSGSIZE;
    }

    attr = (struct nlattr *)(buf + *offset);
    attr->nla_type = type;
    attr->nla_len = attr_len;
    memcpy((char *)attr + NLA_HDRLEN, data, len);
    memset(buf + *offset + attr_len, 0, aligned_len - attr_len);
    *offset += aligned_len;

    return 0;
}

static int vio_nl_add_string(char *buf, size_t buflen, size_t *offset,
                             int type, const char *str)
{
    return vio_nl_add_attr(buf, buflen, offset, type, str, strlen(str) + 1);
}

static int vio_nl_add_u32(char *buf, size_t buflen, size_t *offset,
                          int type, uint32_t value)
{
    return vio_nl_add_attr(buf, buflen, offset, type, &value, sizeof(value));
}

static bool vio_nl_attr_ok(const struct nlattr *attr, size_t remain)
{
    return remain >= sizeof(*attr) &&
           attr->nla_len >= sizeof(*attr) &&
           attr->nla_len <= remain;
}

static int vio_vdpa_netlink_open(void)
{
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) {
        return -errno;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int ret = -errno;

        close(fd);
        return ret;
    }

    return fd;
}

static int vio_vdpa_netlink_recv_ack(int fd, uint32_t seq, char *buf,
                                     size_t buflen, ssize_t *received)
{
    struct nlmsghdr *nlh;
    ssize_t len;

    len = recv(fd, buf, buflen, 0);
    if (len < 0) {
        return -errno;
    }

    for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
         nlh = NLMSG_NEXT(nlh, len)) {
        struct nlmsgerr *err;

        if (nlh->nlmsg_seq != seq) {
            continue;
        }

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            err = NLMSG_DATA(nlh);
            return err->error;
        }

        *received = (char *)nlh + nlh->nlmsg_len - buf;
        return 0;
    }

    return -ENOENT;
}

static int vio_vdpa_genl_family_id(void)
{
    static unsigned int err_logs;
    struct {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[128];
    } req = {
        .nlh.nlmsg_type = GENL_ID_CTRL,
        .nlh.nlmsg_flags = NLM_F_REQUEST,
        .nlh.nlmsg_seq = 1,
        .genlh.cmd = CTRL_CMD_GETFAMILY,
        .genlh.version = 1,
    };
    char resp[4096];
    struct nlmsghdr *nlh;
    struct genlmsghdr *genlh;
    struct nlattr *attr;
    ssize_t received = 0;
    size_t offset = 0;
    size_t remain;
    int fd, ret;

    ret = vio_nl_add_string(req.attrs, sizeof(req.attrs), &offset,
                            CTRL_ATTR_FAMILY_NAME, VDPA_GENL_NAME);
    if (ret < 0) {
        return ret;
    }
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.genlh)) + offset;

    fd = vio_vdpa_netlink_open();
    if (fd < 0) {
        if (err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stats genl open failed, ret=%d\n", fd);
        }
        return fd;
    }

    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        ret = -errno;
        if (err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stats genl family send failed, ret=%d\n",
                          ret);
        }
        goto out;
    }

    ret = vio_vdpa_netlink_recv_ack(fd, req.nlh.nlmsg_seq, resp,
                                    sizeof(resp), &received);
    if (ret < 0) {
        if (err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stats genl family recv failed, ret=%d\n",
                          ret);
        }
        goto out;
    }

    nlh = (struct nlmsghdr *)resp;
    genlh = NLMSG_DATA(nlh);
    attr = (struct nlattr *)((char *)genlh + GENL_HDRLEN);
    remain = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

    ret = -ENOENT;
    while (vio_nl_attr_ok(attr, remain)) {
        if (attr->nla_type == CTRL_ATTR_FAMILY_ID &&
            attr->nla_len >= NLA_HDRLEN + sizeof(uint16_t)) {
            uint16_t id;

            memcpy(&id, (char *)attr + NLA_HDRLEN, sizeof(id));
            ret = id;
            break;
        }
        remain -= NLA_ALIGN(attr->nla_len);
        attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
    }

out:
    if (ret < 0 && err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: stats genl family lookup failed, ret=%d\n",
                      ret);
    } else if (ret > 0 && vio_vdpa_debug_enabled()) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: stats genl family id=%d\n", ret);
    }
    close(fd);
    return ret;
}

static int vio_vdpa_query_queue_stats(const char *dev_name, int qidx,
                                      uint64_t *received_desc,
                                      uint64_t *completed_desc)
{
    static int family_id;
    static unsigned int err_logs;
    struct {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[256];
    } req = {
        .nlh.nlmsg_flags = NLM_F_REQUEST,
        .nlh.nlmsg_seq = 2,
        .genlh.cmd = VDPA_CMD_DEV_VSTATS_GET,
        .genlh.version = VDPA_GENL_VERSION,
    };
    char resp[8192];
    struct nlmsghdr *nlh;
    struct genlmsghdr *genlh;
    struct nlattr *attr;
    ssize_t received = 0;
    size_t offset = 0;
    size_t remain;
    char last_name[64] = "";
    bool found = false;
    int fd, ret;

    if (family_id <= 0) {
        family_id = vio_vdpa_genl_family_id();
        if (family_id < 0) {
            ret = family_id;
            family_id = 0;
            if (err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "VIO-VDPA: stats qidx=%d family lookup failed, "
                              "dev=%s, ret=%d\n",
                              qidx, dev_name, ret);
            }
            return ret;
        }
    }

    ret = vio_nl_add_string(req.attrs, sizeof(req.attrs), &offset,
                            VDPA_ATTR_DEV_NAME, dev_name);
    if (ret < 0) {
        return ret;
    }
    ret = vio_nl_add_u32(req.attrs, sizeof(req.attrs), &offset,
                         VDPA_ATTR_DEV_QUEUE_INDEX, qidx);
    if (ret < 0) {
        return ret;
    }

    req.nlh.nlmsg_type = family_id;
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.genlh)) + offset;

    fd = vio_vdpa_netlink_open();
    if (fd < 0) {
        if (err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stats qidx=%d open failed, dev=%s, "
                          "ret=%d\n",
                          qidx, dev_name, fd);
        }
        return fd;
    }

    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        ret = -errno;
        if (err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stats qidx=%d send failed, dev=%s, "
                          "ret=%d\n",
                          qidx, dev_name, ret);
        }
        goto out;
    }

    ret = vio_vdpa_netlink_recv_ack(fd, req.nlh.nlmsg_seq, resp,
                                    sizeof(resp), &received);
    if (ret < 0) {
        if (err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stats qidx=%d recv failed, dev=%s, "
                          "ret=%d\n",
                          qidx, dev_name, ret);
        }
        goto out;
    }

    *received_desc = 0;
    *completed_desc = 0;
    nlh = (struct nlmsghdr *)resp;
    genlh = NLMSG_DATA(nlh);
    attr = (struct nlattr *)((char *)genlh + GENL_HDRLEN);
    remain = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

    while (vio_nl_attr_ok(attr, remain)) {
        void *data = (char *)attr + NLA_HDRLEN;
        size_t data_len = attr->nla_len - NLA_HDRLEN;

        if (attr->nla_type == VDPA_ATTR_DEV_VENDOR_ATTR_NAME && data_len) {
            size_t len = MIN(data_len, sizeof(last_name) - 1);

            memcpy(last_name, data, len);
            last_name[len] = '\0';
        } else if (attr->nla_type == VDPA_ATTR_DEV_VENDOR_ATTR_VALUE &&
                   data_len >= sizeof(uint64_t)) {
            uint64_t value;

            memcpy(&value, data, sizeof(value));
            if (!strcmp(last_name, "received_desc")) {
                *received_desc = value;
                found = true;
            } else if (!strcmp(last_name, "completed_desc")) {
                *completed_desc = value;
                found = true;
            }
        }

        remain -= NLA_ALIGN(attr->nla_len);
        attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
    }

    ret = found ? 0 : -ENOENT;

out:
    if (ret == 0 && vio_vdpa_debug_enabled()) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: stats qidx=%d raw, dev=%s, "
                      "received=%" PRIu64 ", completed=%" PRIu64 "\n",
                      qidx, dev_name, *received_desc, *completed_desc);
    } else if (ret < 0 && err_logs++ < VIO_VDPA_STATS_ERR_LOG_LIMIT) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: stats qidx=%d query failed, dev=%s, ret=%d, "
                      "found=%d, last_attr=%s\n",
                      qidx, dev_name, ret, found, last_name);
    }
    close(fd);
    return ret;
}

static char *vio_vdpa_dev_name_from_path(const char *vhostdev)
{
    const char *prefix = "/dev/vhost-vdpa-";
    const char *idx;
    char *endptr = NULL;
    unsigned long parsed;

    if (!vhostdev || !g_str_has_prefix(vhostdev, prefix)) {
        return NULL;
    }

    idx = vhostdev + strlen(prefix);
    parsed = g_ascii_strtoull(idx, &endptr, 10);
    if (endptr == idx || *endptr != '\0') {
        return NULL;
    }

    return g_strdup_printf("vdpa%lu", parsed);
}

static void vio_vdpa_shared_init(VhostVDPAState *s, bool start_with_svq)
{
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    bool threshold_default = start_with_svq ||
                             vio_vdpa_threshold_env_present();

    shared->vio_threshold_enabled =
        vio_vdpa_getenv_bool("VIO_VDPA_THRESHOLD", threshold_default);
    shared->vio_svq_control_enabled = start_with_svq;
    shared->vio_backend_switch_enabled =
        start_with_svq && vio_vdpa_getenv_bool("VIO_BACKEND_SWITCH", false);
    shared->vio_switch_pending = false;
    shared->vio_mode = VIO_VDPA_MODE_SNOOP;
    shared->vio_iops_count = 0;
    shared->vio_window_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    shared->vio_last_switch_ns = 0;
    shared->vio_passthrough_enter_ns = 0;
    shared->vio_high_iops = vio_vdpa_getenv_u64("VIO_HIGH_IOPS",
                                                VIO_VDPA_DEFAULT_HIGH_IOPS);
    shared->vio_low_iops = vio_vdpa_getenv_u64("VIO_LOW_IOPS",
                                               VIO_VDPA_DEFAULT_LOW_IOPS);
    shared->vio_window_ns = vio_vdpa_getenv_u64("VIO_WINDOW_NS",
                                                VIO_VDPA_DEFAULT_WINDOW_NS);
    shared->vio_cooldown_ns = vio_vdpa_getenv_u64("VIO_COOLDOWN_NS",
                                                  VIO_VDPA_DEFAULT_COOLDOWN_NS);
    shared->vio_passthrough_min_ns =
        vio_vdpa_getenv_u64("VIO_PASSTHROUGH_MIN_NS",
                            VIO_VDPA_DEFAULT_PASSTHROUGH_MIN_NS);
    shared->vio_passthrough_warmup_windows =
        vio_vdpa_getenv_u64("VIO_PASSTHROUGH_WARMUP_WINDOWS",
                            VIO_VDPA_DEFAULT_WARMUP_WINDOWS);
    shared->vio_low_windows_required =
        vio_vdpa_getenv_u64("VIO_LOW_WINDOWS",
                            VIO_VDPA_DEFAULT_LOW_WINDOWS);
    shared->vio_stats_stabilize_windows =
        vio_vdpa_getenv_u64("VIO_STATS_STABILIZE_WINDOWS",
                            VIO_VDPA_DEFAULT_STATS_STABILIZE_WINDOWS);
    shared->vio_stats_stabilize_remaining = 0;
    shared->vio_vdpa_baseline_valid = false;
    shared->vio_passthrough_samples = 0;
    shared->vio_low_windows = 0;
    shared->vio_vdev = NULL;
    shared->vio_vdpa_dev = g_strdup(g_getenv("VIO_VDPA_DEV"));
    shared->vio_data_vqs = 0;
    shared->vio_vq_size = 0;
    shared->vio_sample_failures = 0;

    if (shared->vio_low_iops > shared->vio_high_iops) {
        error_report("VIO-VDPA: VIO_LOW_IOPS must be <= VIO_HIGH_IOPS; "
                     "using defaults");
        shared->vio_high_iops = VIO_VDPA_DEFAULT_HIGH_IOPS;
        shared->vio_low_iops = VIO_VDPA_DEFAULT_LOW_IOPS;
    }

    if (!shared->vio_window_ns) {
        shared->vio_window_ns = VIO_VDPA_DEFAULT_WINDOW_NS;
    }
    if (!shared->vio_passthrough_min_ns) {
        shared->vio_passthrough_min_ns = VIO_VDPA_DEFAULT_PASSTHROUGH_MIN_NS;
    }
    if (!shared->vio_low_windows_required) {
        shared->vio_low_windows_required = 1;
    }

    shared->vio_sample_timer = timer_new_ns(QEMU_CLOCK_REALTIME,
                                           vhost_vdpa_net_vio_timer_cb, s);
    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: threshold=%d, svq_control=%d, "
                  "backend_switch=%d, initial_mode=%s\n",
                  shared->vio_threshold_enabled,
                  shared->vio_svq_control_enabled,
                  shared->vio_backend_switch_enabled,
                  shared->vio_mode == VIO_VDPA_MODE_SNOOP ?
                  "SNOOP" : "PASSTHROUGH");
}

static struct vhost_net *vhost_vdpa_get_vhost_net(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    return s->vhost_net;
}

static size_t vhost_vdpa_net_cvq_cmd_len(void)
{
    /*
     * MAC_TABLE_SET is the ctrl command that produces the longer out buffer.
     * In buffer is always 1 byte, so it should fit here
     */
    return sizeof(struct virtio_net_ctrl_hdr) +
           2 * sizeof(struct virtio_net_ctrl_mac) +
           MAC_TABLE_ENTRIES * ETH_ALEN;
}

static size_t vhost_vdpa_net_cvq_cmd_page_len(void)
{
    return ROUND_UP(vhost_vdpa_net_cvq_cmd_len(), qemu_real_host_page_size());
}

static bool vhost_vdpa_net_valid_svq_features(uint64_t features, Error **errp)
{
    uint64_t invalid_dev_features =
        features & ~vdpa_svq_device_features &
        /* Transport are all accepted at this point */
        ~MAKE_64BIT_MASK(VIRTIO_TRANSPORT_F_START,
                         VIRTIO_TRANSPORT_F_END - VIRTIO_TRANSPORT_F_START);

    if (invalid_dev_features) {
        error_setg(errp, "vdpa svq does not work with features 0x%" PRIx64,
                   invalid_dev_features);
        return false;
    }

    return vhost_svq_valid_features(features, errp);
}

static int vhost_vdpa_net_check_device_id(struct vhost_net *net)
{
    uint32_t device_id;
    int ret;
    struct vhost_dev *hdev;

    hdev = (struct vhost_dev *)&net->dev;
    ret = hdev->vhost_ops->vhost_get_device_id(hdev, &device_id);
    if (device_id != VIRTIO_ID_NET) {
        return -ENOTSUP;
    }
    return ret;
}

static int vhost_vdpa_add(NetClientState *ncs, void *be,
                          int queue_pair_index, int nvqs)
{
    VhostNetOptions options;
    struct vhost_net *net = NULL;
    VhostVDPAState *s;
    int ret;

    options.backend_type = VHOST_BACKEND_TYPE_VDPA;
    assert(ncs->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    s = DO_UPCAST(VhostVDPAState, nc, ncs);
    options.net_backend = ncs;
    options.opaque      = be;
    options.busyloop_timeout = 0;
    options.nvqs = nvqs;
    options.feature_bits = vdpa_feature_bits;
    options.get_acked_features = NULL;
    options.save_acked_features = NULL;
    options.max_tx_queue_size = VIRTQUEUE_MAX_SIZE;
    options.is_vhost_user = false;

    net = vhost_net_init(&options);
    if (!net) {
        error_report("failed to init vhost_net for queue");
        goto err_init;
    }
    s->vhost_net = net;
    ret = vhost_vdpa_net_check_device_id(net);
    if (ret) {
        goto err_check;
    }
    return 0;
err_check:
    vhost_net_cleanup(net);
    g_free(net);
err_init:
    return -1;
}

static void vhost_vdpa_cleanup(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);

    munmap(s->cvq_cmd_out_buffer, vhost_vdpa_net_cvq_cmd_page_len());
    munmap(s->status, vhost_vdpa_net_cvq_cmd_page_len());
    if (s->vhost_net) {
        vhost_net_cleanup(s->vhost_net);
        g_free(s->vhost_net);
        s->vhost_net = NULL;
    }
    if (s->vhost_vdpa.index != 0) {
        return;
    }
    if (s->vhost_vdpa.shared->vio_sample_timer) {
        timer_free(s->vhost_vdpa.shared->vio_sample_timer);
        s->vhost_vdpa.shared->vio_sample_timer = NULL;
    }
    g_free(s->vhost_vdpa.shared->vio_vdpa_dev);
    vhost_vdpa_vio_clear_svq_maps(&s->vhost_vdpa);
    qemu_close(s->vhost_vdpa.shared->device_fd);
    g_clear_pointer(&s->vhost_vdpa.shared->iova_tree, vhost_iova_tree_delete);
    g_free(s->vhost_vdpa.shared);
}

static bool vhost_vdpa_has_vnet_hdr(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    return true;
}

static bool vhost_vdpa_get_vnet_hash_supported_types(NetClientState *nc,
                                                     uint32_t *types)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    uint64_t features = s->vhost_vdpa.dev->features;
    int fd = s->vhost_vdpa.shared->device_fd;
    struct {
        struct vhost_vdpa_config hdr;
        uint32_t supported_hash_types;
    } config;

    if (!virtio_has_feature(features, VIRTIO_NET_F_HASH_REPORT) &&
        !virtio_has_feature(features, VIRTIO_NET_F_RSS)) {
        return false;
    }

    config.hdr.off = offsetof(struct virtio_net_config, supported_hash_types);
    config.hdr.len = sizeof(config.supported_hash_types);

    assert(!ioctl(fd, VHOST_VDPA_GET_CONFIG, &config));
    *types = le32_to_cpu(config.supported_hash_types);

    return true;
}

static bool vhost_vdpa_has_ufo(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    uint64_t features = 0;
    features |= (1ULL << VIRTIO_NET_F_HOST_UFO);
    features = vhost_net_get_features(s->vhost_net, features);
    return !!(features & (1ULL << VIRTIO_NET_F_HOST_UFO));

}

/*
 * FIXME: vhost_vdpa doesn't have an API to "set h/w endianness". But it's
 * reasonable to assume that h/w is LE by default, because LE is what
 * virtio 1.0 and later ask for. So, this function just says "yes, the h/w is
 * LE". Otherwise, on a BE machine, higher-level code would mistakely think
 * the h/w is BE and can't support VDPA for a virtio 1.0 client.
 */
static int vhost_vdpa_set_vnet_le(NetClientState *nc, bool enable)
{
    return 0;
}

static bool vhost_vdpa_check_peer_type(NetClientState *nc, ObjectClass *oc,
                                       Error **errp)
{
    const char *driver = object_class_get_name(oc);

    if (!g_str_has_prefix(driver, "virtio-net-")) {
        error_setg(errp, "vhost-vdpa requires frontend driver virtio-net-*");
        return false;
    }

    return true;
}

/** Dummy receive in case qemu falls back to userland tap networking */
static ssize_t vhost_vdpa_receive(NetClientState *nc, const uint8_t *buf,
                                  size_t size)
{
    return size;
}


/** From any vdpa net client, get the netclient of the i-th queue pair */
static VhostVDPAState *vhost_vdpa_net_get_nc_vdpa(VhostVDPAState *s, int i)
{
    NICState *nic = qemu_get_nic(s->nc.peer);
    NetClientState *nc_i = qemu_get_peer(nic->ncs, i);

    return DO_UPCAST(VhostVDPAState, nc, nc_i);
}

static VhostVDPAState *vhost_vdpa_net_first_nc_vdpa(VhostVDPAState *s)
{
    return vhost_vdpa_net_get_nc_vdpa(s, 0);
}

static void vhost_vdpa_net_log_global_enable(VhostVDPAState *s, bool enable)
{
    struct vhost_vdpa *v = &s->vhost_vdpa;
    VirtIONet *n;
    VirtIODevice *vdev;
    int data_queue_pairs, cvq, r;

    /* We are only called on the first data vqs and only if x-svq is not set */
    if (s->vhost_vdpa.shadow_vqs_enabled == enable) {
        return;
    }

    vdev = v->dev->vdev;
    n = VIRTIO_NET(vdev);
    if (!n->vhost_started) {
        return;
    }

    data_queue_pairs = n->multiqueue ? n->max_queue_pairs : 1;
    cvq = virtio_vdev_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ) ?
                                  n->max_ncs - n->max_queue_pairs : 0;
    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: switch queue state, target=%s, enable_svq=%d, "
                  "multiqueue=%d, max_queue_pairs=%u, curr_queue_pairs=%u, "
                  "max_ncs=%d, data_queue_pairs=%d, cvq=%d, "
                  "shadow_vqs_enabled=%d, always_svq=%d, "
                  "vhost_started=%d\n",
                  enable ? "SNOOP" : "PASSTHROUGH", enable,
                  n->multiqueue, n->max_queue_pairs, n->curr_queue_pairs,
                  n->max_ncs, data_queue_pairs, cvq,
                  s->vhost_vdpa.shadow_vqs_enabled, s->always_svq,
                  n->vhost_started);
    v->shared->svq_switching = enable ?
        SVQ_TSTATE_ENABLING : SVQ_TSTATE_DISABLING;
    /*
     * TODO: vhost_net_stop does suspend, get_base and reset. We can be smarter
     * in the future and resume the device if read-only operations between
     * suspend and reset goes wrong.
     */
    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: force stop vhost net for dynamic switch, "
                  "skip_get_vring_base=1\n");
    vhost_net_stop_force(vdev, n->nic->ncs, data_queue_pairs, cvq);

    /* Start will check migration setup_or_active to configure or not SVQ */
    r = vhost_net_start(vdev, n->nic->ncs, data_queue_pairs, cvq);
    if (unlikely(r < 0)) {
        error_report("unable to start vhost net: %s(%d)", g_strerror(-r), -r);
    }
    v->shared->svq_switching = SVQ_TSTATE_DONE;
}

static int vhost_vdpa_net_data_vqs(VhostVDPAState *s)
{
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    VirtIODevice *vdev;
    VirtIONet *n;
    int data_queue_pairs;

    if (!shared->vio_vdev && s->vhost_vdpa.dev && s->vhost_vdpa.dev->vdev) {
        shared->vio_vdev = s->vhost_vdpa.dev->vdev;
    }

    if (!shared->vio_vdev) {
        return 0;
    }

    vdev = shared->vio_vdev;
    n = VIRTIO_NET(vdev);
    data_queue_pairs = n->multiqueue ? n->max_queue_pairs : 1;
    shared->vio_data_vqs = data_queue_pairs * 2;
    shared->vio_vq_size = virtio_queue_get_num(vdev, 0);

    return shared->vio_data_vqs;
}

static void vhost_vdpa_net_vio_reset_avail_sample(VhostVDPAState *s)
{
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    VirtIODevice *vdev;
    int data_vqs = vhost_vdpa_net_data_vqs(s);
    int i;

    vdev = shared->vio_vdev;

    if (!vdev || data_vqs <= 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: avail sample reset unavailable, "
                      "vdev=%p, data_vqs=%d, vdpa_dev=%s\n",
                      vdev, data_vqs,
                      shared->vio_vdpa_dev ? shared->vio_vdpa_dev : "(null)");
        return;
    }

    memset(shared->vio_last_avail_valid, 0,
           sizeof(shared->vio_last_avail_valid));
    shared->vio_sample_failures = 0;

    for (i = 0; i < data_vqs; i++) {
        uint16_t idx;
        int ret;

        ret = virtio_queue_read_avail_idx(vdev, i, &idx);
        if (ret == 0) {
            shared->vio_last_avail_idx[i] = idx;
            shared->vio_last_avail_valid[i] = true;
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: avail sample reset qidx=%d, idx=%u\n",
                          i, idx);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: avail sample reset qidx=%d failed, "
                          "ret=%d\n", i, ret);
        }
    }

    shared->vio_window_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static void vhost_vdpa_net_vio_begin_vdpa_sample(VhostVDPAState *s)
{
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    int data_vqs = vhost_vdpa_net_data_vqs(s);

    memset(shared->vio_last_vdpa_desc_valid, 0,
           sizeof(shared->vio_last_vdpa_desc_valid));
    memset(shared->vio_last_vdpa_sample_ns, 0,
           sizeof(shared->vio_last_vdpa_sample_ns));
    shared->vio_sample_failures = 0;
    shared->vio_vdpa_baseline_valid = false;
    shared->vio_stats_stabilize_remaining =
        shared->vio_stats_stabilize_windows;

    if (!shared->vio_vdpa_dev || data_vqs <= 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: vdpa stats begin unavailable, "
                      "dev=%s, data_vqs=%d\n",
                      shared->vio_vdpa_dev ? shared->vio_vdpa_dev : "(null)",
                      data_vqs);
        shared->vio_window_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        return;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: vdpa stats begin, dev=%s, data_vqs=%d, "
                  "decision_grace_windows=%u\n",
                  shared->vio_vdpa_dev, data_vqs,
                  shared->vio_stats_stabilize_remaining);
    shared->vio_window_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static uint64_t vhost_vdpa_net_vio_counter_delta(VhostVDPAShared *shared,
                                                 uint64_t now,
                                                 uint64_t old)
{
    if (now >= old) {
        return now - old;
    }

    if (shared->vio_vq_size > 0) {
        return (now + shared->vio_vq_size - old % shared->vio_vq_size) %
               shared->vio_vq_size;
    }

    return 0;
}

static bool vhost_vdpa_net_vio_sample_vdpa_stats(VhostVDPAState *s,
                                                 uint64_t *iops,
                                                 bool *not_ready)
{
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    int data_vqs = vhost_vdpa_net_data_vqs(s);
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t elapsed = now - shared->vio_window_start_ns;
    uint64_t iops_sum = 0;
    bool sampled = false;
    int i;

    *not_ready = false;

    if (!shared->vio_vdpa_dev || data_vqs <= 0 || elapsed <= 0) {
        return false;
    }

    if (!shared->vio_vdpa_baseline_valid) {
        bool baseline_ready = false;

        for (i = 0; i < data_vqs; i++) {
            uint64_t received_desc, completed_desc;
            int ret;

            ret = vio_vdpa_query_queue_stats(shared->vio_vdpa_dev, i,
                                             &received_desc, &completed_desc);
            if (ret != 0) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "VIO-VDPA: vdpa stats baseline qidx=%d failed, "
                              "ret=%d, decision_grace_remaining=%u\n",
                              i, ret, shared->vio_stats_stabilize_remaining);
                continue;
            }

            baseline_ready = true;
            shared->vio_last_vdpa_received[i] = received_desc;
            shared->vio_last_vdpa_completed[i] = completed_desc;
            shared->vio_last_vdpa_sample_ns[i] = now;
            shared->vio_last_vdpa_desc_valid[i] = true;

            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: vdpa stats baseline qidx=%d, "
                          "received=%" PRIu64 ", completed=%" PRIu64
                          ", decision_grace_remaining=%u\n",
                          i, received_desc, completed_desc,
                          shared->vio_stats_stabilize_remaining);
        }

        if (!baseline_ready) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: vdpa stats baseline no readable queues, "
                          "dev=%s\n", shared->vio_vdpa_dev);
            return false;
        }

        shared->vio_window_start_ns = now;
        *not_ready = true;
        shared->vio_vdpa_baseline_valid = true;
        shared->vio_sample_failures = 0;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: vdpa stats baseline established immediately, "
                      "dev=%s, data_vqs=%d, decision_grace_windows=%u\n",
                      shared->vio_vdpa_dev, data_vqs,
                      shared->vio_stats_stabilize_remaining);
        return false;
    }

    for (i = 0; i < data_vqs; i++) {
        uint64_t received_desc, completed_desc;
        uint64_t old_received, old_completed;
        uint64_t received_delta = 0, completed_delta = 0, delta = 0;
        int64_t old_sample_ns, q_elapsed;
        uint64_t q_iops = 0;
        bool counter_reset = false;
        bool old_valid;
        int ret;

        old_received = shared->vio_last_vdpa_received[i];
        old_completed = shared->vio_last_vdpa_completed[i];
        old_sample_ns = shared->vio_last_vdpa_sample_ns[i];
        old_valid = shared->vio_last_vdpa_desc_valid[i];
        ret = vio_vdpa_query_queue_stats(shared->vio_vdpa_dev, i,
                                         &received_desc, &completed_desc);
        if (ret != 0) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: vdpa stats sample qidx=%d failed, "
                          "ret=%d, old_valid=%d, old_received=%" PRIu64
                          ", old_completed=%" PRIu64
                          ", keep_previous_baseline=1\n",
                          i, ret, old_valid, old_received, old_completed);
            continue;
        }

        q_elapsed = now - old_sample_ns;
        if (old_valid && q_elapsed > 0) {
            counter_reset =
                (received_desc < old_received &&
                 old_received > shared->vio_vq_size) ||
                (completed_desc < old_completed &&
                 old_completed > shared->vio_vq_size);
            if (!counter_reset) {
                received_delta = vhost_vdpa_net_vio_counter_delta(
                    shared, received_desc, old_received);
                completed_delta = vhost_vdpa_net_vio_counter_delta(
                    shared, completed_desc, old_completed);
                delta = MAX(received_delta, completed_delta);
                q_iops = delta * 1000000000ULL / q_elapsed;
                iops_sum += q_iops;
                sampled = true;
            }
        }

        shared->vio_last_vdpa_received[i] = received_desc;
        shared->vio_last_vdpa_completed[i] = completed_desc;
        shared->vio_last_vdpa_sample_ns[i] = now;
        shared->vio_last_vdpa_desc_valid[i] = true;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: vdpa stats sample qidx=%d, "
                      "received=%" PRIu64 ", completed=%" PRIu64
                      ", old_valid=%d, old_received=%" PRIu64
                      ", old_completed=%" PRIu64
                      ", received_delta=%" PRIu64
                      ", completed_delta=%" PRIu64
                      ", delta=%" PRIu64 ", q_elapsed=%" PRId64
                      ", q_iops=%" PRIu64 ", counter_reset=%d"
                      ", vq_size=%d\n",
                      i, received_desc, completed_desc, old_valid,
                      old_received, old_completed, received_delta,
                      completed_delta, delta, q_elapsed, q_iops,
                      counter_reset, shared->vio_vq_size);
    }

    shared->vio_window_start_ns = now;

    if (!sampled) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: vdpa stats sample has no valid baseline, "
                      "dev=%s, data_vqs=%d, elapsed=%" PRId64 "\n",
                      shared->vio_vdpa_dev, data_vqs, elapsed);
        return false;
    }

    shared->vio_sample_failures = 0;
    *iops = iops_sum;
    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: vdpa stats sample, iops=%" PRIu64
                  ", elapsed=%" PRId64 "\n", *iops, elapsed);
    return true;
}

static bool vhost_vdpa_net_vio_sample_passthrough(VhostVDPAState *s,
                                                  uint64_t *iops)
{
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    VirtIODevice *vdev;
    int data_vqs = vhost_vdpa_net_data_vqs(s);
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t elapsed = now - shared->vio_window_start_ns;
    uint64_t requests = 0;
    bool sampled = false;
    int i;

    vdev = shared->vio_vdev;

    if (!vdev || data_vqs <= 0 || elapsed <= 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: avail sample unavailable before query, "
                      "vdev=%p, data_vqs=%d, elapsed=%" PRId64 "\n",
                      vdev, data_vqs, elapsed);
        return false;
    }

    for (i = 0; i < data_vqs; i++) {
        uint16_t idx;
        uint16_t old_idx = shared->vio_last_avail_idx[i];
        bool old_valid = shared->vio_last_avail_valid[i];
        int ret;

        ret = virtio_queue_read_avail_idx(vdev, i, &idx);
        if (ret != 0) {
            shared->vio_last_avail_valid[i] = false;
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: avail sample qidx=%d failed, ret=%d, "
                          "old_valid=%d, old=%u\n",
                          i, ret, old_valid, old_idx);
            continue;
        }

        if (old_valid) {
            uint16_t delta = idx - old_idx;

            requests += delta;
            sampled = true;
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: avail sample qidx=%d, idx=%u, "
                          "old=%u, delta=%u\n",
                          i, idx, old_idx, delta);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: avail sample qidx=%d, idx=%u, "
                          "old_valid=0\n", i, idx);
        }

        shared->vio_last_avail_idx[i] = idx;
        shared->vio_last_avail_valid[i] = true;
    }

    shared->vio_window_start_ns = now;

    if (!sampled) {
        return false;
    }

    shared->vio_sample_failures = 0;
    *iops = requests * 1000000000ULL / elapsed;
    return true;
}

static void vhost_vdpa_net_vio_timer_cb(void *opaque)
{
    VhostVDPAState *s = opaque;
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint64_t iops = 0;
    bool stats_not_ready = false;
    bool stats_sampled;

    if (!shared->vio_threshold_enabled) {
        return;
    }

    if (shared->vio_switch_pending) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: applying switch, target=%s, "
                      "vdpa_dev=%s, data_vqs=%d, vdev=%p\n",
                      shared->vio_mode == VIO_VDPA_MODE_SNOOP ?
                      "SNOOP" : "PASSTHROUGH",
                      shared->vio_vdpa_dev ? shared->vio_vdpa_dev : "(null)",
                      shared->vio_data_vqs, shared->vio_vdev);
        virtio_vio_set_snoop_enabled(
            shared->vio_vdev, shared->vio_mode == VIO_VDPA_MODE_SNOOP);
        if (shared->vio_backend_switch_enabled) {
            vhost_vdpa_net_log_global_enable(
                s, shared->vio_mode == VIO_VDPA_MODE_SNOOP);
        } else {
            if (shared->vio_mode == VIO_VDPA_MODE_SNOOP) {
                vhost_vdpa_vio_release_guest_memory(&s->vhost_vdpa);
            } else {
                vhost_vdpa_vio_restore_guest_memory(&s->vhost_vdpa);
            }
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: keep SVQ state unchanged, "
                          "logical_target=%s, snoop_touch=%d\n",
                          shared->vio_mode == VIO_VDPA_MODE_SNOOP ?
                          "SNOOP" : "PASSTHROUGH",
                          shared->vio_mode == VIO_VDPA_MODE_SNOOP);
        }
        shared->vio_switch_pending = false;
        if (shared->vio_mode == VIO_VDPA_MODE_PASSTHROUGH) {
            vhost_vdpa_net_vio_begin_vdpa_sample(s);
            if (!shared->vio_vdpa_dev) {
                vhost_vdpa_net_vio_reset_avail_sample(s);
            }
            timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        }
        return;
    }

    if (shared->vio_guest_mem_restore_pending) {
        vhost_vdpa_vio_restore_guest_memory(&s->vhost_vdpa);
    }

    if (shared->vio_mode != VIO_VDPA_MODE_PASSTHROUGH &&
        shared->vio_svq_control_enabled) {
        return;
    }

    if (shared->vio_svq_control_enabled &&
        !shared->vio_backend_switch_enabled &&
        shared->vio_mode == VIO_VDPA_MODE_PASSTHROUGH) {
        int64_t elapsed = now - shared->vio_window_start_ns;

        if (elapsed <= 0) {
            iops = 0;
        } else {
            iops = shared->vio_iops_count * 1000000000ULL / elapsed;
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: SVQ passthrough sample, iops=%" PRIu64
                      ", desc=%" PRIu64 ", elapsed=%" PRId64 "\n",
                      iops, shared->vio_iops_count, elapsed);
        shared->vio_iops_count = 0;
        shared->vio_window_start_ns = now;
        stats_sampled = true;
    } else {
        stats_sampled = vhost_vdpa_net_vio_sample_vdpa_stats(s, &iops,
                                                             &stats_not_ready);
    }
    if (!stats_sampled && stats_not_ready) {
        timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        return;
    }

    if (!stats_sampled && !shared->vio_svq_control_enabled) {
        shared->vio_sample_failures++;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: stats-only %s sample unavailable, "
                      "failures=%u/%u, keep current mode and skip decision\n",
                      shared->vio_mode == VIO_VDPA_MODE_SNOOP ?
                      "SNOOP" : "PASSTHROUGH",
                      shared->vio_sample_failures,
                      VIO_VDPA_MAX_SAMPLE_FAILURES);
        timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        return;
    }

    if (!stats_sampled &&
        !vhost_vdpa_net_vio_sample_passthrough(s, &iops)) {
        shared->vio_sample_failures++;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: %s sample unavailable, "
                      "failures=%u/%u, keep current mode and skip decision\n",
                      shared->vio_mode == VIO_VDPA_MODE_SNOOP ?
                      "stats-only SNOOP" : "passthrough",
                      shared->vio_sample_failures,
                      VIO_VDPA_MAX_SAMPLE_FAILURES);
        timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        return;
    }

    if (!shared->vio_svq_control_enabled &&
        shared->vio_mode == VIO_VDPA_MODE_SNOOP) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: stats-only SNOOP sample, iops=%" PRIu64
                      ", high=%" PRIu64 ", low=%" PRIu64 "\n",
                      iops, shared->vio_high_iops, shared->vio_low_iops);
        if (iops >= shared->vio_high_iops &&
            now - shared->vio_last_switch_ns >= shared->vio_cooldown_ns) {
            shared->vio_mode = VIO_VDPA_MODE_PASSTHROUGH;
            shared->vio_last_switch_ns = now;
            shared->vio_passthrough_enter_ns = now;
            shared->vio_iops_count = 0;
            shared->vio_sample_failures = 0;
            shared->vio_passthrough_samples = 0;
            shared->vio_low_windows = 0;
            shared->vio_stats_stabilize_remaining = 0;
            vhost_vdpa_net_vio_begin_vdpa_sample(s);
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: logical switch SNOOP -> PASSTHROUGH, "
                          "iops=%" PRIu64
                          ", svq_control=0, backend_path_unchanged=1\n",
                          iops);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stay stats-only SNOOP, iops=%" PRIu64
                          ", high=%" PRIu64 "\n",
                          iops, shared->vio_high_iops);
        }
        timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        return;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: passthrough sample result, iops=%" PRIu64
                  ", low=%" PRIu64 ", elapsed_since_switch=%" PRId64 "\n",
                  iops, shared->vio_low_iops,
                  now - shared->vio_last_switch_ns);

    shared->vio_passthrough_samples++;

    if (shared->vio_stats_stabilize_remaining > 0) {
        shared->vio_stats_stabilize_remaining--;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: keep PASSTHROUGH for stats decision grace, "
                      "remaining=%u, samples=%u, iops=%" PRIu64 "\n",
                      shared->vio_stats_stabilize_remaining,
                      shared->vio_passthrough_samples, iops);
        timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        return;
    }

    if (shared->vio_passthrough_samples <=
        shared->vio_passthrough_warmup_windows ||
        now - shared->vio_passthrough_enter_ns <
        shared->vio_passthrough_min_ns) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: keep PASSTHROUGH for warmup/residency, "
                      "samples=%u/%u, low_windows=%u/%u, residency=%" PRId64
                      "/%" PRId64 "\n",
                      shared->vio_passthrough_samples,
                      shared->vio_passthrough_warmup_windows,
                      shared->vio_low_windows,
                      shared->vio_low_windows_required,
                      now - shared->vio_passthrough_enter_ns,
                      shared->vio_passthrough_min_ns);
        timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        return;
    }

    if (iops <= shared->vio_low_iops) {
        shared->vio_low_windows++;
    } else {
        shared->vio_low_windows = 0;
    }

    if (iops <= shared->vio_low_iops &&
        shared->vio_low_windows >= shared->vio_low_windows_required &&
        now - shared->vio_last_switch_ns >= shared->vio_cooldown_ns) {
        shared->vio_mode = VIO_VDPA_MODE_SNOOP;
        shared->vio_last_switch_ns = now;
        shared->vio_iops_count = 0;
        shared->vio_window_start_ns = now;
        shared->vio_sample_failures = 0;
        shared->vio_passthrough_samples = 0;
        shared->vio_low_windows = 0;
        shared->vio_vdpa_baseline_valid = false;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: switch PASSTHROUGH -> SNOOP, "
                      "iops=%" PRIu64 ", low_windows=%u/%u\n",
                      iops, shared->vio_low_windows_required,
                      shared->vio_low_windows_required);
        if (shared->vio_backend_switch_enabled) {
            vhost_vdpa_net_schedule_vio_switch(s);
        } else {
            vhost_vdpa_vio_release_guest_memory(&s->vhost_vdpa);
            virtio_vio_set_snoop_enabled(shared->vio_vdev, true);
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: logical switch PASSTHROUGH -> SNOOP, "
                          "backend_path_unchanged=1, svq_kept_enabled=1, "
                          "snoop_touch=1\n");
            timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        }
        return;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: stay PASSTHROUGH, iops=%" PRIu64
                  ", low=%" PRIu64 ", low_windows=%u/%u\n",
                  iops, shared->vio_low_iops, shared->vio_low_windows,
                  shared->vio_low_windows_required);
    timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
}

static void vhost_vdpa_net_schedule_vio_switch(VhostVDPAState *s)
{
    VhostVDPAShared *shared = s->vhost_vdpa.shared;

    if (shared->vio_switch_pending) {
        return;
    }

    shared->vio_switch_pending = true;
    timer_mod(shared->vio_sample_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME));
}

static void vhost_vdpa_net_data_svq_account(VhostShadowVirtqueue *svq,
                                            void *opaque)
{
    VhostVDPAState *s = opaque;
    VhostVDPAState *s0 = vhost_vdpa_net_first_nc_vdpa(s);
    VhostVDPAShared *shared = s0->vhost_vdpa.shared;
    int64_t now, elapsed;
    uint64_t iops;

    (void)svq;

    if (!shared->vio_threshold_enabled || !shared->vio_svq_control_enabled) {
        return;
    }

    if (!shared->vio_backend_switch_enabled &&
        shared->vio_mode == VIO_VDPA_MODE_SNOOP &&
        !shared->vio_guest_mem_released) {
        vhost_vdpa_vio_release_guest_memory(&s0->vhost_vdpa);
    }

    now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    elapsed = now - shared->vio_window_start_ns;
    shared->vio_iops_count++;

    if (elapsed < shared->vio_window_ns) {
        return;
    }

    if (shared->vio_mode == VIO_VDPA_MODE_PASSTHROUGH) {
        return;
    }

    iops = shared->vio_iops_count * 1000000000ULL / elapsed;

    if (iops >= shared->vio_high_iops &&
        now - shared->vio_last_switch_ns >= shared->vio_cooldown_ns) {
        shared->vio_mode = VIO_VDPA_MODE_PASSTHROUGH;
        shared->vio_last_switch_ns = now;
        shared->vio_passthrough_enter_ns = now;
        shared->vio_iops_count = 0;
        shared->vio_window_start_ns = now;
        shared->vio_sample_failures = 0;
        shared->vio_passthrough_samples = 0;
        shared->vio_low_windows = 0;
        shared->vio_vdpa_baseline_valid = false;
        shared->vio_stats_stabilize_remaining =
            shared->vio_stats_stabilize_windows;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "VIO-VDPA: switch SNOOP -> PASSTHROUGH, "
                      "iops=%" PRIu64 ", svq_kept_enabled=%d\n",
                      iops, !shared->vio_backend_switch_enabled);
        if (shared->vio_backend_switch_enabled) {
            vhost_vdpa_net_schedule_vio_switch(s0);
        } else {
            vhost_vdpa_vio_restore_guest_memory(&s0->vhost_vdpa);
            virtio_vio_set_snoop_enabled(shared->vio_vdev, false);
            vhost_vdpa_net_vio_begin_vdpa_sample(s0);
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: logical switch SNOOP -> PASSTHROUGH, "
                          "backend_path_unchanged=1, svq_kept_enabled=1, "
                          "snoop_touch=0\n");
            timer_mod(shared->vio_sample_timer, now + shared->vio_window_ns);
        }
        return;
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "VIO-VDPA: stay %s, iops=%" PRIu64
                  ", low=%" PRIu64 ", high=%" PRIu64 "\n",
                  shared->vio_mode == VIO_VDPA_MODE_SNOOP ?
                  "SNOOP" : "PASSTHROUGH",
                  iops, shared->vio_low_iops, shared->vio_high_iops);
    shared->vio_iops_count = 0;
    shared->vio_window_start_ns = now;
}

static int vhost_vdpa_net_data_svq_handle(VhostShadowVirtqueue *svq,
                                          VirtQueueElement *elem,
                                          void *opaque)
{
    VhostVDPAState *s = opaque;
    VhostVDPAShared *shared = s->vhost_vdpa.shared;
    int r;

    if (shared->vio_guest_mem_released) {
        r = vhost_vdpa_vio_svq_map_elem(&s->vhost_vdpa, elem);
        if (unlikely(r < 0)) {
            return r;
        }
    }

    r = vhost_svq_add(svq, elem->out_sg, elem->out_num, elem->out_addr,
                      elem->in_sg, elem->in_num, elem->in_addr, elem);
    if (unlikely(r != 0) && shared->vio_guest_mem_released) {
        vhost_vdpa_vio_svq_unmap_elem(&s->vhost_vdpa, elem);
    }

    return r;
}

static void vhost_vdpa_net_data_svq_used(VhostShadowVirtqueue *svq,
                                         VirtQueueElement *elem,
                                         void *opaque)
{
    VhostVDPAState *s = opaque;

    (void)svq;

    vhost_vdpa_vio_svq_unmap_elem(&s->vhost_vdpa, elem);
}

static const VhostShadowVirtqueueOps vhost_vdpa_net_data_svq_ops = {
    .avail_account = vhost_vdpa_net_data_svq_account,
    .avail_handler = vhost_vdpa_net_data_svq_handle,
    .used_handler = vhost_vdpa_net_data_svq_used,
};

static int vdpa_net_migration_state_notifier(NotifierWithReturn *notifier,
                                             MigrationEvent *e, Error **errp)
{
    VhostVDPAState *s = container_of(notifier, VhostVDPAState, migration_state);

    if (e->type == MIG_EVENT_PRECOPY_SETUP) {
        vhost_vdpa_net_log_global_enable(s, true);
    } else if (e->type == MIG_EVENT_PRECOPY_FAILED) {
        vhost_vdpa_net_log_global_enable(s, false);
    }
    return 0;
}

static void vhost_vdpa_net_data_start_first(VhostVDPAState *s)
{
    migration_add_notifier(&s->migration_state,
                           vdpa_net_migration_state_notifier);
}

static int vhost_vdpa_net_data_start(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    struct vhost_vdpa *v = &s->vhost_vdpa;

    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    if (v->shared->vio_threshold_enabled &&
        v->shared->vio_svq_control_enabled &&
        v->shared->vio_backend_switch_enabled) {
        v->shadow_vqs_enabled =
            migration_is_running() || v->shared->vio_mode == VIO_VDPA_MODE_SNOOP;
    } else if (s->always_svq || migration_is_running()) {
        v->shadow_vqs_enabled = true;
    } else {
        v->shadow_vqs_enabled = false;
    }

    if (v->index == 0) {
        v->shared->vio_vdev = v->dev ? v->dev->vdev : NULL;
        v->shared->vio_data_vqs = vhost_vdpa_net_data_vqs(s);
        v->shared->shadow_data = v->shadow_vqs_enabled;
        virtio_vio_set_snoop_enabled(
            v->shared->vio_vdev,
            v->shared->vio_threshold_enabled ?
            v->shared->vio_mode == VIO_VDPA_MODE_SNOOP :
            s->always_svq);
        if (v->shared->vio_threshold_enabled &&
            (!v->shared->vio_svq_control_enabled ||
             v->shared->vio_mode == VIO_VDPA_MODE_PASSTHROUGH) &&
            !v->shared->vio_switch_pending) {
            vhost_vdpa_net_vio_begin_vdpa_sample(s);
            if (!v->shared->vio_vdpa_dev) {
                vhost_vdpa_net_vio_reset_avail_sample(s);
            }
            timer_mod(v->shared->vio_sample_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_REALTIME) +
                      v->shared->vio_window_ns);
        }
        vhost_vdpa_net_data_start_first(s);
        return 0;
    }

    return 0;
}

static int vhost_vdpa_net_data_load(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    struct vhost_vdpa *v = &s->vhost_vdpa;
    bool has_cvq = v->dev->vq_index_end % 2;

    if (has_cvq) {
        return 0;
    }

    for (int i = 0; i < v->dev->nvqs; ++i) {
        int ret = vhost_vdpa_set_vring_ready(v, i + v->dev->vq_index);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

static void vhost_vdpa_net_client_stop(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);

    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    if (s->vhost_vdpa.index == 0) {
        migration_remove_notifier(&s->migration_state);
    }
}

static NetClientInfo net_vhost_vdpa_info = {
        .type = NET_CLIENT_DRIVER_VHOST_VDPA,
        .size = sizeof(VhostVDPAState),
        .receive = vhost_vdpa_receive,
        .start = vhost_vdpa_net_data_start,
        .load = vhost_vdpa_net_data_load,
        .stop = vhost_vdpa_net_client_stop,
        .cleanup = vhost_vdpa_cleanup,
        .has_vnet_hdr = vhost_vdpa_has_vnet_hdr,
        .get_vnet_hash_supported_types = vhost_vdpa_get_vnet_hash_supported_types,
        .has_ufo = vhost_vdpa_has_ufo,
        .set_vnet_le = vhost_vdpa_set_vnet_le,
        .check_peer_type = vhost_vdpa_check_peer_type,
        .get_vhost_net = vhost_vdpa_get_vhost_net,
};

static int64_t vhost_vdpa_get_vring_group(int device_fd, unsigned vq_index,
                                          Error **errp)
{
    struct vhost_vring_state state = {
        .index = vq_index,
    };
    int r = ioctl(device_fd, VHOST_VDPA_GET_VRING_GROUP, &state);

    if (unlikely(r < 0)) {
        r = -errno;
        error_setg_errno(errp, errno, "Cannot get VQ %u group", vq_index);
        return r;
    }

    return state.num;
}

static int vhost_vdpa_set_address_space_id(struct vhost_vdpa *v,
                                           unsigned vq_group,
                                           unsigned asid_num)
{
    struct vhost_vring_state asid = {
        .index = vq_group,
        .num = asid_num,
    };
    int r;

    trace_vhost_vdpa_set_address_space_id(v, vq_group, asid_num);

    r = ioctl(v->shared->device_fd, VHOST_VDPA_SET_GROUP_ASID, &asid);
    if (unlikely(r < 0)) {
        error_report("Can't set vq group %u asid %u, errno=%d (%s)",
                     asid.index, asid.num, errno, g_strerror(errno));
    }
    return r;
}

static void vhost_vdpa_cvq_unmap_buf(struct vhost_vdpa *v, void *addr)
{
    VhostIOVATree *tree = v->shared->iova_tree;
    DMAMap needle = {
        /*
         * No need to specify size or to look for more translations since
         * this contiguous chunk was allocated by us.
         */
        .translated_addr = (hwaddr)(uintptr_t)addr,
    };
    const DMAMap *map = vhost_iova_tree_find_iova(tree, &needle);
    int r;

    if (unlikely(!map)) {
        error_report("Cannot locate expected map");
        return;
    }

    r = vhost_vdpa_dma_unmap(v->shared, v->address_space_id, map->iova,
                             map->size + 1);
    if (unlikely(r != 0)) {
        error_report("Device cannot unmap: %s(%d)", g_strerror(r), r);
    }

    vhost_iova_tree_remove(tree, *map);
}

/** Map CVQ buffer. */
static int vhost_vdpa_cvq_map_buf(struct vhost_vdpa *v, void *buf, size_t size,
                                  bool write)
{
    DMAMap map = {};
    hwaddr taddr = (hwaddr)(uintptr_t)buf;
    int r;

    map.size = size - 1;
    map.perm = write ? IOMMU_RW : IOMMU_RO,
    r = vhost_iova_tree_map_alloc(v->shared->iova_tree, &map, taddr);
    if (unlikely(r != IOVA_OK)) {
        error_report("Cannot map injected element");

        if (map.translated_addr == taddr) {
            error_report("Insertion to IOVA->HVA tree failed");
            /* Remove the mapping from the IOVA-only tree */
            goto dma_map_err;
        }
        return r;
    }

    r = vhost_vdpa_dma_map(v->shared, v->address_space_id, map.iova,
                           vhost_vdpa_net_cvq_cmd_page_len(), buf, !write);
    if (unlikely(r < 0)) {
        goto dma_map_err;
    }

    return 0;

dma_map_err:
    vhost_iova_tree_remove(v->shared->iova_tree, map);
    return r;
}

static int vhost_vdpa_net_cvq_start(NetClientState *nc)
{
    VhostVDPAState *s, *s0;
    struct vhost_vdpa *v;
    int64_t cvq_group;
    int r;
    Error *err = NULL;

    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    s = DO_UPCAST(VhostVDPAState, nc, nc);
    v = &s->vhost_vdpa;

    s0 = vhost_vdpa_net_first_nc_vdpa(s);
    v->shadow_vqs_enabled = s0->vhost_vdpa.shadow_vqs_enabled;
    s->vhost_vdpa.address_space_id = VHOST_VDPA_GUEST_PA_ASID;

    if (v->shared->shadow_data) {
        /* SVQ is already configured for all virtqueues */
        goto out;
    }

    /*
     * If we early return in these cases SVQ will not be enabled. The migration
     * will be blocked as long as vhost-vdpa backends will not offer _F_LOG.
     */
    if (!vhost_vdpa_net_valid_svq_features(v->dev->features, NULL)) {
        return 0;
    }

    if (!s->cvq_isolated) {
        return 0;
    }

    cvq_group = vhost_vdpa_get_vring_group(v->shared->device_fd,
                                           v->dev->vq_index_end - 1,
                                           &err);
    if (unlikely(cvq_group < 0)) {
        error_report_err(err);
        return cvq_group;
    }

    r = vhost_vdpa_set_address_space_id(v, cvq_group, VHOST_VDPA_NET_CVQ_ASID);
    if (unlikely(r < 0)) {
        return r;
    }

    v->shadow_vqs_enabled = true;
    s->vhost_vdpa.address_space_id = VHOST_VDPA_NET_CVQ_ASID;

out:
    if (!s->vhost_vdpa.shadow_vqs_enabled) {
        return 0;
    }

    r = vhost_vdpa_cvq_map_buf(&s->vhost_vdpa, s->cvq_cmd_out_buffer,
                               vhost_vdpa_net_cvq_cmd_page_len(), false);
    if (unlikely(r < 0)) {
        return r;
    }

    r = vhost_vdpa_cvq_map_buf(&s->vhost_vdpa, s->status,
                               vhost_vdpa_net_cvq_cmd_page_len(), true);
    if (unlikely(r < 0)) {
        vhost_vdpa_cvq_unmap_buf(&s->vhost_vdpa, s->cvq_cmd_out_buffer);
    }

    return r;
}

static void vhost_vdpa_net_cvq_stop(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);

    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    if (s->vhost_vdpa.shadow_vqs_enabled) {
        vhost_vdpa_cvq_unmap_buf(&s->vhost_vdpa, s->cvq_cmd_out_buffer);
        vhost_vdpa_cvq_unmap_buf(&s->vhost_vdpa, s->status);
    }

    vhost_vdpa_net_client_stop(nc);
}

static ssize_t vhost_vdpa_net_cvq_add(VhostVDPAState *s,
                                    const struct iovec *out_sg, size_t out_num,
                                    const struct iovec *in_sg, size_t in_num)
{
    VhostShadowVirtqueue *svq = g_ptr_array_index(s->vhost_vdpa.shadow_vqs, 0);
    int r;

    r = vhost_svq_add(svq, out_sg, out_num, NULL, in_sg, in_num, NULL, NULL);
    if (unlikely(r != 0)) {
        if (unlikely(r == -ENOSPC)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: No space on device queue\n",
                          __func__);
        }
    }

    return r;
}

/*
 * Convenience wrapper to poll SVQ for multiple control commands.
 *
 * Caller should hold the BQL when invoking this function, and should take
 * the answer before SVQ pulls by itself when BQL is released.
 */
static ssize_t vhost_vdpa_net_svq_poll(VhostVDPAState *s, size_t cmds_in_flight)
{
    VhostShadowVirtqueue *svq = g_ptr_array_index(s->vhost_vdpa.shadow_vqs, 0);
    return vhost_svq_poll(svq, cmds_in_flight);
}

static void vhost_vdpa_net_load_cursor_reset(VhostVDPAState *s,
                                             struct iovec *out_cursor,
                                             struct iovec *in_cursor)
{
    /* reset the cursor of the output buffer for the device */
    out_cursor->iov_base = s->cvq_cmd_out_buffer;
    out_cursor->iov_len = vhost_vdpa_net_cvq_cmd_page_len();

    /* reset the cursor of the in buffer for the device */
    in_cursor->iov_base = s->status;
    in_cursor->iov_len = vhost_vdpa_net_cvq_cmd_page_len();
}

/*
 * Poll SVQ for multiple pending control commands and check the device's ack.
 *
 * Caller should hold the BQL when invoking this function.
 *
 * @s: The VhostVDPAState
 * @len: The length of the pending status shadow buffer
 */
static ssize_t vhost_vdpa_net_svq_flush(VhostVDPAState *s, size_t len)
{
    /* device uses a one-byte length ack for each control command */
    ssize_t dev_written = vhost_vdpa_net_svq_poll(s, len);
    if (unlikely(dev_written != len)) {
        return -EIO;
    }

    /* check the device's ack */
    for (int i = 0; i < len; ++i) {
        if (s->status[i] != VIRTIO_NET_OK) {
            return -EIO;
        }
    }
    return 0;
}

static ssize_t vhost_vdpa_net_load_cmd(VhostVDPAState *s,
                                       struct iovec *out_cursor,
                                       struct iovec *in_cursor, uint8_t class,
                                       uint8_t cmd, const struct iovec *data_sg,
                                       size_t data_num)
{
    const struct virtio_net_ctrl_hdr ctrl = {
        .class = class,
        .cmd = cmd,
    };
    size_t data_size = iov_size(data_sg, data_num), cmd_size;
    struct iovec out, in;
    ssize_t r;
    unsigned dummy_cursor_iov_cnt;
    VhostShadowVirtqueue *svq = g_ptr_array_index(s->vhost_vdpa.shadow_vqs, 0);

    assert(data_size < vhost_vdpa_net_cvq_cmd_page_len() - sizeof(ctrl));
    cmd_size = sizeof(ctrl) + data_size;
    trace_vhost_vdpa_net_load_cmd(s, class, cmd, data_num, data_size);
    if (vhost_svq_available_slots(svq) < 2 ||
        iov_size(out_cursor, 1) < cmd_size) {
        /*
         * It is time to flush all pending control commands if SVQ is full
         * or control commands shadow buffers are full.
         *
         * We can poll here since we've had BQL from the time
         * we sent the descriptor.
         */
        r = vhost_vdpa_net_svq_flush(s, in_cursor->iov_base -
                                     (void *)s->status);
        if (unlikely(r < 0)) {
            return r;
        }

        vhost_vdpa_net_load_cursor_reset(s, out_cursor, in_cursor);
    }

    /* pack the CVQ command header */
    iov_from_buf(out_cursor, 1, 0, &ctrl, sizeof(ctrl));
    /* pack the CVQ command command-specific-data */
    iov_to_buf(data_sg, data_num, 0,
               out_cursor->iov_base + sizeof(ctrl), data_size);

    /* extract the required buffer from the cursor for output */
    iov_copy(&out, 1, out_cursor, 1, 0, cmd_size);
    /* extract the required buffer from the cursor for input */
    iov_copy(&in, 1, in_cursor, 1, 0, sizeof(*s->status));

    r = vhost_vdpa_net_cvq_add(s, &out, 1, &in, 1);
    if (unlikely(r < 0)) {
        trace_vhost_vdpa_net_load_cmd_retval(s, class, cmd, r);
        return r;
    }

    /* iterate the cursors */
    dummy_cursor_iov_cnt = 1;
    iov_discard_front(&out_cursor, &dummy_cursor_iov_cnt, cmd_size);
    dummy_cursor_iov_cnt = 1;
    iov_discard_front(&in_cursor, &dummy_cursor_iov_cnt, sizeof(*s->status));

    return 0;
}

static int vhost_vdpa_net_load_mac(VhostVDPAState *s, const VirtIONet *n,
                                   struct iovec *out_cursor,
                                   struct iovec *in_cursor)
{
    if (virtio_vdev_has_feature(&n->parent_obj, VIRTIO_NET_F_CTRL_MAC_ADDR)) {
        const struct iovec data = {
            .iov_base = (void *)n->mac,
            .iov_len = sizeof(n->mac),
        };
        ssize_t r = vhost_vdpa_net_load_cmd(s, out_cursor, in_cursor,
                                            VIRTIO_NET_CTRL_MAC,
                                            VIRTIO_NET_CTRL_MAC_ADDR_SET,
                                            &data, 1);
        if (unlikely(r < 0)) {
            return r;
        }
    }

    /*
     * According to VirtIO standard, "The device MUST have an
     * empty MAC filtering table on reset.".
     *
     * Therefore, there is no need to send this CVQ command if the
     * driver also sets an empty MAC filter table, which aligns with
     * the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (!virtio_vdev_has_feature(&n->parent_obj, VIRTIO_NET_F_CTRL_RX) ||
        n->mac_table.in_use == 0) {
        return 0;
    }

    uint32_t uni_entries = n->mac_table.first_multi,
             uni_macs_size = uni_entries * ETH_ALEN,
             mul_entries = n->mac_table.in_use - uni_entries,
             mul_macs_size = mul_entries * ETH_ALEN;
    struct virtio_net_ctrl_mac uni = {
        .entries = cpu_to_le32(uni_entries),
    };
    struct virtio_net_ctrl_mac mul = {
        .entries = cpu_to_le32(mul_entries),
    };
    const struct iovec data[] = {
        {
            .iov_base = &uni,
            .iov_len = sizeof(uni),
        }, {
            .iov_base = n->mac_table.macs,
            .iov_len = uni_macs_size,
        }, {
            .iov_base = &mul,
            .iov_len = sizeof(mul),
        }, {
            .iov_base = &n->mac_table.macs[uni_macs_size],
            .iov_len = mul_macs_size,
        },
    };
    ssize_t r = vhost_vdpa_net_load_cmd(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_MAC,
                                        VIRTIO_NET_CTRL_MAC_TABLE_SET,
                                        data, ARRAY_SIZE(data));
    if (unlikely(r < 0)) {
        return r;
    }

    return 0;
}

static int vhost_vdpa_net_load_rss(VhostVDPAState *s, const VirtIONet *n,
                                   struct iovec *out_cursor,
                                   struct iovec *in_cursor, bool do_rss)
{
    struct virtio_net_rss_config cfg = {};
    ssize_t r;
    g_autofree uint16_t *table = NULL;

    /*
     * According to VirtIO standard, "Initially the device has all hash
     * types disabled and reports only VIRTIO_NET_HASH_REPORT_NONE.".
     *
     * Therefore, there is no need to send this CVQ command if the
     * driver disables the all hash types, which aligns with
     * the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (!n->rss_data.enabled ||
        n->rss_data.runtime_hash_types == VIRTIO_NET_HASH_REPORT_NONE) {
        return 0;
    }

    table = g_malloc_n(n->rss_data.indirections_len,
                       sizeof(n->rss_data.indirections_table[0]));
    cfg.hash_types = cpu_to_le32(n->rss_data.runtime_hash_types);

    if (do_rss) {
        /*
         * According to VirtIO standard, "Number of entries in indirection_table
         * is (indirection_table_mask + 1)".
         */
        cfg.indirection_table_mask = cpu_to_le16(n->rss_data.indirections_len -
                                                 1);
        cfg.unclassified_queue = cpu_to_le16(n->rss_data.default_queue);
        for (int i = 0; i < n->rss_data.indirections_len; ++i) {
            table[i] = cpu_to_le16(n->rss_data.indirections_table[i]);
        }
        cfg.max_tx_vq = cpu_to_le16(n->curr_queue_pairs);
    } else {
        /*
         * According to VirtIO standard, "Field reserved MUST contain zeroes.
         * It is defined to make the structure to match the layout of
         * virtio_net_rss_config structure, defined in 5.1.6.5.7.".
         *
         * Therefore, we need to zero the fields in
         * struct virtio_net_rss_config, which corresponds to the
         * `reserved` field in struct virtio_net_hash_config.
         *
         * Note that all other fields are zeroed at their definitions,
         * except for the `indirection_table` field, where the actual data
         * is stored in the `table` variable to ensure compatibility
         * with RSS case. Therefore, we need to zero the `table` variable here.
         */
        table[0] = 0;
    }

    /*
     * Considering that virtio_net_handle_rss() currently does not restore
     * the hash key length parsed from the CVQ command sent from the guest
     * into n->rss_data and uses the maximum key length in other code, so
     * we also employ the maximum key length here.
     */
    cfg.hash_key_length = sizeof(n->rss_data.key);

    const struct iovec data[] = {
        {
            .iov_base = &cfg,
            .iov_len = offsetof(struct virtio_net_rss_config,
                                indirection_table),
        }, {
            .iov_base = table,
            .iov_len = n->rss_data.indirections_len *
                       sizeof(n->rss_data.indirections_table[0]),
        }, {
            .iov_base = &cfg.max_tx_vq,
            .iov_len = offsetof(struct virtio_net_rss_config, hash_key_data) -
                       offsetof(struct virtio_net_rss_config, max_tx_vq),
        }, {
            .iov_base = (void *)n->rss_data.key,
            .iov_len = sizeof(n->rss_data.key),
        }
    };

    r = vhost_vdpa_net_load_cmd(s, out_cursor, in_cursor,
                                VIRTIO_NET_CTRL_MQ,
                                do_rss ? VIRTIO_NET_CTRL_MQ_RSS_CONFIG :
                                VIRTIO_NET_CTRL_MQ_HASH_CONFIG,
                                data, ARRAY_SIZE(data));
    if (unlikely(r < 0)) {
        return r;
    }

    return 0;
}

static int vhost_vdpa_net_load_mq(VhostVDPAState *s,
                                  const VirtIONet *n,
                                  struct iovec *out_cursor,
                                  struct iovec *in_cursor)
{
    struct virtio_net_ctrl_mq mq;
    ssize_t r;

    if (!virtio_vdev_has_feature(&n->parent_obj, VIRTIO_NET_F_MQ)) {
        return 0;
    }

    trace_vhost_vdpa_net_load_mq(s, n->curr_queue_pairs);

    mq.virtqueue_pairs = cpu_to_le16(n->curr_queue_pairs);
    const struct iovec data = {
        .iov_base = &mq,
        .iov_len = sizeof(mq),
    };
    r = vhost_vdpa_net_load_cmd(s, out_cursor, in_cursor,
                                VIRTIO_NET_CTRL_MQ,
                                VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET,
                                &data, 1);
    if (unlikely(r < 0)) {
        return r;
    }

    if (virtio_vdev_has_feature(&n->parent_obj, VIRTIO_NET_F_RSS)) {
        /* load the receive-side scaling state */
        r = vhost_vdpa_net_load_rss(s, n, out_cursor, in_cursor, true);
        if (unlikely(r < 0)) {
            return r;
        }
    } else if (virtio_vdev_has_feature(&n->parent_obj,
                                       VIRTIO_NET_F_HASH_REPORT)) {
        /* load the hash calculation state */
        r = vhost_vdpa_net_load_rss(s, n, out_cursor, in_cursor, false);
        if (unlikely(r < 0)) {
            return r;
        }
    }

    return 0;
}

static int vhost_vdpa_net_load_offloads(VhostVDPAState *s,
                                        const VirtIONet *n,
                                        struct iovec *out_cursor,
                                        struct iovec *in_cursor)
{
    uint64_t offloads;
    ssize_t r;

    if (!virtio_vdev_has_feature(&n->parent_obj,
                                 VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)) {
        return 0;
    }

    if (n->curr_guest_offloads == virtio_net_supported_guest_offloads(n)) {
        /*
         * According to VirtIO standard, "Upon feature negotiation
         * corresponding offload gets enabled to preserve
         * backward compatibility.".
         *
         * Therefore, there is no need to send this CVQ command if the
         * driver also enables all supported offloads, which aligns with
         * the device's defaults.
         *
         * Note that the device's defaults can mismatch the driver's
         * configuration only at live migration.
         */
        return 0;
    }

    offloads = cpu_to_le64(n->curr_guest_offloads);
    const struct iovec data = {
        .iov_base = &offloads,
        .iov_len = sizeof(offloads),
    };
    r = vhost_vdpa_net_load_cmd(s, out_cursor, in_cursor,
                                VIRTIO_NET_CTRL_GUEST_OFFLOADS,
                                VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET,
                                &data, 1);
    if (unlikely(r < 0)) {
        return r;
    }

    return 0;
}

static int vhost_vdpa_net_load_rx_mode(VhostVDPAState *s,
                                       struct iovec *out_cursor,
                                       struct iovec *in_cursor,
                                       uint8_t cmd,
                                       uint8_t on)
{
    const struct iovec data = {
        .iov_base = &on,
        .iov_len = sizeof(on),
    };
    ssize_t r;

    r = vhost_vdpa_net_load_cmd(s, out_cursor, in_cursor,
                                VIRTIO_NET_CTRL_RX, cmd, &data, 1);
    if (unlikely(r < 0)) {
        return r;
    }

    return 0;
}

static int vhost_vdpa_net_load_rx(VhostVDPAState *s,
                                  const VirtIONet *n,
                                  struct iovec *out_cursor,
                                  struct iovec *in_cursor)
{
    ssize_t r;

    if (!virtio_vdev_has_feature(&n->parent_obj, VIRTIO_NET_F_CTRL_RX)) {
        return 0;
    }

    /*
     * According to virtio_net_reset(), device turns promiscuous mode
     * on by default.
     *
     * Additionally, according to VirtIO standard, "Since there are
     * no guarantees, it can use a hash filter or silently switch to
     * allmulti or promiscuous mode if it is given too many addresses.".
     * QEMU marks `n->mac_table.uni_overflow` if guest sets too many
     * non-multicast MAC addresses, indicating that promiscuous mode
     * should be enabled.
     *
     * Therefore, QEMU should only send this CVQ command if the
     * `n->mac_table.uni_overflow` is not marked and `n->promisc` is off,
     * which sets promiscuous mode on, different from the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (!n->mac_table.uni_overflow && !n->promisc) {
        r = vhost_vdpa_net_load_rx_mode(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_RX_PROMISC, 0);
        if (unlikely(r < 0)) {
            return r;
        }
    }

    /*
     * According to virtio_net_reset(), device turns all-multicast mode
     * off by default.
     *
     * According to VirtIO standard, "Since there are no guarantees,
     * it can use a hash filter or silently switch to allmulti or
     * promiscuous mode if it is given too many addresses.". QEMU marks
     * `n->mac_table.multi_overflow` if guest sets too many
     * non-multicast MAC addresses.
     *
     * Therefore, QEMU should only send this CVQ command if the
     * `n->mac_table.multi_overflow` is marked or `n->allmulti` is on,
     * which sets all-multicast mode on, different from the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (n->mac_table.multi_overflow || n->allmulti) {
        r = vhost_vdpa_net_load_rx_mode(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_RX_ALLMULTI, 1);
        if (unlikely(r < 0)) {
            return r;
        }
    }

    if (!virtio_vdev_has_feature(&n->parent_obj, VIRTIO_NET_F_CTRL_RX_EXTRA)) {
        return 0;
    }

    /*
     * According to virtio_net_reset(), device turns all-unicast mode
     * off by default.
     *
     * Therefore, QEMU should only send this CVQ command if the driver
     * sets all-unicast mode on, different from the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (n->alluni) {
        r = vhost_vdpa_net_load_rx_mode(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_RX_ALLUNI, 1);
        if (r < 0) {
            return r;
        }
    }

    /*
     * According to virtio_net_reset(), device turns non-multicast mode
     * off by default.
     *
     * Therefore, QEMU should only send this CVQ command if the driver
     * sets non-multicast mode on, different from the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (n->nomulti) {
        r = vhost_vdpa_net_load_rx_mode(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_RX_NOMULTI, 1);
        if (r < 0) {
            return r;
        }
    }

    /*
     * According to virtio_net_reset(), device turns non-unicast mode
     * off by default.
     *
     * Therefore, QEMU should only send this CVQ command if the driver
     * sets non-unicast mode on, different from the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (n->nouni) {
        r = vhost_vdpa_net_load_rx_mode(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_RX_NOUNI, 1);
        if (r < 0) {
            return r;
        }
    }

    /*
     * According to virtio_net_reset(), device turns non-broadcast mode
     * off by default.
     *
     * Therefore, QEMU should only send this CVQ command if the driver
     * sets non-broadcast mode on, different from the device's defaults.
     *
     * Note that the device's defaults can mismatch the driver's
     * configuration only at live migration.
     */
    if (n->nobcast) {
        r = vhost_vdpa_net_load_rx_mode(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_RX_NOBCAST, 1);
        if (r < 0) {
            return r;
        }
    }

    return 0;
}

static int vhost_vdpa_net_load_single_vlan(VhostVDPAState *s,
                                           const VirtIONet *n,
                                           struct iovec *out_cursor,
                                           struct iovec *in_cursor,
                                           uint16_t vid)
{
    const struct iovec data = {
        .iov_base = &vid,
        .iov_len = sizeof(vid),
    };
    ssize_t r = vhost_vdpa_net_load_cmd(s, out_cursor, in_cursor,
                                        VIRTIO_NET_CTRL_VLAN,
                                        VIRTIO_NET_CTRL_VLAN_ADD,
                                        &data, 1);
    if (unlikely(r < 0)) {
        return r;
    }

    return 0;
}

static int vhost_vdpa_net_load_vlan(VhostVDPAState *s,
                                    const VirtIONet *n,
                                    struct iovec *out_cursor,
                                    struct iovec *in_cursor)
{
    int r;

    if (!virtio_vdev_has_feature(&n->parent_obj, VIRTIO_NET_F_CTRL_VLAN)) {
        return 0;
    }

    for (int i = 0; i < MAX_VLAN >> 5; i++) {
        for (int j = 0; n->vlans[i] && j <= 0x1f; j++) {
            if (n->vlans[i] & (1U << j)) {
                r = vhost_vdpa_net_load_single_vlan(s, n, out_cursor,
                                                    in_cursor, (i << 5) + j);
                if (unlikely(r != 0)) {
                    return r;
                }
            }
        }
    }

    return 0;
}

static int vhost_vdpa_net_cvq_load(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    struct vhost_vdpa *v = &s->vhost_vdpa;
    const VirtIONet *n;
    int r;
    struct iovec out_cursor, in_cursor;

    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    r = vhost_vdpa_set_vring_ready(v, v->dev->vq_index);
    if (unlikely(r < 0)) {
        return r;
    }

    if (v->shadow_vqs_enabled) {
        n = VIRTIO_NET(v->dev->vdev);
        vhost_vdpa_net_load_cursor_reset(s, &out_cursor, &in_cursor);
        r = vhost_vdpa_net_load_mac(s, n, &out_cursor, &in_cursor);
        if (unlikely(r < 0)) {
            return r;
        }
        r = vhost_vdpa_net_load_mq(s, n, &out_cursor, &in_cursor);
        if (unlikely(r)) {
            return r;
        }
        r = vhost_vdpa_net_load_offloads(s, n, &out_cursor, &in_cursor);
        if (unlikely(r)) {
            return r;
        }
        r = vhost_vdpa_net_load_rx(s, n, &out_cursor, &in_cursor);
        if (unlikely(r)) {
            return r;
        }
        r = vhost_vdpa_net_load_vlan(s, n, &out_cursor, &in_cursor);
        if (unlikely(r)) {
            return r;
        }

        /*
         * We need to poll and check all pending device's used buffers.
         *
         * We can poll here since we've had BQL from the time
         * we sent the descriptor.
         */
        r = vhost_vdpa_net_svq_flush(s, in_cursor.iov_base - (void *)s->status);
        if (unlikely(r)) {
            return r;
        }
    }

    for (int i = 0; i < v->dev->vq_index; ++i) {
        r = vhost_vdpa_set_vring_ready(v, i);
        if (unlikely(r < 0)) {
            return r;
        }
    }

    return 0;
}

static NetClientInfo net_vhost_vdpa_cvq_info = {
    .type = NET_CLIENT_DRIVER_VHOST_VDPA,
    .size = sizeof(VhostVDPAState),
    .receive = vhost_vdpa_receive,
    .start = vhost_vdpa_net_cvq_start,
    .load = vhost_vdpa_net_cvq_load,
    .stop = vhost_vdpa_net_cvq_stop,
    .cleanup = vhost_vdpa_cleanup,
    .has_vnet_hdr = vhost_vdpa_has_vnet_hdr,
    .get_vnet_hash_supported_types = vhost_vdpa_get_vnet_hash_supported_types,
    .has_ufo = vhost_vdpa_has_ufo,
    .check_peer_type = vhost_vdpa_check_peer_type,
    .get_vhost_net = vhost_vdpa_get_vhost_net,
};

/*
 * Forward the excessive VIRTIO_NET_CTRL_MAC_TABLE_SET CVQ command to
 * vdpa device.
 *
 * Considering that QEMU cannot send the entire filter table to the
 * vdpa device, it should send the VIRTIO_NET_CTRL_RX_PROMISC CVQ
 * command to enable promiscuous mode to receive all packets,
 * according to VirtIO standard, "Since there are no guarantees,
 * it can use a hash filter or silently switch to allmulti or
 * promiscuous mode if it is given too many addresses.".
 *
 * Since QEMU ignores MAC addresses beyond `MAC_TABLE_ENTRIES` and
 * marks `n->mac_table.x_overflow` accordingly, it should have
 * the same effect on the device model to receive
 * (`MAC_TABLE_ENTRIES` + 1) or more non-multicast MAC addresses.
 * The same applies to multicast MAC addresses.
 *
 * Therefore, QEMU can provide the device model with a fake
 * VIRTIO_NET_CTRL_MAC_TABLE_SET command with (`MAC_TABLE_ENTRIES` + 1)
 * non-multicast MAC addresses and (`MAC_TABLE_ENTRIES` + 1) multicast
 * MAC addresses. This ensures that the device model marks
 * `n->mac_table.uni_overflow` and `n->mac_table.multi_overflow`,
 * allowing all packets to be received, which aligns with the
 * state of the vdpa device.
 */
static int vhost_vdpa_net_excessive_mac_filter_cvq_add(VhostVDPAState *s,
                                                       VirtQueueElement *elem,
                                                       struct iovec *out,
                                                       const struct iovec *in)
{
    struct virtio_net_ctrl_mac mac_data, *mac_ptr;
    struct virtio_net_ctrl_hdr *hdr_ptr;
    uint32_t cursor;
    ssize_t r;
    uint8_t on = 1;

    /* parse the non-multicast MAC address entries from CVQ command */
    cursor = sizeof(*hdr_ptr);
    r = iov_to_buf(elem->out_sg, elem->out_num, cursor,
                   &mac_data, sizeof(mac_data));
    if (unlikely(r != sizeof(mac_data))) {
        /*
         * If the CVQ command is invalid, we should simulate the vdpa device
         * to reject the VIRTIO_NET_CTRL_MAC_TABLE_SET CVQ command
         */
        *s->status = VIRTIO_NET_ERR;
        return sizeof(*s->status);
    }
    cursor += sizeof(mac_data) + le32_to_cpu(mac_data.entries) * ETH_ALEN;

    /* parse the multicast MAC address entries from CVQ command */
    r = iov_to_buf(elem->out_sg, elem->out_num, cursor,
                   &mac_data, sizeof(mac_data));
    if (r != sizeof(mac_data)) {
        /*
         * If the CVQ command is invalid, we should simulate the vdpa device
         * to reject the VIRTIO_NET_CTRL_MAC_TABLE_SET CVQ command
         */
        *s->status = VIRTIO_NET_ERR;
        return sizeof(*s->status);
    }
    cursor += sizeof(mac_data) + le32_to_cpu(mac_data.entries) * ETH_ALEN;

    /* validate the CVQ command */
    if (iov_size(elem->out_sg, elem->out_num) != cursor) {
        /*
         * If the CVQ command is invalid, we should simulate the vdpa device
         * to reject the VIRTIO_NET_CTRL_MAC_TABLE_SET CVQ command
         */
        *s->status = VIRTIO_NET_ERR;
        return sizeof(*s->status);
    }

    /*
     * According to VirtIO standard, "Since there are no guarantees,
     * it can use a hash filter or silently switch to allmulti or
     * promiscuous mode if it is given too many addresses.".
     *
     * Therefore, considering that QEMU is unable to send the entire
     * filter table to the vdpa device, it should send the
     * VIRTIO_NET_CTRL_RX_PROMISC CVQ command to enable promiscuous mode
     */
    hdr_ptr = out->iov_base;
    out->iov_len = sizeof(*hdr_ptr) + sizeof(on);

    hdr_ptr->class = VIRTIO_NET_CTRL_RX;
    hdr_ptr->cmd = VIRTIO_NET_CTRL_RX_PROMISC;
    iov_from_buf(out, 1, sizeof(*hdr_ptr), &on, sizeof(on));
    r = vhost_vdpa_net_cvq_add(s, out, 1, in, 1);
    if (unlikely(r < 0)) {
        return r;
    }

    /*
     * We can poll here since we've had BQL from the time
     * we sent the descriptor.
     */
    r = vhost_vdpa_net_svq_poll(s, 1);
    if (unlikely(r < sizeof(*s->status))) {
        return r;
    }
    if (*s->status != VIRTIO_NET_OK) {
        return sizeof(*s->status);
    }

    /*
     * QEMU should also send a fake VIRTIO_NET_CTRL_MAC_TABLE_SET CVQ
     * command to the device model, including (`MAC_TABLE_ENTRIES` + 1)
     * non-multicast MAC addresses and (`MAC_TABLE_ENTRIES` + 1)
     * multicast MAC addresses.
     *
     * By doing so, the device model can mark `n->mac_table.uni_overflow`
     * and `n->mac_table.multi_overflow`, enabling all packets to be
     * received, which aligns with the state of the vdpa device.
     */
    cursor = 0;
    uint32_t fake_uni_entries = MAC_TABLE_ENTRIES + 1,
             fake_mul_entries = MAC_TABLE_ENTRIES + 1,
             fake_cvq_size = sizeof(struct virtio_net_ctrl_hdr) +
                             sizeof(mac_data) + fake_uni_entries * ETH_ALEN +
                             sizeof(mac_data) + fake_mul_entries * ETH_ALEN;

    assert(fake_cvq_size < vhost_vdpa_net_cvq_cmd_page_len());
    out->iov_len = fake_cvq_size;

    /* pack the header for fake CVQ command */
    hdr_ptr = out->iov_base + cursor;
    hdr_ptr->class = VIRTIO_NET_CTRL_MAC;
    hdr_ptr->cmd = VIRTIO_NET_CTRL_MAC_TABLE_SET;
    cursor += sizeof(*hdr_ptr);

    /*
     * Pack the non-multicast MAC addresses part for fake CVQ command.
     *
     * According to virtio_net_handle_mac(), QEMU doesn't verify the MAC
     * addresses provided in CVQ command. Therefore, only the entries
     * field need to be prepared in the CVQ command.
     */
    mac_ptr = out->iov_base + cursor;
    mac_ptr->entries = cpu_to_le32(fake_uni_entries);
    cursor += sizeof(*mac_ptr) + fake_uni_entries * ETH_ALEN;

    /*
     * Pack the multicast MAC addresses part for fake CVQ command.
     *
     * According to virtio_net_handle_mac(), QEMU doesn't verify the MAC
     * addresses provided in CVQ command. Therefore, only the entries
     * field need to be prepared in the CVQ command.
     */
    mac_ptr = out->iov_base + cursor;
    mac_ptr->entries = cpu_to_le32(fake_mul_entries);

    /*
     * Simulating QEMU poll a vdpa device used buffer
     * for VIRTIO_NET_CTRL_MAC_TABLE_SET CVQ command
     */
    return sizeof(*s->status);
}

/**
 * Validate and copy control virtqueue commands.
 *
 * Following QEMU guidelines, we offer a copy of the buffers to the device to
 * prevent TOCTOU bugs.
 */
static int vhost_vdpa_net_handle_ctrl_avail(VhostShadowVirtqueue *svq,
                                            VirtQueueElement *elem,
                                            void *opaque)
{
    VhostVDPAState *s = opaque;
    size_t in_len;
    const struct virtio_net_ctrl_hdr *ctrl;
    virtio_net_ctrl_ack status = VIRTIO_NET_ERR;
    /* Out buffer sent to both the vdpa device and the device model */
    struct iovec out = {
        .iov_base = s->cvq_cmd_out_buffer,
    };
    /* in buffer used for device model */
    const struct iovec model_in = {
        .iov_base = &status,
        .iov_len = sizeof(status),
    };
    /* in buffer used for vdpa device */
    const struct iovec vdpa_in = {
        .iov_base = s->status,
        .iov_len = sizeof(*s->status),
    };
    ssize_t dev_written = -EINVAL;

    out.iov_len = iov_to_buf(elem->out_sg, elem->out_num, 0,
                             s->cvq_cmd_out_buffer,
                             vhost_vdpa_net_cvq_cmd_page_len());

    ctrl = s->cvq_cmd_out_buffer;
    if (ctrl->class == VIRTIO_NET_CTRL_ANNOUNCE) {
        /*
         * Guest announce capability is emulated by qemu, so don't forward to
         * the device.
         */
        dev_written = sizeof(status);
        *s->status = VIRTIO_NET_OK;
    } else if (unlikely(ctrl->class == VIRTIO_NET_CTRL_MAC &&
                        ctrl->cmd == VIRTIO_NET_CTRL_MAC_TABLE_SET &&
                        iov_size(elem->out_sg, elem->out_num) > out.iov_len)) {
        /*
         * Due to the size limitation of the out buffer sent to the vdpa device,
         * which is determined by vhost_vdpa_net_cvq_cmd_page_len(), excessive
         * MAC addresses set by the driver for the filter table can cause
         * truncation of the CVQ command in QEMU. As a result, the vdpa device
         * rejects the flawed CVQ command.
         *
         * Therefore, QEMU must handle this situation instead of sending
         * the CVQ command directly.
         */
        dev_written = vhost_vdpa_net_excessive_mac_filter_cvq_add(s, elem,
                                                            &out, &vdpa_in);
        if (unlikely(dev_written < 0)) {
            goto out;
        }
    } else {
        ssize_t r;
        r = vhost_vdpa_net_cvq_add(s, &out, 1, &vdpa_in, 1);
        if (unlikely(r < 0)) {
            dev_written = r;
            goto out;
        }

        /*
         * We can poll here since we've had BQL from the time
         * we sent the descriptor.
         */
        dev_written = vhost_vdpa_net_svq_poll(s, 1);
    }

    if (unlikely(dev_written < sizeof(status))) {
        error_report("Insufficient written data (%zu)", dev_written);
        goto out;
    }

    if (*s->status != VIRTIO_NET_OK) {
        goto out;
    }

    status = VIRTIO_NET_ERR;
    virtio_net_handle_ctrl_iov(svq->vdev, &model_in, 1, &out, 1);
    if (status != VIRTIO_NET_OK) {
        error_report("Bad CVQ processing in model");
    }

out:
    in_len = iov_from_buf(elem->in_sg, elem->in_num, 0, &status,
                          sizeof(status));
    if (unlikely(in_len < sizeof(status))) {
        error_report("Bad device CVQ written length");
    }
    vhost_svq_push_elem(svq, elem, MIN(in_len, sizeof(status)));
    /*
     * `elem` belongs to vhost_vdpa_net_handle_ctrl_avail() only when
     * the function successfully forwards the CVQ command, indicated
     * by a non-negative value of `dev_written`. Otherwise, it still
     * belongs to SVQ.
     * This function should only free the `elem` when it owns.
     */
    if (dev_written >= 0) {
        g_free(elem);
    }
    return dev_written < 0 ? dev_written : 0;
}

static const VhostShadowVirtqueueOps vhost_vdpa_net_svq_ops = {
    .avail_handler = vhost_vdpa_net_handle_ctrl_avail,
};

/**
 * Probe if CVQ is isolated
 *
 * @device_fd         The vdpa device fd
 * @features          Features offered by the device.
 * @cvq_index         The control vq pair index
 *
 * Returns <0 in case of failure, 0 if false and 1 if true.
 */
static int vhost_vdpa_probe_cvq_isolation(int device_fd, uint64_t features,
                                          int cvq_index, Error **errp)
{
    ERRP_GUARD();
    uint64_t backend_features;
    int64_t cvq_group;
    uint8_t status = VIRTIO_CONFIG_S_ACKNOWLEDGE |
                     VIRTIO_CONFIG_S_DRIVER;
    int r;

    r = ioctl(device_fd, VHOST_GET_BACKEND_FEATURES, &backend_features);
    if (unlikely(r < 0)) {
        error_setg_errno(errp, errno, "Cannot get vdpa backend_features");
        return r;
    }

    if (!(backend_features & BIT_ULL(VHOST_BACKEND_F_IOTLB_ASID))) {
        return 0;
    }

    r = ioctl(device_fd, VHOST_VDPA_SET_STATUS, &status);
    if (unlikely(r)) {
        error_setg_errno(errp, -r, "Cannot set device status");
        goto out;
    }

    r = ioctl(device_fd, VHOST_SET_FEATURES, &features);
    if (unlikely(r)) {
        error_setg_errno(errp, -r, "Cannot set features");
        goto out;
    }

    status |= VIRTIO_CONFIG_S_FEATURES_OK;
    r = ioctl(device_fd, VHOST_VDPA_SET_STATUS, &status);
    if (unlikely(r)) {
        error_setg_errno(errp, -r, "Cannot set device status");
        goto out;
    }

    cvq_group = vhost_vdpa_get_vring_group(device_fd, cvq_index, errp);
    if (unlikely(cvq_group < 0)) {
        if (cvq_group != -ENOTSUP) {
            r = cvq_group;
            goto out;
        }

        /*
         * The kernel report VHOST_BACKEND_F_IOTLB_ASID if the vdpa frontend
         * support ASID even if the parent driver does not.  The CVQ cannot be
         * isolated in this case.
         */
        error_free(*errp);
        *errp = NULL;
        r = 0;
        goto out;
    }

    for (int i = 0; i < cvq_index; ++i) {
        int64_t group = vhost_vdpa_get_vring_group(device_fd, i, errp);
        if (unlikely(group < 0)) {
            r = group;
            goto out;
        }

        if (group == (int64_t)cvq_group) {
            r = 0;
            goto out;
        }
    }

    r = 1;

out:
    status = 0;
    ioctl(device_fd, VHOST_VDPA_SET_STATUS, &status);
    return r;
}

static NetClientState *net_vhost_vdpa_init(NetClientState *peer,
                                       const char *device,
                                       const char *name,
                                       int vdpa_device_fd,
                                       int queue_pair_index,
                                       int nvqs,
                                       bool is_datapath,
                                       bool svq,
                                       struct vhost_vdpa_iova_range iova_range,
                                       uint64_t features,
                                       VhostVDPAShared *shared,
                                       const char *vhostdev,
                                       Error **errp)
{
    NetClientState *nc = NULL;
    VhostVDPAState *s;
    int ret = 0;
    assert(name);
    int cvq_isolated = 0;

    if (is_datapath) {
        nc = qemu_new_net_client(&net_vhost_vdpa_info, peer, device,
                                 name);
    } else {
        cvq_isolated = vhost_vdpa_probe_cvq_isolation(vdpa_device_fd, features,
                                                      queue_pair_index * 2,
                                                      errp);
        if (unlikely(cvq_isolated < 0)) {
            return NULL;
        }

        nc = qemu_new_net_control_client(&net_vhost_vdpa_cvq_info, peer,
                                         device, name);
    }
    qemu_set_info_str(nc, TYPE_VHOST_VDPA);
    s = DO_UPCAST(VhostVDPAState, nc, nc);

    s->vhost_vdpa.index = queue_pair_index;
    s->always_svq = svq;
    s->migration_state.notify = NULL;
    s->vhost_vdpa.shadow_vqs_enabled = svq;
    if (queue_pair_index == 0) {
        vhost_vdpa_net_valid_svq_features(features,
                                          &s->vhost_vdpa.migration_blocker);
        s->vhost_vdpa.shared = g_new0(VhostVDPAShared, 1);
        s->vhost_vdpa.shared->device_fd = vdpa_device_fd;
        s->vhost_vdpa.shared->iova_range = iova_range;
        s->vhost_vdpa.shared->shadow_data = svq;
        s->vhost_vdpa.shared->iova_tree = vhost_iova_tree_new(iova_range.first,
                                                              iova_range.last);
        vio_vdpa_shared_init(s, svq);
        if (!s->vhost_vdpa.shared->vio_vdpa_dev && vhostdev) {
            s->vhost_vdpa.shared->vio_vdpa_dev =
                vio_vdpa_dev_name_from_path(vhostdev);
        }
        if (s->vhost_vdpa.shared->vio_vdpa_dev) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: using vDPA stats device %s\n",
                          s->vhost_vdpa.shared->vio_vdpa_dev);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: no vDPA stats device; "
                          "set VIO_VDPA_DEV=vdpaX to enable stats sampling\n");
        }
        if (s->vhost_vdpa.shared->vio_threshold_enabled &&
            !s->vhost_vdpa.shared->vio_svq_control_enabled) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: stats-only threshold mode without SVQ; "
                          "IOPS comes from vDPA stats; SNOOP/PASSTHROUGH "
                          "are logical modes and the backend path is not "
                          "restarted\n");
        } else if (s->vhost_vdpa.shared->vio_threshold_enabled &&
                   s->vhost_vdpa.shared->vio_svq_control_enabled &&
                   !s->vhost_vdpa.shared->vio_backend_switch_enabled) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "VIO-VDPA: SVQ-always threshold mode; "
                          "SNOOP/PASSTHROUGH switch only toggles snoop touch, "
                          "shadow virtqueues stay enabled and vhost is not "
                          "restarted\n");
        }
    } else if (!is_datapath) {
        s->cvq_cmd_out_buffer = mmap(NULL, vhost_vdpa_net_cvq_cmd_page_len(),
                                     PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        s->status = mmap(NULL, vhost_vdpa_net_cvq_cmd_page_len(),
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                         -1, 0);

        s->vhost_vdpa.shadow_vq_ops = &vhost_vdpa_net_svq_ops;
        s->vhost_vdpa.shadow_vq_ops_opaque = s;
        s->cvq_isolated = cvq_isolated;
    }
    if (queue_pair_index != 0) {
        s->vhost_vdpa.shared = shared;
    }
    if (is_datapath) {
        s->vhost_vdpa.shadow_vq_ops = &vhost_vdpa_net_data_svq_ops;
        s->vhost_vdpa.shadow_vq_ops_opaque = s;
    }

    ret = vhost_vdpa_add(nc, (void *)&s->vhost_vdpa, queue_pair_index, nvqs);
    if (ret) {
        qemu_del_net_client(nc);
        return NULL;
    }

    return nc;
}

static int vhost_vdpa_get_features(int fd, uint64_t *features, Error **errp)
{
    int ret = ioctl(fd, VHOST_GET_FEATURES, features);
    if (unlikely(ret < 0)) {
        error_setg_errno(errp, errno,
                         "Fail to query features from vhost-vDPA device");
    }
    return ret;
}

static int vhost_vdpa_get_max_queue_pairs(int fd, uint64_t features,
                                          int *has_cvq, Error **errp)
{
    unsigned long config_size = offsetof(struct vhost_vdpa_config, buf);
    g_autofree struct vhost_vdpa_config *config = NULL;
    __virtio16 *max_queue_pairs;
    int ret;

    if (features & (1 << VIRTIO_NET_F_CTRL_VQ)) {
        *has_cvq = 1;
    } else {
        *has_cvq = 0;
    }

    if (features & (1 << VIRTIO_NET_F_MQ)) {
        config = g_malloc0(config_size + sizeof(*max_queue_pairs));
        config->off = offsetof(struct virtio_net_config, max_virtqueue_pairs);
        config->len = sizeof(*max_queue_pairs);

        ret = ioctl(fd, VHOST_VDPA_GET_CONFIG, config);
        if (ret) {
            error_setg(errp, "Fail to get config from vhost-vDPA device");
            return -ret;
        }

        max_queue_pairs = (__virtio16 *)&config->buf;

        return lduw_le_p(max_queue_pairs);
    }

    return 1;
}

int net_init_vhost_vdpa(const Netdev *netdev, const char *name,
                        NetClientState *peer, Error **errp)
{
    ERRP_GUARD();
    const NetdevVhostVDPAOptions *opts;
    uint64_t features;
    int vdpa_device_fd;
    g_autofree NetClientState **ncs = NULL;
    struct vhost_vdpa_iova_range iova_range;
    NetClientState *nc;
    int queue_pairs, r, i = 0, has_cvq = 0;

    assert(netdev->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    opts = &netdev->u.vhost_vdpa;
    if (!opts->vhostdev && !opts->vhostfd) {
        error_setg(errp,
                   "vhost-vdpa: neither vhostdev= nor vhostfd= was specified");
        return -1;
    }

    if (opts->vhostdev && opts->vhostfd) {
        error_setg(errp,
                   "vhost-vdpa: vhostdev= and vhostfd= are mutually exclusive");
        return -1;
    }

    if (opts->vhostdev) {
        vdpa_device_fd = qemu_open(opts->vhostdev, O_RDWR, errp);
        if (vdpa_device_fd == -1) {
            return -errno;
        }
    } else {
        /* has_vhostfd */
        vdpa_device_fd = monitor_fd_param(monitor_cur(), opts->vhostfd, errp);
        if (vdpa_device_fd == -1) {
            error_prepend(errp, "vhost-vdpa: unable to parse vhostfd: ");
            return -1;
        }
    }

    r = vhost_vdpa_get_features(vdpa_device_fd, &features, errp);
    if (unlikely(r < 0)) {
        goto err;
    }

    queue_pairs = vhost_vdpa_get_max_queue_pairs(vdpa_device_fd, features,
                                                 &has_cvq, errp);
    if (queue_pairs <= 0) {
        goto err;
    }

    r = vhost_vdpa_get_iova_range(vdpa_device_fd, &iova_range);
    if (unlikely(r < 0)) {
        error_setg(errp, "vhost-vdpa: get iova range failed: %s",
                   strerror(-r));
        goto err;
    }

    if (opts->x_svq && !vhost_vdpa_net_valid_svq_features(features, errp)) {
        goto err;
    }

    ncs = g_malloc0(sizeof(*ncs) * queue_pairs);

    for (i = 0; i < queue_pairs; i++) {
        VhostVDPAShared *shared = NULL;

        if (i) {
            shared = DO_UPCAST(VhostVDPAState, nc, ncs[0])->vhost_vdpa.shared;
        }
        ncs[i] = net_vhost_vdpa_init(peer, TYPE_VHOST_VDPA, name,
                                     vdpa_device_fd, i, 2, true, opts->x_svq,
                                     iova_range, features, shared,
                                     opts->vhostdev, errp);
        if (!ncs[i])
            goto err;
    }

    if (has_cvq) {
        VhostVDPAState *s0 = DO_UPCAST(VhostVDPAState, nc, ncs[0]);
        VhostVDPAShared *shared = s0->vhost_vdpa.shared;

        nc = net_vhost_vdpa_init(peer, TYPE_VHOST_VDPA, name,
                                 vdpa_device_fd, i, 1, false,
                                 opts->x_svq, iova_range, features, shared,
                                 opts->vhostdev, errp);
        if (!nc)
            goto err;
    }

    return 0;

err:
    if (i) {
        for (i--; i >= 0; i--) {
            qemu_del_net_client(ncs[i]);
        }
    }

    qemu_close(vdpa_device_fd);

    return -1;
}
