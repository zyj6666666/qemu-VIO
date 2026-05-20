/*
 * vhost-vdpa.h
 *
 * Copyright(c) 2017-2018 Intel Corporation.
 * Copyright(c) 2020 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef HW_VIRTIO_VHOST_VDPA_H
#define HW_VIRTIO_VHOST_VDPA_H

#include <gmodule.h>

#include "hw/virtio/vhost-iova-tree.h"
#include "hw/virtio/vhost-shadow-virtqueue.h"
#include "hw/virtio/virtio.h"
#include "qemu/timer.h"
#include "standard-headers/linux/vhost_types.h"

/*
 * ASID dedicated to map guest's addresses.  If SVQ is disabled it maps GPA to
 * qemu's IOVA.  If SVQ is enabled it maps also the SVQ vring here
 */
#define VHOST_VDPA_GUEST_PA_ASID 0

typedef struct VhostVDPAHostNotifier {
    MemoryRegion mr;
    void *addr;
} VhostVDPAHostNotifier;

typedef enum SVQTransitionState {
    SVQ_TSTATE_DISABLING = -1,
    SVQ_TSTATE_DONE,
    SVQ_TSTATE_ENABLING
} SVQTransitionState;

typedef enum VioVdpaMode {
    VIO_VDPA_MODE_SNOOP = 0,
    VIO_VDPA_MODE_PASSTHROUGH = 1,
} VioVdpaMode;

/* Info shared by all vhost_vdpa device models */
typedef struct vhost_vdpa_shared {
    int device_fd;
    MemoryListener listener;
    struct vhost_vdpa_iova_range iova_range;
    QLIST_HEAD(, vdpa_iommu) iommu_list;

    /*
     * IOVA mapping used by the Shadow Virtqueue
     *
     * It is shared among all ASID for simplicity, whether CVQ shares ASID with
     * guest or not:
     * - Memory listener need access to guest's memory addresses allocated in
     *   the IOVA tree.
     * - There should be plenty of IOVA address space for both ASID not to
     *   worry about collisions between them.  Guest's translations are still
     *   validated with virtio virtqueue_pop so there is no risk for the guest
     *   to access memory that it shouldn't.
     *
     * To allocate a iova tree per ASID is doable but it complicates the code
     * and it is not worth it for the moment.
     */
    VhostIOVATree *iova_tree;

    /* Copy of backend features */
    uint64_t backend_cap;

    bool iotlb_batch_begin_sent;

    /*
     * The memory listener has been registered, so DMA maps have been sent to
     * the device.
     */
    bool listener_registered;

    /* Vdpa must send shadow addresses as IOTLB key for data queues, not GPA */
    bool shadow_data;

    /* SVQ switching is in progress, or already completed? */
    SVQTransitionState svq_switching;

    bool vio_threshold_enabled;
    bool vio_svq_control_enabled;
    bool vio_backend_switch_enabled;
    bool vio_guest_mem_released;
    bool vio_guest_mem_restore_pending;
    bool vio_switch_pending;
    VioVdpaMode vio_mode;
    uint64_t vio_iops_count;
    int64_t vio_window_start_ns;
    int64_t vio_last_switch_ns;
    int64_t vio_passthrough_enter_ns;
    uint64_t vio_high_iops;
    uint64_t vio_low_iops;
    int64_t vio_window_ns;
    int64_t vio_cooldown_ns;
    int64_t vio_passthrough_min_ns;
    unsigned int vio_passthrough_warmup_windows;
    unsigned int vio_low_windows_required;
    unsigned int vio_passthrough_samples;
    unsigned int vio_low_windows;
    unsigned int vio_stats_stabilize_windows;
    unsigned int vio_stats_stabilize_remaining;
    bool vio_vdpa_baseline_valid;
    QEMUTimer *vio_sample_timer;
    VirtIODevice *vio_vdev;
    char *vio_vdpa_dev;
    int vio_data_vqs;
    int vio_vq_size;
    unsigned int vio_sample_failures;
    uint64_t vio_last_vdpa_received[VIRTIO_QUEUE_MAX];
    uint64_t vio_last_vdpa_completed[VIRTIO_QUEUE_MAX];
    int64_t vio_last_vdpa_sample_ns[VIRTIO_QUEUE_MAX];
    bool vio_last_vdpa_desc_valid[VIRTIO_QUEUE_MAX];
    uint16_t vio_last_avail_idx[VIRTIO_QUEUE_MAX];
    bool vio_last_avail_valid[VIRTIO_QUEUE_MAX];
    GHashTable *vio_svq_dma_refs;
    GHashTable *vio_svq_elem_dma_keys;
} VhostVDPAShared;

typedef struct vhost_vdpa {
    int index;
    uint32_t address_space_id;
    uint64_t acked_features;
    bool shadow_vqs_enabled;
    /* Device suspended successfully */
    bool suspended;
    VhostVDPAShared *shared;
    GPtrArray *shadow_vqs;
    const VhostShadowVirtqueueOps *shadow_vq_ops;
    void *shadow_vq_ops_opaque;
    struct vhost_dev *dev;
    Error *migration_blocker;
    VhostVDPAHostNotifier notifier[VIRTIO_QUEUE_MAX];
    IOMMUNotifier n;
} VhostVDPA;

int vhost_vdpa_get_iova_range(int fd, struct vhost_vdpa_iova_range *iova_range);
int vhost_vdpa_set_vring_ready(struct vhost_vdpa *v, unsigned idx);

int vhost_vdpa_dma_map(VhostVDPAShared *s, uint32_t asid, hwaddr iova,
                       hwaddr size, void *vaddr, bool readonly);
int vhost_vdpa_dma_unmap(VhostVDPAShared *s, uint32_t asid, hwaddr iova,
                         hwaddr size);
int vhost_vdpa_vio_release_guest_memory(struct vhost_vdpa *v);
int vhost_vdpa_vio_restore_guest_memory(struct vhost_vdpa *v);
int vhost_vdpa_vio_svq_map_elem(struct vhost_vdpa *v, VirtQueueElement *elem);
void vhost_vdpa_vio_svq_unmap_elem(struct vhost_vdpa *v,
                                   VirtQueueElement *elem);
void vhost_vdpa_vio_clear_svq_maps(struct vhost_vdpa *v);

typedef struct vdpa_iommu {
    VhostVDPAShared *dev_shared;
    IOMMUMemoryRegion *iommu_mr;
    hwaddr iommu_offset;
    IOMMUNotifier n;
    QLIST_ENTRY(vdpa_iommu) iommu_next;
} VDPAIOMMUState;


#endif
