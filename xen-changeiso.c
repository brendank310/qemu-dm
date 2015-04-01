#include "xen-changeiso.h"

static QTAILQ_HEAD(IsoNodeHead, IsoNode) iso_list = QTAILQ_HEAD_INITIALIZER(iso_list);

static void update_iso_cb(void *opaque)
{
    struct IsoNode *node = opaque;
    Error *err = NULL;

    if (!node) {
        return;
    }

    // Don't try to do  the change if node->iso_file doesn't exist
    if (access(node->iso_file, F_OK) != -1) {
        qmp_change_blockdev(bdrv_get_device_name(node->drive->bdrv), node->iso_file, false, NULL, &err);
    }

    if (err) {
        fprintf(stderr, "%s Error: %s", __FUNCTION__, error_get_pretty(err));
    }
}

static void xenstore_update_iso(void *opaque)
{
#ifdef CONFIG_STUBDOM
    char *state = NULL;
#else
    char *newFile = NULL;
#endif
    struct IsoNode *node = opaque;
    size_t len;
    char path[XEN_BUFSIZE];

    if(!xenstore || !node)
        return;

    if(!node->first_watch) {
        memset(path, 0x00, XEN_BUFSIZE);

#ifdef CONFIG_STUBDOM
        snprintf(path, XEN_BUFSIZE, "%s/state", node->xen_vbd_id);
        state = xs_read(xenstore, XBT_NULL, path, &len);

        if (!state)
            return;
#else
        snprintf(path, XEN_BUFSIZE, "%s/params", node->xen_vbd_id);

        newFile = xs_read(xenstore, XBT_NULL, path, &len);

        // Switch out the file path to the iso, so change gets made
        // when the node->timer fires.
        if (newFile) {
            g_free(node->iso_file);
            node->iso_file = NULL;
            node->iso_file = g_strdup(newFile);
            free(newFile);

            if (!node->iso_file) {
                return;
            }
        }
#endif

#ifdef CONFIG_STUBDOM
        // Wait for blkfront<->blkback to get ready before changing
        // the disk
        if (!strcmp(state, BLKFRONT_READY_STATE)) {
#endif
            qemu_mod_timer(node->timer, qemu_get_clock_ms(rt_clock) + 1000);
#ifdef CONFIG_STUBDOM
        }

        if(state) {
            free(state);
            state = NULL;
        }
#endif

    } else {
        node->first_watch = false;
    }
}

/*

*/
int xenstore_register_iso_dev(const char *file, DriveInfo *dinfo)
{
    struct IsoNode *node = NULL;

    if (!file || !dinfo) {
        fprintf(stderr, "Failed to register iso device due to incorrect parameters");
        return -EINVAL;
    }

    node = g_malloc0(sizeof(*node));

    if (!node) {
        return -ENOMEM;
    }

    /*
       We can't do our Xen business just yet, because hvm init domain hasn't
       been called yet. So we have to save any information needed for registering
       until later.
    */

    node->iso_file = g_strdup(file);
    node->drive = dinfo;
    node->xen_vbd_id = NULL;
    node->frontend_state = NULL;
    node->first_watch = true;
    node->timer = qemu_new_timer_ms(rt_clock, update_iso_cb, node);

    if (!node->iso_file || !node->timer) {
        g_free(node);
        return -ENOMEM;
    }

    QTAILQ_INSERT_TAIL(&iso_list, node, next);

    return 0;
}

int xenstore_init_iso_dev(void)
{
    unsigned int dirNum = 0, i = 0;
    char *dompath = NULL;
    char **vbd_devs = NULL;
    char path[XEN_BUFSIZE];
    char token[XEN_BUFSIZE];

    memset(path, 0x00, XEN_BUFSIZE);
    memset(token, 0x00, XEN_BUFSIZE);

    if (0 > xenstore_generic_init()) {
        return -ENOENT;
    }

    // Stubdom domid is xen_domid+1
#ifdef CONFIG_STUBDOM
    dompath = xs_get_domain_path(xenstore, STUBDOMID(xen_domid));
#else
    dompath = xs_get_domain_path(xenstore, xen_domid);
#endif

    if (!dompath) {
        fprintf(stderr, "%s: Failed to retrieve dompath", __FUNCTION__);
        return -1;
    }

    snprintf(path, XEN_BUFSIZE, "%s/device/vbd", dompath);

    // Find the virtual-device id that blkfront is using for this device
    vbd_devs = xs_directory(xenstore, XBT_NULL, path, &dirNum);

    if (!vbd_devs) {
        return -1;
    }

    for (i = 0; i < dirNum; i++) {

        if (!vbd_devs[i]) {
            continue;
        }

        // Build paths to get necessary information from Xenstore
        // Check the device type as CDROM, and get the backend path
        memset(path, 0x00, XEN_BUFSIZE);
        snprintf(path, XEN_BUFSIZE, "%s/device/vbd/%s", dompath, vbd_devs[i]);
        char *dev_type = xenstore_read_str(path, "device-type");
        char *be = xenstore_read_str(path, "backend");

        if (dev_type && be && !strcmp(dev_type, "cdrom")) {
            // We need to watch the backend for this device now.
            char *params = xenstore_read_str(be, "params");
            struct IsoNode *node;

            QTAILQ_FOREACH(node, &iso_list, next) {
                if (node && params &&
                    node->xen_vbd_id == NULL &&
                    node->frontend_state == NULL) {
                    // For mapping a fired watch to a specific device later
                    node->xen_vbd_id = strdup(be);

                    // Before the guest disk change can occur, make sure the state
                    // of the specified blkfront device is ready
                    memset(path, 0x00, XEN_BUFSIZE);
                    snprintf(path, XEN_BUFSIZE, "%s/device/vbd/%s/state", dompath, vbd_devs[i]);
                    node->frontend_state = strdup(path);
                    break;
                }
            }

            if (!xenstore_add_watch(be, "params", xenstore_update_iso, (void *) node)) {
                fprintf(stderr, "[OXT-ISO] Failed to install xenstore watch on path: %s/params", be);
            }

            if (be) {
                free(be);
                be = NULL;
            }

            if (dev_type) {
                free(dev_type);
                dev_type = NULL;
            }

            if (params) {
                free(params);
                params = NULL;
            }
        }
    }

    if (dompath) {
        free(dompath);
        dompath = NULL;
    }

    if (vbd_devs) {
        free(vbd_devs);
        vbd_devs = NULL;
    }

    return 0;
}
