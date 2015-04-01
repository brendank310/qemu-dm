#ifndef XEN_CHANGEISO__H
#define XEN_CHANGEISO__H

/* OpenXT CD-ROM ISO Change
 * Xenstore mechanism for informing a guest about changes in the media
 * of a ISO backed CD-ROM drive within OpenXT
 */

#include "block/block.h"
#include "sysemu/blockdev.h"
#include "qemu/timer.h"
#include "hw/xen_backend.h"

#define BLKFRONT_READY_STATE "4"
#define STUBDOMID(x) (x+1)

struct IsoNode {
    DriveInfo *drive;
    char *iso_file;
    char *xen_vbd_id;
    char *frontend_state;
    bool first_watch;
    QEMUTimer *timer;
    QTAILQ_ENTRY(IsoNode) next;
};

int xenstore_register_iso_dev(const char *file, DriveInfo *dinfo);
int xenstore_init_iso_dev(void);

#endif
