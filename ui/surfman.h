#ifndef _SURFMAN_H_
# define _SURFMAN_H_

#include "hw/xen.h"
#include "ui/console.h"
#include "xen-dmbus.h"
#include "exec/memory.h"

#define SURFMAN_DEBUG 0
#define SURFMAN_FLAG "surfman-ui: "
# define surfman_debug(fmt, ...)                            \
    do {                                                    \
        if (SURFMAN_DEBUG)                                  \
            fprintf(stdout, SURFMAN_FLAG "%s:%d " fmt "\n", \
                    __FILE__, __LINE__, ##__VA_ARGS__);     \
    } while (0)
#define surfman_info(fmt, ...) \
    fprintf(stdout, SURFMAN_FLAG fmt "\n", ##__VA_ARGS__)
#define surfman_warn(fmt, ...) \
    fprintf(stderr, SURFMAN_FLAG "warning: " fmt "\n", ##__VA_ARGS__)
#define surfman_error(fmt, ...) \
    fprintf(stderr, SURFMAN_FLAG "error: " fmt "\n", ##__VA_ARGS__)

/* Display on which a surface is drawn currently. */

struct lfb_state {
    unsigned int width;
    unsigned int height;
    unsigned int linesize;
    FramebufferFormat format;
    hwaddr addr;
};
struct SurfmanState {
    struct DisplayState *ds;
    dmbus_service_t dmbus_service;
    MemoryRegion *vram;         // VRAM region hackishly recovered.
    uint8_t *vram_ptr;		// Pointer to the vram mapped in the mapcache.
    struct lfb_state current;
};

static inline FramebufferFormat surfman_get_format(pixman_format_code_t format)
{
    switch (format) {
        /* 32b */
        case PIXMAN_a8r8g8b8:
        case PIXMAN_x8r8g8b8:
            return FRAMEBUFFER_FORMAT_BGRX8888;	// TODO: Surfman does not care ?!
        case PIXMAN_a8b8g8r8:
        case PIXMAN_x8b8g8r8:
            return 0;
        case PIXMAN_b8g8r8a8:
        case PIXMAN_b8g8r8x8:
            return FRAMEBUFFER_FORMAT_BGRX8888;
        case PIXMAN_x2r10g10b10:
        case PIXMAN_a2r10g10b10:
        case PIXMAN_x2b10g10r10:
        case PIXMAN_a2b10g10r10:
            return 0;

    /* 24bpp formats */
        case PIXMAN_r8g8b8:
            return FRAMEBUFFER_FORMAT_RGB888;
        case PIXMAN_b8g8r8:
            return FRAMEBUFFER_FORMAT_BGR888;

    /* 16bpp formats */
        case PIXMAN_r5g6b5:
            return FRAMEBUFFER_FORMAT_RGB565;
        case PIXMAN_b5g6r5:
            return FRAMEBUFFER_FORMAT_BGR565;
        case PIXMAN_a1r5g5b5:
        case PIXMAN_x1r5g5b5:
            return FRAMEBUFFER_FORMAT_RGB555;
        case PIXMAN_a1b5g5r5:
        case PIXMAN_x1b5g5r5:
            return FRAMEBUFFER_FORMAT_BGR555;

        case PIXMAN_a4r4g4b4:
        case PIXMAN_x4r4g4b4:
        case PIXMAN_a4b4g4r4:
        case PIXMAN_x4b4g4r4:
            return 0;

        /* 8bpp formats */
        case PIXMAN_a8:
        case PIXMAN_r3g3b2:
        case PIXMAN_b2g3r3:
        case PIXMAN_a2r2g2b2:
        case PIXMAN_a2b2g2r2:
        case PIXMAN_c8:
        case PIXMAN_g8:
        case PIXMAN_x4a4:
//        case PIXMAN_x4c4:
//        case PIXMAN_x4g4:

        /* 4bpp formats */
        case PIXMAN_a4:
        case PIXMAN_r1g2b1:
        case PIXMAN_b1g2r1:
        case PIXMAN_a1r1g1b1:
        case PIXMAN_a1b1g1r1:
        case PIXMAN_c4:
        case PIXMAN_g4:

        /* 1bpp formats */
        case PIXMAN_a1:
        case PIXMAN_g1:

        /* YUV formats */
        case PIXMAN_yuy2:
        case PIXMAN_yv12:
        default:
            return 0;
    }
}

#endif /* !_SURFMAN_H_ */

