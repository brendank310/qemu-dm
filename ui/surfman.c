/*
 * QEMU graphical console
 *
 * Copyright (c) 2015, Assured Information Security, Inc.
 * Copyright (c) 2012, Citrix Systems
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "surfman.h"

/**
 * HACK: 
 * When the video RAM isn't shared between the host and the guest, the LFB (linear framebuffer) will start
 * at a memory address appropriate for a VGA graphics card. This is the offset into VRAM at which the LFB
 * will be located.
 * */
#define HIDDEN_LFB_OFFSET   0xa00000

/**
 * The state of the Surfman DCL ("display plugin").
 * This is initialized when the graphic console hardware is initialized.
 */
static struct SurfmanState *ss = NULL;

/**
 * Maintain the Surfman display state.
 * Called every DisplayChangeListener::gui_timer_interval.
 *
 * @param ds The state of the Surfman display to be applied. (Not currently used.)
 */
static void surfman_dpy_refresh(struct DisplayState *ds)
{
    (void) ds;

    //Maintain the state of the framebuffer per our emulated hardware.
    vga_hw_update();
}

/**
 * Update the Surfman-managed display. 
 * This should be called whenever a portion of the framebuffer (Surface) of DisplayState /s/ has changed. 
 *
 * @param ds The state of the Surfman-managed display.
 * @param x, y, w, h The rectangular bounds of the section of the display that requires an update.
 */
static void surfman_dpy_gfx_update(struct DisplayState *ds, int x, int y, int w, int h)
{
    //In many cases, the framebuffer is directly shared with Surfman (and the integrated graphics
    //hardware), so the update is handled "in hardware", and we don't need to copy anything.
    
    //In rarer cases (e.g. text mode), QEMU manages the contents of the screen directly, rather
    //than allowing the HVM guest to manage the framebuffer contents. In these cases, we'll need
    //to copy QEMU's buffer into the guest's VRAM framebuffer-- in other words, to the location
    //where Surfman is looking. (This is similar to what the hardware does in modern text mode
    //impelementations-- the equivalent of rendering the glyph data into a scanout buffer.)
    if (!is_buffer_shared(ds->surface)) {
        
        //Get the "stride" for each line of the target image.
        unsigned int linesize = ds_get_linesize(ds);     // Somehow, the pixman_image_t is 64b aligned ... always?

        //And get the byte depth, which tells us how many bytes we'll need to copy 
        //per pixel in the rectangle's width.
        unsigned int Bpp = ds_get_bytes_per_pixel(ds);

        //Compute the location of the VRAM segment we want to update. This factors in:
        // -The location of the LFB (linear framebuffer) in the emulated VRAM; and
        // -The location of the target rectangle in the emulated LFB.
        uint8_t *dest = ss->vram_ptr + HIDDEN_LFB_OFFSET + y * linesize + x * Bpp;

        //Compute the location of the QEMU buffer we want to copy /from/. This location
        //is only computed in terms of the rectangle's "offset" in the source image.
        uint8_t *src = ds_get_data(ds) + y * linesize + x * Bpp;
        unsigned int i;

        surfman_debug("update vram:%#"HWADDR_PRIx" src:%p dest:%p %d,%d (%dx%d).",
                      ss->vram->addr, src, dest, x, y, w, h);

        //Finally, manually copy each line of the rectangle from the QEMU buffer
        //to the surfman-watched VRAM.
        for (i = 0; i < h; ++i) {
            memcpy(dest, src, w * Bpp);
            dest += linesize;
            src += linesize;
        }
    }
}

/**
 * Update the Surfman UI's knowledge of the LFB (linear framebuffer) bounds. 
 * This effectively lets the plugin know where the video data will be in the
 * emualted VRAM, and how it will be formatted.
 */
static void surfman_lfb_state_save(struct SurfmanState *ss)
{
    struct DisplayState *ds = ss->ds;

    ss->current.width = ds_get_width(ds);
    ss->current.height = ds_get_height(ds);
    ss->current.linesize = ds_get_linesize(ds);
    ss->current.format = surfman_get_format(ds_get_format(ds));
    ss->current.addr = ss->vram->addr;
}

/**
 * Returns a non-zero value iff the given DisplayState contains a different LFB configuration
 * (i.e. size, format and/or address) than the LFB state provided.
 */
static int surfman_lfb_state_compare(const struct lfb_state *s, struct DisplayState *ds)
{
    hwaddr lfb_addr;

    //Determine the address of the LFB in VRAM. This is either the start of VRAM 
    //(when the LFB is shared), or at an offset into VRAM when QEMU is performing its own rendering.
    lfb_addr = is_buffer_shared(ds->surface) ? ss->vram->addr : ss->vram->addr + HIDDEN_LFB_OFFSET;

    //Determine if any of the DisplayState parameters differ from those of the known LFB.
    return !((s->width == ds_get_width(ds)) &&
             (s->height == ds_get_height(ds)) &&
             (s->linesize == ds_get_linesize(ds)) &&
             (s->format == surfman_get_format(ds_get_format(ds))) &&
             (s->addr == lfb_addr));
}

/**
 * Inform Surfman of a change in the framebuffer to be displayed. This handles cases in which the 
 * framebuffer is moved, reformatted, or resized.
 */ 
static void surfman_dpy_gfx_resize(struct DisplayState *ds)
{
    struct msg_display_resize msg;
    struct msg_empty_reply reply;

    //If Surfman is already correctly set up to display the relevant framebuffer,
    //skip sending it the RPC call; we're done!
    if (!surfman_lfb_state_compare(&ss->current, ds)) {
        return;
    }

    //Build the RPC message that informs Surfman of the change in display state.
    
    //The DisplayID originally provided a mechanism for QEMU to specify the target monitor for the
    //given display. Unfortunately, Surfman does not currently support multi-monitor. Since we're
    //currently always targeting a single monitor/surface, we'll leave this at zero-- the first 
    //(and only) monitor.
    msg.DisplayID = 0;  /* Not supported anyway. */

    //Include the LFB size...
    msg.width = ds_get_width(ds);
    msg.height = ds_get_height(ds);
    msg.linesize = ds_get_linesize(ds);

    //... and pixel format. Note that we attempt to convert from a pixman pixelformat to a 
    //surfman pixel format. This is a potentially lossy step, as Surfman does not support
    //certain color formats.
    msg.format = surfman_get_format(ds_get_format(ds));

    //If we weren't able to map the LFB's pixel format to a Surfman-supported format,
    //throw an error and abort. Ideally, we'd always convert the output to a surfman-supported
    //format; but this isn't always possible. Instead, we use VBE (the VGA bios extensions) to
    //only advertise hardware support for Surfman-supported formats-- this should help to make
    //this an an exception, rather than a common case.Could not recover VRAM MemoryRegion
    if (!msg.format) {
        surfman_error("Unsupported pixel format `%#x'.", ds_get_format(ds));
        return;
    }

    //Specify the offset at which the LFB exists inside the provided VRAM.
    //Since we're providing the address of the LFB directly below (even when the LFB
    //is embedded inside of our emulated VRAM), this offset will always be zero.
    //
    //It might be cleaner to conditionally provide the HIDDEN_LFB_OFFSET here, but having
    //a discrete RPC argument for the offset seems needless, and may go away.
    msg.fb_offset = 0;  

    //If the guest is performing the rendering, rather than having QEMU perform rendering...
    if (is_buffer_shared(ds->surface)) {
        //... then the LFB is accessible at the start of VRAM..
        msg.lfb_addr = ss->vram->addr;

        //... and Surfman should be able to see the VRAM at all times.
        //(This allow it to determine which parts of the surface have changed, 
        // and thus need to be updated.)
        msg.lfb_traceable = 1;

    } 
    //Otherwise, QEMU has a hand in rendering (e.g. in text mode), and...
    else {
        //... the LFB is accessible at an offset into the VRAM...
        msg.lfb_addr = ss->vram->addr + HIDDEN_LFB_OFFSET;

        //... and Surfman shouldn't try to make determinations as to what's 
        //been changed.
        msg.lfb_traceable = 0;
    }

    //Log the change...
    surfman_info("resize %dx%d:%d -> %dx%d:%d%s %s %s.",
                 ss->current.width, ss->current.height, ss->current.linesize,
                 msg.width, msg.height, msg.linesize,
                 msg.lfb_addr == ss->vram->addr ? " (shared)": "",
                 ds->have_text ? "have text" : "",
                 ds->have_gfx ? "have gfx" : "");

    //... send our message to surfman via the device-management bus...
    dmbus_send(ss->dmbus_service, DMBUS_MSG_DISPLAY_RESIZE, &msg, sizeof (msg));
    dmbus_sync_recv(ss->dmbus_service, DMBUS_MSG_EMPTY_REPLY, &reply, sizeof (reply));

    //... and keep track of the change internally. 
    surfman_lfb_state_save(ss);
}

/**
 * Notify Surfman of a change in the LFB address.
 * From Surfman's perspective, this is the same event as a resize; so we recycle that RPC.
 */
static void surfman_dpy_gfx_setdata(struct DisplayState *ds)
{
    surfman_dpy_gfx_resize(ds);
}

/**
 * Request the display size limitations (e.g. the maximum size that can be displayed on a monitor)
 * from Surfman via the DMBUS. (Be careful: this call is synchonous, and thus should be called
 * infrequently, lest we slow down the guest.)
 *
 * Note: If the VBE resolution patches are applied, this method is used to determine the
 * "EDID-reported" resolution reported by the VGA Bios Extensions.
 *
 * @param ds The current state of the display provider. (Not currently used)
 * @param width_max, height_max If information about the maximum width/height is  
 *      available, these out-args will be updated.
 * @param stride_alignment If information about the monitor's "stride" is avilable,
 *      this out argument will be updated with the relevant alignment.
 */ 
static void surfman_dpy_get_display_limits(DisplayState *ds,
                                           unsigned int *width_max, unsigned int *height_max,
                                           unsigned int *stride_alignment)
{
    struct msg_display_get_info msg;
    struct msg_display_info reply;

    (void) ds;

    //Retreive the resolution of the first monitor.
    //FIXME: This should not use only the first monitor! Ideally, this should be replaced
    //with a different RPC which allows Surfman to /select/ which resolution should be used.
    msg.DisplayID = 0;
    dmbus_send(ss->dmbus_service, DMBUS_MSG_DISPLAY_GET_INFO, &msg, sizeof (msg));
    dmbus_sync_recv(ss->dmbus_service, DMBUS_MSG_DISPLAY_INFO, &reply, sizeof (reply));

    //If we obtained any information about the target monitor, update the relevant out arguments.
    if (width_max)
        *width_max = reply.max_xres;
    if (height_max)
        *height_max = reply.max_yres;
    if (stride_alignment)
        *stride_alignment = reply.align;

    surfman_debug("display_limits: %ux%u stride aligned on %u.", *width_max, *height_max, *stride_alignment);
}

/**
 * An event handler which should be called each time surfman reconnects.
 */ 
static void surfman_on_reconnect(void *opaque)
{
    (void) opaque;
    surfman_dpy_gfx_resize(ss->ds);
}

//NOTE: The following functions are not implemened; instead, default display functions are used.
// -static void surfman_dpy_gfx_copy(struct DisplayState *s, int src_x, int src_y, int dst_x, int dst_y, int w, int h);
// -static void surfman_dpy_text_cursor(struct DisplayState *s, int x, int y);
// -static void surfman_dpy_text_resize(struct DisplayState *s, int w, int h);
// -static void surfman_dpy_text_update(struct DisplayState *s, int x, int y, int w, int h);Could not recover VRAM MemoryRegion
// -static void surfman_dpy_mouse_set(struct DisplayState *s, int x, int y, int on);
// -static void surfman_dpy_cursor_define(struct DisplayState *s, QEMUCursor *cursor);

/**
 * Set up the RPC connection so we're notified on a surfman reconnect.
 * TODO: Additional RPC events should likely be handled, long term-- including resolution updates.
 */ 
static struct dmbus_ops surfman_dmbus_ops = {
    .dom0_input_event = NULL,
    .dom0_input_pvm = NULL,
    .input_config = NULL,
    .input_config_reset = NULL,
    .display_info = NULL,
    .display_edid = NULL,
    .reconnect = surfman_on_reconnect
};

/**
 * Initializes a Surfman multiplexed display, creating the DisplayChangeListener object
 * that tracks display events.
 */ 
void surfman_display_init(DisplayState *ds)
{
    DisplayChangeListener *dcl;

    surfman_info("Initialize Surfman display.");

    //Create the SurfmanState "ss" object, which compartmentalizes the state of the Surfman
    //display plugin...
    ss = g_malloc0(sizeof (*ss));
    ss->ds = ds;

    //... populate its internal reference to the guest's VRAM...
    //(Note again that this should not be used to get references to 
    // the VRAM for modification by QEMU.)
    ss->vram = xen_get_framebuffer();
    if (!ss->vram) {
        surfman_error("Could not recover VRAM MemoryRegion.");
        goto err_vram;
    }

    //... and get a QEMU-accesible pointer to the guest's VRAM. This is used by QEMU to update the video ram,
    //    whenever the emulated hardware would be touching the framebuffer-- e.g. in text mode.
    ss->vram_ptr = xen_get_framebuffer_ptr();

    //Connect to Surfman itself via the device management bus. This will open the connection used to
    //invoke remote procedures.
    ss->dmbus_service = dmbus_service_connect(DMBUS_SERVICE_SURFMAN, DEVICE_TYPE_VESA, &surfman_dmbus_ops, ss);
    if (!ss->dmbus_service) {
        surfman_error("Could not initialize dmbus.");
        goto err_dmbus;
    }

    //Finally, bind each of the actual display "change handlers"
    //that actually form the core display API.
    dcl = g_malloc0(sizeof (*dcl));
    dcl->idle = 0;
    dcl->dpy_refresh = surfman_dpy_refresh;
    dcl->dpy_gfx_update = surfman_dpy_gfx_update;
    dcl->dpy_gfx_resize = surfman_dpy_gfx_resize;
    dcl->dpy_gfx_setdata = surfman_dpy_gfx_setdata;
    dcl->dpy_get_display_limits = surfman_dpy_get_display_limits;
    register_displaychangelistener(ds, dcl);

    return;

err_dmbus:
err_vram:
    g_free(ss);
}

