#include <linux/input.h>
#include <stdlib.h>
#include "ui/console.h"
#include "qemu-common.h"
#include "xen-input.h"
#include "sysemu/sysemu.h"

#define DEBUG_INPUT

#ifdef DEBUG_INPUT
# define DEBUG_MSG(...) printf("XenInput:" __VA_ARGS__)
#else
# define DEBUG_MSG(...)
#endif

/* Following defines are only temporary measure
 * They should come from input.h
 */

#define ABS_MT_SLOT     0x2f /* MT slot being modified */
#define ABS_MT_PRESSURE 0x3a /* Pressure on contact area */
#define ABS_MT_DISTANCE 0x3b /* Contact hover distance */

/* These are used to set a slot with xenmou */
#define EV_DEV          0x6
#define DEV_SET         0x1

struct xen_state {
    int x;
    int y;
    int z;
    int count;
};

typedef struct XenInput {
    dmbus_service_t service;
    int abs_enabled;
    xen_input_direct_event_cb_t direct_event_handler;
    void *direct_event_opaque;
    xen_input_set_slot_cb_t set_slot_handler;
    xen_input_config_cb_t config_handler;
    xen_input_config_reset_cb_t config_reset_handler;
    void *opaque;
    QEMUPutLEDEntry *leds;
} XenInput;

static XenInput input = { .service = 0 };

static void input_inject_pause_key(void)
{
    kbd_put_keycode(0xE1);
    kbd_put_keycode(0x1D);
    kbd_put_keycode(0x45);

    kbd_put_keycode(0xE1);
    kbd_put_keycode(0x9D);
    kbd_put_keycode(0xC5);
}

static void input_key_inject(int code, uint32_t keycode)
{
    int first = 0;

    if (keycode == KEY_PAUSE) {
        if (code != 0) {
            input_inject_pause_key();
        }
        return;
    }

    switch (keycode) {
    /* XCP-367 */
    case KEY_MUHENKAN:
        keycode = 0x7b;
        break;
    case KEY_HENKAN:
        keycode = 0x79;
        break;
    case KEY_KATAKANAHIRAGANA:
        keycode = 0x70;
        break;
    case KEY_YEN:
        keycode = 0x7d;
        break;
    case KEY_RO:
        keycode = 0x73;
        break;
    case KEY_F11:
        keycode = 0X57;
        break;                    /* F11 */
    case KEY_F12:
        keycode = 0X58;
        break;                    /* F12 */
    case KEY_INSERT:
        keycode = 0X52;
        first = 0xe0;
        break;
    case KEY_HOME:
        keycode = 0X47;
        first = 0xe0;
        break;
    case KEY_PAGEUP:
        keycode = 0X49;
        first = 0xe0;
        break;
    case KEY_DELETE:
        keycode = 0X53;
        first = 0xe0;
        break;
    case KEY_END:
        keycode = 0X4F;
        first = 0xe0;
        break;
    case KEY_PAGEDOWN:
        keycode = 0x51;
        first = 0xe0;
        break;
    case KEY_UP:
        keycode = 0X48;
        first = 0xe0;
        break;
    case KEY_LEFT:
        keycode = 0X4B;
        first = 0xe0;
        break;
    case KEY_DOWN:
        keycode = 0X50;
        first = 0xe0;
        break;
    case KEY_RIGHT:
        keycode = 0X4D;
        first = 0xe0;
        break;
    case KEY_RIGHTALT:
        keycode = 0x38;
        first = 0xe0;
        break;
    case KEY_LEFTMETA:
        keycode = 0x5B;
        first = 0xe0;
        break;
    case KEY_RIGHTMETA:
        keycode = 0x5C;
        first = 0xe0;
        break;
    case KEY_RIGHTCTRL:
        keycode = 0x1d;
        first = 0xe0;
        break;
    case KEY_PROG1:
        keycode = 0x1;
        first = 0xe0;
        break;
    case KEY_SYSRQ:
        keycode = 0x37;
        first = 0xe0;
        break;
    case KEY_MUTE:
        keycode = 0x20;
        first = 0xe0;
        break;
    case KEY_VOLUMEDOWN:
        keycode = 0x2e;
        first = 0xe0;
        break;
    case KEY_VOLUMEUP:
        keycode = 0x30;
        first = 0xe0;
        break;
    case KEY_COMPOSE:
        keycode = 0x5D;
        first = 0xe0;
        break;
    case KEY_KPENTER:
        keycode = 0x1C;
        first = 0xe0;
        break;
    case KEY_KPSLASH:
        keycode = 0x35;
        first = 0xe0;
        break;
    }

    if (first) {
        kbd_put_keycode(first);
    }

    if (keycode < 0x80) {
        if (code == 0) {
            kbd_put_keycode(keycode | 0x80);
        } else {
            kbd_put_keycode(keycode & 0x7f);
        }
    }
}

static int input_demultitouch(uint16_t *type, uint16_t *code, int32_t *value)
{
    /* TODO: WORST THING EVER
     * Do not iniatialize static var */
    static int slot = 0;
    static int pressed = 0;

    if ((*type == EV_SYN) && (*code == SYN_REPORT)) {
        slot = 0;
    }

    if (*type == EV_ABS) {
        switch (*code) {
        case ABS_MT_POSITION_X:
            *code = ABS_X;
            break;
        case ABS_MT_POSITION_Y:
            *code = ABS_Y;
            break;
        case ABS_MT_TRACKING_ID:
            if (slot == 0) {
                int nowpressed = (*value != 0xffffffff);

                if (pressed != nowpressed) {
                    pressed = nowpressed;
                    *type = EV_KEY;
                    *code = BTN_LEFT;
                    *value = pressed << 1;
                    return true;
                }
            }
            return false;
        case ABS_MT_SLOT:
            slot = *value;
            /* Fall through */
        case ABS_MT_TOUCH_MAJOR:
        case ABS_MT_TOUCH_MINOR:
        case ABS_MT_WIDTH_MAJOR:
        case ABS_MT_WIDTH_MINOR:
        case ABS_MT_ORIENTATION:
        case ABS_MT_TOOL_TYPE:
        case ABS_MT_BLOB_ID:
        case ABS_MT_PRESSURE:
        case ABS_MT_DISTANCE:
            return false;
        }

        return (slot == 0);
    }

    return true;
}

static void input_set_slot(XenInput *x, uint8_t slot)
{
    if (x->set_slot_handler) {
        x->set_slot_handler(x->opaque, slot);
    } else {
        DEBUG_MSG("no set slot handler\n");
    }
}

static void input_event(void *opaque, uint16_t type,
                        uint16_t code, int32_t value)
{
    XenInput *x = opaque;
    static int mouse_button_state = 0;
    static int mouse_key = 0;
    static struct xen_state absolute = { 0, 0, 0, 0 };
    static struct xen_state relative = { 0, 0, 0, 0 };
    static int use_abs = 0;
    static int deferbutton = 0;
    static int slot = 0;


    if (type == EV_DEV && code == DEV_SET) {
        slot = value;
        input_set_slot(x, slot);
    }

    if (slot >= 0 && x->direct_event_handler) {
        DEBUG_MSG("direct event handler\n");
        x->direct_event_handler(x->direct_event_opaque, type, code, value);
        return;
    }

    if (!input_demultitouch(&type, &code, &value)) {
        return;
    }

    switch (type) {
    case EV_KEY:
        if (code >= BTN_MOUSE) {
            switch (code) {
            case BTN_LEFT:
                mouse_key = MOUSE_EVENT_LBUTTON;
                break;
            case BTN_RIGHT:
                mouse_key = MOUSE_EVENT_RBUTTON;
                break;
            case BTN_MIDDLE:
                mouse_key = MOUSE_EVENT_MBUTTON;
                break;
            }

            if (value == 2) { /* The button will be send later */
                deferbutton = 1;
            } else if (!value) { /* The button was released */
                mouse_button_state &= ~mouse_key;
            } else {
                mouse_button_state |= mouse_key;
            }
        } else {
            input_key_inject(value, code);
        }
        break;
    /* Mouse relative motion */
    case EV_REL:
        use_abs = 0;
        switch (code) {
        case REL_X:
            relative.x = value;
            break;
        case REL_Y:
            relative.y = value;
            break;
        case REL_WHEEL:
            relative.z = -value;
            break;
        }
        relative.count++;
        break;
    /* Mouse absolute motion */
    case EV_ABS:
        use_abs = 1;
        switch (code) {
        case ABS_X:
            absolute.x = value;
            break;
        case ABS_Y:
            absolute.y = value;
            break;
        case ABS_WHEEL:
            absolute.z = -value;
        }
        absolute.count++;
        break;
    case EV_SYN:
        if (code != SYN_REPORT) { /* Do anything if it's not a sync report */
            break;
        }

        if (relative.count || (!absolute.count && !use_abs && mouse_key)) {
            kbd_mouse_event(relative.x, relative.y,
                            relative.z, mouse_button_state);
            relative.count = 0;
            relative.x = relative.y = relative.z = 0;
        }
        if (absolute.count || (!relative.count && use_abs && mouse_key)) {
            if (deferbutton) {
                if (absolute.count) {
                    kbd_mouse_event_absolute(absolute.x, absolute.y,
                                             absolute.z, mouse_button_state);
                    absolute.count = 0;
                }
                mouse_button_state |= mouse_key;
            }
            kbd_mouse_event_absolute(absolute.x, absolute.y,
                                     absolute.z, mouse_button_state);
            absolute.count = 0;
            absolute.z = 0;
        }
        mouse_key = 0;
        deferbutton = 0;

        break;
    }
}

static void input_reconnect(void *opaque)
{
    XenInput *x = opaque;

    xen_input_abs_enabled(x->abs_enabled);
}

static void xen_input_config(void *opaque, InputConfig *c)
{
    XenInput *x = opaque;

    if (x->config_handler) {
        x->config_handler(x->opaque, c);
    } else {
        DEBUG_MSG("no config handler\n");
    }
}

static void xen_input_send_ledcode(void *opaque, int ledstate)
{
    XenInput *x = opaque;
    struct msg_switcher_leds msg;

    DEBUG_MSG("send led keycode 0x%x\n", ledstate);
    msg.led_code = ledstate;

    dmbus_send(x->service, DMBUS_MSG_SWITCHER_LEDS, &msg, sizeof(msg));
}

static void xen_input_config_reset(void *opaque, uint8_t slot)
{
    XenInput *x = opaque;

    if (x->config_reset_handler) {
        x->config_reset_handler(x->opaque, slot);
    } else {
        DEBUG_MSG("no config reset handler\n");
    }
}

static void xen_input_wakeup(void)
{
    if (runstate_check(RUN_STATE_SUSPENDED)) {
        qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER);
    } else {
        DEBUG_MSG("wakeup requested but state != suspended\n");
    }
}

const struct dmbus_ops input_ops = {
    .dom0_input_event = input_event,
    .reconnect = input_reconnect,
    .input_config = xen_input_config,
    .input_config_reset = xen_input_config_reset,
    .input_wakeup = xen_input_wakeup,
};

void xen_input_init(void)
{
    printf("initialize input\n");
    input.service = dmbus_service_connect(DMBUS_SERVICE_INPUT,
                                          DEVICE_TYPE_INPUT,
                                          &input_ops, &input);
    if (!input.service) {
        fprintf(stderr, "unable to connect to input server\n");
        exit(1);
    }

    input.leds = qemu_add_led_event_handler(xen_input_send_ledcode, &input);
}

void xen_input_abs_enabled(int enabled)
{
    struct msg_switcher_abs msg;

    input.abs_enabled = enabled;
    msg.enabled = enabled;
    /* FIXME: check dmbus_send return */
    dmbus_send(input.service, DMBUS_MSG_SWITCHER_ABS, &msg, sizeof(msg));
}

void xen_input_set_direct_event_handler(xen_input_direct_event_cb_t handler,
                                        void *opaque)
{
    /* If handler is NULL, it means removing */
    if (!handler) {
        input.direct_event_handler = NULL;
        input.direct_event_opaque = NULL;
    } else {
        input.direct_event_handler = handler;
        input.direct_event_opaque = opaque;
    }
}

void xen_input_set_handlers(xen_input_set_slot_cb_t slot_handler,
                            xen_input_config_cb_t config_handler,
                            xen_input_config_reset_cb_t config_reset_handler,
                            void *opaque)
{
    input.set_slot_handler = slot_handler;
    input.config_handler = config_handler;
    input.config_reset_handler = config_reset_handler;
    input.opaque = opaque;
}

int32_t xen_input_send_shutdown(int32_t reason)
{
  int32_t rc;
  struct msg_switcher_shutdown msg;

  msg.reason = reason;

  rc = dmbus_send(input.service, DMBUS_MSG_SWITCHER_SHUTDOWN, &msg,
                  sizeof(struct msg_switcher_shutdown));

  return rc;
}
