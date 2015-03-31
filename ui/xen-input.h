#ifndef UI_XEN_INPUT_H_
# define UI_XEN_INPUT_H_

# include "xen-dmbus.h"

void xen_input_init(void);
void xen_input_abs_enabled(int enabled);

typedef void (*xen_input_direct_event_cb_t)(void *opaque,
                                            uint16_t type,
                                            uint16_t code,
                                            int32_t value);
typedef void (*xen_input_set_slot_cb_t)(void *opaque, uint8_t slot);
typedef void (*xen_input_config_cb_t)(void *opaque, InputConfig *c);
typedef void (*xen_input_config_reset_cb_t)(void *opaque, uint8_t slot);


void xen_input_set_direct_event_handler(xen_input_direct_event_cb_t handler,
                                        void *opaque);

/* This function is ugly but I have no idea to avoid some xenmou code in input
 * file */
void xen_input_set_handlers(xen_input_set_slot_cb_t slot_handler,
                            xen_input_config_cb_t config_handler,
                            xen_input_config_reset_cb_t config_reset_handler,
                            void *opaque);

int32_t xen_input_send_shutdown(int32_t reason);

#endif /* !UI_XEN_INPUT_H_ */
