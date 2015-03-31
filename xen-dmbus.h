#ifndef XEN_DMBUS_H_
# define XEN_DMBUS_H_

#include <libdmbus.h>

typedef void *dmbus_service_t;

struct dmbus_ops {
  void (*dom0_input_event)(void *opaque, uint16_t type,
                           uint16_t code, int32_t value);
  void (*dom0_input_pvm)(void *opaque, uint32_t domid);
  void (*input_config)(void *opaque, InputConfig *c);
  void (*input_config_reset)(void *opaque, uint8_t slot);
  void (*input_wakeup)(void);
  void (*display_info)(void *opaque, uint8_t DisplayID, uint16_t max_xres,
                       uint16_t max_yres, uint16_t align);
  void (*display_edid)(void *opaque, uint8_t DisplayID, uint8_t *buff);
  void (*reconnect)(void *opaque);
};

dmbus_service_t dmbus_service_connect(int service, DeviceType devtype,
                                      const struct dmbus_ops *ops,
                                      void *opaque);
void dmbus_service_disconnect(dmbus_service_t service);
int dmbus_sync_recv(dmbus_service_t service, int type,
                    void *data, size_t size);
int dmbus_send(dmbus_service_t service, int msgtype, void *data, size_t len);

#endif /* XEN_DMBUS_H_ */
