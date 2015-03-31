#ifndef XENMOU_H_
# define XENMOU_H_

#include "xenmou_regs.h"

#include "xen-dmbus.h"
#include "ui/xen-input.h"

#define ABSOLUTE                0x0001
#define RELATIVE                0x0002
#define FENCE                   0x0004
#define LEFT_BUTTON_DOW         0x0008
#define LEFT_BUTTON_U           0x0010
#define RIGHT_BUTTON_DOW        0x0020
#define RIGHT_BUTTON_U          0x0040
#define MIDDLE_BUTTON_DOW       0x0080
#define MIDDLE_BUTTON_U         0x0100

#define HWHEEL                  0x0200
#define VWHEEL                  0x0400

#define EVENT_N_BYTES           8
#define EVENT_N_BITS            (8 * EVENT_N_BYTES)

#define XENMOU_CURRENT_REV      0x2

#endif /* !XENMOU_H_ */
