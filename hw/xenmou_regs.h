#ifndef XENMOU_REGS_H_
# define XENMOU_REGS_H_

/* Global Registers */
#define XMOU_GLOBAL_BASE        0x000000

#define XMOU_MAGIC              0x000000
#define XMOU_REV                0x000004
#define XMOU_CONTROL            0x00100
#define XMOU_EVENT_SIZE         0x00104
#define XMOU_EVENT_NPAGES       0x00108
#define XMOU_ACCELERATION       0x0010C
#define XMOU_ISR                0x00110
#define XMOU_CONF_SIZE          0x00114
#define XMOU_CLIENT_REV         0x00118

#define XMOU_MAGIC_VALUE        0x584D4F55

/* XMOU_CONTROL bits */
#define XMOU_CONTROL_XMOU_EN    0x00000001
#define XMOU_CONTROL_INT_EN     0x00000002
#define XMOU_CONTROL_XMOU_V2    0x00000004

/* XMOU_ISR bits */
#define XMOU_ISR_INT            0x00000001

/* Event Registers */
#define XMOU_EVENT_BASE         0x10000

#define XMOU_READ_PTR           0x00000
#define XMOU_WRITE_PTR          0x00004

#endif /* !XENMOU_REGS_H_ */
