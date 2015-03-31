/*
 * ATAPI guest commands translation.
 *
 * Copyright (C) 2014 Citrix Systems Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef ATAPI_PT_H_
# define ATAPI_PT_H_

/* Use for sense comand and CDROM management */
# include <linux/cdrom.h>
# include <linux/bsg.h>
/* useful for thread management... (TODO: push it in the Block Driver */
# include <pthread.h>
/* use IOCTL to send for communication between the main processus and the
 * block driver socketpair */
# include <linux/ioctl.h>
/* use for socketpair */
# include <sys/types.h>
# include <sys/socket.h>
/* Qemu EventNotifier
 * TODO: Remove socketpair */
# include "qemu/event_notifier.h"

/* The generic packet command opcodes for CD/DVD Logical Units,
 * From Table 57 of the SFF8090 Ver. 3 (Mt. Fuji) draft standard. */
# define GPCMD_BLANK                              0xa1
# define GPCMD_CLOSE_TRACK                        0x5b
# define GPCMD_FLUSH_CACHE                        0x35
# define GPCMD_FORMAT_UNIT                        0x04
# define GPCMD_GET_CONFIGURATION                  0x46
# define GPCMD_GET_EVENT_STATUS_NOTIFICATION      0x4a
# define GPCMD_GET_PERFORMANCE                    0xac
# define GPCMD_INQUIRY                            0x12
# define GPCMD_LOAD_UNLOAD                        0xa6
# define GPCMD_MECHANISM_STATUS                   0xbd
# define GPCMD_MODE_SELECT_10                     0x55
# define GPCMD_MODE_SENSE_10                      0x5a
# define GPCMD_PAUSE_RESUME                       0x4b
# define GPCMD_PLAY_AUDIO_10                      0x45
# define GPCMD_PLAY_AUDIO_MSF                     0x47
# define GPCMD_PLAY_AUDIO_TI                      0x48
# define GPCMD_PLAY_CD                            0xbc
# define GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL       0x1e
# define GPCMD_READ_10                            0x28
# define GPCMD_READ_12                            0xa8
# define GPCMD_READ_BUFFER                        0x3c
# define GPCMD_READ_BUFFER_CAPACITY               0x5c
# define GPCMD_READ_CDVD_CAPACITY                 0x25
# define GPCMD_READ_CD                            0xbe
# define GPCMD_READ_CD_MSF                        0xb9
# define GPCMD_READ_DISC_INFO                     0x51
# define GPCMD_READ_DVD_STRUCTURE                 0xad
# define GPCMD_READ_FORMAT_CAPACITIES             0x23
# define GPCMD_READ_HEADER                        0x44
# define GPCMD_READ_TRACK_RZONE_INFO              0x52
# define GPCMD_READ_SUBCHANNEL                    0x42
# define GPCMD_READ_TOC_PMA_ATIP                  0x43
# define GPCMD_REPAIR_RZONE_TRACK                 0x58
# define GPCMD_REPORT_KEY                         0xa4
# define GPCMD_REQUEST_SENSE                      0x03
# define GPCMD_RESERVE_RZONE_TRACK                0x53
# define GPCMD_SEND_CUE_SHEET                     0x5d
# define GPCMD_SCAN                               0xba
# define GPCMD_SEEK                               0x2b
# define GPCMD_SEND_DVD_STRUCTURE                 0xbf
# define GPCMD_SEND_EVENT                         0xa2
# define GPCMD_SEND_KEY                           0xa3
# define GPCMD_SEND_OPC                           0x54
# define GPCMD_SET_READ_AHEAD                     0xa7
# define GPCMD_SET_SPEED                          0xbb
# define GPCMD_SET_STREAMING                      0xb6
# define GPCMD_START_STOP_UNIT                    0x1b
# define GPCMD_STOP_PLAY_SCAN                     0x4e
# define GPCMD_TEST_UNIT_READY                    0x00
# define GPCMD_VERIFY_10                          0x2f
# define GPCMD_WRITE_10                           0x2a
# define GPCMD_WRITE_12                           0xaa
# define GPCMD_WRITE_AND_VERIFY_10                0x2e
# define GPCMD_WRITE_BUFFER                       0x3b

/* Sense keys */
#define SENSE_NONE              0
#define SENSE_RECOVERED_ERROR   1
#define SENSE_NOT_READY         2
#define SENSE_MEDIUM_ERROR      3
#define SENSE_HARDWARE_ERROR    4
#define SENSE_ILLEGAL_REQUEST   5
#define SENSE_UNIT_ATTENTION    6
#define SENSE_DATA_PROTECT      7
#define SENSE_BLANK_CHECK       8
#define SENSE_VENDOR_SPECIFIC   9
#define SENSE_COPY_ABORTED     10
#define SENSE_ABORTED_COMMAND  11
#define SENSE_VOLUME_OVERFLOW  13
#define SENSE_MISCOMPARE       14

/* same constants as bochs */
#define ASC_NONE                             0x00
#define ASC_READ_ERROR                       0x11
#define ASC_ILLEGAL_OPCODE                   0x20
#define ASC_LOGICAL_BLOCK_OOR                0x21
#define ASC_INV_FIELD_IN_CMD_PACKET          0x24
#define ASC_MEDIUM_MAY_HAVE_CHANGED          0x28
#define ASC_INCOMPATIBLE_FORMAT              0x30
#define ASC_MEDIUM_NOT_PRESENT               0x3a
#define ASC_SAVING_PARAMETERS_NOT_SUPPORTED  0x39

typedef struct ATAPIPassThroughState {
    /* The ATAPI packet request */
    struct request_sense sense;
    /* Maximum transfert length */
    uint32_t             max_xfer_len;

    uint8_t              request[ATAPI_PACKET_SIZE];
    uint32_t             dout_xfer_len;
    uint32_t             din_xfer_len;
    uint32_t             timeout;
    uint32_t             result;
    /* Thread communication */
    QemuThread           thread;
    bool                 thread_continue;
    /* Use sgio_worker_fd ou sgio_dispatch_fd to get the needed file
     * descriptor */
    EventNotifier        e_cmd;
    EventNotifier        e_ret;
} ATAPIPassThroughState;

int32_t atapi_pt_init(IDEState *s);
void atapi_pt_cmd(IDEState *s);
void atapi_pt_dout_fetch_pio_done(IDEState *s);

#endif /* !ATAPI_PT_H_ */
