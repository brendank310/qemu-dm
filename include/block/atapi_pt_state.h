/*
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

#ifndef _ATAPI_PT_H_
#define _ATAPI_PT_H_

enum ATAPIMediaState {
    MEDIA_STATE_UNKNOWN = 0x00,
    MEDIA_PRESENT = 0x01,
    MEDIA_ABSENT = 0x02
};

enum block_pt_cmd {
    BLOCK_PT_CMD_ERROR                   = 0x00,
    BLOCK_PT_CMD_SET_MEDIA_STATE_UNKNOWN = 0x01,
    BLOCK_PT_CMD_SET_MEDIA_PRESENT       = 0x02,
    BLOCK_PT_CMD_SET_MEDIA_ABSENT        = 0x03,
    BLOCK_PT_CMD_GET_LASTMEDIASTATE      = 0x04,
    BLOCK_PT_CMD_GET_SHM_MEDIASTATE      = 0x05
};

#endif /* !_ATAPI_PT_H_ */
