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

#include <sys/mman.h>
#include <scsi/sg.h>

#include "hw/ide/internal.h"
#include "atapi_pt.h"
#include "block/block.h"
#include "block/block_int.h"
#include "block/atapi_pt_state.h"

//#define ATAPI_PT_DEBUG

#if defined(ATAPI_PT_DEBUG)
/* From Table 459 of the SFF8090 Ver. 4 (Mt. Fuji) draft standard.
 * Code is (key << 16) | (asc << 8) | ascq
 * Mask is a bit mask, since some codes span ranges of values. */

static const struct {
    uint32_t code;
    uint32_t mask;
    char const *const text;
} sense_data_texts[] = {
    { 0x080000, 0xFF0000, "BLANK CHECK"},
    { 0x000000, 0xFFFFFF, "NO ADDITIONAL SENSE INFORMATION"},
    { 0x000001, 0xFFFFFF, "FILEMARK DETECTED"},
    { 0x000002, 0xFFFFFF, "END-OF-PARTITION/MEDIUM DETECTED"},
    { 0x000003, 0xFFFFFF, "SETMARK DETECTED"},
    { 0x000004, 0xFFFFFF, "BEGINNING-OF-PARTITION/MEDIUM DETECTED"},
    { 0x000005, 0xFFFFFF, "END-OF-DATA DETECTED"},
    { 0x0B0006, 0xFFFFFF, "I/O PROCESS TERMINATED, PLAY OPERATION ABORTED"},
    { 0x000011, 0xFFFFFF, "AUDIO PLAY OPERATION IN PROGRESS"},
    { 0x000012, 0xFFFFFF, "AUDIO PLAY OPERATION PAUSED"},
    { 0x000013, 0xFFFFFF, "AUDIO PLAY OPERATION SUCCESSFULLY COMPLETED"},
    { 0x000014, 0xFFFFFF, "AUDIO PLAY OPERATION STOPPED DUE TO ERROR"},
    { 0x000015, 0xFFFFFF, "NO CURRENT AUDIO STATUS TO RETURN"},
    { 0x000016, 0xFFFFFF, "OPERATION IN PROGRESS"},
    { 0x040017, 0xFFFFFF, "CLEANING REQUESTED"},
    { 0x040100, 0xFFFFFF, "NO INDEX/SECTOR SIGNAL"},
    { 0x030200, 0xFFFFFF, "NO SEEK COMPLETE"},
    { 0x030300, 0xFFFFFF, "PERIPHERAL DEVICE WRITE FAULT"},
    { 0x030301, 0xFFFFFF, "NO WRITE CURRENT"},
    { 0x030302, 0xFFFFFF, "EXCESSIVE WRITE ERRORS"},
    { 0x020400, 0xFFFFFF, "LOGICAL UNIT NOT READY, CAUSE NOT REPORTABLE"},
    { 0x020401, 0xFFFFFF, "LOGICAL UNIT IS IN PROCESS OF BECOMING READY"},
    { 0x020402, 0xFFFFFF, "LOGICAL UNIT NOT READY, INITIALIZING CMD. REQUIRED"},
    { 0x020403, 0xFFFFFF, "LOGICAL UNIT NOT READY, MANUAL INTERVENTION REQUIRED"},
    { 0x020404, 0xFFFFFF, "LOGICAL UNIT NOT READY, FORMAT IN PROGRESS"},
    { 0x020405, 0xFFFFFF, "LOGICAL UNIT NOT READY, REBUILD IN PROGRESS"},
    { 0x020406, 0xFFFFFF, "LOGICAL UNIT NOT READY, RECALCULATION IN PROGRESS"},
    { 0x020407, 0xFFFFFF, "LOGICAL UNIT NOT READY, OPERATION IN PROGRESS"},
    { 0x020408, 0xFFFFFF, "LOGICAL UNIT NOT READY, LONG WRITE IN PROGRESS"},
    { 0x020500, 0xFFFFFF, "LOGICAL UNIT DOES NOT RESPOND TO SELECTION"},
    { 0x020600, 0xFFFFFF, "NO REFERENCE POSITION FOUND (medium may be upside down)"},
    { 0x050700, 0xFFFFFF, "MULTIPLE PERIPHERAL DEVICES SELECTED"},
    { 0x040800, 0xFFFFFF, "LOGICAL UNIT COMMUNICATION FAILURE"},
    { 0x040801, 0xFFFFFF, "LOGICAL UNIT COMMUNICATION TIME-OUT"},
    { 0x040802, 0xFFFFFF, "LOGICAL UNIT COMMUNICATION PARITY ERROR"},
    { 0x040803, 0xFFFFFF, "LOGICAL UNIT COMMUNICATION CRC ERROR (ULTRA-DMA/32)"},
    { 0x040900, 0xFFFFFF, "TRACK FOLLOWING ERROR"},
    { 0x040901, 0xFFFFFF, "TRACKING SERVO FAILURE"},
    { 0x040902, 0xFFFFFF, "FOCUS SERVO FAILURE"},
    { 0x040903, 0xFFFFFF, "SPINDLE SERVO FAILURE"},
    { 0x040904, 0xFFFFFF, "HEAD SELECT FAULT"},
    { 0x060A00, 0xFFFFFF, "ERROR LOG OVERFLOW"},
    { 0x010B00, 0xFFFFFF, "WARNING"},
    { 0x010B01, 0xFFFFFF, "WARNING - SPECIFIED TEMPERATURE EXCEEDED"},
    { 0x010B02, 0xFFFFFF, "WARNING - ENCLOSURE DEGRADED"},
    { 0x030C00, 0xFFFFFF, "WRITE ERROR"},
    { 0x030C01, 0xFFFFFF, "WRITE ERROR - RECOVERED WITH AUTO REALLOCATION"},
    { 0x030C02, 0xFFFFFF, "WRITE ERROR - AUTO REALLOCATION FAILED"},
    { 0x030C03, 0xFFFFFF, "WRITE ERROR - RECOMMEND REASSIGNMENT"},
    { 0x030C04, 0xFFFFFF, "COMPRESSION CHECK MISCOMPARE ERROR"},
    { 0x030C05, 0xFFFFFF, "DATA EXPANSION OCCURRED DURING COMPRESSION"},
    { 0x030C06, 0xFFFFFF, "BLOCK NOT COMPRESSIBLE"},
    { 0x030C07, 0xFFFFFF, "WRITE ERROR - RECOVERY NEEDED"},
    { 0x030C08, 0xFFFFFF, "WRITE ERROR - RECOVERY FAILED"},
    { 0x030C09, 0xFFFFFF, "WRITE ERROR - LOSS OF STREAMING"},
    { 0x010C0A, 0xFFFFFF, "WRITE ERROR - PADDING BLOCKS ADDED"},
    { 0x000D00, 0x00FFFF, "Reserved"},
    { 0x000E00, 0x00FFFF, "Reserved"},
    { 0x000F00, 0x00FFFF, "Reserved"},
    { 0x031000, 0xFFFFFF, "ID CRC OR ECC ERROR"},
    { 0x031100, 0xFFFFFF, "UNRECOVERED READ ERROR"},
    { 0x031101, 0xFFFFFF, "READ RETRIES EXHAUSTED"},
    { 0x031102, 0xFFFFFF, "ERROR TOO LONG TO CORRECT"},
    { 0x031103, 0xFFFFFF, "MULTIPLE READ ERRORS"},
    { 0x031104, 0xFFFFFF, "UNRECOVERED READ ERROR - AUTO REALLOCATE FAILED"},
    { 0x031105, 0xFFFFFF, "L-EC UNCORRECTABLE ERROR"},
    { 0x031106, 0xFFFFFF, "CIRC UNRECOVERED ERROR"},
    { 0x031107, 0xFFFFFF, "RE-SYNCHRONIZATION ERROR"},
    { 0x031108, 0xFFFFFF, "INCOMPLETE BLOCK READ"},
    { 0x031109, 0xFFFFFF, "NO GAP FOUND"},
    { 0x03110A, 0xFFFFFF, "MISCORRECTED ERROR"},
    { 0x03110B, 0xFFFFFF, "UNRECOVERED READ ERROR - RECOMMEND REASSIGNMENT"},
    { 0x03110C, 0xFFFFFF, "UNRECOVERED READ ERROR - RECOMMEND REWRITE THE DATA"},
    { 0x03110D, 0xFFFFFF, "DE-COMPRESSION CRC ERROR"},
    { 0x03110E, 0xFFFFFF, "CANNOT DECOMPRESS USING DECLARED ALGORITHM"},
    { 0x03110F, 0xFFFFFF, "ERROR READING UPC/EAN NUMBER"},
    { 0x031110, 0xFFFFFF, "ERROR READING ISRC NUMBER"},
    { 0x0B1111, 0xFFFFFF, "READ ERROR - LOSS OF STREAMING"},
    { 0x031200, 0xFFFFFF, "ADDRESS MARK NOT FOUND FOR ID FIELD"},
    { 0x031300, 0xFFFFFF, "ADDRESS MARK NOT FOUND FOR DATA FIELD"},
    { 0x031400, 0xFFFFFF, "RECORDED ENTITY NOT FOUND"},
    { 0x031401, 0xFFFFFF, "RECORD NOT FOUND"},
    { 0x031402, 0xFFFFFF, "FILEMARK OR SETMARK NOT FOUND"},
    { 0x031403, 0xFFFFFF, "END-OF-DATA NOT FOUND"},
    { 0x031404, 0xFFFFFF, "BLOCK SEQUENCE ERROR"},
    { 0x031405, 0xFFFFFF, "RECORD NOT FOUND - RECOMMEND REASSIGNMENT"},
    { 0x031406, 0xFFFFFF, "RECORD NOT FOUND - DATA AUTO-REALLOCATED"},
    { 0x041500, 0xFFFFFF, "RANDOM POSITIONING ERROR"},
    { 0x041501, 0xFFFFFF, "MECHANICAL POSITIONING ERROR"},
    { 0x031502, 0xFFFFFF, "POSITIONING ERROR DETECTED BY READ OF MEDIUM"},
    { 0x031600, 0xFFFFFF, "DATA SYNCHRONIZATION MARK ERROR"},
    { 0x031601, 0xFFFFFF, "DATA SYNC ERROR - DATA REWRITTEN"},
    { 0x031602, 0xFFFFFF, "DATA SYNC ERROR - RECOMMEND REWRITE"},
    { 0x031603, 0xFFFFFF, "DATA SYNC ERROR - DATA AUTO-REALLOCATED"},
    { 0x031604, 0xFFFFFF, "DATA SYNC ERROR - RECOMMEND REASSIGNMENT"},
    { 0x011700, 0xFFFFFF, "RECOVERED DATA WITH NO ERROR CORRECTION APPLIED"},
    { 0x011701, 0xFFFFFF, "RECOVERED DATA WITH RETRIES"},
    { 0x011702, 0xFFFFFF, "RECOVERED DATA WITH POSITIVE HEAD OFFSET"},
    { 0x011703, 0xFFFFFF, "RECOVERED DATA WITH NEGATIVE HEAD OFFSET"},
    { 0x011704, 0xFFFFFF, "RECOVERED DATA WITH RETRIES AND/OR CIRC APPLIED"},
    { 0x011705, 0xFFFFFF, "RECOVERED DATA USING PREVIOUS SECTOR ID"},
    { 0x011706, 0xFFFFFF, "RECOVERED DATA WITHOUT ECC - DATA AUTO-REALLOCATED"},
    { 0x011707, 0xFFFFFF, "RECOVERED DATA WITHOUT ECC - RECOMMEND REASSIGNMENT"},
    { 0x011708, 0xFFFFFF, "RECOVERED DATA WITHOUT ECC - RECOMMEND REWRITE"},
    { 0x011709, 0xFFFFFF, "RECOVERED DATA WITHOUT ECC - DATA REWRITTEN"},
    { 0x011800, 0xFFFFFF, "RECOVERED DATA WITH ERROR CORRECTION APPLIED"},
    { 0x011801, 0xFFFFFF, "RECOVERED DATA WITH ERROR CORR. & RETRIES APPLIED"},
    { 0x011802, 0xFFFFFF, "RECOVERED DATA - DATA AUTO-REALLOCATED"},
    { 0x011803, 0xFFFFFF, "RECOVERED DATA WITH CIRC"},
    { 0x011804, 0xFFFFFF, "RECOVERED DATA WITH L-EC"},
    { 0x011805, 0xFFFFFF, "RECOVERED DATA - RECOMMEND REASSIGNMENT"},
    { 0x011806, 0xFFFFFF, "RECOVERED DATA - RECOMMEND REWRITE"},
    { 0x011807, 0xFFFFFF, "RECOVERED DATA WITH ECC - DATA REWRITTEN"},
    { 0x011808, 0xFFFFFF, "RECOVERED DATA WITH LINKING"},
    { 0x031900, 0xFFFFFF, "DEFECT LIST ERROR"},
    { 0x031901, 0xFFFFFF, "DEFECT LIST NOT AVAILABLE"},
    { 0x031902, 0xFFFFFF, "DEFECT LIST ERROR IN PRIMARY LIST"},
    { 0x031903, 0xFFFFFF, "DEFECT LIST ERROR IN GROWN LIST"},
    { 0x051A00, 0xFFFFFF, "PARAMETER LIST LENGTH ERROR"},
    { 0x041B00, 0xFFFFFF, "SYNCHRONOUS DATA TRANSFER ERROR"},
    { 0x041C00, 0xFFFFFF, "DEFECT LIST NOT FOUND"},
    { 0x041C01, 0xFFFFFF, "PRIMARY DEFECT LIST NOT FOUND"},
    { 0x041C02, 0xFFFFFF, "GROWN DEFECT LIST NOT FOUND"},
    { 0x0E1D00, 0xFFFFFF, "MISCOMPARE DURING VERIFY OPERATION"},
    { 0x011E00, 0xFFFFFF, "RECOVERED ID WITH ECC CORRECTION"},
    { 0x031F00, 0xFFFFFF, "PARTIAL DEFECT LIST TRANSFER"},
    { 0x052000, 0xFFFFFF, "INVALID COMMAND OPERATION CODE"},
    { 0x052100, 0xFFFFFF, "LOGICAL BLOCK ADDRESS OUT OF RANGE"},
    { 0x052101, 0xFFFFFF, "INVALID ELEMENT ADDRESS"},
    { 0x052102, 0xFFFFFF, "INVALID ADDRESS FOR WRITE"},
    { 0x052200, 0xFFFFFF, "ILLEGAL FUNCTION (USE 20 00, 24 00, OR 26 00)"},
    { 0x002300, 0x00FFFF, "Reserved"},
    { 0x052400, 0xFFFFFF, "INVALID FIELD IN CDB"},
    { 0x052500, 0xFFFFFF, "LOGICAL UNIT NOT SUPPORTED"},
    { 0x052600, 0xFFFFFF, "INVALID FIELD IN PARAMETER LIST"},
    { 0x052601, 0xFFFFFF, "PARAMETER NOT SUPPORTED"},
    { 0x052602, 0xFFFFFF, "PARAMETER VALUE INVALID"},
    { 0x052603, 0xFFFFFF, "THRESHOLD PARAMETERS NOT SUPPORTED"},
    { 0x052604, 0xFFFFFF, "INVALID RELEASE OF ACTIVE PERSISTENT RESERVATION"},
    { 0x072700, 0xFFFFFF, "WRITE PROTECTED"},
    { 0x072701, 0xFFFFFF, "HARDWARE WRITE PROTECTED"},
    { 0x072702, 0xFFFFFF, "LOGICAL UNIT SOFTWARE WRITE PROTECTED"},
    { 0x072703, 0xFFFFFF, "ASSOCIATED WRITE PROTECT"},
    { 0x072704, 0xFFFFFF, "PERSISTENT WRITE PROTECT"},
    { 0x072705, 0xFFFFFF, "PERMANENT WRITE PROTECT"},
    { 0x072706, 0xFFFFFF, "CONDITIONAL WRITE PROTECT"},
    { 0x062800, 0xFFFFFF, "NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED"},
    { 0x062801, 0xFFFFFF, "IMPORT OR EXPORT ELEMENT ACCESSED"},
    { 0x062900, 0xFFFFFF, "POWER ON, RESET, OR BUS DEVICE RESET OCCURRED"},
    { 0x062901, 0xFFFFFF, "POWER ON OCCURRED"},
    { 0x062902, 0xFFFFFF, "SCSI BUS RESET OCCURRED"},
    { 0x062903, 0xFFFFFF, "BUS DEVICE RESET FUNCTION OCCURRED"},
    { 0x062904, 0xFFFFFF, "DEVICE INTERNAL RESET"},
    { 0x062A00, 0xFFFFFF, "PARAMETERS CHANGED"},
    { 0x062A01, 0xFFFFFF, "MODE PARAMETERS CHANGED"},
    { 0x062A02, 0xFFFFFF, "LOG PARAMETERS CHANGED"},
    { 0x062A03, 0xFFFFFF, "RESERVATIONS PREEMPTED"},
    { 0x052B00, 0xFFFFFF, "COPY CANNOT EXECUTE SINCE HOST CANNOT DISCONNECT"},
    { 0x052C00, 0xFFFFFF, "COMMAND SEQUENCE ERROR"},
    { 0x052C01, 0xFFFFFF, "TOO MANY WINDOWS SPECIFIED"},
    { 0x052C02, 0xFFFFFF, "INVALID COMBINATION OF WINDOWS SPECIFIED"},
    { 0x052C03, 0xFFFFFF, "CURRENT PROGRAM AREA IS NOT EMPTY"},
    { 0x052C04, 0xFFFFFF, "CURRENT PROGRAM AREA IS EMPTY"},
    { 0x052C05, 0xFFFFFF, "PERSISTENT PREVENT CONFLICT"},
    { 0x032D00, 0xFFFFFF, "OVERWRITE ERROR ON UPDATE IN PLACE"},
    { 0x062E00, 0xFFFFFF, "INSUFFICIENT TIME FOR OPERATION"},
    { 0x062F00, 0xFFFFFF, "COMMANDS CLEARED BY ANOTHER INITIATOR"},
    { 0x023000, 0xFFFFFF, "INCOMPATIBLE MEDIUM INSTALLED"},
    { 0x023001, 0xFFFFFF, "CANNOT READ MEDIUM - UNKNOWN FORMAT"},
    { 0x023002, 0xFFFFFF, "CANNOT READ MEDIUM - INCOMPATIBLE FORMAT"},
    { 0x053002, 0xFFFFFF, "CANNOT READ MEDIUM - INCOMPATIBLE FORMAT"},
    { 0x023003, 0xFFFFFF, "CLEANING CARTRIDGE INSTALLED"},
    { 0x053004, 0xFFFFFF, "CANNOT WRITE MEDIUM - UNKNOWN FORMAT"},
    { 0x053005, 0xFFFFFF, "CANNOT WRITE MEDIUM - INCOMPATIBLE FORMAT"},
    { 0x053006, 0xFFFFFF, "CANNOT FORMAT MEDIUM - INCOMPATIBLE MEDIUM"},
    { 0x023007, 0xFFFFFF, "CLEANING FAILURE"},
    { 0x053008, 0xFFFFFF, "CANNOT WRITE - APPLICATION CODE MISMATCH"},
    { 0x053009, 0xFFFFFF, "CURRENT SESSION NOT FIXATED FOR APPEND"},
    { 0x033100, 0xFFFFFF, "MEDIUM FORMAT CORRUPTED"},
    { 0x033101, 0xFFFFFF, "FORMAT COMMAND FAILED"},
    { 0x033102, 0xFFFFFF, "ZONED FORMATTING FAILED DUE TO SPARE LINKING"},
    { 0x033200, 0xFFFFFF, "NO DEFECT SPARE LOCATION AVAILABLE"},
    { 0x033201, 0xFFFFFF, "DEFECT LIST UPDATE FAILURE"},
    { 0x033300, 0xFFFFFF, "TAPE LENGTH ERROR"},
    { 0x043400, 0xFFFFFF, "ENCLOSURE FAILURE"},
    { 0x043500, 0xFFFFFF, "ENCLOSURE SERVICES FAILURE"},
    { 0x053501, 0xFFFFFF, "UNSUPPORTED ENCLOSURE FUNCTION"},
    { 0x023502, 0xFFFFFF, "ENCLOSURE SERVICES UNAVAILABLE"},
    { 0x043503, 0xFFFFFF, "ENCLOSURE SERVICES TRANSFER FAILURE"},
    { 0x053504, 0xFFFFFF, "ENCLOSURE SERVICES TRANSFER REFUSED"},
    { 0x033600, 0xFFFFFF, "RIBBON, INK, OR TONER FAILURE"},
    { 0x013700, 0xFFFFFF, "ROUNDED PARAMETER"},
    { 0x053800, 0xFFFFFF, "Reserved"},
    { 0x053900, 0xFFFFFF, "SAVING PARAMETERS NOT SUPPORTED"},
    { 0x023A00, 0xFFFFFF, "MEDIUM NOT PRESENT"},
    { 0x023A01, 0xFFFFFF, "MEDIUM NOT PRESENT - TRAY CLOSED"},
    { 0x023A02, 0xFFFFFF, "MEDIUM NOT PRESENT - TRAY OPEN"},
    { 0x033B00, 0xFFFFFF, "SEQUENTIAL POSITIONING ERROR"},
    { 0x033B01, 0xFFFFFF, "TAPE POSITION ERROR AT BEGINNING-OF-MEDIUM"},
    { 0x033B02, 0xFFFFFF, "TAPE POSITION ERROR AT END-OF-MEDIUM"},
    { 0x033B03, 0xFFFFFF, "TAPE OR ELECTRONIC VERTICAL FORMS UNIT NOT READY"},
    { 0x043B04, 0xFFFFFF, "SLEW FAILURE"},
    { 0x043B05, 0xFFFFFF, "PAPER JAM"},
    { 0x033B06, 0xFFFFFF, "FAILED TO SENSE TOP-OF-FORM"},
    { 0x033B07, 0xFFFFFF, "FAILED TO SENSE BOTTOM-OF-FORM"},
    { 0x033B08, 0xFFFFFF, "REPOSITION ERROR"},
    { 0x033B09, 0xFFFFFF, "READ PAST END OF MEDIUM"},
    { 0x033B0A, 0xFFFFFF, "READ PAST BEGINNING OF MEDIUM"},
    { 0x033B0B, 0xFFFFFF, "POSITION PAST END OF MEDIUM"},
    { 0x033B0C, 0xFFFFFF, "POSITION PAST BEGINNING OF MEDIUM"},
    { 0x053B0D, 0xFFFFFF, "MEDIUM DESTINATION ELEMENT FULL"},
    { 0x053B0E, 0xFFFFFF, "MEDIUM SOURCE ELEMENT EMPTY"},
    { 0x063B0F, 0xFFFFFF, "END OF MEDIUM REACHED"},
    { 0x023B11, 0xFFFFFF, "MEDIUM MAGAZINE NOT ACCESSIBLE"},
    { 0x063B12, 0xFFFFFF, "MEDIUM MAGAZINE REMOVED"},
    { 0x063B13, 0xFFFFFF, "MEDIUM MAGAZINE INSERTED"},
    { 0x063B14, 0xFFFFFF, "MEDIUM MAGAZINE LOCKED"},
    { 0x063B15, 0xFFFFFF, "MEDIUM MAGAZINE UNLOCKED"},
    { 0x043B16, 0xFFFFFF, "MECHANICAL POSITIONING OR CHANGER ERROR"},
    { 0x003C00, 0x00FFFF, "Reserved"},
    { 0x053D00, 0xFFFFFF, "INVALID BITS IN IDENTIFY MESSAGE"},
    { 0x023E00, 0xFFFFFF, "LOGICAL UNIT HAS NOT SELF-CONFIGURED YET"},
    { 0x043E01, 0xFFFFFF, "LOGICAL UNIT FAILURE"},
    { 0x043E02, 0xFFFFFF, "TIMEOUT ON LOGICAL UNIT"},
    { 0x063F00, 0xFFFFFF, "TARGET OPERATING CONDITIONS HAVE CHANGED"},
    { 0x063F01, 0xFFFFFF, "MICROCODE HAS BEEN CHANGED"},
    { 0x063F02, 0xFFFFFF, "CHANGED OPERATING DEFINITION"},
    { 0x063F03, 0xFFFFFF, "INQUIRY DATA HAS CHANGED"},
    { 0x044000, 0xFFFFFF, "RAM FAILURE (SHOULD USE 40 NN)"},
    { 0x044000, 0xFFFF80, "DIAGNOSTIC FAILURE ON COMPONENT NN (80H-FFH)"},
    { 0x044100, 0xFFFFFF, "DATA PATH FAILURE (SHOULD USE 40 NN)"},
    { 0x044200, 0xFFFFFF, "POWER-ON OR SELF-TEST FAILURE (SHOULD USE 40 NN)"},
    { 0x054300, 0xFFFFFF, "MESSAGE ERROR"},
    { 0x044400, 0xFFFFFF, "INTERNAL TARGET FAILURE"},
    { 0x0b4500, 0xFFFFFF, "SELECT OR RESELECT FAILURE"},
    { 0x044600, 0xFFFFFF, "UNSUCCESSFUL SOFT RESET"},
    { 0x044700, 0xFFFFFF, "SCSI PARITY ERROR"},
    { 0x0b4800, 0xFFFFFF, "INITIATOR DETECTED ERROR MESSAGE RECEIVED"},
    { 0x0b4900, 0xFFFFFF, "INVALID MESSAGE ERROR"},
    { 0x044A00, 0xFFFFFF, "COMMAND PHASE ERROR"},
    { 0x044B00, 0xFFFFFF, "DATA PHASE ERROR"},
    { 0x044C00, 0xFFFFFF, "LOGICAL UNIT FAILED SELF-CONFIGURATION"},
    { 0x0b4D00, 0xFFFF00, "TAGGED OVERLAPPED COMMANDS (NN = QUEUE TAG)"},
    { 0x0B4E00, 0xFFFFFF, "OVERLAPPED COMMANDS ATTEMPTED"},
    { 0x004F00, 0x00FFFF, "Reserved"},
    { 0x005000, 0x00FFFF, "WRITE APPEND ERROR"},
    { 0x005001, 0x00FFFF, "WRITE APPEND POSITION ERROR"},
    { 0x005002, 0x00FFFF, "POSITION ERROR RELATED TO TIMING"},
    { 0x035100, 0xFFFFFF, "ERASE FAILURE"},
    { 0x035101, 0xFFFFFF, "ERASE FAILURE - Incomplete erase operation detected"},
    { 0x035200, 0xFFFFFF, "CARTRIDGE FAULT"},
    { 0x045300, 0xFFFFFF, "MEDIA LOAD OR EJECT FAILED"},
    { 0x005301, 0x00FFFF, "UNLOAD TAPE FAILURE"},
    { 0x025302, 0xFFFFFF, "MEDIUM REMOVAL PREVENTED"},
    { 0x055302, 0xFFFFFF, "MEDIUM REMOVAL PREVENTED"},
    { 0x005400, 0x00FFFF, "SCSI TO HOST SYSTEM INTERFACE FAILURE"},
    { 0x055500, 0xFFFFFF, "SYSTEM RESOURCE FAILURE"},
    { 0x005501, 0x00FFFF, "SYSTEM BUFFER FULL"},
    { 0x005600, 0x00FFFF, "Reserved"},
    { 0x035700, 0xFFFFFF, "UNABLE TO RECOVER TABLE-OF-CONTENTS"},
    { 0x005800, 0x00FFFF, "GENERATION DOES NOT EXIST"},
    { 0x005900, 0x00FFFF, "UPDATED BLOCK READ"},
    { 0x065A00, 0xFFFFFF, "OPERATOR REQUEST OR STATE CHANGE INPUT"},
    { 0x065A01, 0xFFFFFF, "OPERATOR MEDIUM REMOVAL REQUEST"},
    { 0x065A02, 0xFFFFFF, "OPERATOR SELECTED WRITE PROTECT"},
    { 0x065A03, 0xFFFFFF, "OPERATOR SELECTED WRITE PERMIT"},
    { 0x065B00, 0xFFFFFF, "LOG EXCEPTION"},
    { 0x065B01, 0xFFFFFF, "THRESHOLD CONDITION MET"},
    { 0x065B02, 0xFFFFFF, "LOG COUNTER AT MAXIMUM"},
    { 0x065B03, 0xFFFFFF, "LOG LIST CODES EXHAUSTED"},
    { 0x065C00, 0xFFFFFF, "RPL STATUS CHANGE"},
    { 0x065C01, 0xFFFFFF, "SPINDLES SYNCHRONIZED"},
    { 0x035C02, 0xFFFFFF, "SPINDLES NOT SYNCHRONIZED"},
    { 0x015D00, 0xFFFFFF, "FAILURE PREDICTION THRESHOLD EXCEEDED - Predicted Logical Unit Failure"},
    { 0x015D01, 0xFFFFFF, "FAILURE PREDICTION THRESHOLD EXCEEDED - Predicted Media Failure"},
    { 0x015D03, 0xFFFFFF, "FAILURE PREDICTION THRESHOLD EXCEEDED - Predicted Spare Area Exhaustion"},
    { 0x015DFF, 0xFFFFFF, "FAILURE PREDICTION THRESHOLD EXCEEDED (FALSE)"},
    { 0x065E00, 0xFFFFFF, "LOW POWER CONDITION ON"},
    { 0x065E01, 0xFFFFFF, "IDLE CONDITION ACTIVATED BY TIMER"},
    { 0x065E02, 0xFFFFFF, "STANDBY CONDITION ACTIVATED BY TIMER"},
    { 0x065E03, 0xFFFFFF, "IDLE CONDITION ACTIVATED BY COMMAND"},
    { 0x065E04, 0xFFFFFF, "STANDBY CONDITION ACTIVATED BY COMMAND"},
    { 0x005F00, 0x00FFFF, "Reserved"},
    { 0x046000, 0xFFFFFF, "LAMP FAILURE"},
    { 0x036100, 0xFFFFFF, "VIDEO ACQUISITION ERROR"},
    { 0x036101, 0xFFFFFF, "UNABLE TO ACQUIRE VIDEO"},
    { 0x036102, 0xFFFFFF, "OUT OF FOCUS"},
    { 0x046200, 0xFFFFFF, "SCAN HEAD POSITIONING ERROR"},
    { 0x056300, 0xFFFFFF, "END OF USER AREA ENCOUNTERED ON THIS TRACK"},
    { 0x056301, 0xFFFFFF, "PACKET DOES NOT FIT IN AVAILABLE SPACE"},
    { 0x056400, 0xFFFFFF, "ILLEGAL MODE FOR THIS TRACK"},
    { 0x056401, 0xFFFFFF, "INVALID PACKET SIZE"},
    { 0x046500, 0xFFFFFF, "VOLTAGE FAULT"},
    { 0x046600, 0xFFFFFF, "AUTOMATIC DOCUMENT FEEDER COVER UP"},
    { 0x046601, 0xFFFFFF, "AUTOMATIC DOCUMENT FEEDER LIFT UP"},
    { 0x046602, 0xFFFFFF, "DOCUMENT JAM IN AUTOMATIC DOCUMENT FEEDER"},
    { 0x046603, 0xFFFFFF, "DOCUMENT MISS FEED AUTOMATIC IN DOCUMENT FEEDER"},
    { 0x046700, 0xFFFFFF, "CONFIGURATION FAILURE"},
    { 0x046701, 0xFFFFFF, "CONFIGURATION OF INCAPABLE LOGICAL UNITS FAILED"},
    { 0x046702, 0xFFFFFF, "ADD LOGICAL UNIT FAILED"},
    { 0x046703, 0xFFFFFF, "MODIFICATION OF LOGICAL UNIT FAILED"},
    { 0x046704, 0xFFFFFF, "EXCHANGE OF LOGICAL UNIT FAILED"},
    { 0x046705, 0xFFFFFF, "REMOVE OF LOGICAL UNIT FAILED"},
    { 0x046706, 0xFFFFFF, "ATTACHMENT OF LOGICAL UNIT FAILED"},
    { 0x046707, 0xFFFFFF, "CREATION OF LOGICAL UNIT FAILED"},
    { 0x026800, 0xFFFFFF, "LOGICAL UNIT NOT CONFIGURED"},
    { 0x046900, 0xFFFFFF, "DATA LOSS ON LOGICAL UNIT"},
    { 0x046901, 0xFFFFFF, "MULTIPLE LOGICAL UNIT FAILURES"},
    { 0x046902, 0xFFFFFF, "A PARITY/DATA MISMATCH"},
    { 0x016A00, 0xFFFFFF, "INFORMATIONAL, REFER TO LOG"},
    { 0x066B00, 0xFFFFFF, "STATE CHANGE HAS OCCURRED"},
    { 0x066B01, 0xFFFFFF, "REDUNDANCY LEVEL GOT BETTER"},
    { 0x066B02, 0xFFFFFF, "REDUNDANCY LEVEL GOT WORSE"},
    { 0x036C00, 0xFFFFFF, "REBUILD FAILURE OCCURRED"},
    { 0x036D00, 0xFFFFFF, "RECALCULATE FAILURE OCCURRED"},
    { 0x046E00, 0xFFFFFF, "COMMAND TO LOGICAL UNIT FAILED"},
    { 0x056F00, 0xFFFFFF, "COPY PROTECTION KEY EXCHANGE FAILURE - AUTHENTICATION FAILURE"},
    { 0x056F01, 0xFFFFFF, "COPY PROTECTION KEY EXCHANGE FAILURE - KEY NOT PRESENT"},
    { 0x056F02, 0xFFFFFF, "COPY PROTECTION KEY EXCHANGE FAILURE - KEY NOT ESTABLISHED"},
    { 0x056F03, 0xFFFFFF, "READ OF SCRAMBLED SECTOR WITHOUT AUTHENTICATION"},
    { 0x056F04, 0xFFFFFF, "MEDIA REGION CODE IS MISMATCHED TO LOGICAL UNIT REGION"},
    { 0x056F05, 0xFFFFFF, "DRIVE REGION MUST BE PERMANENT/REGION RESET COUNT ERROR"},
    { 0x037000, 0xFFFF00, "DECOMPRESSION EXCEPTION SHORT ALGORITHM ID OF NN"},
    { 0x037100, 0xFFFFFF, "DECOMPRESSION EXCEPTION LONG ALGORITHM ID"},
    { 0x037200, 0xFFFFFF, "SESSION FIXATION ERROR"},
    { 0x037201, 0xFFFFFF, "SESSION FIXATION ERROR WRITING LEAD-IN"},
    { 0x037202, 0xFFFFFF, "SESSION FIXATION ERROR WRITING LEAD-OUT"},
    { 0x057203, 0xFFFFFF, "SESSION FIXATION ERROR - INCOMPLETE TRACK IN SESSION"},
    { 0x057204, 0xFFFFFF, "EMPTY OR PARTIALLY WRITTEN RESERVED TRACK"},
    { 0x057205, 0xFFFFFF, "NO MORE RZONE RESERVATIONS ARE ALLOWED"},
    { 0x037300, 0xFFFFFF, "CD CONTROL ERROR"},
    { 0x017301, 0xFFFFFF, "POWER CALIBRATION AREA ALMOST FULL"},
    { 0x037302, 0xFFFFFF, "POWER CALIBRATION AREA IS FULL"},
    { 0x037303, 0xFFFFFF, "POWER CALIBRATION AREA ERROR"},
    { 0x037304, 0xFFFFFF, "PROGRAM MEMORY AREA/RMA UPDATE FAILURE"},
    { 0x037305, 0xFFFFFF, "PROGRAM MEMORY AREA/RMA IS FULL"},
    { 0x017306, 0xFFFFFF, "PROGRAM MEMORY AREA/RMA IS (almost) FULL"},
    { 0x008000, 0x008000, "VENDOR SPECIFIC"},
    { 0x000000, 0x000000, "Unrecognised sense data"}
};

static char const *atapi_sense_to_str(uint8_t const key,
                      uint8_t const asc, uint8_t const ascq)
{
    uint32_t i;
    uint32_t code;

    code = ((key & 0xFF) << 16) | ((asc & 0xFF) << 8) | (ascq & 0xFF);

    for (i = 0; 1; ++i)
        if ((code & sense_data_texts[i].mask) ==
            sense_data_texts[i].code)
            break;

    return sense_data_texts[i].text;
}

static void atapi_pt_dump_hexa(void *message, unsigned int len)
{
    char buf[128];
    char *p;
    int i;

    if (NULL != message) {
        p = message;
        memset(buf, 0, sizeof(buf));

        fprintf(stderr, "dump: [");
        for (i = 0; i < len; i++) {
            fprintf(stderr, "%02x ", p[i]);
        }

        fprintf(stderr, "]\n");
    }
}

#define ATAPI_DPRINTF(fmt, args...) \
    do { \
        fprintf(stderr, "[%s][%s(%d)]: " fmt "\n", \
                __FILE__, __func__, __LINE__, ## args); \
    } while (0)

#define ATAPI_DUMP_SENSE(key, asc, ascq) \
    do {\
        ATAPI_DPRINTF("sense 0x%02x.%02x.%02x (\e[0;31m%s\e[m)", \
                      key, asc, ascq, atapi_sense_to_str(key, asc, ascq)); \
    } while (0)

#else                /* !ATAPI_PT_DEBUG */
#define ATAPI_DPRINTF(fmt, args...) \
    do { } while (0)
#define ATAPI_DUMP_SENSE(key, asc, ascq) \
    do { } while (0)
#endif

/* For each SCSI command we need to know up to 3 data sizes. These are:
 * 1. The amount of data to send to the LU.
 * 2. The size of the buffer provided for data sent back from the LU.
 * 3. The amount of data the LU wanted to send.
 *
 * These are all measured in bytes.
 *
 * The table ide_atapi_cmd_data_sizes specifies how to determine these sizes
 * for each SCSI command. Each size is given by:
 *
 *   constant + (base * block_size)
 *
 * where base is a value specified within the command data. This is specified
 * in our table as an offset into the data at which the value starts and the
 * size of the value, in bytes. All base value are assumed to be MSB first
 * (lowest offset).
 *
 * The number of bytes forming the base value can only take values between 0
 * and 4 inclusive, with 0 indicating that there is no base value.
 *
 * The amount of data to send to the LU and the size of the receiving buffer
 * are both determined from the CDB. A value of 0 means that no data is
 * transfered and a value of -1 indicates that the table entry is invalid (eg
 * undefined command).
 *
 * The amount of data the LU wanted to return is determined from the returned
 * data. A value of 0 is invalid and a value of -1 indicates that this size is
 * the same as the receiving buffer size.
 *
 * A few commands are too complex for this scheme and so are handled by code in
 * ide_atapi_pt_cmd() and ide_atapi_pt_do_sg_io().
 */

#define SET_ATAPI_CMD(cmd, o1, o2, o3, o4, b1, b2, b3, b4, i1, i2, i3, i4) \
    [ cmd ] = { \
      .dout_recipe = {.len_const = o1, .len_offset = o2, .len_size =  o3, .block_size = o4}, \
      .buffer_recipe = {.len_const = b1, .len_offset = b2, .len_size =  b3, .block_size = b4}, \
      .din_recipe = {.len_const = i1, .len_offset = i2, .len_size = i3, .block_size = i4}, \
      .name = #cmd \
    }
struct atapi_pt_size_recipes {
    uint32_t len_const;
    uint32_t len_offset;
    uint32_t len_size;
    uint32_t block_size;
};

// define a shorter name to make the following table easier to read
#define CDFSZ          CD_FRAMESIZE

static const struct {
    struct atapi_pt_size_recipes dout_recipe;
    struct atapi_pt_size_recipes buffer_recipe;
    struct atapi_pt_size_recipes din_recipe;
    char const *name;
} atapi_cmd_table[0x100] = {
    /*                  CMD Number                    |     OUT       |   BUFFER      |     IN     */
    SET_ATAPI_CMD(GPCMD_TEST_UNIT_READY,                0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_REQUEST_SENSE,                  0, 0, 0, 0,     0, 4, 1, 1,     8, 7, 1, 1),
    SET_ATAPI_CMD(GPCMD_FORMAT_UNIT,                   12, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_INQUIRY,                        0, 0, 0, 0,     0, 4, 1, 1,     5, 4, 1, 1),
    SET_ATAPI_CMD(GPCMD_START_STOP_UNIT,                0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL,   0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_READ_FORMAT_CAPACITIES,         0, 0, 0, 0,     0, 7, 2, 1,     4, 3, 1, 1),
    SET_ATAPI_CMD(GPCMD_READ_CDVD_CAPACITY,             0, 0, 0, 0,     8, 0, 0, 0,     8, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_READ_10,                        0, 0, 0, 0,     0, 7, 2, CDFSZ, -1,0, 0, 0),
    SET_ATAPI_CMD(GPCMD_WRITE_10,                       0, 7, 2, CDFSZ, 0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SEEK,                           0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_WRITE_AND_VERIFY_10,            0, 7, 2, CDFSZ, 0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_VERIFY_10,                      0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_FLUSH_CACHE,                    0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_WRITE_BUFFER,                   0, 6, 3, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_READ_BUFFER,                    0, 0, 0, 0,     0, 6, 3, 1,     4, 1, 3, 1),
    SET_ATAPI_CMD(GPCMD_READ_SUBCHANNEL,                0, 0, 0, 0,     0, 7, 2, 1,     4, 2, 2, 1),
    SET_ATAPI_CMD(GPCMD_READ_TOC_PMA_ATIP,              0, 0, 0, 0,     0, 7, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_READ_HEADER,                    0, 0, 0, 0,     0, 7, 2, 1,     8, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_PLAY_AUDIO_10,                  0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_GET_CONFIGURATION,              0, 0, 0, 0,     0, 7, 2, 1,     4, 0, 4, 1),
    SET_ATAPI_CMD(GPCMD_PLAY_AUDIO_MSF,                 0, 0, 0, 0,     -1,0, 0, 0,     -1,0, 0, 0),
    SET_ATAPI_CMD(GPCMD_GET_EVENT_STATUS_NOTIFICATION,  0, 0, 0, 0,     0, 7, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_PAUSE_RESUME,                   0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_STOP_PLAY_SCAN,                 0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_READ_DISC_INFO,                 0, 0, 0, 0,     0, 7, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_READ_TRACK_RZONE_INFO,          0, 0, 0, 0,     0, 7, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_RESERVE_RZONE_TRACK,            0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SEND_OPC,                       0, 7, 2, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_MODE_SELECT_10,                 0, 7, 2, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_REPAIR_RZONE_TRACK,             0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_MODE_SENSE_10,                  0, 0, 0, 0,     0, 7, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_CLOSE_TRACK,                    0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_READ_BUFFER_CAPACITY,           0, 0, 0, 0,     0, 7, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_SEND_CUE_SHEET,                 0, 6, 3, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_BLANK,                          0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SEND_EVENT,                     0, 8, 2, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SEND_KEY,                       0, 8, 2, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_REPORT_KEY,                     0, 0, 0, 0,     0, 8, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_LOAD_UNLOAD,                    0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SET_READ_AHEAD,                 0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_READ_12,                        0, 0, 0, 0,     0, 6, 4, CDFSZ, -1,0, 0, 0),
    SET_ATAPI_CMD(GPCMD_WRITE_12,                       0, 6, 4, CDFSZ, 0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_GET_PERFORMANCE,                0, 0, 0, 0,     0, 8, 2, 1,     4, 0, 4, 1),
    SET_ATAPI_CMD(GPCMD_READ_DVD_STRUCTURE,             0, 0, 0, 0,     0, 8, 2, 1,     2, 0, 2, 1),
    SET_ATAPI_CMD(GPCMD_SET_STREAMING,                  0, 9, 2, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_READ_CD_MSF,                    0, 0, 0, 0,     -1,0, 0, 0,     -1,0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SCAN,                           0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SET_SPEED,                      0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_PLAY_CD,                        0, 0, 0, 0,     0, 0, 0, 0,     0, 0, 0, 0),
    SET_ATAPI_CMD(GPCMD_MECHANISM_STATUS,               0, 0, 0, 0,     0, 8, 2, 1,     8, 6, 2, 1),
    SET_ATAPI_CMD(GPCMD_READ_CD,                        0, 0, 0, 0,     0, 6, 3, 1,     -1,0, 0, 0),
    SET_ATAPI_CMD(GPCMD_SEND_DVD_STRUCTURE,             0, 8, 2, 1,     0, 0, 0, 0,     0, 0, 0, 0),
    /* 0xC0 - 0xFF: intentionaly left blank */
};

enum atapi_pt_recipe_select {
    ide_atapi_pt_size_dout,    // size of dout
    ide_atapi_pt_size_buffer,    // size of din buffer
    ide_atapi_pt_size_din    // size of din data
};

#if defined(ATAPI_PT_DEBUG)
static inline char const *atapi_cmd_to_str(uint8_t const cmd)
{
    if (atapi_cmd_table[cmd].name == NULL) {
        return "Unsupported command";
    }

    return atapi_cmd_table[cmd].name;
}
#endif

#define MSF_TO_FRAMES(M, S, F) (((M) * CD_SECS + (S)) * CD_FRAMES + (F))

static inline void cpu_to_ube16(uint8_t * buf, int val)
{
    buf[0] = val >> 8;
    buf[1] = val & 0xff;
}

static inline void cpu_to_ube32(uint8_t * buf, unsigned int val)
{
    buf[0] = val >> 24;
    buf[1] = val >> 16;
    buf[2] = val >> 8;
    buf[3] = val & 0xff;
}

static inline int ube16_to_cpu(const uint8_t * buf)
{
    return (buf[0] << 8) | buf[1];
}

static inline int ube24_to_cpu(const uint8_t * buf)
{
    return (buf[0] << 16) | (buf[1] << 8) | buf[2];
}

static inline int ube32_to_cpu(const uint8_t * buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

/* The table ide_atapi_cmd_data_sizes specifies how to determine these sizes
 * for each SCSI command. Each size is given by:
 *
 * constant + (base * block_size)
 *
 * This function help us to compute the size */
static uint32_t
atapi_pt_get_data_size(enum atapi_pt_recipe_select size_select,
               uint8_t command, uint8_t * data)
{
    struct atapi_pt_size_recipes const *size_devfn = NULL;
    uint32_t size = 0;

    if (atapi_cmd_table[command].name == 0) {
        ATAPI_DPRINTF("Invalide command (\e[0;34m0x%02x\e[m)", command);
        return -1;
    }

    /* Get the size recipe */
    switch (size_select) {
    case ide_atapi_pt_size_dout:
        size_devfn = &atapi_cmd_table[command].dout_recipe;
        break;
    case ide_atapi_pt_size_buffer:
        size_devfn = &atapi_cmd_table[command].buffer_recipe;
        break;
    case ide_atapi_pt_size_din:
        size_devfn = &atapi_cmd_table[command].din_recipe;
        break;
    default:
        ATAPI_DPRINTF("Invalid data size selection %d", size_select);
        return -1;
    }

    /* Determine the base size. */
    switch (size_devfn->len_size) {
    case 0:        /* If no specified len size, keep 0 */
        size = 0;
        break;
    case 1:        /* Get a size on 8 bits from the command buffer */
        size = data[size_devfn->len_offset];
        break;
    case 2:        /* Get a size on 16bits from the command buffer */
        size = ube16_to_cpu(data + size_devfn->len_offset);
        break;
    case 3:        /* Get a size on 24bits from the command buffer */
        size = ube24_to_cpu(data + size_devfn->len_offset);
        break;
    case 4:        /* Get a size on 32bits from the command buffer */
        size = ube32_to_cpu(data + size_devfn->len_offset);
        break;
    default:
        ATAPI_DPRINTF
            ("Invalid data size length in table, command(0x%02x)"
             " select(%d), size(%d)\n", command, size_select,
             size_devfn->len_size);
        return -1;
    }

    /* Compute the size of data:
     * (base * block_size) + len_const */
    size *= size_devfn->block_size;
    size += size_devfn->len_const;
    return size;
}

/* This function set an error on the IDE Bus, the guest will be notified */
static void atapi_pt_set_error(IDEState * s,
                   int sense_key, int asc, int ascq, int error)
{
    ATAPIPassThroughState *as = s->atapipts;
    memset(&as->sense, 0, 18);
    *((char *)&as->sense) = 0x70;
    as->sense.sense_key = sense_key;
    as->sense.asc = asc;
    as->sense.ascq = ascq;
    as->sense.error_code = error;
    as->sense.add_sense_len = 10;

    ATAPI_DUMP_SENSE(as->sense.sense_key, as->sense.asc, as->sense.ascq);

    s->status = READY_STAT | ERR_STAT;
    s->nsector =
        (s->nsector & ~7) | ATAPI_INT_REASON_IO | ATAPI_INT_REASON_CD;
    ide_set_irq(s->bus);
}

static void atapi_pt_error(IDEState * s)
{
    s->status = READY_STAT | ERR_STAT;
    s->nsector =
        (s->nsector & ~7) | ATAPI_INT_REASON_IO | ATAPI_INT_REASON_CD;
    ide_set_irq(s->bus);
}

static int atapi_pt_do_dispatch(volatile IDEState * s)
{
    int r = 0;
    struct sg_io_v4 cmd;
    int is_dout = 0;
    uint32_t seg_offset = 0;
    uint32_t lba;
    uint16_t len;
    uint32_t segment = 0;
    __u32 *cmd_len_p;
    uint32_t *req_len_p;
    uint8_t request[ATAPI_PACKET_SIZE];
    ATAPIPassThroughState *as = s->atapipts;

    memcpy(request, (void *)as->request, sizeof(request));
    is_dout = (as->dout_xfer_len > 0) ? 1 : 0;
    cmd_len_p = is_dout ? &(cmd.dout_xfer_len) : &(cmd.din_xfer_len);
    req_len_p = is_dout ? &(as->dout_xfer_len) : &(as->din_xfer_len);

    memset(&cmd, 0, sizeof(struct sg_io_v4));
    cmd.guard = 'Q';    /* To differentiate from v3 */
    cmd.protocol = BSG_PROTOCOL_SCSI;
    cmd.subprotocol = BSG_SUB_PROTOCOL_SCSI_CMD;
    cmd.request_len = ATAPI_PACKET_SIZE;
    cmd.request = (uintptr_t) request;
    cmd.response = (uintptr_t) & (as->sense);
    cmd.max_response_len = sizeof(as->sense);
    cmd.timeout = as->timeout;

    /* -- SEGMENT ---------------------------------------------------------- */
    do {
        cmd.din_xferp = (uintptr_t) (s->io_buffer + seg_offset);
        cmd.dout_xferp = (uintptr_t) (s->io_buffer + seg_offset);
        *cmd_len_p = (as->max_xfer_len > (*req_len_p - seg_offset)) ?
            (*req_len_p - seg_offset) : as->max_xfer_len;

        if (*req_len_p > as->max_xfer_len) {
            if ((as->request[0] == GPCMD_WRITE_10) ||
                (as->request[0] == GPCMD_WRITE_AND_VERIFY_10) ||
                (as->request[0] == GPCMD_READ_10)) {
                ATAPI_DPRINTF
                    ("'%s' total(%d) seg(%d:%d), remaining: %d\n",
                     atapi_cmd_to_str(as->request[0]),
                     *req_len_p, segment, *cmd_len_p,
                     *req_len_p - seg_offset - *cmd_len_p);

                segment++;
                /* Adjust LBA offset and length */
                lba = ube32_to_cpu((uint8_t *) as->request + 2);
                lba += seg_offset / CD_FRAMESIZE;
                cpu_to_ube32(request + 2, lba);
                len = *cmd_len_p / CD_FRAMESIZE;
                cpu_to_ube16(request + 7, len);

                ATAPI_DPRINTF
                    ("adjust lba from %d to %d, length from %d to %d\n",
                     ube32_to_cpu((uint8_t *) as->request + 2),
                     lba,
                     ube16_to_cpu((uint8_t *) as->request + 7),
                     len);
            } else {
                ATAPI_DPRINTF
                    ("FAILING OVERLONG '%s' (%d, max: %d)\n",
                     atapi_cmd_to_str(as->request[0]),
                     *req_len_p, as->max_xfer_len);
                atapi_pt_set_error((IDEState *) s,
                           SENSE_ILLEGAL_REQUEST,
                           ASC_INV_FIELD_IN_CMD_PACKET,
                           0, 0x70);
                r = -1;
            }
        }
        seg_offset += *cmd_len_p;

        if (cmd.timeout != 15000) {
            ATAPI_DPRINTF("Timeout %d msec", cmd.timeout);
        }

        if (!r) {
            r = bdrv_ioctl(s->bs, SG_IO, &cmd);
        }
        if (r) {
            as->result = r;
        } else if (cmd.driver_status) {
            as->result = cmd.driver_status;
        } else if (cmd.transport_status) {
            as->result = cmd.transport_status;
        } else if (cmd.device_status) {
            as->result = cmd.device_status;
        } else {
            as->result = 0;
        }
        ATAPI_DPRINTF("ioctl(%d) driver(%d) transport(%d) device(%d)",
                  r, cmd.driver_status, cmd.transport_status,
                  cmd.device_status);
        ATAPI_DPRINTF("result(%d) req_len(%d) seg_offset(%d)"
                  "last_segment(%s)",
                  as->result, *req_len_p, seg_offset,
                  (*req_len_p > seg_offset) ? "no" : "yes");
    } while ((!as->result) && (*req_len_p > seg_offset));
    /* --------------------------------------------------------------------- */

    if (as->result) {
        char *p = (char *)&as->sense;

        switch (p[0] & 0x7F) {
        case 0x70 ... 0x71:
            ATAPI_DPRINTF
                ("[\e[1;31mERROR(%s)\e[m] sense(0x%02x,%02x,%02x)(%s)",
                 atapi_cmd_to_str(as->request[0]),
                 as->sense.sense_key, as->sense.asc, as->sense.ascq,
                 atapi_sense_to_str(as->sense.sense_key,
                        as->sense.asc, as->sense.ascq));
            break;
        case 0x72 ... 0x73:
            ATAPI_DPRINTF
                ("[\e[1;31mERROR SPC-3(%s)\e[m] sense(0x%02x,%02x,%02x)(%s)",
                 atapi_cmd_to_str(as->request[0]), p[1] & 0xF, p[2],
                 p[3], atapi_sense_to_str(p[1] & 0xF, p[2], p[3]));
            ATAPI_DPRINTF("Suppressing error\n");
            as->result = 0;
            break;
        default:
            ATAPI_DPRINTF
                ("[\e[1;31mERROR - unrecognised sense format\e[m] (%s)\n",
                 atapi_cmd_to_str(as->request[0]));
            break;
        }
    }

    return r;
}

/* Worker thread... This thread is waiting for a signal from the main processus
 * and perform the command via the atapi_pt_do_dispatch function. */
static void *atapi_pt_worker_thread(void *arg)
{
    volatile IDEState *s = (volatile IDEState *)arg;
    ATAPIPassThroughState *as = s->atapipts;

    while (as->thread_continue) {
        if (event_notifier_wait_and_clear(&as->e_cmd, 0) == 1) {
            atapi_pt_do_dispatch(s);
            event_notifier_set(&as->e_ret);
        }
    }

    qemu_thread_exit(NULL);
    return NULL;
}

/* Allow the device emulation module to send comand to the driver
 * in order to notify it from change */
static int bdrv_set_device_state(BlockDriverState *bs,
                       uint32_t const cmd)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_set_device_state) {
        return drv->bdrv_set_device_state(bs, cmd);
    }
    return -ENOTSUP;
}

static int bdrv_get_device_state(BlockDriverState *bs,
                     uint32_t const cmd, uint32_t *answer)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_get_device_state) {
        if (!answer) {
            return -ENOTSUP;
        }
        return drv->bdrv_get_device_state(bs, cmd, answer);
    }
    return -ENOTSUP;
}

/* AIO Read handler:
 * This function is call to receive message from the sgio_dispatch_fd.
 * It help us to get the return code of IOCTL from the worker thread
 * 'atapi_pt_worker_thread', notify the guest of the return status of the SG_IO
 * and handle error */
static void atapi_pt_event_read(struct EventNotifier *e)
{                /* Mop up result */
    IDEState *s = (IDEState *) e->opaque;
    ATAPIPassThroughState *as = s->atapipts;
    uint32_t din_actual;
    uint32_t lastmediastate;
    uint32_t shm_mediastate;

    event_notifier_test_and_clear(&as->e_ret);

    bdrv_get_device_state(s->bs, BLOCK_PT_CMD_GET_LASTMEDIASTATE,
                      &lastmediastate);
    bdrv_get_device_state(s->bs, BLOCK_PT_CMD_GET_SHM_MEDIASTATE,
                      &shm_mediastate);

    if (as->result) {
        if ((as->sense.sense_key == SENSE_NOT_READY) &&
            (as->sense.asc == ASC_MEDIUM_NOT_PRESENT)) {
            bdrv_set_device_state(s->bs, BLOCK_PT_CMD_SET_MEDIA_ABSENT);
        }
        atapi_pt_error(s);
        return;
    }

    if ((as->request[0] == GPCMD_TEST_UNIT_READY) ||
        (as->request[0] == GPCMD_REQUEST_SENSE) ||
        (as->request[0] == GPCMD_READ_CDVD_CAPACITY) ||
        (as->request[0] == GPCMD_READ_10) ||
        (as->request[0] == GPCMD_READ_12) ||
        (as->request[0] == GPCMD_READ_DISC_INFO)) {
        if (lastmediastate != MEDIA_PRESENT) {
            bdrv_set_device_state(s->bs, BLOCK_PT_CMD_SET_MEDIA_PRESENT);
        }
    }

    if (as->request[0] == GPCMD_GET_EVENT_STATUS_NOTIFICATION) {
        switch (s->io_buffer[4]) {
        case 2:    /* NEW MEDIA */
            if (s->io_buffer[2] == 4) {
                if (lastmediastate != MEDIA_PRESENT) {
                    bdrv_set_device_state(s->bs, BLOCK_PT_CMD_SET_MEDIA_PRESENT);
                }
            }
            break;
        case 3:    /* REMOVED MEDIA */
            if (s->io_buffer[2] == 4) {
                if (lastmediastate != MEDIA_ABSENT) {
                    bdrv_set_device_state(s->bs, BLOCK_PT_CMD_SET_MEDIA_ABSENT);
                }
            }
            break;
        case 0:    /* NO EVENT... but... */
            if ((s->io_buffer[2] == 4 && s->io_buffer[5] == 2) ||
                (!s->io_buffer[5] && !s->io_buffer[6]
                 && !s->io_buffer[7])) {
                /* This is a no activity message... We can hijack it if
                 * needed */
                if ((lastmediastate != shm_mediastate) &&
                    (shm_mediastate != MEDIA_STATE_UNKNOWN)) {
                    lastmediastate = shm_mediastate;
                    switch (lastmediastate) {
                    case MEDIA_ABSENT:
                        /* May be an eject message that we havn't seen yet */
                        s->io_buffer[2] = 4;
                        s->io_buffer[4] = 3;
                        s->io_buffer[5] = 1;
                        s->io_buffer[6] = 0;
                        s->io_buffer[7] = 0;
                        bdrv_set_device_state(s->bs,
                                        BLOCK_PT_CMD_SET_MEDIA_ABSENT);
                        /* TODO: Try to release lock... */
                        break;
                    case MEDIA_PRESENT:
                        /* Check exclusivity here... */
                        s->io_buffer[2] = 4;
                        s->io_buffer[4] = 2;
                        s->io_buffer[5] = 2;
                        s->io_buffer[6] = 0;
                        s->io_buffer[7] = 0;
                        /* TODO: Try to lock... */
                        bdrv_set_device_state(s->bs,
                                        BLOCK_PT_CMD_SET_MEDIA_PRESENT);
                        break;
                    default:
                        break;
                    }
                }
            }
            break;
        default:
            break;
        }
    }

    if (as->din_xfer_len == 0) {
        /* Nothing else to do */
        ide_atapi_cmd_ok(s);
        return;
    }

    din_actual = atapi_pt_get_data_size(ide_atapi_pt_size_din,
                        as->request[0], s->io_buffer);

    /* din_xfer_len is the size of the buffer provided for the din data,
     * din_actual in the size of the data the LU tried to send to us. Either one
     * may be bigger. */
    if (as->request[0] == GPCMD_READ_BUFFER) {
        switch (as->request[1] & 7) {
        case 0:    // data with header, as specified in atapi_data_sizes table
            break;
        case 2:    // data only
            din_actual = as->din_xfer_len;
            break;
        case 3:    // header only
            din_actual = 4;
            break;
        case 1:    // vendor specific
        default:
            ATAPI_DPRINTF("Illegal read buffer mode %d",
                      s->io_buffer[1] & 7);
            atapi_pt_set_error(s, SENSE_ILLEGAL_REQUEST,
                       ASC_INV_FIELD_IN_CMD_PACKET, 0,
                       0x70);
            return;
        }
    }

    if (din_actual == (__u32) - 1)
        din_actual = as->din_xfer_len;

    ATAPI_DPRINTF("Read %d bytes of data (buffer size %d)",
              din_actual, as->din_xfer_len);

    ide_atapi_cmd_reply(s, din_actual, as->din_xfer_len);
}

int atapi_pt_init(IDEState * s)
{
    ATAPIPassThroughState *as = NULL;
    int ret = 0, error = 0;

    /* -- ATAPI Pass Through State initialization -------------------------- */
    as = g_malloc(sizeof(ATAPIPassThroughState));
    if (NULL == as) {
        ATAPI_DPRINTF("no space left on RAM for the device");
        goto atapi_pt_init_failed;
    }
    memset(as, 0, sizeof(ATAPIPassThroughState));
    s->atapipts = as;
    /* --------------------------------------------------------------------- */

    /* -- Create event notifier --------------------------------------------- */
    error =
        event_notifier_init(&as->e_cmd, 0 /* Do not activate it now */ );
    if (error != 0) {
        ATAPI_DPRINTF("[%s] unable to creat EventNotifier",
                  strerror(error));
        goto atapi_pt_init_clean;
    }
    error =
        event_notifier_init(&as->e_ret, 0 /* Do not activate it now */ );
    if (error != 0) {
        ATAPI_DPRINTF("[%s] unable to creat EventNotifier",
                  strerror(error));
        goto atapi_pt_init_clean;
    }
    /* --------------------------------------------------------------------- */

    /* -- Create the worker thread ----------------------------------------- */
    as->thread_continue = true;
    qemu_thread_create(&(as->thread), atapi_pt_worker_thread,
               s, QEMU_THREAD_JOINABLE);
    /* No error checking, qemu_thread_create exit on fail */
    /* --------------------------------------------------------------------- */

    /* -- Get the reserved size --------------------------------------------
     * Find out the maximum block size the hardware supports. This is needed
     * for USB drives where it is 120kb (less than the normal 128kb for some
     * reason) */
    if (bdrv_ioctl(s->bs, SG_GET_RESERVED_SIZE, &(as->max_xfer_len))) {
        ATAPI_DPRINTF
            ("[%s] unable to send an IOCTL (GET_RESERVED_SIZE)",
             strerror(errno));
        goto atapi_pt_init_kill_thread;
    }
    as->max_xfer_len = (as->max_xfer_len + CD_FRAMESIZE - 1) &
        ~(CD_FRAMESIZE - 1);
    /* --------------------------------------------------------------------- */

    as->e_ret.opaque = s;
    event_notifier_set_handler(&as->e_ret, atapi_pt_event_read);
    bdrv_set_device_state(s->bs, BLOCK_PT_CMD_SET_MEDIA_STATE_UNKNOWN);
    goto atapi_pt_init_end;

 atapi_pt_init_kill_thread:
    as->thread_continue = false;
    event_notifier_cleanup(&as->e_cmd);
    event_notifier_cleanup(&as->e_ret);
 atapi_pt_init_clean:
    g_free(as);
 atapi_pt_init_failed:
    ret = -1;
 atapi_pt_init_end:
    ATAPI_DPRINTF("Initialization %s", (ret == 0) ? "succeed" : "failed");
    return ret;
}

/* -- Command functions ---------------------------------------------------- */

static void atapi_pt_do_sg_io(IDEState * s)
{
    /* POKE The worker thread to send command using SG_IO ioctl */
    event_notifier_set(&s->atapipts->e_cmd);
}

void atapi_pt_dout_fetch_pio_done(IDEState * s)
{
    ide_transfer_stop(s);
    atapi_pt_do_sg_io(s);
}

static void atapi_pt_dout_fetch_dma_done(void *opaque, int ret)
{
    IDEState *s = opaque;

    if (ret < 0) {
        ide_atapi_io_error(s, ret);
        return;
    }

    s->bus->dma->ops->rw_buf(s->bus->dma, 0);

    atapi_pt_do_sg_io(s);
}

static void atapi_pt_wcmd(IDEState * s)
{
    s->io_buffer_index = 0;
    if (s->atapi_dma) {
        s->io_buffer_size = s->atapipts->dout_xfer_len;
        s->bus->dma->ops->start_dma(s->bus->dma, s,
                        atapi_pt_dout_fetch_dma_done);
    } else {        /* PIO */
        s->packet_transfer_size = s->atapipts->dout_xfer_len;
        s->io_buffer_size = 0;
        s->elementary_transfer_size = 0;
        s->status |= DRQ_STAT;
        s->status &= ~BUSY_STAT;
        s->nsector = (s->nsector & ~7) &
            ~ATAPI_INT_REASON_IO & ~ATAPI_INT_REASON_CD;
        ide_transfer_start(s, s->io_buffer, s->atapipts->dout_xfer_len,
                   atapi_pt_dout_fetch_pio_done);
        ide_set_irq(s->bus);
    }
}

static int atapi_pt_read_cd_block_size(uint8_t const *io_buffer)
{
    int sector_type = (io_buffer[1] >> 2) & 7;
    int error_flags = (io_buffer[9] >> 1) & 3;
    int flags_bits = io_buffer[9] & ~7;
    int block_size = 0;

    // expected sector type
    switch (sector_type) {
    case 0:        // Any type
        switch (flags_bits) {
        case 0x0:
            block_size = 0;
            break;
        case 0x10:
            block_size = 2048;
            break;
        case 0xf8:
            block_size = 2352;
            break;

        default:
            return -1;    // illegal
        }
        break;

    case 1:        // CD-DA
        block_size = (flags_bits) ? 2352 : 0;
        break;

    case 2:        // Mode 1
        switch (flags_bits) {
        case 0x0:
            block_size = 0;
            break;
        case 0x10:
        case 0x50:
            block_size = 2048;
            break;
        case 0x18:
        case 0x58:
            block_size = 2336;
            break;
        case 0x20:
        case 0x60:
            block_size = 4;
            break;
        case 0x30:
        case 0x70:
        case 0x78:
            block_size = 2052;
            break;
        case 0x38:
            block_size = 2340;
            break;
        case 0x40:
            block_size = 0;
            break;
        case 0xa0:
            block_size = 16;
            break;
        case 0xb0:
            block_size = 2064;
            break;
        case 0xb8:
            block_size = 2352;
            break;
        case 0xe0:
            block_size = 16;
            break;
        case 0xf0:
            block_size = 2064;
            break;
        case 0xf8:
            block_size = 2352;
            break;

        default:
            return -1;    // illegal
        }
        break;

    case 3:        // Mode 2
        switch (flags_bits) {
        case 0x0:
            block_size = 0;
            break;
        case 0x10:
        case 0x50:
        case 0x18:
        case 0x58:
            block_size = 2336;
            break;
        case 0x20:
        case 0x60:
            block_size = 4;
            break;
        case 0x30:
        case 0x70:
        case 0x78:
        case 0x38:
            block_size = 2340;
            break;
        case 0x40:
            block_size = 0;
            break;
        case 0xa0:
            block_size = 16;
            break;
        case 0xb0:
        case 0xb8:
            block_size = 2352;
            break;
        case 0xe0:
            block_size = 16;
            break;
        case 0xf0:
        case 0xf8:
            block_size = 2352;
            break;

        default:
            return -1;    // illegal
        }
        break;

    case 4:        // Mode 2 Form 1
        switch (flags_bits) {
        case 0x0:
            block_size = 0;
            break;
        case 0x10:
            block_size = 2048;
            break;
        case 0x18:
            block_size = 2328;
            break;
        case 0x20:
            block_size = 4;
            break;
        case 0x40:
            block_size = 8;
            break;
        case 0x50:
            block_size = 2056;
            break;
        case 0x58:
            block_size = 2336;
            break;
        case 0x60:
            block_size = 12;
            break;
        case 0x70:
            block_size = 2060;
            break;
        case 0x78:
            block_size = 2340;
            break;
        case 0xa0:
            block_size = 16;
            break;
        case 0xe0:
            block_size = 24;
            break;
        case 0xf0:
            block_size = 2072;
            break;
        case 0xf8:
            block_size = 2352;
            break;

        default:
            return -1;    // illegal
        }
        break;

    case 5:        // Mode 2 Form 2
        switch (flags_bits) {
        case 0x0:
            block_size = 0;
            break;
        case 0x10:
        case 0x18:
            block_size = 2328;
            break;
        case 0x20:
            block_size = 4;
            break;
        case 0x40:
            block_size = 8;
            break;
        case 0x50:
        case 0x58:
            block_size = 2336;
            break;
        case 0x60:
            block_size = 12;
            break;
        case 0x70:
        case 0x78:
            block_size = 2340;
            break;
        case 0xa0:
            block_size = 16;
            break;
        case 0xe0:
            block_size = 24;
            break;
        case 0xf0:
        case 0xf8:
            block_size = 2352;
            break;

        default:
            return -1;    // illegal
        }
        break;

    default:
        return -1;
    }

    switch (error_flags) {
    case 1:
        block_size += 294;
        break;
    case 2:
        block_size += 296;
        break;

    default:
        break;
    }

    return block_size;
}

void atapi_pt_cmd(IDEState * s)
{
    ATAPIPassThroughState *as = s->atapipts;
    uint8_t cmd_code;
    int block_size;

    memcpy(as->request, s->io_buffer, ATAPI_PACKET_SIZE);
    cmd_code = as->request[0];
    as->timeout = 15000;
    s->status |= BUSY_STAT;

    if (cmd_code == GPCMD_REQUEST_SENSE && ((char *)&as->sense)[0] != 0) {
        int max_size = atapi_pt_get_data_size(ide_atapi_pt_size_buffer,
                              GPCMD_REQUEST_SENSE,
                              as->request);

        int size = atapi_pt_get_data_size(ide_atapi_pt_size_din,
                          GPCMD_REQUEST_SENSE,
                          (uint8_t *) & as->sense);

        memcpy(s->io_buffer, &as->sense, sizeof(as->sense));

        ide_atapi_cmd_reply(s, size, max_size);

        ATAPI_DUMP_SENSE(as->sense.sense_key, as->sense.asc,
                 as->sense.ascq);
        // Make sure we don't send the same reply again
        *(char *)(&as->sense) = '\0';
        return;
    }
    // Make sure we don't re-use an old Request Sense reply
    // if another command was processed in between
    *(char *)(&as->sense) = '\0';

    as->dout_xfer_len = atapi_pt_get_data_size(ide_atapi_pt_size_dout,
                           cmd_code, as->request);

    as->din_xfer_len = atapi_pt_get_data_size(ide_atapi_pt_size_buffer,
                          cmd_code, as->request);

    /* Claim exclusive use if we're doing any kind of writing */
    if ((cmd_code == GPCMD_BLANK) || (cmd_code == GPCMD_CLOSE_TRACK) ||
        (cmd_code == GPCMD_FLUSH_CACHE) || (cmd_code == GPCMD_FORMAT_UNIT)
        || (cmd_code == GPCMD_SEND_DVD_STRUCTURE)
        || (cmd_code == GPCMD_SEND_OPC) || (cmd_code == GPCMD_WRITE_10)
        || (cmd_code == GPCMD_WRITE_12)
        || (cmd_code == GPCMD_WRITE_AND_VERIFY_10)
        || (cmd_code == GPCMD_WRITE_BUFFER)) {
        if (bdrv_is_read_only(s->bs)) {
            atapi_pt_set_error(s, SENSE_ILLEGAL_REQUEST,
                       ASC_ILLEGAL_OPCODE, 0, 0x70);
            ATAPI_DPRINTF("Unable to perform(%s): readonly device",
                      atapi_cmd_to_str(cmd_code));
            return;
        }
    }

    if (cmd_code == GPCMD_START_STOP_UNIT) {
        if ((as->request[4] & 0x3) == 0x0) {
            // Stop motor command: Win7 guest sends this on shutdown,
            // we ignore this so other VM's don't get shafted
            ATAPI_DPRINTF
                ("Stop motor command: win7 sends this on shutdown");
            ide_atapi_cmd_ok(s);
            return;
        }
    }

    ATAPI_DPRINTF("sending command: 0x%02x (\e[0;32m%s\e[m) dma=%d"
              " timeout(%u)",
              cmd_code, atapi_cmd_to_str(cmd_code), s->atapi_dma,
              s->atapipts->timeout);
#if defined(ATAPI_PT_DEBUG)
    atapi_pt_dump_hexa(as->request, ATAPI_PACKET_SIZE);
#endif

    /* A few commands need special attention */
    switch (cmd_code) {
    //case GPCMD_SET_STREAMING:
    case GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL:
        // we don't allow locking, to prevent a VM from hogging the drive
        ATAPI_DPRINTF("Don't allow(%s)", atapi_cmd_to_str(cmd_code));
        ide_atapi_cmd_ok(s);
        return;

    case GPCMD_FLUSH_CACHE:    // bigger timeout while flushing write cache
        as->timeout = 1000 * 60;
        break;

    case GPCMD_SEND_OPC:    // bigger timeout while sending OPC
        as->timeout = 1000 * 60;
        break;

    case GPCMD_FORMAT_UNIT:    // bigger timeout while formatting
        if ((s->io_buffer[1] & 2) == 0) {    // and only if Immed bit not set
            as->timeout = 1000 * 60 * 20;
        }
        /* If Format Code == 7 the drive expects 4 more bytes.
         * Not sure which spec that's defined in, the ATAPI spec
         * requires it to be 1. */
        if ((as->request[1] & 7) != 1) {
            as->dout_xfer_len += 4;
        }
        break;

    case GPCMD_BLANK:    // bigger timeout while blanking
        as->timeout = 1000 * 60 * 80;    // 80 mins
        break;

    case GPCMD_CLOSE_TRACK:
        as->timeout = 1000 * 60 * 5;    // 5 mins
        break;

    case GPCMD_WRITE_BUFFER:
        if ((s->io_buffer[1] & 7) != 0 &&    /* Combined header and data mode */
            (s->io_buffer[1] & 7) != 2) {    /* Data mode */
            atapi_pt_set_error(s, SENSE_ILLEGAL_REQUEST,
                       ASC_INV_FIELD_IN_CMD_PACKET, 0,
                       0x70);
            ATAPI_DPRINTF
                ("Illegal request(%s): invalid field in CMD Packet",
                 atapi_cmd_to_str(cmd_code));
            return;
        }
        break;

    case GPCMD_WRITE_10:    // bigger timout while writing
        as->timeout = 1000 * 60;
        break;

    case GPCMD_READ_CD:
        // We read blocks, not bytes
        block_size = atapi_pt_read_cd_block_size(s->io_buffer);
        if (block_size < 0) {
            atapi_pt_set_error(s, SENSE_ILLEGAL_REQUEST,
                       ASC_INV_FIELD_IN_CMD_PACKET, 0,
                       0x70);
            ATAPI_DPRINTF
                ("Illegal request(%s): read a not handled field",
                 atapi_cmd_to_str(cmd_code));
            return;
        }
        as->din_xfer_len *= block_size;
        break;

    case GPCMD_READ_CD_MSF:
        {
            // command fields
            int starting_frame =
                MSF_TO_FRAMES(s->io_buffer[3], s->io_buffer[4],
                      s->io_buffer[5]);
            int ending_frame =
                MSF_TO_FRAMES(s->io_buffer[6], s->io_buffer[7],
                      s->io_buffer[8]);
            int block_count = ending_frame - starting_frame;

            block_size = atapi_pt_read_cd_block_size(s->io_buffer);
            if (block_size < 0) {
                atapi_pt_set_error(s, SENSE_ILLEGAL_REQUEST,
                           ASC_INV_FIELD_IN_CMD_PACKET,
                           0, 0x70);
                ATAPI_DPRINTF
                    ("Illegal request(%s): read a not handled frame field",
                     atapi_cmd_to_str(cmd_code));
                return;
            }
            as->din_xfer_len = block_count * block_size;
            break;
        }

    case GPCMD_PLAY_AUDIO_MSF:
        {
            int starting_frame =
                MSF_TO_FRAMES(s->io_buffer[3], s->io_buffer[4],
                      s->io_buffer[5]);
            int ending_frame =
                MSF_TO_FRAMES(s->io_buffer[6], s->io_buffer[7],
                      s->io_buffer[8]);
            int block_count = ending_frame - starting_frame;
            as->din_xfer_len = block_count * CD_FRAMESIZE;
            break;
        }

    case GPCMD_GET_PERFORMANCE:
        // din_xfer_len is currently the max number of descriptors
        switch (s->io_buffer[10]) {
        case 0:    // performance
            if ((s->io_buffer[1] & 3) == 0) {    // nominal performance, 16 byte descriptors
                as->din_xfer_len *= 16;
            } else {    // exceptions, 6 byte descriptors
                as->din_xfer_len *= 6;
            }
            break;

        case 1:    // unusable area
            as->din_xfer_len *= 8;    // 8 byte descriptors
            break;

        case 2:    // defect status
            as->din_xfer_len *= 2048;    // 2048 byte descriptors
            break;

        case 3:    // write speed
            as->din_xfer_len *= 16;    // 16 byte descriptors
            break;

        case 4:    // DBI data
            as->din_xfer_len *= 8;    // 8 byte descriptors
            break;

        default:
            atapi_pt_set_error(s, SENSE_ILLEGAL_REQUEST,
                       ASC_INV_FIELD_IN_CMD_PACKET, 0,
                       0x70);
            ATAPI_DPRINTF
                ("Illegal request(%s): bad field in CMD Packet",
                 atapi_cmd_to_str(cmd_code));
            return;
        }

        as->din_xfer_len += 8;    // 8 bytes of header
        break;

    case GPCMD_LOAD_UNLOAD:
        break;
    default:
        break;
    }

    /* Clear sense data */
    memset(&as->sense, 0, sizeof(as->sense));

    if (as->dout_xfer_len == (__u32) - 1) {
        atapi_pt_set_error(s, SENSE_ILLEGAL_REQUEST,
                   ASC_ILLEGAL_OPCODE, 0, 0x70);
        ATAPI_DPRINTF
            ("Illegal request(%s): illegal opcode (dout_xfer_len == -1)",
             atapi_cmd_to_str(cmd_code));
        return;
    }

    if (as->dout_xfer_len > 0) {
        /* dout data is required, get it from somewhere */
        atapi_pt_wcmd(s);
        return;
    }

    atapi_pt_do_sg_io(s);
}
