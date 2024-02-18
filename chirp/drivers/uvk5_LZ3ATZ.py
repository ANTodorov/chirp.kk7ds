# Quansheng UV-K5 driver (c) 2023 Jacek Lipkowski <sq5bpf@lipkowski.org>
# 
# based on uvk5_egzumer.py Copyright 2023 EGZUMER, JOD
#
#
# This is a preliminary version of a driver for the UV-K5
# It is based on my reverse engineering effort described here:
# https://github.com/sq5bpf/uvk5-reverse-engineering
#
# Warning: this driver is experimental, it may brick your radio,
# eat your lunch and mess up your configuration.
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import struct
import logging
import re

from chirp import chirp_common, directory, bitwise, memmap, errors, util
from chirp.drivers import uvk5
from chirp.drivers import uvk5_egzumer
from chirp.settings import RadioSetting, RadioSettingGroup, \
    RadioSettingValueBoolean, RadioSettingValueList, \
    RadioSettingValueInteger, RadioSettingValueString, \
    RadioSettings, InvalidValueError, RadioSettingSubGroup

LOG = logging.getLogger(__name__)

MEM_FORMAT = """
#seekto 0xe40;
ul16 fmfreq[20];

#seekto 0xe78;
u8 backlight_min:4,
backlight_max:4;

u8 channel_display_mode;
u8 crossband;
u8 battery_save;
u8 dual_watch;
u8 backlight_time;
u8 ste;
u8 freq_mode_allowed;

#seekto 0xe90;
u8 keyM_longpress_action:7,
    button_beep:1;

u8 key1_shortpress_action;
u8 key1_longpress_action;
u8 key2_shortpress_action;
u8 key2_longpress_action;
u8 scan_resume_mode;
u8 auto_keypad_lock;
u8 power_on_dispmode;
ul32 password;

#seekto 0xea0;
u8 voice;
u8 s0_level;
u8 s9_level;

#seekto 0xea8;
u8 alarm_mode;
u8 roger_beep;
u8 rp_ste;
u8 TX_VFO;
u8 Battery_type;

#seekto 0xeb0;
char logo_line1[16];
char logo_line2[16];

//#seekto 0xed0;
struct {
    u8 side_tone;
    char separate_code;
    char group_call_code;
    u8 decode_response;
    u8 auto_reset_time;
    u8 preload_time;
    u8 first_code_persist_time;
    u8 hash_persist_time;
    u8 code_persist_time;
    u8 code_interval_time;
    u8 permit_remote_kill;

    #seekto 0xee0;
    char local_code[3];
    #seek 5;
    char kill_code[5];
    #seek 3;
    char revive_code[5];
    #seek 3;
    char up_code[16];
    char down_code[16];
} dtmf;

#seekto 0xf40;
u8 int_flock;
u8 int_350tx;
u8 int_KILLED;
u8 int_200tx;
u8 int_500tx;
u8 int_350en;
u8 int_scren;


u8  backlight_on_TX_RX:2,
    AM_fix:1,
    mic_bar:1,
    battery_text:2,
    live_DTMF_decoder:1,
    unknown:1;


#seekto 0x1c00;
struct {
char name[8];
char number[3];
#seek 5;
} dtmfcontact[16];

struct {
    struct {
        #seekto 0x1E00;
        u8 openRssiThr[10];
        #seekto 0x1E10;
        u8 closeRssiThr[10];
        #seekto 0x1E20;
        u8 openNoiseThr[10];
        #seekto 0x1E30;
        u8 closeNoiseThr[10];
        #seekto 0x1E40;
        u8 closeGlitchThr[10];
        #seekto 0x1E50;
        u8 openGlitchThr[10];
    } sqlBand4_7;

    struct {
        #seekto 0x1E60;
        u8 openRssiThr[10];
        #seekto 0x1E70;
        u8 closeRssiThr[10];
        #seekto 0x1E80;
        u8 openNoiseThr[10];
        #seekto 0x1E90;
        u8 closeNoiseThr[10];
        #seekto 0x1EA0;
        u8 closeGlitchThr[10];
        #seekto 0x1EB0;
        u8 openGlitchThr[10];
    } sqlBand1_3;

    #seekto 0x1EC0;
    struct {
        ul16 level1;
        ul16 level2;
        ul16 level4;
        ul16 level6;
    } rssiLevelsBands3_7;

    struct {
        ul16 level1;
        ul16 level2;
        ul16 level4;
        ul16 level6;
    } rssiLevelsBands1_2;

    struct {
        struct {
            u8 lower;
            u8 center;
            u8 upper;
        } low;
        struct {
            u8 lower;
            u8 center;
            u8 upper;
        } mid;
        struct {
            u8 lower;
            u8 center;
            u8 upper;
        } hi;
        #seek 7;
    } txp[7];

    #seekto 0x1F40;
    ul16 batLvl[6];

    #seekto 0x1F50;
    ul16 vox1Thr[10];

    #seekto 0x1F68;
    ul16 vox0Thr[10];

    #seekto 0x1F80;
    u8 micLevel[5];

    #seekto 0x1F88;
    il16 xtalFreqLow;

    #seekto 0x1F8E;
    u8 volumeGain;
    u8 dacGain;
} cal;


#seekto 0x1FF0;
struct {
u8 ENABLE_DTMF_CALLING:1,
   ENABLE_PWRON_PASSWORD:1,
   ENABLE_TX1750:1,
   ENABLE_ALARM:1,
   ENABLE_VOX:1,
   ENABLE_VOICE:1,
   ENABLE_NOAA:1,
   ENABLE_FMRADIO:1;
u8 __UNUSED:3,
   ENABLE_AM_FIX:1,
   ENABLE_BLMIN_TMP_OFF:1,
   ENABLE_RAW_DEMODULATORS:1,
   ENABLE_WIDE_RX:1,
   ENABLE_FLASHLIGHT:1;
} BUILD_OPTIONS;


// 0x0E80 EEPROM_DISP_CH_STORE_OFF
#seekto 0x2000;
u16 ScreenChannel_A;
u16 MrChannel_A;
u16 FreqChannel_A;
u16 ScreenChannel_B;
u16 MrChannel_B;
u16 FreqChannel_B;
u16 NoaaChannel_A;
u16 NoaaChannel_B;

// 0x0E70 EEPROM_SETTINGS_OFF
//#seekto 0x2010;
u16 call_channel;
u16 squelch;
u16 max_talk_time;
u16 noaa_autoscan;
u16 key_lock;
u16 vox_switch;
u16 vox_level;
u16 mic_gain;

// 0x0E70 EEPROM_SCANLIST_OFF
//#seekto 0x2020;
u16 slDef;
u16 sl1PriorEnab;
u16 sl1PriorCh1;
u16 sl1PriorCh2;
u16 sl2PriorEnab;
u16 sl2PriorCh1;
u16 sl2PriorCh2;
//u16 unused

// 0x0F50 EEPROM_MR_CH_NAME_OFF
#seekto 0x2030;
struct {
    char name[16];
// channels
} channelname[channels_name_count];

// 0x0000 EEPROM_MR_CH_FREQ_OFF
// 0x0C80 EEPROM_FREQ_CH_FREQ_OFF
//#seekto 0x5ea0;
struct {
  ul32 freq;
  ul32 offset;

// 0x08
  u8 rxcode;
  u8 txcode;

// 0x0A
  u8 txcodeflag:4,
  rxcodeflag:4;

// 0x0B
  u8 modulation:4,
  shift:4;

// 0x0C
  u8 __UNUSED1:3,
  bclo:1,
  txpower:2,
  bandwidth:1,
  freq_reverse:1;

  // 0x0D
  u8 __UNUSED2:4,
  dtmf_pttid:3,
  dtmf_decode:1;

  // 0x0E
  u8 step;
  u8 scrambler;
// channels + 14
} channel[channels_freq_count];

// 0x0D60 EEPROM_MR_CH_ATTR_OFF
// 0x0E28 EEPROM_FREQ_CH_ATTR_OFF
//#seekto 0x9df0;
struct {
  u8 is_scanlist1:1,
  is_scanlist2:1,
  compander:2,
  is_free:1,
   band:3;
// channels + 7
} channel_attributes[channels_attr_count];
"""


@directory.register
@directory.detected_by(uvk5.UVK5Radio)
class UVK5RadioLZ3ATZ999(uvk5_egzumer.UVK5RadioEgzumer):
    """Quansheng UV-K5 (LZ3ATZ) 999 channels"""
    VARIANT = "k5EZ999"
    FIRMWARE_VERSION = ""
    _mem_size = 0x10000 # eeprom total size
    _prog_size = 0x10000 # eeprom size without calibration
    _channels = 999  # number of MR channels
    _channels_mask = 0xffff  # max channel number
    _upload_calibration = False

    @classmethod
    def k5_approve_firmware(cls, firmware):
        return firmware.startswith('K5EZ999 ') or firmware.startswith('EGZUMR3 ')
    
    # Convert the raw byte array into a memory object structure
    def process_mmap(self):
        self._check_firmware_at_load()
        self._memobj = bitwise.parse(
            MEM_FORMAT.replace('channels_name_count', str(self._channels))
                      .replace('channels_freq_count', str(self._channels+14))
                      .replace('channels_attr_count', str(self._channels+7)),
            self._mmap,
        )


@directory.register
@directory.detected_by(uvk5.UVK5Radio)
class UVK5RadioLZ3ATZ736(uvk5_egzumer.UVK5RadioEgzumer):
    """Quansheng UV-K5 (LZ3ATZ) 736 channels"""
    VENDOR = "Quansheng"
    MODEL = "UV-K5"
    VARIANT = "K5EZ736"
    BAUD_RATE = 38400
    NEEDS_COMPAT_SERIAL = False
    FIRMWARE_VERSION = ""
    _mem_size = 0x8000 # eeprom total size
    _prog_size = 0x8000 # eeprom size without calibration
    _channels = 736  # number of MR channels
    _channels_mask = 0xffff  # max channel number

    @classmethod
    def k5_approve_firmware(cls, firmware):
        return firmware.startswith('K5EZ736 ') or firmware.startswith('EGZUMR2 ')
    
    # Convert the raw byte array into a memory object structure
    def process_mmap(self):
        self._check_firmware_at_load()
        self._memobj = bitwise.parse(
            MEM_FORMAT.replace('channels_name_count', str(self._channels))
                      .replace('channels_freq_count', str(self._channels+14))
                      .replace('channels_attr_count', str(self._channels+7)),
            self._mmap,
        )
        

@directory.register
@directory.detected_by(uvk5.UVK5Radio)
class UVK5RadioLZ3ATZ239(uvk5_egzumer.UVK5RadioEgzumer):
    """Quansheng UV-K5 (LZ3ATZ) 239 channels"""
    VENDOR = "Quansheng"
    MODEL = "UV-K5"
    VARIANT = "K5EZ239"
    BAUD_RATE = 38400
    NEEDS_COMPAT_SERIAL = False
    FIRMWARE_VERSION = ""
    _mem_size = 0x4000 # eeprom total size
    _prog_size = 0x4000 # eeprom size without calibration
    _channels = 239  # number of MR channels
    _channels_mask = 0xffff  # max channel number

    @classmethod
    def k5_approve_firmware(cls, firmware):
        return firmware.startswith('K5EZ239 ') or firmware.startswith('EGZUMR1 ')
    
    # Convert the raw byte array into a memory object structure
    def process_mmap(self):
        self._check_firmware_at_load()
        self._memobj = bitwise.parse(
            MEM_FORMAT.replace('channels_name_count', str(self._channels))
                      .replace('channels_freq_count', str(self._channels+14))
                      .replace('channels_attr_count', str(self._channels+7)),
            self._mmap,
        )
