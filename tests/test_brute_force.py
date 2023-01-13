import copy
import logging

from chirp import chirp_common
from chirp import errors
from tests import base

LOG = logging.getLogger(__name__)


class TestCaseBruteForce(base.DriverTest):
    def set_and_compare(self, m):
        msgs = self.radio.validate_memory(m)
        if msgs:
            # If the radio correctly refuses memories it can't
            # store, don't fail
            return

        self.radio.set_memory(m)
        ret_m = self.radio.get_memory(m.number)

        # Damned Baofeng radios don't seem to properly store
        # shift and direction, so be gracious here
        if m.duplex == "split" and ret_m.duplex in ["-", "+"]:
            ret_m.offset = ret_m.freq + \
                (ret_m.offset * int(ret_m.duplex + "1"))
            ret_m.duplex = "split"

        self.assertEqualMem(m, ret_m)

    def test_tone(self):
        m = self.get_mem()
        for tone in chirp_common.TONES:
            for tmode in self.rf.valid_tmodes:
                if tmode not in chirp_common.TONE_MODES:
                    continue
                elif tmode in ["DTCS", "DTCS-R", "Cross"]:
                    continue  # We'll test DCS and Cross tones separately

                m.tmode = tmode
                if tmode == "":
                    pass
                elif tmode == "Tone":
                    m.rtone = tone
                elif tmode in ["TSQL", "TSQL-R"]:
                    if self.rf.has_ctone:
                        m.ctone = tone
                    else:
                        m.rtone = tone
                else:
                    self.fail("Unknown tone mode `%s'" % tmode)

                try:
                    self.set_and_compare(m)
                except errors.UnsupportedToneError as e:
                    # If a radio doesn't support a particular tone value,
                    # don't punish it
                    pass

    @base.requires_feature('has_dtcs')
    def test_dtcs(self):
        m = self.get_mem()
        m.tmode = "DTCS"
        for code in self.rf.valid_dtcs_codes:
            m.dtcs = code
            self.set_and_compare(m)

        if not self.rf.has_dtcs_polarity:
            return

        for pol in self.rf.valid_dtcs_pols:
            m.dtcs_polarity = pol
            self.set_and_compare(m)

    @base.requires_feature('has_cross')
    def test_cross(self):
        m = self.get_mem()
        m.tmode = "Cross"
        # No fair asking a radio to detect two identical tones as Cross instead
        # of TSQL
        m.rtone = 100.0
        m.ctone = 107.2
        m.dtcs = 506
        m.rx_dtcs = 516
        for cross_mode in self.rf.valid_cross_modes:
            m.cross_mode = cross_mode
            self.set_and_compare(m)

    @base.requires_feature('valid_duplexes')
    def do_duplex(self):
        m = self.get_mem()
        for duplex in self.rf.valid_duplexes:
            if duplex not in ["", "-", "+", "split"]:
                continue
            if duplex == 'split':
                self.assertTrue(self.rf.can_odd_split,
                                'Radio supports split but does not set '
                                'can_odd_split=True in features')
                m.offset = self.rf.valid_bands[0][1] - 100000
            m.duplex = duplex
            self.set_and_compare(m)

        if self.rf.can_odd_split:
            self.assertIn('split', self.rf.valid_duplexes,
                          'Radio claims can_odd_split but split not in '
                          'valid_duplexes')

    @base.requires_feature('valid_skips')
    def test_skip(self):
        m = self.get_mem()
        for skip in self.rf.valid_skips:
            m.skip = skip
            self.set_and_compare(m)

    @base.requires_feature('valid_modes')
    def do_mode(self):
        m = self.get_mem()
        def ensure_urcall(call):
            l = self.radio.get_urcall_list()
            l[0] = call
            self.radio.set_urcall_list(l)

        def ensure_rptcall(call):
            l = self.radio.get_repeater_call_list()
            l[0] = call
            self.radio.set_repeater_call_list(l)

        def freq_is_ok(freq):
            for lo, hi in self.rf.valid_bands:
                if freq > lo and freq < hi:
                    return True
            return False

        successes = 0
        for mode in self.rf.valid_modes:
            self.assertIn(mode, chirp_common.MODES,
                          'Radio exposes non-standard mode')
            tmp = copy.deepcopy(m)
            if mode == "DV" and \
                   isinstance(self.radio,
                              chirp_common.IcomDstarSupport):
                tmp = chirp_common.DVMemory()
                try:
                    ensure_urcall(tmp.dv_urcall)
                    ensure_rptcall(tmp.dv_rpt1call)
                    ensure_rptcall(tmp.dv_rpt2call)
                except IndexError:
                    if self.rf.requires_call_lists:
                        raise
                    else:
                        # This radio may not do call lists at all,
                        # so let it slide
                        pass
            if mode == "FM" and freq_is_ok(tmp.freq + 100000000):
                # Some radios don't support FM below approximately 30MHz,
                # so jump up by 100MHz, if they support that
                tmp.freq += 100000000

            tmp.mode = mode

            if self.rf.validate_memory(tmp):
                # A result (of error messages) from validate means the radio
                # thinks this is invalid, so don't fail the test
                LOG.warning('Failed to validate %s: %s' % (
                    tmp, self.rf.validate_memory(tmp)))
                continue

            self.set_and_compare(tmp)
            successes += 1