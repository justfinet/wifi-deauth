from enum import Enum

BD_MACADDR = "ff:ff:ff:ff:ff:ff"


class BandType(Enum):
    T_24GHZ = "24GHZ"
    T_50GHZ = "50GHZ"


class SSID:
    def __init__(self,
                 name: str,
                 mac_addr: str,
                 band_type: BandType):
        self.name = name
        self.mac_addr = mac_addr

        self._band_type = band_type
        self._channel_list = list()

    def add_channel(self, ch: int):
        self._channel_list.append(ch)
        self._channel_list = sorted(self._channel_list)

    @property
    def channel(self) -> int:  # return the most frequently seen channel
        ch_counts = {ch: self._channel_list.count(ch) for ch in set(self._channel_list)}
        return min(ch_counts, key=lambda ch: (-ch_counts[ch], ch))


def frequency_to_channel(freq: int) -> int:
    if freq == 2484:  # channel 14 doesn't follow the 5 MHz spacing rule
        return 14
    base = 5000 if freq // 1000 == 5 else 2407
    return (freq - base) // 5
