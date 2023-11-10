import json
import struct

from pathlib import Path
from math import ceil

from multirange import MultiRange

__all__ = [
    "Aria2Parser",
    "Aria2ParserError",
    "MalformedPartialFileError",
    "BadControlFileError",
]

_INFO = ">HLL"
_LENGTHS = ">LQQL"
_IN_FLIGHT_NUM = ">L"
_IN_FLIGHT = ">LLL"
_CHUNK_SIZE = 2 << 13  # 16 KiB
_PIECE_SIZE = 2 << 19  # 1 MiB


class Aria2ParserError(Exception):
    pass


class MalformedPartialFileError(Aria2ParserError):
    pass


class BadControlFileError(Aria2ParserError):
    pass


def _s(version, format_):
    """Return struct format using big-endian or native depending on the version."""
    if version == 1:
        return format_
    elif version == 0:
        return format_.replace(">", "=")
    else:
        raise BadControlFileError("version other than 0 and 1 not supported")


def _read(f, format_):
    size = struct.calcsize(format_)
    tmp = f.read(size)
    if len(tmp) != size:
        raise BadControlFileError("truncated control file")

    return tmp


def _range(i, piece_size, total_size):
    return (i * piece_size, min((i + 1) * piece_size, total_size))


def _parse_bitfield(bitfield, piece_size, total_size):
    completed_ranges = []
    for i in range(len(bitfield) * 8):
        if (bitfield[i // 8] >> (7 - i % 8)) & 1 == 1:
            completed_ranges.append(_range(i, piece_size, total_size))

    return MultiRange(completed_ranges)


def _create_bitfield(downloaded, piece_size, total_size):
    incomplete_pieces = []

    pieces = ceil(total_size / piece_size)
    bitfield_len = ceil(pieces / 8)
    bitfield = [0] * bitfield_len
    for i in range(pieces):
        fragment = MultiRange([_range(i, piece_size, total_size)])
        real_fragment = downloaded & fragment

        if (real_len := len(real_fragment)) == 0:
            continue

        if (fragment_size := len(fragment)) == real_len:
            bitfield[i // 8] |= 1 << (7 - i % 8)
        else:
            incomplete_pieces.append((i, real_fragment, fragment_size))

    return bytes(bitfield), incomplete_pieces


class Aria2Parser:
    """Class for parsing and creating .aria2 control files."""

    def __init__(self, filepath, filesize):
        self.filesize = filesize

        filepath = str(filepath)
        self._control_file = Path(filepath + ".aria2")
        self._temporary_control_file = Path(filepath + ".aria2_TMP")
        self._partial_file = Path(filepath + ".aria2_partial")
        self._temporary_partial_file = Path(filepath + ".aria2_partial_TMP")
        self._download_file = Path(filepath)

        self.__full_file = MultiRange([(0, filesize)])

        self._upload_len = 0
        self.piece_size = _PIECE_SIZE

        if not self._download_file.is_file():
            for x in (self._control_file, self._partial_file):
                try:
                    x.unlink()
                except FileNotFoundError:
                    pass
            self.downloaded = self._downloaded = self._requested = MultiRange([])
        else:
            self.parse()

    def parse(self):
        self._requested = self.__full_file
        try:
            with open(self._partial_file, "r") as f:
                try:
                    self._requested = MultiRange(json.load(f))
                except (IndexError, ValueError, json.JSONDecodeError):
                    raise MalformedPartialFileError(
                        f"{str(self._partial_file)} is malformed",
                        self._partial_file,
                    )
        except FileNotFoundError:
            pass

        self._downloaded = self.__full_file
        if self._control_file.is_file():
            self._parse_control_file()

        self.downloaded = self._downloaded & self._requested

    def _parse_control_file(self):
        with open(self._control_file, "rb") as f:
            tmp = _read(f, _INFO)
            version, extension, info_hash_len = struct.unpack(_s(1, _INFO), tmp)
            if version == 0:
                version, extension, info_hash_len = struct.unpack(
                    _s(version, _INFO), tmp
                )

            if extension != 0:
                raise BadControlFileError("extension other than 0 not supported")

            if info_hash_len != 0:
                raise BadControlFileError("info hash not supported")

            tmp = _read(f, _LENGTHS)
            (
                self.piece_size,
                total_len,
                self._upload_len,
                bitfield_len,
            ) = struct.unpack(_s(version, _LENGTHS), tmp)

            if total_len != self.filesize:
                raise BadControlFileError(
                    f"filesize doesn't match ({total_len} vs {self.filesize})"
                )

            bitfield = _read(f, f"{bitfield_len}B")
            downloaded = _parse_bitfield(bitfield, self.piece_size, self.filesize)

            tmp = _read(f, _IN_FLIGHT_NUM)
            (in_flight_pieces_num,) = struct.unpack(_s(version, _IN_FLIGHT_NUM), tmp)
            for _ in range(in_flight_pieces_num):
                tmp = _read(f, _IN_FLIGHT)
                index, piece_length, piece_bitfield_len = struct.unpack(
                    _s(version, _IN_FLIGHT), tmp
                )

                piece_bitfield = _read(f, f"{piece_bitfield_len}B")
                piece_downloaded = _parse_bitfield(
                    piece_bitfield, _CHUNK_SIZE, piece_length
                ) + (index * self.piece_size)

                downloaded |= piece_downloaded

            self._downloaded = downloaded & self.__full_file

    def _save_partial_file(self, multirange):
        ranges = multirange.ranges
        if 0 <= len(multirange) < self.filesize:
            with open(self._temporary_partial_file, "w") as f:
                json.dump(ranges, f)
            self._temporary_partial_file.replace(self._partial_file)
        else:
            try:
                self._partial_file.unlink()
            except FileNotFoundError:
                pass

    def save(self, requested=None, new_piece_size=None):
        if new_piece_size is None:
            piece_size = self.piece_size
        else:
            piece_size = new_piece_size

        if requested is None:
            requested = self.__full_file
        elif isinstance(requested, MultiRange):
            pass
        else:
            requested = MultiRange(requested)
        requested &= self.__full_file

        # Set the partial metadata file to actually downloaded ranges.
        # In case of failure we still know what's actually downloaded.
        self._save_partial_file(self.downloaded)

        # Create a fake control file.
        fake_downloaded = (self.__full_file - requested) | self.downloaded
        with open(self._temporary_control_file, "wb") as f:
            f.write(struct.pack(_INFO, 1, 0, 0))

            bitfield, incomplete_pieces = _create_bitfield(
                fake_downloaded, piece_size, self.filesize
            )

            f.write(
                struct.pack(
                    _LENGTHS,
                    piece_size,
                    self.filesize,
                    self._upload_len,
                    len(bitfield),
                )
            )
            f.write(bitfield)

            f.write(struct.pack(_IN_FLIGHT_NUM, len(incomplete_pieces)))
            for index, real_fragment, fragment_size in incomplete_pieces:
                offset = index * piece_size
                fragment_ranges = real_fragment.ranges
                # aria will download all chunks in a piece after the one we want, even
                # if they are marked as downloaded. So we can request it as well.
                if fragment_ranges[0][0] - offset == 0:
                    split_index = 1
                else:
                    split_index = 0

                requested |= MultiRange(fragment_ranges[split_index:])

                piece_bitfield, incomplete = _create_bitfield(
                    MultiRange(fragment_ranges[:split_index]) - offset,
                    _CHUNK_SIZE,
                    fragment_size,
                )

                # Incomplete fragments are ranges we don't want to download but must
                # because of the minimum chunk size (16 KiB). Add them to requested
                # range so it has a real data once they are downloaded.
                for _, fragment, _ in incomplete:
                    requested |= fragment + offset

                f.write(
                    struct.pack(_IN_FLIGHT, index, fragment_size, len(piece_bitfield))
                )
                f.write(piece_bitfield)
        self._temporary_control_file.replace(self._control_file)

        # Save the ranges requested | ranges actually downloaded.
        self._save_partial_file(requested | self.downloaded)

        # Touch the download file if it doesn't exist.
        try:
            with open(self._download_file, "x"):
                pass
        except FileExistsError:
            pass

        self.parse()

    @property
    def to_download(self):
        return self.filesize - len(self._downloaded)
