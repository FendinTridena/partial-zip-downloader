import subprocess
import zipfile
import os
import io
import binascii
import base64

import requests

from multirange import MultiRange
from aria2_parser import Aria2Parser
from multifile import MultiFile

__all__ = ["PartialZipDownloader", "encode_cache", "decode_cache"]

_VERSION = "1.0.0"
_CHUNK_SIZE = 2 << 15  # 64KiB
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0"
)


class PartialZipDownloaderError(Exception):
    pass


class CannotResumeError(PartialZipDownloaderError):
    pass


class BadResponseError(PartialZipDownloaderError):
    pass


def encode_cache(cache, errors="ignore"):
    result = {}
    for key, c in cache.items():
        try:
            result[key] = (c[0], c[1], base64.b64encode(c[2]).decode())
        except binascii.Error:
            if errors != "ignore":
                raise
    return result


def decode_cache(cache, errors="ignore"):
    result = {}
    for key, c in cache.items():
        try:
            result[key] = (c[0], c[1], base64.b64decode(c[2]))
        except binascii.Error:
            if errors != "ignore":
                raise
    return result


def _get_filenames(path, file_count):
    path = (
        str(path)
        .replace("<", "_")
        .replace(">", "_")
        .replace(":", "_")
        .replace('"', "_")
        .replace("|", "_")
        .replace("?", "_")
        .replace("*", "_")
    )

    if file_count == 1:
        return [path]
    else:
        return [path + f".{i:03}" for i in range(1, file_count + 1)]


def _try_delete(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


class PartialZipDownloader:
    def __init__(
        self,
        url,
        path,
        split_size=0,
        headers=None,
        url_parser=None,
        cache=None,
        cache_name=None,
        run_function=None,
        check_function=None,
        piece_size=None,
        force_download=False,
        extra_params=None,
    ):
        """Construct PartialZipDownloader object.

        Arguments:
        url -- download URL; can be a list of URLs if the archive is split into
               multiple files (like with split command, this is NOT for multi-volume
               archives!)
        path -- save location; with multiple URLs it will be path.001, path.002, etc.

        Keyword arguments:
        split_size -- required with multiple URLs
        cache -- dict, can be used for caching file size and central directory
        cache_name -- name to be used in the cache; required if cache is not None
        run_function -- alternative function to run aria2c
        check_function -- function that raises some error if you want to stop
        piece_size -- piece size to use in aria2; None means default, so 1 MiB
        force_download -- force downloading parts that don't have any requested files
        extra_params -- extra parameters for aria2c
        """
        if isinstance(url, str):
            self.urls = [url]
        elif isinstance(url, list):
            self.urls = url
        else:
            raise ValueError("url must be str or list of str")
        if (url_len := len(self.urls)) == 0:
            raise ValueError("url can't be an empty list")

        self._multifiles = []

        self.filenames = _get_filenames(path, url_len)
        self._sizes = [None] * url_len

        if url_len > 1 and split_size == 0:
            raise ValueError("split_size can't be 0 with multiple URLs")
        self._split_size = split_size

        if headers is None:
            self._headers = {}
        else:
            self._headers = headers

        self.url_parser = url_parser

        self.cache = cache
        if self.cache is not None and cache_name is None:
            raise ValueError("cache_name can't be None if cache is set")
        self.cache_name = cache_name

        self._run_function = run_function

        self._check_function = check_function

        self._piece_size = piece_size

        self._force_download = force_download

        if extra_params is None:
            self._extra_params = []
        else:
            self._extra_params = extra_params

        self._filesize = None
        self._central_dir = None

    def _get_range(self, url, headers, start, end):
        if self._check_function is not None:
            self._check_function()

        if start < 0:
            start = 0

        headers = headers.copy()
        headers["Range"] = f"bytes={start}-{end}"

        r = requests.get(url, headers=headers, stream=True, timeout=15)

        r.raise_for_status()
        if r.status_code != 206 or "Content-Range" not in r.headers:
            r.close()
            raise BadResponseError("server doesn't support range headers")
        cr = r.headers["Content-Range"].strip()
        if not cr.startswith(f"bytes {start}-{end}/") or "*" in cr:
            r.close()
            raise BadResponseError("server returned wrong range")

        r.content
        r.close()

        return r

    def _get_chunk(self, url, headers, start, end):
        return self._get_range(url, headers, start, end).content

    def _get_size(self, url, headers):
        r = self._get_range(url, headers, 0, 0)
        cr = r.headers["Content-Range"]
        return int(cr[cr.rfind("/") + 1 :])

    def _get_download_url(self, url):
        if self._check_function is not None:
            self._check_function()

        if self.url_parser is None:
            return url, self._headers
        else:
            return self.url_parser(url, self._headers)

    def _get_central_dir(self):
        buffer = b""
        url_count = len(self.urls) - 1
        for i, url in enumerate(reversed(self.urls)):
            download_url, headers = self._get_download_url(url)

            if i == 0:
                size = self._get_size(download_url, headers)

                if url_count == 0:
                    self._filesize = size
                else:
                    self._filesize = size + url_count * self._split_size
            else:
                size = self._split_size

            self._sizes[url_count - i] = size

            downloaded = 0
            while downloaded < size:
                end = size - downloaded
                start = end - _CHUNK_SIZE
                end -= 1

                chunk = self._get_chunk(download_url, headers, start, end)
                buffer = chunk + buffer
                downloaded += len(chunk)

                try:
                    with zipfile.ZipFile(io.BytesIO(buffer)) as zf:
                        self._central_dir = buffer[zf.start_dir :]
                    break
                except:
                    pass

            if self._central_dir is not None:
                if self.cache is not None:
                    self.cache[self.cache_name] = (
                        self._filesize,
                        self._split_size,
                        self._central_dir,
                    )
                break

    def get_info(self):
        """Return a list of tuples with ZipInfo, downloaded size and raw size."""

        # Load central dir and filesize from cache.
        if self.cache is not None:
            try:
                (
                    filesize,
                    split_size,
                    central_dir,
                ) = self.cache[self.cache_name]
                with zipfile.ZipFile(io.BytesIO(central_dir)):
                    pass
            except (KeyError, zipfile.BadZipFile):
                pass
            else:
                if split_size != self._split_size:
                    self._filesize = None
                    self._central_dir = None
                else:
                    self._filesize = filesize
                    self._central_dir = central_dir

        # Load central dir and filesize from links.
        if self._central_dir is None:
            self._get_central_dir()

            if self._central_dir is None:
                raise PartialZipDownloaderError("not a ZIP file")

        central_dir_size = len(self._central_dir)
        # Can be equal - empty ZIP.
        if central_dir_size > self._filesize:
            raise PartialZipDownloaderError("filesize is bigger than the central dir")

        # Get offset fix, filelist and "name to info" dict.
        offset_fix = self._filesize - central_dir_size
        with zipfile.ZipFile(io.BytesIO(self._central_dir)) as zf:
            self.filelist = zf.filelist
            self._name_to_info = zf.NameToInfo
            start_dir = zf.start_dir
        del zf

        # Fix offsets.
        start_dir += offset_fix
        for zinfo in self.filelist:
            zinfo.header_offset += offset_fix
        self.filelist.sort(key=lambda x: x.header_offset)

        # Get files and central dir ranges.
        ranges = {}
        for i, zinfo in enumerate(self.filelist):
            try:
                end = self.filelist[i + 1].header_offset
            except IndexError:
                end = start_dir

            ranges[zinfo] = (zinfo.header_offset, end)
        self._file_ranges = ranges
        self._central_dir_range = (start_dir, self._filesize)

        downloaded = MultiRange([])

        parts_count = len(self.filenames)
        self._control_files = [None] * parts_count
        for i, filename in enumerate(self.filenames):
            offset = i * self._split_size

            if (size := self._sizes[i]) is None:
                if parts_count > 1:
                    if parts_count - 1 == i:
                        # Last part:
                        size = self._filesize - offset
                    else:
                        size = self._split_size
                else:
                    size = self._filesize

                self._sizes[i] = size

            self._control_files[i] = Aria2Parser(filename, size)
            downloaded |= self._control_files[i].downloaded + offset

        return tuple(
            (zinfo, len((r := MultiRange([ranges[zinfo]])) & downloaded), len(r))
            for zinfo in self.filelist
        )

    def set_files(self, files):
        requested_ranges = [self._central_dir_range]
        for file in files:
            if isinstance(file, str):
                file = self._name_to_info[file]
            requested_ranges.append(self._file_ranges[file])

        requested = MultiRange(requested_ranges)
        max_split = MultiRange([(0, self._split_size)])

        to_download = 0

        parts_count = len(self._control_files)
        for i, control_file in enumerate(self._control_files):
            if parts_count > 1:
                offset = i * self._split_size
                requested_part = (requested - offset) & max_split
            else:
                requested_part = requested

            try:
                size = os.path.getsize(self.filenames[i])
            except FileNotFoundError:
                size = 0

            if (
                size != control_file.filesize
                and self._force_download
                and len(requested_part) == 0
            ):
                requested_part = MultiRange([(self._split_size - 1, self._split_size)])

            control_file.save(requested=requested_part, new_piece_size=self._piece_size)
            to_download += control_file.to_download

        return to_download

    def download(self):
        common_params = [
            "aria2c",
            "--file-allocation=trunc",
            "--auto-file-renaming=false",
        ] + self._extra_params

        if self._piece_size is not None:
            common_params.append(f"--piece-length={self._piece_size}")

        for i, control_file in enumerate(self._control_files):
            filename = self.filenames[i]

            if (to_download := control_file.to_download) == 0:
                continue

            path, name = os.path.split(filename)

            url = self.urls[i]
            download_url, headers = self._get_download_url(url)

            piece_params = [
                f"--header={key}: {value}" for key, value in headers.items()
            ]
            path_params = []
            if path != "":
                path_params += ["-d", path]
            path_params += ["-o", name, download_url]

            if self._run_function is None:
                subprocess.check_call(common_params + piece_params + path_params)
            else:
                self._run_function(
                    common_params + piece_params,
                    filename,
                    download_url,
                    control_file.filesize - to_download,  # already downloaded
                    control_file.filesize,
                    url,
                )

            control_file.parse()

    def get_file(self):
        central_dir_size_left = len(self._central_dir)

        files = [(name, self._sizes[i]) for i, name in enumerate(self.filenames)]

        while central_dir_size_left > 0:
            name, size = files.pop()

            if size > central_dir_size_left:
                files.append((name, size - central_dir_size_left))
                break
            else:
                central_dir_size_left -= size

        files.append(io.BytesIO(self._central_dir))

        mf = MultiFile(files)
        self._multifiles.append(mf)

        return mf

    def get_all_filenames(self):
        all_names = []
        for name in self.filenames:
            all_names.append(name)
            all_names.append(f"{name}.aria2")
            all_names.append(f"{name}.aria2_partial")

        return all_names


if __name__ == "__main__":
    import sys
    import argparse

    from urllib.parse import urlparse

    sys.stdout.reconfigure(encoding="utf-8")

    def _get_name_from_url(url, default=None):
        path = urlparse(url).path.rstrip("/")
        name = os.path.basename(path)
        return default if name == "" else name

    def _e(*args):
        raise PartialZipDownloaderError("Something went wrong!")

    parser = argparse.ArgumentParser(
        prog="pzd",
        description=(
            "Partial Zip Downloader lets you download selected "
            "files from a link to a zip archive."
        ),
        usage=(
            "%(prog)s <command> [<switches>...] <archive_url_or_file> "
            "[<file_names>...] [@listfile]"
        ),
        add_help=False,
    )

    commands = parser.add_argument_group("<commands>")
    commands.add_argument("d", action="store_true", help="download files")
    commands.add_argument("l", action="store_true", help="list files")
    commands.add_argument("x", action="store_true", help="extract files")
    commands.add_argument("command", choices=["d", "l", "x"], help=argparse.SUPPRESS)

    switches = parser.add_argument_group("<switches>")
    switches.add_argument(
        "-s",
        "--show-details",
        action="store_true",
        help="modify l command to list size, downloaded size, CRC and filename",
    )
    switches.add_argument(
        "-o",
        "--out",
        metavar="FILE",
        help=(
            "output file for the archive; if you skip it %(prog)s will try to get"
            " it from the URL and if that fails it will use 'archive.zip'"
        ),
    )
    switches.add_argument(
        "-d",
        "--dir",
        metavar="DIR",
        default=".",
        help="extraction directory",
    )
    switches.add_argument(
        "-p",
        "--pwd",
        metavar="PWD",
        help="archive password",
    )
    switches.add_argument(
        "-H",
        "--header",
        metavar="VAL",
        dest="headers",
        action="append",
        help="add HTTP header",
    )
    switches.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {_VERSION}",
    )

    parser.add_argument("-h", "--help", action="help", help=argparse.SUPPRESS)
    parser.add_argument("archive", help=argparse.SUPPRESS)
    parser.add_argument("files", nargs="*", help=argparse.SUPPRESS)

    args, _ = parser.parse_known_intermixed_args()

    if args.archive == "curl":
        try:
            args.archive = args.files.pop(0)
        except IndexError:
            parser.print_usage()
            sys.exit(1)

    url = "://" in args.archive
    cache = None
    cache_name = None
    url_parser = None

    if url:
        if args.out is None:
            args.out = _get_name_from_url(args.archive, "archive.zip")
    else:
        if args.command == "d":
            parser.exit(status=2, message="[ERROR] d command requires archive URL")

        args.out = args.archive
        cache = {}
        cache_name = args.out
        try:
            with open(args.archive, "rb") as f:
                try:
                    with zipfile.ZipFile(f) as zf:
                        sd = zf.start_dir
                except:
                    parser.exit(
                        status=4,
                        message=f'[ERROR] "{args.archive}" is not a ZIP archive',
                    )

                f.seek(0, 2)
                size = f.tell()
                f.seek(sd)
                cache[cache_name] = (size, 0, f.read())
        except FileNotFoundError:
            parser.exit(
                status=3,
                message=f'[ERROR] Archive "{args.archive}" not found',
            )

        url_parser = lambda x: 1 / 0

    headers = {}
    if args.headers is not None:
        for header in args.headers:
            name, value = header.split(": ", 1)
            headers[name] = value

    try:
        pzd = PartialZipDownloader(
            args.archive,
            args.out,
            url_parser=url_parser,
            cache=cache,
            cache_name=cache_name,
            extra_params=["-s", "4", "-x", "4"],
        )

        files = pzd.get_info()

        if args.command == "l":
            if args.show_details:
                parsed = [("DOWNLOADED", "TOTAL", "CRC", "FILENAME")]
                max_downloaded = 0
                max_total = 0
                for zinfo, downloaded, total in files:
                    parsed.append(
                        (
                            downloaded,
                            total,
                            format(zinfo.CRC & 0xFFFFFFFF, "08X"),
                            zinfo.filename,
                        )
                    )
                    if downloaded > max_downloaded:
                        max_downloaded = downloaded
                    if total > max_total:
                        max_total = total

                d = str(max(len(str(max_downloaded)), 10))  # DOWNLOADED
                t = str(max(len(str(max_total)), 5))  # TOTAL

                filelist = "\n".join(
                    ("{:>" + d + "} {:>" + t + "} {:>8} {}").format(*x) for x in parsed
                )
            else:
                filelist = "\n".join(x.filename for x, _, _ in files)

            for file in args.files:
                if file.startswith("@"):
                    with open(file[1:], "w", encoding="utf-8") as f:
                        f.write(filelist)
                        f.write("\n")
                    sys.exit(0)
            print(filelist)
        else:
            filtered = []
            requested_files = set()
            for file in args.files:
                if file.startswith("@"):
                    with open(file[1:], "r", encoding="utf-8") as f:
                        for x in f.readlines():
                            requested_files.add(x.strip())
                else:
                    requested_files.add(file)
            requested_files.discard("")

            if none_requested := (len(requested_files) == 0):
                filtered = files
            else:
                for x in files:
                    if (name := x[0].filename) in requested_files:
                        filtered.append(x)
                        requested_files.remove(name)

                if len(requested_files) > 0:
                    unknown = "\n".join(sorted(requested_files))
                    parser.exit(
                        status=5,
                        message=(
                            f"[ERROR] These files are not in the archive:\n{unknown}"
                        ),
                    )

            if args.command == "x" and not url:
                tmp = []
                for x in filtered:
                    if x[1] == x[2]:
                        tmp.append(x)
                    elif none_requested:
                        pass
                    else:
                        parser.exit(
                            status=6,
                            message=(
                                f'[ERROR] "{x[0].filename}" can\'t be extracted, '
                                "it's not fully downloaded"
                            ),
                        )
                filtered = tmp

            zinfos = [zinfo for zinfo, _, _ in filtered]

            # When extracting a local file those downloads won't even connect to the
            # internet since the files to extract are already downloaded.

            # Grab the central dir first so extraction is possible.
            pzd.set_files([])
            pzd.download()

            pzd.set_files(zinfos)
            pzd.download()

            if args.command == "x":
                with pzd.get_file() as f:
                    with zipfile.ZipFile(f) as zf:
                        for zinfo in zinfos:
                            print(f"extracting {zinfo.filename}")
                            zf.extract(zinfo, path=args.dir, pwd=args.pwd)

    except PartialZipDownloaderError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(10)
