import os

__all__ = ["MultiFile", "MultiWritableFile"]


class MultiFileBase:
    def __init__(self):
        self.closed = False
        self._position = 0
        self._fps = []

    def _check_closed(self):
        if self.closed:
            raise ValueError("I/O operation on closed file.")

    def tell(self):
        self._check_closed()

        return self._position

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()
        return False

    def close(self):
        self.closed = True

        for i, fp in enumerate(self._fps):
            if fp is not None:
                fp.close()
                self._fps[i] = None


class MultiFile(MultiFileBase):
    """Class for combining multiple files/readables in binary mode."""

    def __init__(self, files):
        """Construct a readable, seekable and tellable MultiFile object.

        Arguments:
        files -- iterable of str/PathLike/file-like objects or tuples with size
        """

        super().__init__()

        self._names = []
        self._ranges = []

        total_size = 0

        for i, file in enumerate(files):
            fp = None
            name = None
            size = None

            if isinstance(file, tuple):
                file, size = file

            if hasattr(file, "read"):
                fp = file
            else:
                name = file

            if size is None:
                if fp is None:
                    fp = open(name, "rb")

                fp.seek(0, os.SEEK_END)
                size = fp.tell()

            self._fps.append(fp)
            self._names.append(name)
            new_total = total_size + size
            self._ranges.append(range(total_size, new_total))
            total_size = new_total

        self._total_size = total_size

    def seek(self, offset, whence=os.SEEK_SET):
        self._check_closed()

        if whence == os.SEEK_SET:
            pos = 0
        elif whence == os.SEEK_CUR:
            pos = self._position
        elif whence == os.SEEK_END:
            pos = self._total_size
        else:
            raise ValueError(f"whence value {whence} unsupported")
        pos += offset

        if pos < 0:
            # That's the behaviour in Python 3.10.
            raise OSError(22, "Invalid argument")

        self._position = pos

        return self._position

    def read(self, size=-1):
        self._check_closed()

        if size < -1:
            raise ValueError("read length must be non-negative or -1")

        buffer = bytearray()
        # EOF or reading 0 bytes.
        if size == 0 or self._position >= self._total_size:
            return bytes(buffer)

        # Reading to EOF
        left_to_read = self._total_size - self._position
        if size > -1:
            # Reading to EOF or up to "size" bytes, whichever is shorter.
            left_to_read = min(left_to_read, size)

        i = 0
        while left_to_read > 0:
            try:
                file_range = self._ranges[i]
            except IndexError:
                # This shouldn't happen.
                break

            if self._position not in file_range:
                i += 1
                continue

            if (fp := self._fps[i]) is None:
                try:
                    fp = self._fps[i] = open(self._names[i], "rb")
                except (FileNotFoundError, TypeError):
                    break

            fp.seek(self._position - file_range.start)
            requested_read = min(file_range.stop - self._position, left_to_read)

            chunk = fp.read(requested_read)
            chunk_len = len(chunk)

            self._position += chunk_len
            left_to_read -= chunk_len
            buffer.extend(chunk)

            if chunk_len != requested_read:
                break

        return bytes(buffer)

    def readable(self):
        return True

    def seekable(self):
        return True

    def writable(self):
        return False


class MultiWritableFile(MultiFileBase):
    """Class for writing to multiple files in binary mode given split size."""

    def __init__(self, name, split_size):
        """Construct a writable and tellable MultiWritableFile object.

        Arguments:
        name -- str/PathLike, output name, if total size is bigger than split size
                extension is added: ".001", ".002", ".003" and so on
        split_size -- int, split size
        """

        super().__init__()

        if split_size < 1:
            raise ValueError("split_size must be larger than 1")

        self._split_size = split_size
        self._name = str(name)
        self.names = []

    def _open_new_fp(self):
        if (fps := len(self._fps)) == 0:
            name = self._name
        else:
            self._fps[-1].close()

            if fps == 1:
                name = f"{self._name}.{fps:03}"
                os.replace(self.names[0], name)
                self.names[0] = name

            name = f"{self._name}.{fps + 1:03}"

        self.names.append(name)
        self._fps.append(open(name, "wb"))

    def flush(self):
        self._check_closed()

        if len(self._fps) > 0:
            fp = self._fps[-1]
            fp.flush()
            os.fsync(fp.fileno())

    def write(self, b):
        self._check_closed()

        buffer = bytearray(b)
        written = 0

        while len(buffer) > 0:
            size = len(buffer)
            current_max = len(self._fps) * self._split_size
            new_pos = self._position + size

            if new_pos > current_max:
                to_write = current_max - self._position
            else:
                to_write = size

            if to_write == 0:
                self._open_new_fp()
                continue

            self._fps[-1].write(buffer[:to_write])
            del buffer[:to_write]
            written += to_write
            self._position += to_write

        return written

    def readable(self):
        return False

    def seekable(self):
        return False

    def writable(self):
        return True
