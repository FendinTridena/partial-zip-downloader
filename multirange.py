from math import inf

__all__ = ["MultiRange"]


def _range_sort(r):
    if r.start >= r.stop:
        return -inf
    else:
        return r.start


class MultiRange:
    def __init__(self, ranges):
        self.__ranges = []
        for r in ranges:
            if isinstance(r, range):
                if r.step != 1:
                    raise ValueError("Only ranges with step 1 are supported")
                self.__ranges.append(r)
            else:
                self.__ranges.append(range(r[0], r[1]))

        self.normalize()

    def __repr__(self):
        return "MultiRange(" + repr(self.ranges) + ")"

    def __add__(self, other):
        return MultiRange([(r.start + other, r.stop + other) for r in self.__ranges])

    def __sub__(self, other):
        if not isinstance(other, MultiRange):
            return self + (-other)

        self.normalize()
        other.normalize()
        result = []
        ranges = self.__ranges[::]
        while len(ranges) > 0:
            r1 = ranges.pop(0)
            for r2 in other.__ranges:
                if r2.stop <= r1.start:
                    continue
                if r2.start >= r1.stop:
                    break

                if r2.start <= r1.start:
                    if r2.stop < r1.stop:
                        r1 = range(r2.stop, r1.stop)
                    else:
                        r1 = None
                        break
                else:
                    if r2.stop < r1.stop:
                        ranges.insert(0, range(r2.stop, r1.stop))
                    r1 = range(r1.start, r2.start)
            if r1 is not None:
                result.append(r1)
        return MultiRange(result)

    def __and__(self, other):
        self.normalize()
        other.normalize()
        result = []
        for r1 in self.__ranges:
            for r2 in other.__ranges:
                if r2.stop <= r1.start:
                    continue
                if r2.start >= r1.stop:
                    break

                result.append(range(max(r1.start, r2.start), min(r1.stop, r2.stop)))
        return MultiRange(result)

    def __or__(self, other):
        self.normalize()
        other.normalize()
        return MultiRange(self.__ranges + other.__ranges)

    def __len__(self):
        return sum(x.stop - x.start for x in self.__ranges)

    def normalize(self):
        self.__ranges.sort(key=_range_sort)
        i = 0
        try:
            while True:
                r = self.__ranges[i]
                if r.start >= r.stop:
                    del self.__ranges[i]
                    continue
                r2 = self.__ranges[i + 1]
                if r.stop >= r2.start:
                    self.__ranges[i] = range(r.start, max(r.stop, r2.stop))
                    del self.__ranges[i + 1]
                else:
                    i += 1
        except IndexError:
            pass

    @property
    def ranges(self):
        return [(x.start, x.stop) for x in self.__ranges]
