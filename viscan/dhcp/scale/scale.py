import math

from typing import Tuple, List


def scale(addrs: List[int]) -> Tuple[str, int, int, int]:
    diffs = [addrs[i + 1] - addrs[i] for i in range(len(addrs) - 1)]
    zeros = [d for d in diffs if d == 0]
    poses = [d for d in diffs if d > 0]
    negs = [d for d in diffs if d < 0]

    if len(zeros) == len(diffs):
        return 'static', addrs[0], addrs[-1], 0

    if len(poses) >= 0.9 * len(diffs):
        avg = sum(poses) / len(poses)
        if len(negs) == 0 or abs(min(negs)) < 2 * avg:
            return 'linear', addrs[0], addrs[-1], math.ceil(avg)

    if len(negs) >= 0.9 * len(diffs):
        avg = sum(negs) / len(negs)
        if len(poses) == 0 or max(poses) < 2 * abs(avg):
            return 'linear', addrs[0], addrs[-1], math.ceil(avg)

    a1, a2 = min(addrs), max(addrs)
    d = math.ceil((a2 - a1) / (len(addrs) - 1))
    return 'random', a1, a2, d
