"""Shared helpers: sliding windows over timestamps, and event grouping."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Sequence, Tuple


def best_window(times: Sequence[datetime], window: timedelta) -> Tuple[int, datetime, datetime]:
    """Largest number of timestamps inside any window of the given size.

    Returns (count, start, end). Two pointers over a sorted list, so it stays linear
    even on a large log.
    """
    ordered = sorted(times)
    if not ordered:
        raise ValueError("best_window needs at least one timestamp")

    best_count, best_start, best_end = 0, ordered[0], ordered[0]
    left = 0
    for right, moment in enumerate(ordered):
        while moment - ordered[left] > window:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count, best_start, best_end = count, ordered[left], moment
    return best_count, best_start, best_end


def group_by(events: Iterable, key) -> Dict[str, List]:
    grouped: Dict[str, List] = defaultdict(list)
    for event in events:
        grouped[key(event)].append(event)
    return grouped


def sample_lines(events: Sequence, limit: int = 3) -> List[str]:
    """First few raw lines, plus the last one when the list is longer."""
    raws = [event.raw for event in events]
    if len(raws) <= limit:
        return raws
    return raws[:limit] + [raws[-1]]


def distinct_users_in_window(failures: Sequence, window: timedelta) -> Tuple[int, datetime, datetime]:
    """Most distinct usernames seen from one source inside a window."""
    ordered = sorted(failures, key=lambda event: event.timestamp)
    counts: Dict[str, int] = {}
    best, best_start, best_end = 0, None, None
    left = 0

    for right, event in enumerate(ordered):
        counts[event.user] = counts.get(event.user, 0) + 1
        while event.timestamp - ordered[left].timestamp > window:
            leaving = ordered[left].user
            counts[leaving] -= 1
            if not counts[leaving]:
                del counts[leaving]
            left += 1
        if len(counts) > best:
            best = len(counts)
            best_start, best_end = ordered[left].timestamp, event.timestamp

    return best, best_start or ordered[0].timestamp, best_end or ordered[0].timestamp
