"""Compare the UI tree with the screenshot: text with no contrast cannot be seen by a human.

Catches what geometry cannot (opacity:0, same-colour text, clip-path, covered text).
Needs Pillow; without it, or without a screenshot, this check is skipped.
"""

from __future__ import annotations

import io

Bounds = tuple[int, int, int, int]


class PixelView:
    def __init__(self, png: bytes):
        from PIL import Image

        self.image = Image.open(io.BytesIO(png)).convert("L")

    @property
    def usable(self) -> bool:
        """False for blank captures, which some GPU modes and secure windows produce."""
        low, high = self.image.getextrema()
        return high - low > 0

    def contrast(self, bounds: Bounds) -> int:
        x1, y1, x2, y2 = bounds
        box = (max(x1, 0), max(y1, 0), min(x2, self.image.width), min(y2, self.image.height))
        if box[2] <= box[0] or box[3] <= box[1]:
            return 0
        low, high = self.image.crop(box).getextrema()
        return high - low


def load(png: bytes | None) -> PixelView | None:
    if not png:
        return None
    try:
        view = PixelView(png)
    except (ImportError, OSError):
        return None
    return view if view.usable else None
