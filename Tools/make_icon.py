"""生成 App 图标 PNG。

不依赖第三方库：用有符号距离场（SDF）画形状，靠距离做边缘抗锯齿，
再用 zlib + struct 手写 PNG。

iOS 图标不允许带 alpha 通道，所以输出 8 位 RGB（color type 2）、完全不透明。
"""

import math
import struct
import sys
import zlib

SIZE = 1024

# 背景渐变：左上纯白 → 右下浅灰
BG_TOP = (0xFF, 0xFF, 0xFF)
BG_BOTTOM = (0xE2, 0xE8, 0xF0)

# 钥匙本体
KEY = (0x00, 0x00, 0x00)

# 钥匙整体旋转，斜着放才填得满方形画布
ANGLE = math.radians(-38)
SCALE = 1.24


def sd_ring(px, py, cx, cy, radius, half_thickness):
    return abs(math.hypot(px - cx, py - cy) - radius) - half_thickness


def sd_round_box(px, py, cx, cy, half_w, half_h, radius):
    dx = abs(px - cx) - (half_w - radius)
    dy = abs(py - cy) - (half_h - radius)
    outside = math.hypot(max(dx, 0.0), max(dy, 0.0))
    inside = min(max(dx, dy), 0.0)
    return outside + inside - radius


def key_distance(px, py):
    """竖直钥匙的 SDF：环形钥匙头 + 钥匙杆 + 两枚齿。"""
    # 先把采样点变换到钥匙自身的坐标系
    cx = cy = SIZE / 2.0
    dx, dy = (px - cx) / SCALE, (py - cy) / SCALE
    cos_a, sin_a = math.cos(ANGLE), math.sin(ANGLE)
    x = dx * cos_a - dy * sin_a + cx
    y = dx * sin_a + dy * cos_a + cy

    d = sd_ring(x, y, cx, 368, 130, 33)
    d = min(d, sd_round_box(x, y, cx, 650, 33, 182, 33))          # 杆
    d = min(d, sd_round_box(x, y, 608, 700, 66, 26, 19))          # 长齿
    d = min(d, sd_round_box(x, y, 588, 792, 46, 26, 19))          # 短齿
    return d * SCALE


def render():
    pixels = bytearray(SIZE * SIZE * 3)
    span = 2.0 * (SIZE - 1)

    for y in range(SIZE):
        row = y * SIZE * 3
        for x in range(SIZE):
            # 对角渐变
            t = (x + y) / span
            base = (
                BG_TOP[0] + (BG_BOTTOM[0] - BG_TOP[0]) * t,
                BG_TOP[1] + (BG_BOTTOM[1] - BG_TOP[1]) * t,
                BG_TOP[2] + (BG_BOTTOM[2] - BG_TOP[2]) * t,
            )

            # 距离直接当覆盖率用，边缘一个像素内平滑过渡
            coverage = 0.5 - key_distance(x + 0.5, y + 0.5)
            coverage = 0.0 if coverage < 0.0 else (1.0 if coverage > 1.0 else coverage)

            offset = row + x * 3
            for channel in range(3):
                value = base[channel] + (KEY[channel] - base[channel]) * coverage
                pixels[offset + channel] = int(value + 0.5)

        if y % 128 == 0:
            print(f"  {y}/{SIZE}", file=sys.stderr)

    return bytes(pixels)


def write_png(path, width, height, rgb):
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)                                  # 每行的滤波器字节
        raw += rgb[y * stride:(y + 1) * stride]

    def chunk(kind, payload):
        crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)   # 8 位 RGB，无 alpha
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
           + chunk(b"IEND", b""))

    with open(path, "wb") as handle:
        handle.write(png)
    return len(png)


if __name__ == "__main__":
    target = sys.argv[1]
    size = write_png(target, SIZE, SIZE, render())
    print(f"已写出 {target} ({size / 1024:.0f} KB)")
