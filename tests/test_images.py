"""Tests for image compression utilities.

Tests the compress_image function for image processing and compression.
"""
import io

import pytest
from PIL import Image

from python.helpers.images import compress_image


class TestCompressImage:
    """Test compress_image function"""

    def _create_image_bytes(self, width: int, height: int, mode: str = "RGB") -> bytes:
        """Helper to create a test image in memory"""
        img = Image.new(mode, (width, height), color="red")
        output = io.BytesIO()
        img.save(output, format="PNG")
        return output.getvalue()

    def test_compress_returns_bytes(self):
        """Test that compress_image returns bytes"""
        img_bytes = self._create_image_bytes(100, 100)
        result = compress_image(img_bytes)
        assert isinstance(result, bytes)

    def test_compress_returns_jpeg(self):
        """Test that compressed image is JPEG format"""
        img_bytes = self._create_image_bytes(100, 100)
        result = compress_image(img_bytes)
        # JPEG files start with these bytes
        assert result[:2] == b"\xff\xd8"

    def test_compress_reduces_size(self):
        """Test that compression reduces file size"""
        img_bytes = self._create_image_bytes(1000, 1000)
        result = compress_image(img_bytes)
        # JPEG should be smaller than PNG
        assert len(result) < len(img_bytes)

    def test_compress_with_custom_max_pixels(self):
        """Test compression with custom max_pixels"""
        img_bytes = self._create_image_bytes(2000, 2000)
        result = compress_image(img_bytes, max_pixels=100000)
        # Verify image was resized
        img = Image.open(io.BytesIO(result))
        assert img.width * img.height <= 100000

    def test_compress_preserves_aspect_ratio(self):
        """Test that aspect ratio is preserved"""
        img_bytes = self._create_image_bytes(2000, 1000)  # 2:1 ratio
        result = compress_image(img_bytes, max_pixels=100000)
        img = Image.open(io.BytesIO(result))
        # Should maintain approximately 2:1 aspect ratio (accounting for integer rounding)
        ratio = img.width / img.height
        assert 1.9 < ratio < 2.1
    def test_compress_with_rgba_mode(self):
        img_bytes = self._create_image_bytes(2000, 1000)  # 2:1 ratio
        result = compress_image(img_bytes, max_pixels=100000)
        img = Image.open(io.BytesIO(result))
        # Should maintain 2:1 aspect ratio
        assert img.width == img.height * 2

    def test_compress_with_rgba_mode(self):
        """Test compression of RGBA image (with transparency)"""
        img = Image.new("RGBA", (100, 100), color=(255, 0, 0, 128))
        output = io.BytesIO()
        img.save(output, format="PNG")
        img_bytes = output.getvalue()

        result = compress_image(img_bytes)
        # Should convert to RGB
        img_result = Image.open(io.BytesIO(result))
        assert img_result.mode == "RGB"

    def test_compress_with_palette_mode(self):
        """Test compression of palette (P) mode image"""
        img = Image.new("P", (100, 100))
        output = io.BytesIO()
        img.save(output, format="PNG")
        img_bytes = output.getvalue()

        result = compress_image(img_bytes)
        # Should convert to RGB
        img_result = Image.open(io.BytesIO(result))
        assert img_result.mode == "RGB"

    def test_compress_small_image_no_resize(self):
        """Test that small images below max_pixels are not resized"""
        img_bytes = self._create_image_bytes(100, 100)
        result = compress_image(img_bytes, max_pixels=20000)
        img = Image.open(io.BytesIO(result))
        # Should remain 100x100
        assert img.width == 100
        assert img.height == 100

    def test_compress_custom_quality(self):
        """Test compression with custom quality setting"""
        img_bytes = self._create_image_bytes(500, 500)

        # High quality should be larger
        result_high = compress_image(img_bytes, quality=95)
        # Low quality should be smaller
        result_low = compress_image(img_bytes, quality=10)

        assert len(result_high) > len(result_low)

    def test_compress_with_grayscale(self):
        """Test compression of grayscale image"""
        img = Image.new("L", (100, 100), color=128)
        output = io.BytesIO()
        img.save(output, format="PNG")
        img_bytes = output.getvalue()

        result = compress_image(img_bytes)
        # Grayscale should remain grayscale
        img_result = Image.open(io.BytesIO(result))
        assert img_result.mode == "L"

    def test_compress_very_large_image(self):
        """Test compression of very large image"""
        img_bytes = self._create_image_bytes(10000, 10000)
        result = compress_image(img_bytes, max_pixels=1000000)
        # Should complete without error
        assert isinstance(result, bytes)
        img = Image.open(io.BytesIO(result))
        assert img.width * img.height <= 1000000

    def test_compress_1x1_pixel(self):
        """Test compression of 1x1 pixel image"""
        img_bytes = self._create_image_bytes(1, 1)
        result = compress_image(img_bytes)
        assert isinstance(result, bytes)
        img = Image.open(io.BytesIO(result))
        assert img.width == 1
        assert img.height == 1


class TestCompressImageEdgeCases:
    """Edge case tests for compress_image"""

    def _create_image_bytes(self, width: int, height: int, mode: str = "RGB") -> bytes:
        """Helper to create a test image in memory"""
        img = Image.new(mode, (width, height), color="red")
        output = io.BytesIO()
        img.save(output, format="PNG")
        return output.getvalue()

    def test_compress_preserves_red_color(self):
        """Test that red color is preserved after compression"""
        img_bytes = self._create_image_bytes(100, 100)
        result = compress_image(img_bytes)
        img = Image.open(io.BytesIO(result))
        # Get a pixel from the center
        pixel = img.getpixel((50, 50))
        # Red channel should be dominant
        assert pixel[0] > pixel[1]
        assert pixel[0] > pixel[2]
