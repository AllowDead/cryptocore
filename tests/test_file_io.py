import os
import tempfile
import pytest
from cryptocore.file_io import read_file_with_iv_or_none


def test_read_file_with_iv_short_file():
    """Test that short files raise appropriate error"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # Пишем только 10 байт (меньше 16)
        f.write(b"1234567890")
        temp_path = f.name

    try:
        # Должна возникнуть ошибка
        with pytest.raises(ValueError) as exc_info:
            data, iv = read_file_with_iv_or_none(temp_path)

        assert "too short" in str(exc_info.value)
        assert "needs at least 16 bytes" in str(exc_info.value)

    finally:
        os.unlink(temp_path)


def test_read_file_with_iv_valid_file():
    """Test reading file with proper IV"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        # Пишем 16 байт IV + 10 байт данных
        f.write(b"a" * 16 + b"test data")
        temp_path = f.name

    try:
        data, iv = read_file_with_iv_or_none(temp_path)

        assert len(iv) == 16
        assert iv == b"a" * 16
        assert data == b"test data"

    finally:
        os.unlink(temp_path)


def test_read_file_with_provided_iv():
    """Test reading file with IV provided as argument"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test data without iv in file")
        temp_path = f.name

    try:
        provided_iv = b"b" * 16
        data, iv = read_file_with_iv_or_none(temp_path, provided_iv)

        assert iv == provided_iv
        assert data == b"test data without iv in file"

    finally:
        os.unlink(temp_path)