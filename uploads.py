"""Upload validation: filename, extension, declared MIME, magic bytes, size."""
from __future__ import annotations
import os
import re
import unicodedata

CATEGORIES = {
    "id_card":  "Identity & Insurance",
    "document": "Medical Documents & Personal Health Logs",
    "video":    "Health Videos",
}
# extension -> canonical MIME type, per category
ALLOWED = {
    "id_card": {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"},
    "document": {
        ".pdf": "application/pdf", ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xls": "application/vnd.ms-excel",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    },
    "video": {".mp4": "video/mp4"},
}
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
class UploadError(ValueError):
    """Message is safe to show to the user."""
def sanitize_filename(name: str) -> str:
    """Drop any directory part, control characters and odd symbols; cap length."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKC", name)
    name = re.sub(r"[^\w.\- ()]", "_", name, flags=re.UNICODE)
    name = re.sub(r"\.{2,}", ".", name).strip(" .")  # no ".." sequences anywhere
    if len(name) > 120:
        stem, ext = os.path.splitext(name)
        name = stem[: 120 - len(ext)] + ext
    return name

def _magic_ok(ext: str, head: bytes) -> bool:
    if ext == ".png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in (".jpg", ".jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == ".pdf":
        return b"%PDF-" in head[:1024]
    if ext in (".doc", ".xls"):
        return head.startswith(OLE)
    if ext in (".docx", ".xlsx"):
        return head.startswith(b"PK\x03\x04")
    if ext in (".mp4", ".mov"):
        return head[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip")
    if ext == ".avi":
        return head[:4] == b"RIFF" and head[8:12] == b"AVI "
    if ext in (".webm", ".mkv"):
        return head.startswith(b"\x1aE\xdf\xa3")
    return False

def validate_upload(filename: str, declared_mime: str | None, data: bytes,
                    category: str, max_bytes: int) -> tuple[str, str]:
    """Return (safe_filename, canonical_mime) or raise UploadError."""
    if category not in CATEGORIES:
        raise UploadError("Invalid category.")
    safe = sanitize_filename(filename)
    if not safe:
        raise UploadError("Invalid filename.")
    ext = os.path.splitext(safe)[1].lower()
    allowed = ALLOWED[category]
    if ext not in allowed:
        raise UploadError(
            "File type not supported for this category (" + ", ".join(sorted(allowed)) + ")."
        )
    canonical = allowed[ext]
    if declared_mime and declared_mime not in (canonical, "application/octet-stream", "application/x-zip-compressed"):
        # Browsers sometimes send odd types for Office files, so only reject
        # declared types that clearly belong to something else.
        if not (
            ext in (".docx", ".xlsx", ".doc", ".xls")
            and declared_mime.startswith("application/")
        ):
            raise UploadError(
                "The file MIME type does not match its extension."
            )
    if len(data) == 0:
        raise UploadError("Empty files cannot be uploaded.")
    if len(data) > max_bytes:
        raise UploadError("File size exceeds the allowed limit.")
    if not _magic_ok(ext, data[:1100]):
        raise UploadError("File content does not match its extension.")

    return safe, canonical