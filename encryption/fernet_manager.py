from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

from config.settings import QUARANTINE_DIR


class FileEncryptionManager:
    def __init__(self, key_path: str | Path) -> None:
        self.key_path = Path(key_path)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes()
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        return key

    def encrypt_file(self, file_path: str | Path) -> Path:
        source = Path(file_path)
        encrypted_path = QUARANTINE_DIR / f"{source.name}.enc"
        encrypted_path.write_bytes(self.fernet.encrypt(source.read_bytes()))
        return encrypted_path

    def decrypt_file(self, encrypted_path: str | Path, output_path: str | Path) -> Path:
        source = Path(encrypted_path)
        output = Path(output_path)
        output.write_bytes(self.fernet.decrypt(source.read_bytes()))
        return output
