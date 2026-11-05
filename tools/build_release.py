"""Explicit customer archive allowlist. No journals, client inputs or developer outputs."""

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

EMPTY_ACCOUNT = """version = 1
allow_folder_creation = false
[auth]
login = ""
password = ""
[profiles.sk]
root_url = "https://lk.sarex.io/documentations/2066367"
[profiles.vk]
root_url = "https://lk.sarex.io/documentations/2067117"
"""
ROOT_FILES = (
    "pyproject.toml",
    "MANIFEST.in",
    "customer.routes.toml",
    "README.md",
    "start.py",
    "start.bat",
    "start.command",
    "setup.bat",
    "start-upload.bat",
    "start-fill-urls.bat",
    "tools/mock_demo.py",
)


def build(root, output, version, *, include_account=False):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?", version):
        raise ValueError("Некорректная версия релиза.")
    if output.exists() or output.is_symlink():
        raise ValueError("Архив уже существует; перезапись запрещена.")
    paths = [root / p for p in ROOT_FILES]
    source = root / "src/sarex_loader"
    paths += sorted(source.glob("*.py"))
    paths += [source / "profile-routes.toml", source / "browser_extension.js"]
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError("Файл поставки отсутствует или является ссылкой.")
    account = EMPTY_ACCOUNT.encode("utf-8")
    if include_account:
        p = root / "account.toml"
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 65536:
            raise ValueError("Некорректный конфиг учётной записи.")
        account = p.read_bytes()
        data = tomllib.loads(account.decode("utf-8"))
        if data.get("allow_folder_creation") is not False:
            raise ValueError("Создание папок должно оставаться выключенным.")
    output.parent.mkdir(parents=True, exist_ok=True)
    prefix = "sarex-loader-" + version
    with ZipFile(output, "x", compression=ZIP_DEFLATED) as archive:
        for p in paths:
            archive.write(p, prefix + "/" + p.relative_to(root).as_posix())
        archive.writestr(prefix + "/account.toml", account)
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    return {
        "file": str(output),
        "sha256": checksum,
        "files": len(paths) + 1,
        "account_included_from_workspace": include_account,
        "client_documents_included": False,
        "historical_journals_included": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Создать клиентский ZIP без рабочих данных.")
    parser.add_argument("--version", default="v0.1.0-rc.1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--include-account",
        action="store_true",
        help="Явно включить текущий account.toml вместо пустого образца.",
    )
    args = parser.parse_args()
    try:
        result = build(
            Path(__file__).resolve().parents[1],
            args.output.absolute(),
            args.version,
            include_account=args.include_account,
        )
    except (ValueError, OSError):
        raise SystemExit(
            "Не удалось создать архив; проверьте версию, файлы и новый путь результата."
        ) from None
    print(json.dumps(result, ensure_ascii=False, indent=2))
