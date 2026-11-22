import argparse
import json
import os
import posixpath
import shlex
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko


class SyncError(Exception):
    pass


@dataclass
class SshConfig:
    host: str
    port: int = 22
    user: str = "root"
    key_file: str | None = None
    password: str | None = None
    strict_host_key_checking: bool = False


@dataclass
class EcryptfsConfig:
    enabled: bool = False
    mount_options: list[str] | None = None
    unmount_after_sync: bool = True


@dataclass
class DestinationConfig:
    name: str
    ssh: SshConfig
    private_folder: str
    dest_subfolder: str
    encryption: EcryptfsConfig


@dataclass
class FolderSyncConfig:
    local_folder: str
    destinations: list[DestinationConfig]


@dataclass
class AppConfig:
    folders: list[FolderSyncConfig]


class SshSession:
    def __init__(self, ssh_config: SshConfig, *, dry_run: bool) -> None:
        self.ssh_config = ssh_config
        self.dry_run = dry_run
        self.client: paramiko.SSHClient | None = None
        self.sftp: paramiko.SFTPClient | None = None

    def __enter__(self) -> "SshSession":
        if self.dry_run:
            return self

        client = paramiko.SSHClient()

        if self.ssh_config.strict_host_key_checking:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.ssh_config.host,
            "port": self.ssh_config.port,
            "username": self.ssh_config.user,
            "timeout": 30,
        }

        if self.ssh_config.key_file:
            connect_kwargs["key_filename"] = self.ssh_config.key_file

        if self.ssh_config.password:
            connect_kwargs["password"] = self.ssh_config.password

        client.connect(**connect_kwargs)

        self.client = client
        self.sftp = client.open_sftp()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.sftp is not None:
            self.sftp.close()

        if self.client is not None:
            self.client.close()

    def run(self, command: str, *, check: bool = True) -> tuple[int, str, str]:
        print(f"$ ssh {self.ssh_config.user}@{self.ssh_config.host} {shlex.quote(command)}")

        if self.dry_run:
            return 0, "", ""

        if self.client is None:
            raise SyncError("SSH client is not connected")

        stdin, stdout, stderr = self.client.exec_command(command)

        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")

        if stdout_text:
            print(stdout_text, end="")

        if stderr_text:
            print(stderr_text, end="", file=sys.stderr)

        if check and exit_code != 0:
            raise SyncError(
                f"Remote command failed with code {exit_code}: {command}"
            )

        return exit_code, stdout_text, stderr_text

    def mkdir_p(self, path: str) -> None:
        self.run(f"mkdir -p {shlex.quote(path)}")

    def stat(self, path: str) -> paramiko.SFTPAttributes | None:
        if self.dry_run:
            return None

        if self.sftp is None:
            raise SyncError("SFTP client is not connected")

        try:
            return self.sftp.stat(path)
        except FileNotFoundError:
            return None
        except OSError:
            return None

    def put_file(self, local_path: Path, remote_path: str) -> None:
        print(f"UPLOAD {local_path} -> {remote_path}")

        if self.dry_run:
            return

        if self.sftp is None:
            raise SyncError("SFTP client is not connected")

        self.sftp.put(str(local_path), remote_path)

        local_stat = local_path.stat()
        self.sftp.utime(
            remote_path,
            (
                int(local_stat.st_atime),
                int(local_stat.st_mtime),
            ),
        )

    def remove_file(self, remote_path: str) -> None:
        print(f"DELETE remote file {remote_path}")

        if self.dry_run:
            return

        if self.sftp is None:
            raise SyncError("SFTP client is not connected")

        self.sftp.remove(remote_path)

    def remove_dir(self, remote_path: str) -> None:
        print(f"DELETE remote directory {remote_path}")

        if self.dry_run:
            return

        if self.sftp is None:
            raise SyncError("SFTP client is not connected")

        self.sftp.rmdir(remote_path)

    def listdir_attr(self, remote_path: str) -> list[paramiko.SFTPAttributes]:
        if self.dry_run:
            return []

        if self.sftp is None:
            raise SyncError("SFTP client is not connected")

        try:
            return self.sftp.listdir_attr(remote_path)
        except FileNotFoundError:
            return []
        except OSError:
            return []


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as file:
        raw = json.load(file)

    folders: list[FolderSyncConfig] = []

    for folder_item in raw.get("folders", []):
        destinations: list[DestinationConfig] = []

        for dest_item in folder_item.get("destinations", []):
            ssh_raw = dest_item["ssh"]
            enc_raw = dest_item.get("encryption", {})

            ssh = SshConfig(
                host=ssh_raw["host"],
                port=int(ssh_raw.get("port", 22)),
                user=ssh_raw.get("user", "root"),
                key_file=ssh_raw.get("key_file"),
                password=ssh_raw.get("password"),
                strict_host_key_checking=bool(
                    ssh_raw.get("strict_host_key_checking", False)
                ),
            )

            encryption = EcryptfsConfig(
                enabled=bool(enc_raw.get("enabled", False)),
                mount_options=enc_raw.get("mount_options", []),
                unmount_after_sync=bool(enc_raw.get("unmount_after_sync", True)),
            )

            destinations.append(
                DestinationConfig(
                    name=dest_item["name"],
                    ssh=ssh,
                    private_folder=dest_item["private_folder"],
                    dest_subfolder=dest_item["dest_subfolder"],
                    encryption=encryption,
                )
            )

        folders.append(
            FolderSyncConfig(
                local_folder=folder_item["local_folder"],
                destinations=destinations,
            )
        )

    return AppConfig(folders=folders)


def shell_quote_path(path: str) -> str:
    return shlex.quote(path)


def remote_destination_folder(destination: DestinationConfig) -> str:
    private_folder = destination.private_folder.rstrip("/")
    dest_subfolder = destination.dest_subfolder.strip("/")
    return f"{private_folder}/{dest_subfolder}"


def ensure_remote_directories(
    session: SshSession,
    destination: DestinationConfig,
) -> None:
    private_folder = destination.private_folder
    full_dest = remote_destination_folder(destination)

    session.mkdir_p(private_folder)
    session.mkdir_p(full_dest)


def is_remote_mounted(
    session: SshSession,
    destination: DestinationConfig,
) -> bool:
    private_folder = destination.private_folder

    if session.dry_run:
        print(f"Would check if remote folder is mounted: {private_folder}")
        return False

    command = f"findmnt -T {shell_quote_path(private_folder)} >/dev/null 2>&1"
    exit_code, _, _ = session.run(command, check=False)

    return exit_code == 0


def mount_ecryptfs(
    session: SshSession,
    destination: DestinationConfig,
) -> None:
    private_folder = destination.private_folder
    options = destination.encryption.mount_options or []

    option_part = ""
    if options:
        option_part = "-o " + shlex.quote(",".join(options))

    remote_command = (
        f"mount -t ecryptfs "
        f"{option_part} "
        f"{shell_quote_path(private_folder)} "
        f"{shell_quote_path(private_folder)}"
    )

    session.run(remote_command)


def ensure_ecryptfs_mounted(
    session: SshSession,
    destination: DestinationConfig,
) -> bool:
    """
    Returns True if this function mounted the folder and caller should unmount it later.
    Returns False if it was already mounted.
    """
    if not destination.encryption.enabled:
        return False

    mounted = is_remote_mounted(session, destination)

    if mounted:
        print(
            f"[{destination.name}] encrypted folder is already mounted: "
            f"{destination.private_folder}"
        )
        return False

    print(
        f"[{destination.name}] mounting encrypted folder: "
        f"{destination.private_folder}"
    )
    mount_ecryptfs(session, destination)
    return True


def unmount_ecryptfs(
    session: SshSession,
    destination: DestinationConfig,
) -> None:
    private_folder = destination.private_folder
    session.run(f"umount {shell_quote_path(private_folder)}")


def should_upload_file(
    local_path: Path,
    remote_attrs: paramiko.SFTPAttributes | None,
) -> bool:
    if remote_attrs is None:
        return True

    local_stat = local_path.stat()

    if remote_attrs.st_size != local_stat.st_size:
        return True

    remote_mtime = int(remote_attrs.st_mtime or 0)
    local_mtime = int(local_stat.st_mtime)

    return remote_mtime < local_mtime


def ensure_remote_parent_dir(
    session: SshSession,
    remote_file_path: str,
) -> None:
    remote_parent = posixpath.dirname(remote_file_path)
    session.mkdir_p(remote_parent)


def sync_files_native(
    session: SshSession,
    local_folder: str,
    destination: DestinationConfig,
) -> set[str]:
    source_path = Path(local_folder).expanduser().resolve()

    if not source_path.exists():
        raise SyncError(f"Local folder does not exist: {source_path}")

    if not source_path.is_dir():
        raise SyncError(f"Local path is not a directory: {source_path}")

    remote_root = remote_destination_folder(destination)
    uploaded_or_existing_remote_paths: set[str] = set()

    for local_file in source_path.rglob("*"):
        if not local_file.is_file():
            continue

        relative_path = local_file.relative_to(source_path).as_posix()
        remote_file_path = posixpath.join(remote_root, relative_path)
        uploaded_or_existing_remote_paths.add(remote_file_path)

        remote_attrs = session.stat(remote_file_path)

        if should_upload_file(local_file, remote_attrs):
            ensure_remote_parent_dir(session, remote_file_path)
            session.put_file(local_file, remote_file_path)
        else:
            print(f"SKIP unchanged {local_file}")

    return uploaded_or_existing_remote_paths


def collect_remote_files(
    session: SshSession,
    remote_root: str,
) -> set[str]:
    result: set[str] = set()

    def walk(path: str) -> None:
        for item in session.listdir_attr(path):
            item_path = posixpath.join(path, item.filename)

            if stat.S_ISDIR(item.st_mode or 0):
                walk(item_path)
            elif stat.S_ISREG(item.st_mode or 0):
                result.add(item_path)

    walk(remote_root)
    return result


def delete_remote_extra_files(
    session: SshSession,
    remote_root: str,
    expected_files: set[str],
) -> None:
    remote_files = collect_remote_files(session, remote_root)

    for remote_file in sorted(remote_files - expected_files):
        session.remove_file(remote_file)


def sync_native(
    session: SshSession,
    local_folder: str,
    destination: DestinationConfig,
    *,
    delete: bool,
) -> None:
    expected_files = sync_files_native(
        session,
        local_folder,
        destination,
    )

    if delete:
        delete_remote_extra_files(
            session,
            remote_destination_folder(destination),
            expected_files,
        )


def sync_destination(
    local_folder: str,
    destination: DestinationConfig,
    *,
    dry_run: bool,
    delete: bool,
) -> None:
    print()
    print(f"=== Destination: {destination.name} ===")
    print(f"Host: {destination.ssh.user}@{destination.ssh.host}:{destination.ssh.port}")
    print(f"Private folder: {destination.private_folder}")
    print(f"Destination subfolder: {destination.dest_subfolder}")

    mounted_by_us = False

    with SshSession(destination.ssh, dry_run=dry_run) as session:
        try:
            ensure_remote_directories(session, destination)

            mounted_by_us = ensure_ecryptfs_mounted(session, destination)

            ensure_remote_directories(session, destination)

            sync_native(
                session,
                local_folder,
                destination,
                delete=delete,
            )
        finally:
            if (
                destination.encryption.enabled
                and destination.encryption.unmount_after_sync
                and mounted_by_us
            ):
                print(f"[{destination.name}] unmounting encrypted folder")
                unmount_ecryptfs(session, destination)


def sync_all(
    config: AppConfig,
    *,
    dry_run: bool,
    delete: bool,
) -> None:
    for folder in config.folders:
        print()
        print(f"### Local folder: {folder.local_folder} ###")

        for destination in folder.destinations:
            try:
                sync_destination(
                    folder.local_folder,
                    destination,
                    dry_run=dry_run,
                    delete=delete,
                )
            except Exception as exc:
                print(
                    f"ERROR while syncing '{folder.local_folder}' "
                    f"to destination '{destination.name}': {exc}",
                    file=sys.stderr,
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronize local folders to remote SSH destinations."
    )

    parser.add_argument(
        "-c",
        "--config",
        default="sync-config.json",
        help="Path to JSON config file. Default: sync-config.json",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned operations without changing remote files.",
    )

    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete remote files that no longer exist locally.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        config = load_config(args.config)
        sync_all(
            config,
            dry_run=args.dry_run,
            delete=args.delete,
        )
    except Exception as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())