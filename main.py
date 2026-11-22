import argparse
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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


def run_command(
    command: list[str],
    *,
    dry_run: bool = False,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    printable = " ".join(shlex.quote(part) for part in command)
    print(f"$ {printable}")

    if dry_run:
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    result = subprocess.run(
        command,
        text=True,
        check=False,
        capture_output=capture_output,
    )

    if check and result.returncode != 0:
        if result.stdout:
            print(result.stdout, file=sys.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        raise SyncError(f"Command failed with code {result.returncode}: {printable}")

    return result


def build_ssh_base_command(ssh: SshConfig) -> list[str]:
    command = [
        "ssh",
        "-p",
        str(ssh.port),
    ]

    if ssh.key_file:
        command.extend(["-i", ssh.key_file])

    if not ssh.strict_host_key_checking:
        command.extend(
            [
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
            ]
        )

    command.append(f"{ssh.user}@{ssh.host}")
    return command


def with_password_prefix(ssh: SshConfig, command: list[str]) -> list[str]:
    """
    Password auth for ssh/rsync requires sshpass installed on local machine.

    Example Debian/Ubuntu:
        apt install sshpass

    If password is not configured, normal SSH key/agent auth is used.
    """
    if ssh.password:
        return ["sshpass", "-p", ssh.password, *command]
    return command


def run_remote(
    ssh: SshConfig,
    remote_command: str,
    *,
    dry_run: bool = False,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = build_ssh_base_command(ssh)
    command.append(remote_command)
    command = with_password_prefix(ssh, command)

    return run_command(
        command,
        dry_run=dry_run,
        check=check,
        capture_output=capture_output,
    )


def shell_quote_path(path: str) -> str:
    return shlex.quote(path)


def ensure_remote_directories(
    destination: DestinationConfig,
    *,
    dry_run: bool,
) -> None:
    private_folder = destination.private_folder
    full_dest = remote_destination_folder(destination)

    remote_command = (
        f"mkdir -p {shell_quote_path(private_folder)} "
        f"{shell_quote_path(full_dest)}"
    )

    run_remote(destination.ssh, remote_command, dry_run=dry_run)


def remote_destination_folder(destination: DestinationConfig) -> str:
    private_folder = destination.private_folder.rstrip("/")
    dest_subfolder = destination.dest_subfolder.strip("/")
    return f"{private_folder}/{dest_subfolder}"


def is_remote_mounted(
    destination: DestinationConfig,
    *,
    dry_run: bool,
) -> bool:
    private_folder = destination.private_folder

    if dry_run:
        print(f"Would check if remote folder is mounted: {private_folder}")
        return False

    command = f"findmnt -T {shell_quote_path(private_folder)} >/dev/null 2>&1"
    result = run_remote(
        destination.ssh,
        command,
        dry_run=False,
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def mount_ecryptfs(
    destination: DestinationConfig,
    *,
    dry_run: bool,
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

    run_remote(destination.ssh, remote_command, dry_run=dry_run)


def ensure_ecryptfs_mounted(
    destination: DestinationConfig,
    *,
    dry_run: bool,
) -> bool:
    """
    Returns True if this function mounted the folder and caller should unmount it later.
    Returns False if it was already mounted.
    """
    if not destination.encryption.enabled:
        return False

    mounted = is_remote_mounted(destination, dry_run=dry_run)

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
    mount_ecryptfs(destination, dry_run=dry_run)
    return True


def unmount_ecryptfs(
    destination: DestinationConfig,
    *,
    dry_run: bool,
) -> None:
    private_folder = destination.private_folder

    remote_command = f"umount {shell_quote_path(private_folder)}"
    run_remote(destination.ssh, remote_command, dry_run=dry_run)


def build_rsync_ssh_command(ssh: SshConfig) -> str:
    parts = [
        "ssh",
        "-p",
        str(ssh.port),
    ]

    if ssh.key_file:
        parts.extend(["-i", ssh.key_file])

    if not ssh.strict_host_key_checking:
        parts.extend(
            [
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
            ]
        )

    return " ".join(shlex.quote(part) for part in parts)


def run_rsync(
    local_folder: str,
    destination: DestinationConfig,
    *,
    dry_run: bool,
    delete: bool,
) -> None:
    source_path = Path(local_folder).expanduser().resolve()

    if not source_path.exists():
        raise SyncError(f"Local folder does not exist: {source_path}")

    source = str(source_path)
    if not source.endswith("/"):
        source += "/"

    remote_dest_folder = remote_destination_folder(destination)
    remote_target = (
        f"{destination.ssh.user}@{destination.ssh.host}:"
        f"{shlex.quote(remote_dest_folder)}/"
    )

    command = [
        "rsync",
        "-az",
        "--info=progress2",
        "-e",
        build_rsync_ssh_command(destination.ssh),
    ]

    if delete:
        command.append("--delete")

    command.extend([source, remote_target])

    command = with_password_prefix(destination.ssh, command)

    run_command(command, dry_run=dry_run)


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

    try:
        ensure_remote_directories(destination, dry_run=dry_run)

        mounted_by_us = ensure_ecryptfs_mounted(destination, dry_run=dry_run)

        ensure_remote_directories(destination, dry_run=dry_run)

        run_rsync(
            local_folder,
            destination,
            dry_run=dry_run,
            delete=delete,
        )
    finally:
        if (
            destination.encryption.enabled
            and destination.encryption.unmount_after_sync
            and mounted_by_us
        ):
            print(f"[{destination.name}] unmounting encrypted folder")
            unmount_ecryptfs(destination, dry_run=dry_run)


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
        description="Synchronize local folders to remote SSH destinations via rsync."
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
        help="Print commands without executing them.",
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

