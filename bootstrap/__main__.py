#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path
from subprocess import check_call, check_output


def setup_disk(args):
    print(f"I will now set up the disk {args.device}, writing the following partitions:")
    print("1. EFI partition (512 MB)")
    print("2. Primary partition (rest of the disk)")
    print("THIS WILL ERASE ALL DATA ON THE DISK. Are you sure? [y/N]")

    if input().lower() != "y":
        print("Exiting.")
        sys.exit(1)

    print("Writing partitions...")
    check_call(["parted", "-a", "optimal", args.device, "mklabel", "gpt"])
    check_call(["parted", "-a", "optimal", args.device, "mkpart", "ESP", "fat32", "2MB", "512MB"])
    check_call(["parted", "-a", "optimal", args.device, "mkpart", "primary", "512MB", "100%"])
    check_call(["parted", "-a", "optimal", args.device, "set", "1", "esp", "on"])

    print("Creating filesystems...")
    check_call(["wipefs", "-a", f"{args.device}p1"])
    check_call(["wipefs", "-a", f"{args.device}p2"])
    check_call(["mkfs.fat", f"{args.device}p1"])
    check_call(["mkfs.ext4", f"{args.device}p2"])

    print("Mounting filesystems...")
    check_call(["mount", f"{args.device}p2", "/mnt"])
    check_call(["mkdir", "-p", "/mnt/boot"])
    check_call(["mount", f"{args.device}p1", "/mnt/boot"])


def get_iface(args):
    # The NixOS installer brings up network (dhcp)
    # Get the interface name for the default route
    output = json.loads(check_output(["ip", "--json", "route", "get", "1.1.1.1"]))
    return output[0]["dev"]


def get_nixos_version(args):
    # Get the NixOS installer version to put into system.stateVersion
    output = check_output(["nixos-version"])
    return output[:4]


def write_configs(args):
    # Clone the config repo
    print(f"Downloading configuration files from {args.config_repo_url}...")
    config_path = Path() / "bootstrap-config"
    check_call(["git", "clone", args.config_repo_url, config_path])

    # Generate the hardware configuration
    print(f"Retrieving hardware configuration from nixos-generate-config...")
    hardware_config = check_output(["nixos-generate-config", "--show-hardware-config"])

    # Generate the system configuration
    print("Templating bootstrap system configuration...")
    with open(config_path / "bootstrap" / "template.nix") as f:
        system_config = (
            f.read()
            .replace("{{{ hostname }}}", args.hostname)
            .replace("{{{ iface }}}", get_iface(args))
            .replace("{{{ ip_last_octet }}}", args.ip_last_octet)
            .replace("{{{ nixos_version }}}", get_nixos_version(args))
        )

    # Write the configurations
    print("Writing configurations...")
    with open(config_path / "hardware" / f"{args.hostname}.nix") as f:
        f.write(hardware_config)
    with open(config_path / "hosts" / f"{args.hostname}.nix") as f:
        f.write(system_config)


def install_nixos(args):
    print("Run nixos-install? [y/N]")
    if input().lower() != "y":
        print("Exiting.")
        sys.exit(1)
    check_call(["nixos-install", "--root", "/mnt"])


def main():
    parser = argparse.ArgumentParser(description="Bootstrap a new NixOS system")
    parser.add_argument("--device", help="The device to install NixOS on, e.g. /dev/nvme0n1")
    parser.add_argument("--hostname", help="The hostname of the new machine")
    parser.add_argument("--ip-last-octet", help="The last octet of the IP address to assign")
    parser.add_argument(
        "--config-repo-url",
        help="The git repository to download configurations from",
        default="https://github.com/oliver-ni/ocf-nix-desktops.git",
    )
    args = parser.parse_args()

    print("Welcome to the OCF NixOS bootstrap script!")
    print("This script will partition the disk, write a bootstrap configuration, and install NixOS.")
    print("Please ensure you have a working internet connection before running this script.")
    print("Press Enter to continue or Ctrl-C to exit.")
    input()

    if not args.device:
        args.device = input("Please the device to install NixOS on, e.g. /dev/nvme0n1: ")
    if not args.hostname:
        args.hostname = input("Please the hostname of the new machine: ")
    if not args.ip_last_octet:
        args.ip_last_octet = input("Please the last octet of the IP address to assign: ")

    setup_disk(args)
    write_configs(args)
    install_nixos(args)


main()
