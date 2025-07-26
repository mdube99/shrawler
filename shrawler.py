#!/usr/bin/env python3

from impacket.smbconnection import (
    SMBConnection,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB_DIALECT,
    SessionError,
)
from impacket.examples.utils import parse_target
import socket
import argparse
import logging
import json
import time
import os
from typing import Any
from colorama import init, Fore, Style


# custom log colors
class Formatter(logging.Formatter):
    """Custom Formatter."""

    def format(self, record: logging.LogRecord):
        init()
        if record.levelno == logging.INFO:
            self._style._fmt = f"{Fore.GREEN}[+]{Style.RESET_ALL} %(message)s"
        elif record.levelno == logging.DEBUG:
            self._style._fmt = f"{Fore.YELLOW}[+]{Style.RESET_ALL} %(message)s"
        else:
            self._style._fmt = f"{Fore.RED}[-]{Style.RESET_ALL} %(message)s"
        return super().format(record)


def error(msg: str) -> str:
    """Custom error message."""
    max_length: int = 70
    padding: int = max(0, (max_length - len(msg)) // 2)
    this: str = "-" * padding + msg + "-" * (max_length - len(msg) - padding)
    return Fore.RED + this + Style.RESET_ALL + "\n"


def success(msg: str) -> str:
    """Custom success message."""
    max_length: int = 70
    padding: int = max(0, (max_length - len(msg)) // 2)
    this: str = "-" * padding + msg + "-" * (max_length - len(msg) - padding)
    return Fore.GREEN + this + Style.RESET_ALL + "\n"


def print_share_info(
    share_name: str,
    share_comment: str,
    share_perms: dict[str, str],
    largest_share_name: int,
) -> None:
    """Custom print message."""
    if share_perms["read"] and share_perms["write"]:
        prefix = Fore.GREEN + "[+]" + Style.RESET_ALL
    elif share_perms["read"] and not share_perms["write"]:
        prefix = Fore.YELLOW + "[+]" + Style.RESET_ALL
    else:
        prefix = Fore.RED + "[-]" + Style.RESET_ALL

    if share_perms["read"]:
        read = "Yes"
    else:
        read = "No"

    if share_perms["write"] == "N/A":
        write = "N/A"
    elif share_perms["write"]:
        write = "Yes"
    else:
        write = "No"

    # fmt: off
    print(f"    {prefix} {share_name.ljust(largest_share_name + 20)} | Read: {read.ljust(3)} | Write: {write.ljust(3)} | Comment: {share_comment if share_comment else 'N/A'}")


class Shrawler:
    """SMB Share Crawling Tool."""

    def __init__(self) -> None:
        init()  # for Colorama
        parser = argparse.ArgumentParser(
            """python3 shrawler.py homelab.local/user:password@dc-ip"""
        )
        parser.add_argument(
            "target",
            action="store",
            help="[[domain/]username[:password]@]<dc-ip>",
        )
        parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
        parser.add_argument(
            "--read-only",
            dest="read_only",
            action="store_true",
            help="Skip checking for write permission",
        )
        parser.add_argument(
            "--skip-share",
            dest="skip_share",
            help="Additional shares to skip, separated by comma. Case Sensitive",
        )
        parser.add_argument(
            "--add-share",
            dest="add_share",
            help="Add additional shares to search for, separated by comma. Case sensitive",
        )
        parser.add_argument(
            "--shares",
            dest="shares",
            help="Only scan shares specified with this argument",
        )
        parser.add_argument("--output", action="store_true", help="Json file output")
        parser.add_argument(
            "--hosts-file",
            action="store",
            dest="hosts_file",
            help="File containing IP addresses of target machines",
        )
        parser.add_argument("--host", action="store", help="Specific machine to target")

        group = parser.add_argument_group("authentication")
        group.add_argument(
            "-H",
            "--hashes",
            action="store",
            metavar="LMHASH:NTHASH",
            help="NTLM hashes, format is NTHASH:LMHASH",
        )
        group.add_argument(
            "-no-pass",
            action="store_true",
            help="Don't ask for password (useful for -k)",
        )
        group.add_argument(
            "-k",
            action="store_true",
            help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line",
        )
        group.add_argument(
            "-aesKey",
            action="store",
            metavar="hex key",
            help="AES key to use for Kerberos Authentication (128 or 256 bits)",
        )

        spider = parser.add_argument_group("spider")
        spider.add_argument(
            "--spider", action="store_true", help="Spider all shares found"
        )
        # Download files
        # If you specify nothing, it will download everything
        spider.add_argument(
            "--download",
            action="store",
            dest="download",
            nargs="?",
            const=" ",
            help="Download files. Specify nothing, it will download everything."
            "You can specify specific extensions limited by a ','."
            "You can also specify '--download default' for shrawler to choose the extensions for you.",
        )
        spider.add_argument(
            "--max-depth",
            action="store",
            dest="max_depth",
            type=int,
            default=5,
            help="Max depth of spidering. Default: 5",
        )

        self.args = parser.parse_args()

        self.verbose = self.args.verbose

        self.normal_shares = [
            "ADMIN$",
            "C$",
            "IPC$",
            "NETLOGON",
            "PRINT$",
            "print$",
            "SYSVOL",
        ]

        # extensions that it will look for
        self.extensions = [
            ".txt",
            ".csv",
            ".xlsx",
            ".pdf",
            ".kbdx",
            ".kbd",
            ".docx",
            ".doc",
            ".xls",
            ".ps1",
            ".bat",
            ".vbs",
            ".tar",
            ".zip",
            ".sh",
            ".json",
            ".ini",
            ".conf",
            ".cnf",
            ".config",
            ".properties",
            ".prop",
            ".yaml",
            ".yml",
            ".pem",
            ".key",
            ".sql",
            ".db",
        ]

    def banner(self):
        ascii = r"""
   _____ _                        _           
  / ____| |                      | |          
 | (___ | |__  _ __ __ ___      _| | ___ _ __ 
  \___  | '_  | '__/ _` \ \ /\ / / |/ _ \ '__|
  ____) | | | | | | (_| |\ V  V /| |  __/ |   
 |_____/|_| |_|_|  \__,_| \_/\_/ |_|\___|_|   
        """
        return Fore.GREEN + ascii + Style.RESET_ALL + "\n"

    def check_port(self, machine: str, port: int) -> bool:
        """Check if port is open."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)

            try:
                return s.connect_ex((machine, port)) == 0
            except:
                return False

    def download_file(
        self, smbclient, share: str, remote_path: str, local_filename: str
    ) -> str:
        """
        Downloads a file from the SMB share and saves it locally.

        Args:
            smbclient: The SMB client instance
            share: SMB share name
            remote_path: Full path to the remote file
            local_filename: Local filename to save as

        Returns:
            bool: True if download successful, False otherwise
        """
        try:
            # Create downloads directory if it doesn't exist
            downloads_dir = "downloads"
            if not os.path.exists(downloads_dir):
                os.makedirs(downloads_dir)

            local_path = os.path.join(downloads_dir, local_filename)

            # Download the file using impacket's getFile method
            with open(local_path, "wb") as local_file:
                smbclient.getFile(share, remote_path, local_file.write)

            downloaded = f" {Fore.CYAN}[DOWNLOADED]{Style.RESET_ALL}"
            return downloaded

        except Exception as e:
            failed = f" {Fore.RED}[ERROR]{Style.RESET_ALL} Failed to download: {str(e)}"
            return failed

    def get_shares(
        self,
        target: str,
        mach_name: str,
        smbclient: Any,
        default_shares,
        spider: bool = False,
        desired_share: str = "",
    ) -> dict[str, list[Any]]:
        shares = smbclient.listShares()
        results = {}
        results[target] = []

        largest_share_name = len(max(shares, key=len))

        # Assuming shares is a list of share dictionaries
        share_names = [share["shi1_netname"][:-1] for share in shares]

        # only print desired share
        if desired_share:
            desired_share = desired_share.split(",")
            default_shares = share_names
            for share in desired_share:
                default_shares.remove(share)

        if default_shares not in share_names:
            for share in shares:
                # last char can be a hex value
                # This grabs the sharename without the last character
                # impacket naming scheme
                share_name = share["shi1_netname"][:-1]
                share_comment = share["shi1_remark"][:-1]
                if share_name not in default_shares:
                    try:
                        share_perms = self.check_share_perm(share_name, smbclient)
                        results[target].append(
                            {
                                "computer": {"ip": target},
                                "share": {
                                    "name": share_name,
                                    "comment": share_comment,
                                    "read_write": share_perms,
                                    "path": f"\\{target}\\{share_name}",
                                },
                            }
                        )
                        # If you're spidering you don't need to print out share perms
                        # Assumes you're doing this in separate steps - will still print out what it finds though
                        if spider and share_perms["read"]:
                            print("")
                            logging.info(f"{mach_name}\\{share_name}")
                            self.spider_shares(target, share_name, "", smbclient)

                        # If you're not spidering, will print out
                        else:
                            print_share_info(
                                share_name,
                                share_comment,
                                share_perms,
                                largest_share_name,
                            )

                    except KeyboardInterrupt:
                        input("\nPress enter to continue")
                        continue
        else:
            logging.warning("No desired shares found")
        return results

    def spider_shares(self, target: str, share: str, base_dir: str, smbclient) -> None:
        directories = []
        try:
            # List all items in the base directory
            for result in smbclient.listPath(share, base_dir + "*", password=None):
                if result.get_longname() not in [".", ".."]:
                    next_filedir = result.get_longname()
                    next_fullpath = base_dir + next_filedir
                    file_metadata = Shrawler().parse_file(result)

                    size = file_metadata["size"]
                    mtime = file_metadata["mtime"]

                    file = (
                        size
                        + mtime
                        + f"\\\\{target}\\{share}\\{base_dir}"
                        + result.get_longname()
                    )
                    # Clean up the file path to standardize format
                    file = file.replace("/*", "")
                    file = file.replace("\\*\\", "\\")
                    file = file.replace("/\\", "\\")
                    file = file.replace("/", "\\")
                    file = file.replace("\\\\", "\\")

                    if result.is_directory():
                        # Store the directory for later processing
                        directories.append(next_fullpath + "/")
                        # if self.args.max_depth <= len(directories):
                        self.build_tree_structure(
                            base_dir,
                            result.get_longname(),
                            smbclient,
                            share,
                            mtime,
                        )

        except Exception as e:
            logging.warning(e)

    def check_share_perm(self, share: str, smbclient) -> dict:
        read_write = {"read": False, "write": "N/A"}

        # check for read rights
        try:
            smbclient.listPath(share, "*", password=None)
            read_write["read"] = True
        except SessionError:
            read_write["read"] = False

        # check for write rights
        if not Shrawler().args.read_only:
            try:
                # pretty much all tools that crawl shares have to attempt to write to disk.
                # If it does not allow, you've got your write perms
                # Downside, its possible to allow write but not delete perms.
                # In this case, I like to specify the folder name incase this happens - you can let clients know
                directory = "pentest_temp_dir"
                smbclient.createDirectory(share, directory)
                smbclient.deleteDirectory(share, directory)
                read_write["write"] = True
            except SessionError as e:
                logging.debug(f"Full error: {e}")
                read_write["write"] = False
        return read_write

    def build_tree_structure(
        self,
        base_dir: str,
        directory: str,
        smbclient,
        share: str,
        mtime: str,
        indent: str = "",
        last: bool = False,
        depth: int = 0,
    ) -> None:
        """
        Recursively prints the tree structure for a given directory, appending paths using string concatenation.
        """

        should_download = False

        connector = "└── " if last else "├── "
        print(indent + connector + Fore.BLUE + directory + Style.RESET_ALL)

        # Update the indent for the next depth level
        indent += "    " if last else "│   "

        try:
            results = smbclient.listPath(
                share, base_dir + directory + "/*", password=None
            )

            # Filter out '.' and '..' and get the total number of valid items
            total_items = len(
                [res for res in results if res.get_longname() not in [".", ".."]]
            )
            count = 0

            # depth has an index of 0, max_depth assumes human readable
            if depth < self.args.max_depth - 1:
                for result in results:
                    if result.get_longname() not in [".", ".."]:
                        next_filedir = result.get_longname()
                        count += 1  # Fixed: increment count for each item
                        is_last = (
                            count == total_items
                        )  # Determine if it's the last item

                        # If it's a directory, print its contents
                        if result.is_directory():
                            self.build_tree_structure(
                                base_dir + directory + "/",
                                next_filedir,
                                smbclient,
                                share,
                                mtime,
                                indent,
                                last=is_last,
                                depth=depth + 1,
                            )
                        else:
                            # Print file with the correct connector and indentation
                            file_connector = "└── " if is_last else "├── "
                            download_status = ""

                            if self.args.download and self.args.download != "default":
                                # Split extensions and check if file matches any
                                extensions = self.args.download.split(",")
                                for ext in extensions:
                                    if next_filedir.endswith(ext.strip()):
                                        should_download = True
                                        break
                            elif self.args.download == "default":
                                # Download all files when set to "default"
                                should_download = True
                            else:
                                should_download = False

                            # Download the file if criteria met
                            if should_download:
                                remote_file_path = (
                                    base_dir + directory + "/" + next_filedir
                                )
                                # Create local filename by replacing '/' with '_'
                                local_filename = f"{self.args.host}_{remote_file_path.replace('/', '_').lstrip('_')}"
                                # local_filename = remote_file_path.replace(
                                #     "/", "_"
                                # ).lstrip("_")

                                download_success = self.download_file(
                                    smbclient,
                                    share,
                                    remote_file_path,
                                    local_filename,
                                )
                                # Add download status indicator
                                download_status = (
                                    f" {Fore.CYAN}[DOWNLOADED]{Style.RESET_ALL}"
                                    if download_success
                                    else f" {Fore.RED}[FAILED]{Style.RESET_ALL}"
                                )

                            # Always print the file (regardless of download status)
                            print(
                                indent
                                + file_connector
                                + Fore.GREEN
                                + next_filedir
                                + Style.RESET_ALL
                                + f"  {Fore.YELLOW + mtime + Style.RESET_ALL}"
                                + download_status
                            )

        except Exception as e:
            logging.warning(f"Error accessing directory: {e}")

    def readable_file_size(self, nbytes: float) -> str:
        "Convert into readable file sizes"
        suffixes = ["B", "KB", "MB", "GB"]

        for i in range(len(suffixes)):
            if nbytes < 1024 or i == len(suffixes) - 1:
                break
            nbytes /= 1024

        size_str = f"{nbytes:.2f}".rstrip("0").rstrip(".")

        return f"{size_str}{suffixes[i]}"

    def readable_time(self, timestamp: float) -> str:
        "convert into readable time"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

    def parse_file(self, file_info) -> dict:
        "Parse file and output metadata"
        file_size = file_info.get_filesize()
        file_creation_date = file_info.get_ctime_epoch()
        file_modified_date = file_info.get_mtime_epoch()

        results = {
            "size": self.readable_file_size(file_size),
            "ctime": self.readable_time(file_creation_date),
            "mtime": self.readable_time(file_modified_date),
        }
        return results

    def output_to_json(self, mach_ip: str, username: str, output: dict) -> None:
        "output into json file"
        out_file = f"{mach_ip}_{username}_shares.json"

        with open(out_file, "w") as f:
            f.write(json.dumps(output, indent=2))
        f.close()

    def init_smb_session(
        self,
        domain: str,
        username: str,
        password: str,
        address: str,
        lmhash: str,
        nthash: str,
    ):
        """
        Initiate SMB Session with host using impacket libraries.
        """
        try:
            smbClient = SMBConnection(address, address, sess_port=int(445))

            dialect = smbClient.getDialect()

            if dialect == SMB_DIALECT:
                logging.debug("SMBv1 dialect used")

            elif dialect == SMB2_DIALECT_002:
                logging.debug("SMBv2.0 dialect used")

            elif dialect == SMB2_DIALECT_21:
                logging.debug("SMBv2.1 dialect used")

            else:
                logging.debug("SMBv3.0 dialect used")

            if self.args.k is True:
                smbClient.kerberosLogin(
                    username,
                    password,
                    domain,
                    lmhash,
                    nthash,
                    self.args.aesKey,
                    self.domain_controller,
                )

            else:
                smbClient.login(username, password, domain, lmhash, nthash)
            if smbClient.isGuestSession() > 0:
                logging.debug("GUEST Session Granted")
            else:
                logging.debug("USER Session Granted")
        except SessionError as e:
            logging.warning(f"Invalid login attempt on '{address}'\n")
            logging.debug(f"Full error: {e}")
            print(error(""))
            return None

        logging.info(f"Connected to {address}")
        return smbClient

    def get_ip_addrs(self, file: str) -> list:
        with open(file, "r") as f:
            lines = f.read().splitlines()

        return lines

    def main(self) -> None:
        # Logging
        logger = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(Formatter())

        logger.addHandler(handler)

        if self.verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

        print(self.banner())
        # parses the argument 'target' to get the values needed
        domain, self.username, self.password, self.domain_controller = parse_target(
            self.args.target
        )
        if (
            len(self.password) == 0
            and len(self.username) != 0
            and self.args.hashes is None
            and self.args.no_pass is False
            and self.args.aesKey is None
        ):
            from getpass import getpass

            self.password = getpass("Password:")

        if self.args.aesKey is not None:
            self.args.k = True

        if self.args.hashes is not None:
            lmhash, nthash = self.args.hashes.split(":")
        else:
            lmhash, nthash = "", ""

        if self.args.skip_share:
            shares = self.args.skip_share.split(",")
            for share in shares:
                self.normal_shares.append(share)

        if self.args.add_share:
            shares = self.args.add_share.split(",")
            for share in shares:
                self.normal_shares.remove(share)

        if self.args.hosts_file:
            machine_ip = self.get_ip_addrs(self.args.hosts_file)
            machine_names = machine_ip

        elif self.args.host:
            machine_ip = [self.args.host]
            machine_names = machine_ip

        else:
            logging.warning(
                "Please specify hosts file (--host) or specific host (--hosts) to check"
            )
            quit()

        # iterate through machine IPs and machines at the same time
        for mach_ip, mach_name in zip(machine_ip, machine_names):
            try:
                if self.check_port(mach_ip, 445):
                    # Start SMB session against the host in question
                    try:
                        smbclient = self.init_smb_session(
                            domain,
                            self.username,
                            self.password,
                            mach_ip,
                            lmhash,
                            nthash,
                        )

                        # get shares on host
                        results = self.get_shares(
                            mach_ip,
                            mach_name,
                            smbclient,
                            self.normal_shares,
                            self.args.spider,
                            self.args.shares,
                        )
                        # output to file in json format
                        if self.args.output:
                            self.output_to_json(mach_ip, self.username, results)

                        # just for a new line
                        print("")

                        # This is used to separate hosts. Will print a colored line after each host.
                        print(success(""))
                    except Exception as e:
                        logging.debug(e)
                        continue
                else:
                    logging.warning(f"Port 445 not open on '{mach_ip}'")
                    print(error(""))
            except AttributeError as e:
                logging.debug(f"Full error: {e}")
                continue

            except KeyboardInterrupt:
                input("Press enter to continue...")
                continue


def main() -> None:
    """Calling shrawler."""
    Shrawler().main()


if __name__ == "__main__":
    main()
