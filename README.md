# Shrawler: SMB Share Crawler & Spider

```
   _____ _                        _
  / ____| |                      | |
 | (___ | |__  _ __ __ ___      _| | ___ _ __
  \___ \| '_ \| '__/ _` \ \ /\ / / |/ _ \ '__|
  ____) | | | | | | (_| |\ V  V /| |  __/ |
 |_____/|_| |_|_|  \__,_| \_/\_/ |_|\___|_|
```

`Shrawler` is a powerful and flexible Python tool for enumerating Server Message Block (SMB) shares, checking for read/write permissions, and recursively spidering accessible shares to map out their contents. It's built using `impacket` and is designed for penetration testers and security professionals to quickly assess file shares on a network.

-----

## Features

  * **Multi-Host Scanning**: Scan a single host or provide a file with a list of hosts.
  * **Flexible Authentication**: Supports username/password, NTLM hashes, and Kerberos authentication.
  * **Permission Checking**: Quickly identifies shares with **Read** and/or **Write** access, with color-coded results for easy identification.
  * **Share Filtering**: Fine-tune your scan by skipping default shares, adding specific shares to the scan list, or only scanning a specific list of shares.
  * **Recursive Spidering**: Traverses readable shares to list all subdirectories and files in a clean, tree-like structure.
  * **File Downloading**: Download files from shares. You can download everything, files with specific extensions, or a default list of interesting file types.
  * **JSON Output**: Save all enumeration results to a structured JSON file for easy parsing or record-keeping.
  * **Customizable Depth**: Control the recursion depth of the spider to manage scan time and output verbosity.

-----

## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/your-username/shrawler.git
    cd shrawler
    ```

2.  Install Shrawler

    ```bash
    pipx install .
    ```

-----

## 🚀 Usage

The basic syntax for running Shrawler is:

```bash
shrawler [[domain/]username[:password]@]<target-ip> [options]
```

### Command-Line Arguments

| Argument | Description |
| :--- | :--- |
| **`target`** | **Required**. Specifies the target and credentials. Format: `[[domain/]username[:password]@]<ip>` |
| `-v`, `--verbose` | Enable verbose output for debugging. |
| `--read-only` | Skips the write permission check, only checking for read access. |
| `--skip-share <shares>` | Comma-separated list of additional shares to skip (e.g., `data,backup`). |
| `--add-share <shares>` | Comma-separated list of shares to remove from the default skip list (e.g., `C$,ADMIN$`). |
| `--shares <shares>` | Only scan the shares specified in this comma-separated list. |
| `--output` | Save scan results to a JSON file named `<ip>_<username>_shares.json`. |
| `--hosts-file <file>` | Path to a file containing a list of target IPs (one per line). |
| `--host <ip>` | Specify a single target host IP. Overrides the IP in the main `target` argument. |
| **Authentication** | |
| `-H`, `--hashes <hash>` | Use NTLM hashes for authentication. Format: `LMHASH:NTHASH`. |
| `-no-pass` | Do not prompt for a password when one is not provided. |
| `-k` | Use Kerberos authentication (obtains TGT from ccache). |
| `-aesKey <key>` | Use an AES key for Kerberos Pass-the-Key. |
| **Spidering** | |
| `--spider` | Enable spidering of all readable shares. |
| `--download [ext]` | Download files found during spidering. Use without args to download all, or provide comma-separated extensions (e.g., `.txt,.pdf,.config`). |
| `--max-depth <num>` | Set the maximum recursion depth for the spider (Default: 5). |

### Usage Examples

#### **1. Basic Share Enumeration**

Scan a target using a username and password.

```bash
shrawler homelab.local/user:Password123@192.168.1.100 --host 192.168.1.100
```

#### **2. Using NTLM Hashes**

Authenticate using an NTHASH (leave LMHASH blank).

```bash
shrawler homelab.local/user@192.168.1.100 -H ':<nthash_here>' --host 192.168.1.100
```

#### **3. Scanning Multiple Hosts**

Scan a list of hosts from a file and save the output.

```bash
# hosts.txt contains:
# 192.168.1.100
# 192.168.1.101

shrawler homelab.local/user:Password123@192.168.1.1 --hosts-file hosts.txt --output
```

#### **4. Spidering a Share**

Enumerate and then spider all readable shares found.

```bash
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider
```

#### **5. Spidering and Downloading Files**

Spider a specific share and download all `.config` and `.txt` files. All downloaded files will be saved in a `downloads/` directory.

```bash
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --shares "backup" --spider --download ".config,.txt"
```

Download *everything* found during a spidering session.

```bash
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider --download
```

-----

## 📊 Example Output

#### **Share Enumeration**

The output clearly indicates permissions: **Green** for Read/Write, **Yellow** for Read-Only, and **Red** for No Access.

```
[+] Connected to 192.168.1.100
    [+] backup                                   | Read: Yes | Write: Yes | Comment: N/A
    [+] data                                     | Read: Yes | Write: No  | Comment: Company Data
    [-] private                                  | Read: No  | Write: N/A | Comment: Restricted
```

#### **Spidering Output**

The spider provides a familiar tree structure, showing directories in blue and files in green, along with modification times. If downloading is enabled, a status is shown for each file.

```
[+] 192.168.1.100\backup
└── Users
    ├── administrator
    │   └── Documents
    │       ├── creds.txt  2025-08-06 08:30:00 [DOWNLOADED]
    │       └── report.docx  2025-07-15 11:22:00
    └── public
        └── notes.txt  2025-02-10 16:05:30 [DOWNLOADED]
```
