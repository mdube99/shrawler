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
  * **Nemesis Integration**: Upload downloaded files directly to Nemesis API for centralized file management and analysis.
  * **Environment Variables**: Configure Nemesis settings via `.env` file for streamlined workflow integration.
  * **Consolidated Scan Results**: Automatic generation of `shrawler_results.json` with hierarchical structure containing share enumeration data and detailed metadata for all downloaded files.
  * **File Analysis**: Count files by extension or filename patterns, and identify files with unique modification times.
  * **Cross-Platform Compatibility**: Automatic filename sanitization ensures downloads work across different operating systems.
  * **Enhanced Status Indicators**: Real-time feedback on download success, Nemesis uploads, and unique file identification.

-----

## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/mdube99/shrawler.git
    cd shrawler
    ```

2.  Install Shrawler

    ```bash
    pipx install .
    ```

### Alternative: Run Without Installation

If you prefer to run shrawler without installing it:

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run directly:
   ```bash
   python3 shrawler.py [[domain/]username[:password]@]<dc-ip> [options]
   ```

### Development

Development and test dependencies are managed with `uv`:

```bash
uv sync --extra dev
uv run ruff check shrawler tests shrawler.py
uv run pytest -q
uv build
```

-----

## 🚀 Usage

Shrawler provides task-oriented operating modes:

```bash
shrawler shares [[domain/]username[:password]@]<host> [options]
shrawler spider [[domain/]username[:password]@]<host> [options]
shrawler snaffle [[domain/]username[:password]@]<host> --rules <path> [options]
shrawler report <shrawler_results.json> [--retry-failed]
```

- `shares` enumerates shares and configured permission checks without recursion.
- `spider` inventories files recursively across readable shares.
- `snaffle` spiders and applies Snaffler rules; a rules directory is required.
- `report` summarizes saved results and can retry failed Nemesis uploads without rescanning SMB.

The original `shrawler TARGET [options]` syntax remains available for compatibility.

### Common Command-Line Arguments

| Argument | Description |
| :--- | :--- |
| **`target`** | **Required**. Specifies the target and credentials. Format: `[[domain/]username[:password]@]<dc-ip>` |
| `--profile <quiet|balanced|fast>` | Select a noise and concurrency preset. |
| `--permission-check <none|read|read-write>` | Select permission checks. The default `read-write` mode lists the root and performs non-invasive server access-mask probes without creating files. |
| `--file-write-check` | Explicitly create/delete temporary file and directory objects to verify writes. This modifies the target briefly and may leave artifacts if cleanup is denied or interrupted. |
| `--share <name>` | Scan only this share. Repeat to select more shares. |
| `--exclude-share <name>` | Skip this share. Repeat to exclude more shares. |
| `-o`, `--output <path>` | Set the results directory. |
| `--format <console|csv>` | Add CSV reports when selected; JSON results are always saved. |
| `--view <summary|progress|matches|tree>` | Select terminal detail; interactive terminals default to a single updating progress line. `--output-mode` remains an alias. |
| `--resume [path]` | Resume a scan from its output directory, skipping completed hosts, shares, and discovered paths. |
| `--download-ext [extensions]` | Download all files when no value is supplied, the default set, or comma-separated extensions. |
| `--limits <conservative|standard|unlimited>` | Select download size limits. |
| `--max-file-size <size>` | Override the per-file limit with a readable size such as `20MB`. |
| `--download-budget <size>` | Override the run limit with a readable size such as `2GB`. |
| `--nemesis-url <url>` | Set the Nemesis API URL. |
| `--rules <path>` | Load Snaffler rules recursively (required by `snaffle`). |
| `--interest <0-3>` | Set the minimum Snaffler interest level. |

Standard `shrawler <mode> --help` is authoritative and includes authentication,
diagnostic, target-selection, and tuning controls relevant to that mode.

`--host` overrides only the host embedded in `target`; credentials remain unchanged.
Use `--hosts-file` for multiple targets (one host per non-empty line, with `#`
comments supported). `--host` and `--hosts-file` are mutually exclusive.

### Share Permission Checks and OPSEC

By default, every profile uses `--permission-check read-write`. Shrawler
checks read access once with `listPath` and reuses that listing for spidering. For
disk-tree shares, it then opens the existing share root with `FILE_OPEN` and asks
the SMB server independently for `GENERIC_WRITE`, file creation, subdirectory
creation, ACL modification, and ownership-control rights. These checks do not
create, modify, rename, or delete remote objects. IPC, printer, device, and other
non-filesystem shares are not write-probed.

The result reports direct file rights (`generic_write` or `add_file`), directory
creation (`add_subdirectory`), ACL control (`write_dac`), and ownership control
(`write_owner`) separately. A granted mask means the SMB server authorized that
right on the share root; it does not guarantee a completed write. AV/EDR, quotas,
application policy, or deeper-directory ACLs can produce different effective
behavior, and writable subdirectories can exist beneath a non-writable root.

Use empirical verification only with direct intent:

```bash
# Default: root listing plus non-invasive write-rights assessment
shrawler shares TARGET

# Read check only
shrawler shares TARGET --permission-check read

# Mutating create/delete verification
shrawler shares TARGET --file-write-check
```

`--file-write-check` independently creates/deletes recognizable randomized file
and directory names beginning with `shrawler_write_test_`. Cleanup results and
residual UNC paths are saved. Cleanup can fail or interruption can leave artifacts.
It never runs as a fallback from an inconclusive access-mask probe, and no profile
enables it implicitly. `--permission-check read --file-write-check` is rejected.

### Progress, Checkpoints, and Resume

Modern operating modes continuously append discoveries to `scan-events.jsonl` and publish an atomic `scan-state.json` checkpoint. This preserves useful work if a scan is interrupted. Interactive terminals use the low-noise progress view automatically; select it explicitly with:

```bash
shrawler spider TARGET --view progress -o ./results
```

Resume that scan with:

```bash
shrawler spider TARGET --resume ./results
```

Completed hosts and shares are skipped. Previously recorded file paths in an interrupted share are not processed twice.

### Persistent Configuration

Create and inspect `~/.config/shrawler/config.toml` with:

```bash
shrawler config init
shrawler config show
shrawler config path
shrawler config options
```

Precedence is: explicit command line, TOML configuration, Nemesis environment
variables, then mode/profile defaults. A configuration may contain:

```toml
profile = "quiet"
view = "progress"
format = "json"
output = "./results"

[nemesis]
url = "https://nemesis:7443/api"
auth = "username:password"
project = "assessment"
mode = "downloads"
upload_workers = 2
retries = 2
queue_size = 100

[snaffle]
rules = "./rules"
interest = 1
```

The configuration file is created with permissions `0600` because `nemesis.auth` may contain credentials. You can omit it and use `NEMESIS_AUTH` instead if you do not want credentials stored in the file.

### Usage Examples

#### **1. Basic Share Enumeration**

Scan a target using a username and password.

```bash
shrawler ludus.local/domainuser:password@192.168.1.100 --host 192.168.1.100
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

shrawler ludus.local/domainuser:password@192.168.1.1 --hosts-file hosts.txt
```

#### **4. Spidering a Share**

Enumerate and then spider all readable shares found.

```bash
shrawler ludus.local/domainuser:password@192.168.1.100 --host 192.168.1.100 --spider
```

#### **5. Spidering and Downloading Files**

Spider a specific share and download all `.config` and `.txt` files. All downloaded files will be saved in a `downloads/` directory.

```bash
shrawler ludus.local/domainuser:password@192.168.1.100 --host 192.168.1.100 --shares "backup" --spider --download-ext ".config,.txt"
```

Download *everything* found during a spidering session.

#### **6. Download Files by Name Pattern**

Download files containing specific keywords in their filenames.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --download-name "config,backup,password"
```

#### **7. Rate-Limited Scanning**

Add delays between requests to avoid overwhelming the target system.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --delay 0.5
```

#### **8. File Extension Analysis**

Count files by extension to understand share contents without downloading.

```bash
# Count default extensions
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --count-ext

# Count specific extensions
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --count-ext ".log,.txt,.config"
```

#### **9. String-Based File Analysis**

Count files containing specific keywords in their names.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --count-string "backup,config,password,secret"
```

#### **10. Unique File Discovery**

Identify files with unique modification times (useful for finding recently modified or anomalous files).

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --unique
```

#### **11. Smart Extension-Based Download**

Use default smart extension selection for downloading common interesting file types.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --download-ext default
```

#### **6. Download Files by Name Pattern**

Download files containing specific keywords in their filenames.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --download-name "config,backup,password"
```

#### **7. Rate-Limited Scanning**

Add delays between requests to avoid overwhelming the target system.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --delay 0.5
```

#### **8. File Extension Analysis**

Count files by extension to understand share contents without downloading.

```bash
# Count default extensions
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --count-ext

# Count specific extensions
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --count-ext ".log,.txt,.config"
```

#### **9. String-Based File Analysis**

Count files containing specific keywords in their names.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --count-string "backup,config,password,secret"
```

#### **10. Unique File Discovery**

Identify files with unique modification times (useful for finding recently modified or anomalous files).

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --unique
```

#### **11. Smart Extension-Based Download**

Use default smart extension selection for downloading common interesting file types.

```bash
shrawler ludus.local/domainuser:Password123@192.168.1.100 --host 192.168.1.100 --spider --download-ext default
```

#### **12. Nemesis Integration**

Configure Nemesis settings via environment variables and upload downloaded files automatically.
Nemesis uploads accept self-signed and otherwise untrusted TLS certificates automatically.

Nemesis is a delivery policy layered over local acquisition:

- `off` keeps all evidence local and makes no Nemesis requests.
- `matches` queues only files downloaded because of a Snaffler match.
- `downloads` queues every file Shrawler downloads, regardless of selection method.

Uploads run through a bounded background queue, decoupling normal SMB traversal
from Nemesis latency until the queue reaches its configured capacity. Shrawler
then applies backpressure, retries failures with exponential backoff, preserves
the local file on failure, and waits for the queue before writing final JSON/CSV
reports. Each download contains its final `nemesis.status`, attempt count,
response ID, and last error.

```bash
# Upload Snaffler-matched evidence only
shrawler user@10.2.10.10 --spider \
  --snaffler-rules-dir ./SnaffRules/DefaultRules \
  --nemesis-mode matches

# Upload every file selected by download criteria
shrawler user@10.2.10.10 --spider --download-ext default \
  --nemesis-mode downloads --nemesis-upload-workers 2

# Retry failed uploads later without rescanning SMB
shrawler report ./shrawler_results.json --retry-failed
```

```bash
Example .env file:

NEMESIS_URL=https://nemesis:7443/api
NEMESIS_AUTH=username:password
NEMESIS_PROJECT=assessment_2024
```

```
# Run with automatic Nemesis upload
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider \
  --download-ext default --nemesis-mode downloads
```

#### **13. Comprehensive Analysis with All Features**

Combine multiple analysis features for thorough reconnaissance.

```bash
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider \
  --download-ext default \
  --download-name "backup,config,password" \
  --count-ext \
  --count-string "secret,admin,key" \
  --unique \
  --nemesis-mode downloads \
  --delay 0.2
```

#### **14. CSV Output Format**

Output scan results in CSV format instead of JSON:

```bash
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider --format csv
```

This will generate three CSV files:
- `shrawler_shares.csv` - Share enumeration data
- `shrawler_files.csv` - All files discovered during spidering
- `shrawler_downloads.csv` - Files that were downloaded
- `shrawler_snaffler_matches.csv` - Snaffler rule matches (when Snaffler mode is enabled)

#### **15. Snaffler Rule Engine**

Run Shrawler with a directory of Snaffler TOML classifier rules:

```bash
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider \
  --snaffler-rules-dir ./rules/snaffler/default \
  --snaffler-interest-level 1 \
  --snaffler-max-size-to-grep 1048576 \
  --format csv
```

Snaffler v1 support matrix in Shrawler:

- Supported scopes: `ShareEnumeration`, `DirectoryEnumeration`, `FileEnumeration`, `ContentsEnumeration`, `PostMatch`
- Supported actions: `Discard`, `Snaffle`, `Relay`
- Supported word list types: `Exact`, `Contains`, `Regex`, `StartsWith`, `EndsWith`
- Supported locations: `ShareName`, `FilePath`, `FileName`, `FileExtension`, `FileContentAsString`, `FileLength`
- Deferred in v1 (warn+skip, or fail with `--snaffler-strict`): `CheckForKeys`, `EnterArchive`, `SendToNextScope`, `FileContentAsBytes`, `FileMD5`

**Example shrawler_shares.csv:**
```csv
host,share_name,comment,read_permission,write_permission,write_status,write_check,can_add_file,can_add_subdirectory,can_write_dac,can_write_owner,write_verified,cleanup_succeeded,unc_path,scan_timestamp_utc
192.168.1.100,backup,Backup files,True,True,allowed,access-mask,True,False,False,False,False,,\\192.168.1.100\backup,2025-08-16T14:30:15+00:00
```

**Example shrawler_files.csv:**
```csv
host,share_name,remote_path,unc_path,file_name,size_bytes,readable_size,mtime_utc,is_directory,can_read,can_write,scan_timestamp_utc
192.168.1.100,backup,/Documents/file.txt,\\192.168.1.100\backup\Documents\file.txt,file.txt,1024,1KB,2025-08-06T08:30:15+00:00,False,,,
```

**Example shrawler_downloads.csv:**
```csv
host,share_name,remote_path,unc_path,local_filename,local_path,size_bytes,actual_size_bytes,sha256,mtime_utc,timestamp_utc,nemesis_status,nemesis_attempts,nemesis_response_id,nemesis_last_error
192.168.1.100,backup,/Documents/creds.txt,\\192.168.1.100\backup\Documents\creds.txt,creds.txt,downloads/creds.txt,1024,1024,<sha256>,2025-08-06T08:30:15+00:00,2025-08-16T14:30:16+00:00,uploaded,1,file_12345,
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

The spider provides a table-based tree structure with file metadata, showing directories in blue and files in green. Status indicators show download success, Nemesis uploads, and unique files.

```
[+] 192.168.1.100\backup

     SIZE LAST MODIFIED      NAME
--------- --------------------- ----------------------------------------
        - 2025-08-06 08:30 └── Users
        - 2025-08-05 14:22 ├── administrator
        - 2025-08-05 14:22 │   └── Documents
    1.2KB 2025-08-06 08:30 │       ├── creds.txt [DOWNLOADED]
    4.5MB 2025-07-15 11:22 │       └── report.docx
        - 2025-02-10 16:05 └── public
     856B 2025-02-10 16:05     └── notes.txt [DOWNLOADED]
```


#### **Enhanced Spidering Output with New Features**

The enhanced spider output shows advanced status indicators for downloads, Nemesis uploads, and unique file analysis:

```
[+] 192.168.1.100\backup

     SIZE LAST MODIFIED      NAME
--------- --------------------- ----------------------------------------
        - 2025-08-16 14:30 └── Users
        - 2025-08-15 09:15 ├── administrator
        - 2025-08-15 09:15 │   └── Documents
    1.2KB 2025-08-06 08:30 │       ├── creds.txt [DOWNLOADED] [NEMESIS QUEUED]
    4.5MB 2025-07-15 11:22 │       └── report.docx
        - 2025-02-10 16:05 └── public
     856B 2025-02-10 16:05     └── notes.txt [DOWNLOADED] [UNIQUE]
```

#### **File Count Summary**

When using `--count-ext` or `--count-string`, a summary table is displayed:

```
[+] File Count Summary

+===========+========+
| File Type | Count  |
+===========+========+
| .txt      |     45 |
| .docx     |     23 |
| .pdf      |     18 |
| .config   |     12 |
| backup    |      8 |
| password  |      3 |
+===========+========+
| TOTAL     |    109 |
```

#### **Unique Files Analysis**

When using `--unique`, files with unique modification times are highlighted:

```
[+] Files with Unique Modification Times

[+] 2025-01-15 14:32:10 | /backup/admin/secret_config.txt
[+] 2025-01-20 09:15:45 | /data/recent_backup.zip  
[+] 2025-01-22 16:43:22 | /temp/anomalous_file.log
```

#### **Consolidated Scan Results**

All scan data including share enumeration and downloaded files are tracked in `shrawler_results.json`:

```json
{
  "192.168.1.100": {
    "scan_timestamp_utc": "2025-08-16T14:30:15.123456+00:00",
    "shares": {
      "backup": {
        "comment": "Backup files",
        "permissions": {
          "read": true,
          "write": true,
          "write_check": "access-mask",
          "write_status": "allowed",
          "write_rights": {
            "generic_write": false,
            "add_file": true,
            "add_subdirectory": false,
            "write_dac": false,
            "write_owner": false
          }
        },
        "unc_path": "\\\\192.168.1.100\\backup",
        "downloaded_files": [
          {
            "timestamp": "2025-08-16T10:30:15.123456",
            "timestamp_utc": "2025-08-16T14:30:15.123456+00:00",
            "host": "192.168.1.100",
            "share": "backup",
            "remote_path": "/Documents/creds.txt",
            "unc_path": "\\\\192.168.1.100\\backup\\Documents\\creds.txt",
            "local_filename": "192.168.1.100__backup__Documents_creds.txt",
            "size_bytes": 1024,
            "mtime_epoch": 1723456215.0,
            "mtime_utc": "2025-08-06T08:30:15+00:00",
            "origin_tool": "shrawler"
          }
        ]
      },
      "data": {
        "comment": "Company Data",
        "permissions": {"read": true, "write": false},
        "unc_path": "\\\\192.168.1.100\\data",
        "downloaded_files": []
      }
    }
  }
}
```

-----

## 🔧 Configuration

### Environment Variables

Shrawler supports configuration via a `.env` file in the working directory:

```
# Nemesis API Configuration
NEMESIS_URL=https://nemesis:7443/api
NEMESIS_AUTH=username:password  
NEMESIS_PROJECT=assessment_2024
```

### Default File Extensions

When using `--download-ext default` or `--count-ext` without arguments, Shrawler looks for these file types:

```
.txt, .csv, .xlsx, .pdf, .kbdx, .kbd, .docx, .doc, .xls, .ps1, .bat, .vbs, 
.tar, .zip, .sh, .json, .ini, .conf, .cnf, .config, .properties, .prop, 
.yaml, .yml, .pem, .key, .sql, .db
```

-----

## 📁 Output Files

| File | Description |
| :--- | :--- |
| `shrawler_results.json` | Consolidated scan results generated automatically. |
| `shrawler_shares.csv` | Share enumeration data in CSV format (generated with `--format csv`) |
| `shrawler_files.csv` | All discovered files during spidering in CSV format (generated with `--format csv`) |
| `shrawler_downloads.csv` | Downloaded files metadata in CSV format (generated with `--format csv`) |
| `shrawler_snaffler_matches.csv` | Snaffler match records (generated with `--format csv` in Snaffler mode) |
| `downloads/` | Directory containing all downloaded files with sanitized names |
| `.env` | Optional environment configuration file |

JSON output uses schema version 3. It includes `_schema` and `_summary` metadata,
per-host `status` and `error` fields, discovered-file records for each share, and
download records containing the actual size and SHA-256 digest. Version 3 retains
the aggregate `permissions.read` and `permissions.write` fields while adding
`write_status`, `write_check`, `write_rights`, and optional empirical `write_probe`
evidence. Version 2 resume state remains loadable; legacy shares keep their old
aggregate values without synthesized granular rights. Share CSV adds stable scalar
columns for granular rights, empirical verification, and cleanup outcomes.

### Exit Codes

- `0`: every requested host completed successfully
- `1`: one or more hosts failed, rejected authentication, or had port 445 closed
- `130`: the scan was interrupted by the user

-----

## 🚀 Advanced Features

### Table Format

Shrawler uses a structured table format for spider output with the following specifications:

- **SIZE Column**: Right-aligned, 9 characters wide (shows file sizes like "1.2KB", "4.5MB", "-" for directories)
- **LAST MODIFIED Column**: Left-aligned, 21 characters wide (format: "YYYY-MM-DD HH:MM")
- **NAME Column**: Variable width containing tree structure and status indicators
- **Tree Characters**: Uses Unicode box drawing (`├──`, `└──`, `│   `) for proper hierarchy display

### Status Indicators

Shrawler provides real-time visual feedback during operations:

- **[DOWNLOADED]** - File successfully downloaded to local system
- **[NEMESIS QUEUED]** - File was added to the background Nemesis upload queue
- **[DOWNLOAD FAILED]** - File download failed
- **[UNIQUE]** - File has unique modification time within its directory

### Cross-Platform Compatibility

Downloaded files are automatically sanitized for cross-platform compatibility:
- Illegal characters (`\:*?"<>|\0`) are replaced with underscores
- Multiple consecutive underscores are collapsed to single underscores
- Leading/trailing underscores are removed
- Empty filenames are replaced with "unnamed_file"

### Performance Features

- **Rate Limiting**: Use `--delay` to control request frequency
- **Depth Control**: Use `--max-depth` to limit recursion depth
- **Selective Downloads**: Combine extension and name-based filtering
- **Batch Analysis**: File counting and unique analysis run during traversal
- **Relay-Gated Content Inspection**: The default reads file content only when a metadata rule relays to a content rule
- **Read Reuse**: Content fetched for Snaffler is reused when that file is downloaded
- **Bounded Host Concurrency**: Independent hosts are scanned concurrently without parallelizing a single share tree

### Concurrent output

`--workers` controls concurrent hosts; shares on each host are always processed
sequentially. In `shares --view tree`, each completed host is printed as one
contiguous block. With multiple workers these blocks appear in host-completion
order, which may differ from hosts-file order.

Recursive `spider --view tree` and `snaffle --view tree` scans use one effective
host worker to prevent file-tree output from interleaving, and print a message
when a larger worker count was requested. Use `progress`, `matches`, or `summary`
to retain host concurrency for recursive scans.

```bash
# Four hosts scan concurrently; each share list prints as one host block.
shrawler shares TARGET --hosts-file hosts.txt --workers 4 --view tree

# Concurrent recursive scan with compact terminal rendering.
shrawler spider TARGET --hosts-file hosts.txt --workers 8 --view progress
```

| Profile | Workers | Permission checks | Terminal output | Content mode |
| :--- | ---: | :--- | :--- | :--- |
| `quiet` | 1 | Non-invasive read/write | Matches | Relayed |
| `balanced` | 4 | Non-invasive read/write | Matches | Relayed |
| `fast` | 8 | Non-invasive read/write | Summary | Relayed |

Use `--file-write-check` only when explicit create/delete verification is needed.
`--snaffler-content-mode all` restores exhaustive content-rule scanning
but can generate substantially more SMB traffic.

-----

## 🔍 Tips and Best Practices

1. **Start with enumeration only** before enabling spider mode to understand share structure
2. **Use `--permission-check read`** when write permissions aren't needed
3. **Combine analysis features** (`--count-ext`, `--unique`, `--count-string`) for comprehensive reconnaissance
4. **Set appropriate delays** (`--delay 0.2-0.5`) when scanning production systems
5. **Use environment variables** for Nemesis configuration to avoid exposing credentials in command line
6. **Monitor shrawler_results.json** for comprehensive scan results including share enumeration and download tracking
7. **Use `--download-ext default`** as a starting point, then refine with specific extensions

-----
