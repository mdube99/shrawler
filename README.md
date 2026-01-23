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
    git clone https://github.com/your-username/shrawler.git
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

-----

## 🚀 Usage

The basic syntax for running Shrawler is:

```bash
shrawler [[domain/]username[:password]@]<dc-ip> [options]
```

### Command-Line Arguments

| Argument | Description |
| :--- | :--- |
| **`target`** | **Required**. Specifies the target and credentials. Format: `[[domain/]username[:password]@]<dc-ip>` |
| `-v`, `--verbose` | Enable verbose output for debugging. |
| `--read-only` | Skips the write permission check, only checking for read access. |
| `--skip-share <shares>` | Comma-separated list of additional shares to skip (e.g., `data,backup`). |
| `--add-share <shares>` | Comma-separated list of shares to remove from the default skip list (e.g., `C$,ADMIN$`). |
| `--shares <shares>` | Only scan the shares specified in this comma-separated list. |
| `--hosts-file <file>` | Path to a file containing a list of target IPs (one per line). |
| `--host <ip>` | Specify a single target host IP. Overrides the IP in the main `target` argument. |
| **Authentication** | |
| `-H`, `--hashes <hash>` | Use NTLM hashes for authentication. Format: `LMHASH:NTHASH`. |
| `-no-pass` | Do not prompt for a password when one is not provided. |
| `-k` | Use Kerberos authentication (obtains TGT from ccache). |
| `-aesKey <key>` | Use an AES key for Kerberos Pass-the-Key. |
| **Spidering** | |
| `--spider` | Enable spidering of all readable shares. |
| `--download-ext [ext]` | Download files found during spidering. Use without args to download all, specify 'default' for common extensions, or provide comma-separated extensions (e.g., `.txt,.pdf,.config`). |
| `--download-name <names>` | Download files if their name contains any of these comma-separated substrings (e.g., `backup,config,password`). |
| `--max-depth <num>` | Set the maximum recursion depth for the spider (Default: 5). |
| `--delay <seconds>` | Seconds to wait between file/directory requests (Default: 0). |
| `--count-ext [ext]` | Count files by extension. Use without args for default extensions, or provide comma-separated extensions (e.g., `.txt,.log,.sh`). |
| `--count-string <strings>` | Count files containing specific strings in their names. Provide comma-separated strings (e.g., `backup,config,password`). |
| `--unique` | Identify and display files with unique modification times. |
| `--csv-output` | Output results in CSV format (generates shrawler_shares.csv, shrawler_files.csv, shrawler_downloads.csv). |
| **Nemesis Integration** | |
| `--nemesis-url <url>` | Nemesis API URL (e.g., `https://nemesis:7443/api`). Can also be set via `NEMESIS_URL` environment variable. |
| `--nemesis-auth <auth>` | Nemesis authentication in `username:password` format (e.g., `n:n`). Can also be set via `NEMESIS_AUTH` environment variable. |
| `--nemesis-project <project>` | Project name for Nemesis file submissions. Can also be set via `NEMESIS_PROJECT` environment variable. |
| `--nemesis-ingest` | Enable automatic upload of downloaded files to Nemesis API. |

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

```bash
Example .env file:

NEMESIS_URL=https://nemesis:7443/api
NEMESIS_AUTH=username:password
NEMESIS_PROJECT=assessment_2024
```

```
# Run with automatic Nemesis upload
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider --download-ext default --nemesis-ingest
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
  --nemesis-ingest \
  --delay 0.2
```

#### **14. CSV Output Format**

Output scan results in CSV format instead of JSON:

```bash
shrawler user:Password123@192.168.1.100 --host 192.168.1.100 --spider --csv-output
```

This will generate three CSV files:
- `shrawler_shares.csv` - Share enumeration data
- `shrawler_files.csv` - All files discovered during spidering
- `shrawler_downloads.csv` - Files that were downloaded

**Example shrawler_shares.csv:**
```csv
host,share_name,comment,read_permission,write_permission,unc_path,scan_timestamp_utc
192.168.1.100,backup,Backup files,True,True,\\192.168.1.100\backup,2025-08-16T14:30:15+00:00
192.168.1.100,data,Company Data,True,False,\\192.168.1.100\data,2025-08-16T14:30:15+00:00
```

**Example shrawler_files.csv:**
```csv
host,share_name,remote_path,unc_path,file_name,size_bytes,readable_size,mtime_utc,is_directory,can_read,can_write,scan_timestamp_utc
192.168.1.100,backup,/Documents/file.txt,\\192.168.1.100\backup\Documents\file.txt,file.txt,1024,1KB,2025-08-06T08:30:15+00:00,False,,,
```

**Example shrawler_downloads.csv:**
```csv
host,share_name,remote_path,unc_path,local_filename,size_bytes,mtime_utc,nemesis_success,nemesis_response_id,download_success,timestamp_utc
192.168.1.100,backup,/Documents/creds.txt,\\192.168.1.100\backup\Documents\creds.txt,192.168.1.100__backup__Documents_creds.txt,1024,2025-08-06T08:30:15+00:00,True,file_12345,True,2025-08-16T14:30:16+00:00
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
    1.2KB 2025-08-06 08:30 │       ├── creds.txt [DOWNLOADED] [UPLOADED TO NEMESIS]
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
        "permissions": {"read": true, "write": true},
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
| `shrawler_results.json` | Consolidated scan results with share enumeration and download metadata (default output) |
| `shrawler_shares.csv` | Share enumeration data in CSV format (generated with --csv-output) |
| `shrawler_files.csv` | All discovered files during spidering in CSV format (generated with --csv-output) |
| `shrawler_downloads.csv` | Downloaded files metadata in CSV format (generated with --csv-output) |
| `downloads/` | Directory containing all downloaded files with sanitized names |
| `.env` | Optional environment configuration file |

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
- **[UPLOADED TO NEMESIS]** - File successfully uploaded to Nemesis API  
- **[NEMESIS FAILED]** - Nemesis upload failed (file still downloaded locally)
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

-----

## 🔍 Tips and Best Practices

1. **Start with enumeration only** before enabling spider mode to understand share structure
2. **Use `--read-only`** for faster scanning when write permissions aren't needed
3. **Combine analysis features** (`--count-ext`, `--unique`, `--count-string`) for comprehensive reconnaissance
4. **Set appropriate delays** (`--delay 0.2-0.5`) when scanning production systems
5. **Use environment variables** for Nemesis configuration to avoid exposing credentials in command line
6. **Monitor shrawler_results.json** for comprehensive scan results including share enumeration and download tracking
7. **Use `--download-ext default`** as a starting point, then refine with specific extensions

-----
