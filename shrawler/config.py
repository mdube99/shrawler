"""Persistent user configuration for the compact CLI."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULT_CONFIG = """# Shrawler defaults. Command-line options override these values.
# Run `shrawler config options` to see valid values and environment alternatives.
profile = "balanced"
policy = "audit"
view = "progress"
format = "console"

[nemesis]
url = ""                 # Example: "https://nemesis:7443/api"
auth = ""                # Example: "username:password"; or use NEMESIS_AUTH
project = ""             # Example: "assessment"
mode = "off"             # Options: "off", "matches", "downloads"
upload_workers = 2
retries = 2
queue_size = 100
"""

CONFIG_OPTIONS = """Shrawler configuration options

Top level:
  profile   quiet | balanced | fast
  policy    audit | collect | aggressive
  view      summary | progress | matches | tree
  format    console | json | csv | all
  output    results directory path
  shares    list of included share names
  exclude_shares  list of excluded share names

[nemesis]:
  url             API URL (example: https://nemesis:7443/api)
  auth            username:password (or use NEMESIS_AUTH)
  project         project name (example: assessment)
  mode            off | matches | downloads
  upload_workers  positive integer
  retries         zero or greater
  queue_size      positive integer

[snaffle]:
  rules     Snaffler rules directory
  interest  0 | 1 | 2 | 3

Command-line arguments override values from the configuration file.
"""


def config_path() -> Path:
    root = os.getenv("XDG_CONFIG_HOME")
    return Path(root).expanduser() / "shrawler" / "config.toml" if root else (
        Path.home() / ".config" / "shrawler" / "config.toml"
    )


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    selected = path or config_path()
    if not selected.exists():
        return {}
    with selected.open("rb") as handle:
        data = tomllib.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Configuration root must be a table: {selected}")
    return data


def compact_config_arguments(mode: str, data: Dict[str, Any]) -> List[str]:
    """Translate supported TOML defaults into compact CLI arguments."""
    arguments: List[str] = []
    for key in ("profile", "policy", "view", "format"):
        value = data.get(key)
        if value is not None:
            arguments.extend([f"--{key}", str(value)])
    output = data.get("output")
    if output:
        arguments.extend(["--output", str(output)])
    for share in data.get("shares", []):
        arguments.extend(["--share", str(share)])
    for share in data.get("exclude_shares", []):
        arguments.extend(["--exclude-share", str(share)])
    if mode in {"spider", "snaffle"}:
        for key in ("limits", "download"):
            value = data.get(key)
            if value is not None:
                arguments.extend([f"--{key}", str(value)])
        nemesis = data.get("nemesis", {})
        if isinstance(nemesis, dict):
            if nemesis.get("url"):
                arguments.extend(["--nemesis", str(nemesis["url"])])
            option_names = {
                "auth": "--nemesis-auth",
                "project": "--nemesis-project",
                "mode": "--nemesis-mode",
                "upload_workers": "--nemesis-upload-workers",
                "retries": "--nemesis-retries",
                "queue_size": "--nemesis-queue-size",
            }
            for key, option in option_names.items():
                if nemesis.get(key) is not None:
                    arguments.extend([option, str(nemesis[key])])
    if mode == "snaffle":
        snaffle = data.get("snaffle", {})
        if isinstance(snaffle, dict):
            if snaffle.get("rules"):
                arguments.extend(["--rules", str(snaffle["rules"])])
            if snaffle.get("interest") is not None:
                arguments.extend(["--interest", str(snaffle["interest"])])
    return arguments
