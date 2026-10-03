"""Persistent user configuration for the compact CLI."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULT_CONFIG = """# Shrawler defaults. Command-line options override these values.
# Run `shrawler config options` to see valid values and environment alternatives.
profile = "balanced"
view = "progress"                 # recursive spider/snaffle rendering (shares always lists)
format = "console"
include_all_shares = false

[nemesis]
url = ""                 # Example: "https://nemesis:7443/api"
auth = ""                # Example: "username:password"; or use NEMESIS_AUTH
project = ""             # Example: "assessment"
mode = "off"             # Options: "off", "matches", "downloads"
upload_workers = 2
retries = 2
queue_size = 100

[jev]
# Model-assisted full-coverage assessment. See `shrawler triage jev check`.
enabled = false
endpoint = "https://api.typesafe.ai/v1/systemone"  # default Jev route; hosted
#   https://jevtypesafeai.com/api/v1/decide and a team LiteLLM proxy also work
api_key_env = "JEV_API_KEY"      # environment variable holding the bearer key
model = "jev-latest"             # or a pinned version such as jev-1.13.0
deployment_revision = ""         # operator-pinned immutable revision; defaults to model
objective = ""                   # blank uses the built-in objective text
max_input_tokens = 60000         # state + all questions, under the 64k ceiling
max_state_longest_question_tokens = 30000  # state + longest question, under 32k
max_questions_per_request = 200  # verify the real cap with `check`
request_timeout_seconds = 120
retries = 2
workers = 4
rate_limit_per_minute = 0        # 0 = unset
time_budget_seconds = 0          # 0 = unlimited; a budget pauses, never samples
"""

CONFIG_OPTIONS = """Shrawler configuration options

Top level:
  profile   quiet | balanced | fast (default: balanced)
  view      summary | progress | matches | tree (spider/snaffle only)
  format    console | csv (default: console; JSON is always saved)
  output    results directory path
  shares    list of included share names
  exclude_shares  list of excluded share names
  include_all_shares  include normally skipped administrative shares (default: false)

[nemesis]:
  url             API URL (example: https://nemesis:7443/api)
  auth            username:password (or use NEMESIS_AUTH)
  project         project name (example: assessment)
  mode            off | matches | downloads
  upload_workers  positive integer
  retries         zero or greater
  queue_size      positive integer

[snaffle]:
  rules     Snaffler rules directory (required by snaffle mode)
  interest  0 | 1 | 2 | 3 (default: 0)

[jev]:
  enabled                          boolean (default: false)
  endpoint                         decision endpoint URL
  api_key_env                      environment variable holding the bearer key
  model                            served model alias (default: jev-latest)
  deployment_revision              immutable revision; defaults to model
  objective                        assessment objective text (blank = built-in)
  max_input_tokens                 state + all questions budget (default: 60000)
  max_state_longest_question_tokens  state + longest question budget (default: 30000)
  max_questions_per_request        candidate cap per request (default: 200)
  request_timeout_seconds          per-request timeout (default: 120)
  retries                          retries before a candidate is failed (default: 2)
  workers                          reserved for future bounded concurrency (default: 4)
  rate_limit_per_minute            request cap per minute; 0 = unset
  time_budget_seconds              run budget; 0 = unlimited (pauses, never samples)

Command-line arguments override values from the configuration file.
Run `shrawler COMMAND --help` for scan and integration controls.
"""


def config_path() -> Path:
    root = os.getenv("XDG_CONFIG_HOME")
    return (
        Path(root).expanduser() / "shrawler" / "config.toml"
        if root
        else (Path.home() / ".config" / "shrawler" / "config.toml")
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
