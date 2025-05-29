# ASA2YAML

A tool to convert Cisco ASA firewall configuration files to structured YAML, with robust error handling, logging, and summary reporting.  
Intended as the first step in migrating ASA configs to other firewall platforms (e.g., AhnLab TrusGuard).

## Features

- Parses ASA network/service objects, object-groups, and access-lists
- Outputs each object type to separate YAML files
- Centralized logging with rotating log files (`log/asa2yaml.log`)
- Prints a summary of parsed/skipped/failed entries to stdout
- Exits with non-zero code if critical errors are encountered

## Usage

1. Place your ASA config file in the `config/` directory (e.g., `config/asa_config.txt`).
2. Run the main script `python asa_to_yaml.py` in your terminal.

3. YAML files will be generated in the `yaml/` directory.
4. Check the summary in the terminal and details in `log/asa2yaml.log`.

## Requirements

- Python 3.7+
- PyYAML (`pip install pyyaml`)

## Notes

- Access-list remarks are ignored during parsing.
- IP ranges are stored as strings in the format `startip-endip`.
- Review the log file for any skipped or malformed entries.

---