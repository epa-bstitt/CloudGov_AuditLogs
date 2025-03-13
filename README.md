# Cloud.gov Audit Logs Exporter

This project automates the collection and processing of cloud.gov audit logs using GitHub Actions. It replaces the manual PowerShell process with an automated Python-based solution.

## Features

- Automatically runs every Monday at midnight
- Collects the last 7 days of cloud.gov audit logs
- Exports data to CSV format
- Stores results as GitHub artifacts

## Setup

1. Add the following secrets to your GitHub repository:
   - `CF_USERNAME`: Your cloud.gov username
   - `CF_PASSWORD`: Your cloud.gov password

## Directory Structure

```
.
├── .github/
│   └── workflows/
│       └── audit_logs.yml    # GitHub Actions workflow
├── scripts/
│   └── export_audit_logs.py  # Main Python script
└── exports/                  # Generated CSV files
```

## Manual Execution

You can manually trigger the workflow from the GitHub Actions tab in your repository.

## Output

The script generates two CSV files in the `exports` directory:
- `Events_YYYY-MM-DD.csv`: Raw audit log data
- `Events_YYYY-MM-DD_processed.csv`: Processed audit log data

These files are automatically uploaded as GitHub artifacts after each run.
