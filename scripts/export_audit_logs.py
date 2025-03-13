#!/usr/bin/env python3

import os
import sys
import subprocess
import logging
from datetime import datetime, timedelta
import pandas as pd
import csv
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_cf_cli():
    """Check if CF CLI is installed and accessible"""
    try:
        subprocess.run(['cf', '--version'], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        logger.error('Cloud Foundry CLI is not installed or not accessible')
        raise RuntimeError('Cloud Foundry CLI is not installed or not accessible')
    except FileNotFoundError:
        logger.error('Cloud Foundry CLI (cf) command not found')
        raise RuntimeError('Cloud Foundry CLI (cf) command not found')

def login_to_cloudgov():
    """Login to cloud.gov using CF CLI"""
    username = os.environ.get('CF_USERNAME')
    password = os.environ.get('CF_PASSWORD')
    
    if not username or not password:
        logger.error('Cloud.gov credentials not found in environment variables')
        raise ValueError('Cloud.gov credentials not found in environment variables')
    
    try:
        # Login to cloud.gov
        logger.info('Attempting to login to cloud.gov...')
        login_cmd = ['cf', 'login', '-a', 'https://api.fr.cloud.gov', 
                    '-u', username, '-p', password, '--skip-ssl-validation']
        result = subprocess.run(login_cmd, capture_output=True, text=True, check=True)
        logger.info('Successfully logged into cloud.gov')
    except subprocess.CalledProcessError as e:
        logger.error(f'Failed to login to cloud.gov: {e.stderr}')
        raise RuntimeError(f'Failed to login to cloud.gov: {e.stderr}')

def get_audit_logs():
    """Fetch audit logs from cloud.gov"""
    today = datetime.now()
    last_week = (today - timedelta(days=8)).strftime('%Y%m%d')
    
    # Create exports directory if it doesn't exist
    exports_dir = Path('exports')
    exports_dir.mkdir(exist_ok=True)
    
    # Generate filename
    filename = exports_dir / f"Events_{today.strftime('%Y-%m-%d')}.csv"
    
    try:
        logger.info(f'Fetching audit logs from {last_week} to {today.strftime("%Y-%m-%d")}')
        # Get events from cloud.gov
        with open(filename, 'w', newline='') as f:
            # Write CSV header separator for Excel compatibility
            f.write('sep=,\n')
            
            # Get events from cloud.gov
            events_cmd = ['cf', 'get-events', '--from', last_week]
            result = subprocess.run(events_cmd, capture_output=True, text=True, check=True)
            
            # Write the output to file
            f.write(result.stdout)
        
        logger.info(f'Successfully exported audit logs to {filename}')
        return filename
    except subprocess.CalledProcessError as e:
        logger.error(f'Failed to fetch audit logs: {e.stderr}')
        raise RuntimeError(f'Failed to fetch audit logs: {e.stderr}')
    except IOError as e:
        logger.error(f'Failed to write audit logs to file: {e}')
        raise

def process_audit_logs(filename):
    """Process the audit logs for security checks"""
    try:
        logger.info(f'Processing audit logs from {filename}')
        # Read the CSV file
        df = pd.read_csv(filename, skiprows=1)  # Skip the sep=, line
        
        # Security checks
        # 1. Check for failed login attempts
        failed_logins = df[df['type'].str.contains('LoginFailure', na=False)]
        
        # 2. Check for unauthorized access attempts
        unauthorized_access = df[df['type'].str.contains('Unauthorized', na=False)]
        
        # 3. Check for suspicious activity patterns
        suspicious_activity = df[
            (df['type'].str.contains('Delete', na=False)) |
            (df['type'].str.contains('Update', na=False)) |
            (df['type'].str.contains('Create', na=False))
        ]
        
        # Create processed dataframe with findings
        processed_df = pd.DataFrame({
            'Date': today.strftime('%Y-%m-%d'),
            'Total Events': len(df),
            'Failed Logins': len(failed_logins),
            'Unauthorized Access': len(unauthorized_access),
            'Suspicious Activities': len(suspicious_activity)
        }, index=[0])
        
        # Save processed results
        processed_filename = str(filename).replace('.csv', '_processed.csv')
        processed_df.to_csv(processed_filename, index=False)
        
        logger.info(f'Successfully processed audit logs and saved to {processed_filename}')
        return processed_filename
    except Exception as e:
        logger.error(f'Failed to process audit logs: {e}')
        raise

def main():
    try:
        # Check CF CLI installation
        check_cf_cli()
        
        # Login to cloud.gov
        login_to_cloudgov()
        
        # Get audit logs
        filename = get_audit_logs()
        
        # Process the logs
        processed_file = process_audit_logs(filename)
        
        logger.info('Audit log export and processing completed successfully')
        
    except Exception as e:
        logger.error(f'Error in main execution: {str(e)}')
        sys.exit(1)

if __name__ == '__main__':
    main()
