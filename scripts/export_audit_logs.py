#!/usr/bin/env python3

import os
import subprocess
from datetime import datetime, timedelta
import pandas as pd
import csv

def login_to_cloudgov():
    """Login to cloud.gov using CF CLI"""
    username = os.environ.get('CF_USERNAME')
    password = os.environ.get('CF_PASSWORD')
    
    if not username or not password:
        raise ValueError("Cloud.gov credentials not found in environment variables")
    
    # Login to cloud.gov
    login_cmd = f'cf login -a https://api.fr.cloud.gov -u {username} -p {password}'
    subprocess.run(login_cmd, shell=True, check=True)

def get_audit_logs():
    """Fetch audit logs from cloud.gov"""
    today = datetime.now()
    last_week = (today - timedelta(days=8)).strftime("%Y%m%d")
    
    # Create exports directory if it doesn't exist
    os.makedirs('exports', exist_ok=True)
    
    # Generate filename
    filename = f"exports/Events_{today.strftime('%Y-%m-%d')}.csv"
    
    # Get events from cloud.gov
    with open(filename, 'w', newline='') as f:
        # Write CSV header separator for Excel compatibility
        f.write("sep=,\n")
        
        # Get events from cloud.gov
        events_cmd = f'cf get-events --from {last_week}'
        result = subprocess.run(events_cmd, shell=True, capture_output=True, text=True, check=True)
        
        # Write the output to file
        f.write(result.stdout)
    
    return filename

def process_audit_logs(filename):
    """Process the audit logs for security checks"""
    # Read the CSV file
    df = pd.read_csv(filename, skiprows=1)  # Skip the sep=, line
    
    # Add your security checks here
    # Example: Filter for specific event types, unauthorized access attempts, etc.
    
    # Save processed results
    processed_filename = filename.replace('.csv', '_processed.csv')
    df.to_csv(processed_filename, index=False)
    
    return processed_filename

def main():
    try:
        # Login to cloud.gov
        login_to_cloudgov()
        
        # Get audit logs
        filename = get_audit_logs()
        print(f"Audit logs exported to: {filename}")
        
        # Process the logs
        processed_file = process_audit_logs(filename)
        print(f"Processed audit logs saved to: {processed_file}")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        raise

if __name__ == "__main__":
    main()
