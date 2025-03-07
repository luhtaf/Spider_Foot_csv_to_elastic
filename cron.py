#!/usr/bin/env python3
import sqlite3
import yaml
import os
import sys
import time
from datetime import datetime
from elasticsearch import Elasticsearch
from pygrok import Grok

def load_config():
    """
    Load configuration from cron_config.yaml
    """
    try:
        with open('cron_config.yaml', 'r') as config_file:
            return yaml.safe_load(config_file)
    except FileNotFoundError:
        print("Error: Configuration file 'cron_config.yaml' not found. Please copy from 'cron_config.yaml.example'.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)

def get_last_timestamp(config):
    """
    Get the timestamp from timestamp_cron.txt
    If file doesn't exist, create it with value 0
    """
    timestamp_file = config.get('timestamp_file', 'timestamp_cron.txt')
    if not os.path.exists(timestamp_file):
        with open(timestamp_file, 'w') as f:
            f.write('0')
        return 0
    
    with open(timestamp_file, 'r') as f:
        timestamp = f.read().strip()
        try:
            return int(timestamp)
        except ValueError:
            print(f"Invalid timestamp in {timestamp_file}, using 0 instead")
            return 0

def update_timestamp(config):
    """
    Update timestamp_cron.txt with current timestamp
    """
    timestamp_file = config.get('timestamp_file', 'timestamp_cron.txt')
    current_timestamp = int(time.time())
    with open(timestamp_file, 'w') as f:
        f.write(str(current_timestamp))
    print(f"Updated timestamp to {current_timestamp} ({datetime.fromtimestamp(current_timestamp)})")

def read_sql_query(config):
    """
    Read SQL query from spiderfoot.sql file
    Exit if file not found
    """
    sql_query_file = config.get('sql_query_file', 'spiderfoot.sql')
    try:
        with open(sql_query_file, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: SQL query file '{sql_query_file}' not found.")
        print("Please create the SQL file with your query before running this program.")
        sys.exit(1)

def get_sektor_organisasi_from_string(input_string):
    """
    Extract case, sector, organization and target from scan name
    Similar to _get_sektor_organisasi_from_string in main.py
    """
    pattern = '%{DATA:case}_sektor_%{DATA:sektor}_organisasi_%{DATA:organisasi}_target_%{GREEDYDATA:target}'
    grok = Grok(pattern)
    hasil = grok.match(input_string)
    if hasil:
        case_value = hasil['case'].replace('_', ' ').title()
        sector_value = hasil['sektor'].replace('_', ' ').title()
        organisasi_value = hasil['organisasi'].replace('_', ' ').title()
        target_value = hasil['target']
        return case_value, sector_value, organisasi_value, target_value
    return None, None, None, None

def process_and_index_batch(es, config, batch_data):
    """
    Process and index a batch of vulnerability data to Elasticsearch
    """
    indexed_count = 0
    cache = {}
    tipe = config.get('type', 'development')
    
    for vuln in batch_data:
        data = {}
        # Map fields from SQLite to Elasticsearch format
        data['Scan Name'] = vuln.get('SCAN_NAME', '')
        data['Updated'] = datetime.fromtimestamp(vuln.get('generated')).strftime("%Y-%m-%d %H:%M:%S")
        data['Type'] = vuln.get('type', '')
        data['Module'] = vuln.get('module', '')
        data['Source'] = vuln.get('IP_Addresses', '')
        data['F/P'] = 0  # Default value as it's not in the SQLite data
        data['Data'] = vuln.get('data', '')
        
        # Skip if source is empty 
        if not data['Source'] or data['Source'] == '"':
            continue
        
        # Try to extract case, sector, organization and target from scan name
        try:
            data['Case'], data['Sektor'], data['Organisasi'], data['Target'] = get_sektor_organisasi_from_string(data['Scan Name'])
        except Exception as e:
            print(e)
            data['error'] = f"Format Scan Name Salah, gagal mengambil data Case, Sektor, Organisasi, dan Target: {data['Scan Name']}"
        
        # Format timestamp for Elasticsearch
        updated_time = datetime.strptime(data['Updated'], "%Y-%m-%d %H:%M:%S").isoformat(sep="T") + f".{0:03d}+07:00"
        data['@timestamp'] = updated_time
        
        # Process vulnerability data if it's a CVE
        vuln_data = vuln.get('Vulnerability', '')
        if 'CVE' in vuln_data:
            data['Vuln'] = vuln_data
            try:
                # Try to update CVE information from cache or Elasticsearch
                if vuln_data not in cache:
                    index = 'list-cve-*'
                    search_body = {
                        "query": {
                            "term": {
                                "_id": vuln_data
                            }
                        }
                    }
                    try:
                        cve_data = es.search(index=index, body=search_body)
                        cache[vuln_data] = cve_data['hits']['hits'][0]['_source']
                    except:
                        cache[vuln_data] = {}
                
                # Get score and severity from cache
                try:
                    data['Score'] = cache[vuln_data].get('v3', {}).get('score', 0.0)
                except:
                    try:
                        data['Score'] = cache[vuln_data].get('v2', {}).get('score', 0.0)
                    except:
                        data['Score'] = 0.0
                
                try:
                    data['Severity'] = cache[vuln_data].get('v3', {}).get('sev', 'N/A')
                except:
                    try:
                        data['Severity'] = cache[vuln_data].get('v2', {}).get('sev', 'N/A')
                    except:
                        data['Severity'] = 'N/A'
                
            except:
                data['Score'] = 0.0
                data['Severity'] = 'N/A'
        
        # Index to Elasticsearch
        timestamp = data['Updated'].split(" ")[0].replace("-", ".")
        index_name = config.get('elastic_index', 'nasional_cve')
        if tipe == 'production':
            try:
                es.index(index=f"{index_name}-{timestamp}", body=data)
                indexed_count += 1
                print(f"Indexed: {data['Scan Name']} - {vuln_data}")
            except Exception as e:
                print(f"Error indexing to Elasticsearch: {e}")
        else:
            print(f"Development mode - would index: {data['Scan Name']} - {vuln_data}")
            indexed_count += 1
    
    return indexed_count

def process_vulnerabilities_in_batches(db_path, last_timestamp, config, es, batch_size=100):
    """
    Process vulnerability data in batches to avoid memory issues
    """
    base_query = read_sql_query(config)
    offset = 0
    total_indexed = 0
    total_processed = 0
    
    # Remove existing LIMIT clause if any to allow for our own batching
    if "LIMIT" in base_query:
        base_query = base_query.split('LIMIT')[0].strip()
    
    while True:
        # Query for one batch
        paginated_query = f"{base_query} LIMIT {batch_size} OFFSET {offset}"
        
        try:
            # Connect to SQLite database
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Execute the query with the timestamp parameter
            cursor.execute(paginated_query, (last_timestamp,))
            
            # Fetch results for this batch
            results = cursor.fetchall()
            
            # No more results? We're done
            if not results:
                break
                
            # Convert to list of dictionaries
            batch_data = [dict(row) for row in results]
            total_processed += len(batch_data)
            
            print(f"Processing batch {offset//batch_size + 1}, records: {len(batch_data)}")
            
            # Process and index this batch
            batch_indexed = process_and_index_batch(es, config, batch_data)
            total_indexed += batch_indexed
            
            # Move to next batch
            offset += batch_size
            
            # Optional: small delay between batches to reduce load
            time.sleep(0.5)
            
        except sqlite3.Error as e:
            print(f"SQLite error: {e}")
            break
        finally:
            if conn:
                conn.close()
    
    print(f"Total records processed: {total_processed}")
    return total_indexed

def main():
    # Load configuration
    config = load_config()
    
    # Get database path directly from config
    db_path = config.get('database_path', 'spiderfoot.db')
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at '{db_path}'")
        sys.exit(1)
    
    # Initialize Elasticsearch connection
    username = config.get('username_elastic', '')
    passw = config.get('password_elastic', '')
    url_elastic = config.get('url_elastic', 'http://localhost:9200')
    
    es = Elasticsearch(url_elastic, basic_auth=(username, passw), verify_certs=False)
    
    # Get the last timestamp
    last_timestamp = get_last_timestamp(config)
    print(f"Last run timestamp: {last_timestamp} ({datetime.fromtimestamp(last_timestamp)})")
    
    # Process vulnerability data in batches
    batch_size = config.get('batch_size', 100)
    print(f"Using batch size: {batch_size}")
    
    # Process and index vulnerabilities in batches
    total_indexed = process_vulnerabilities_in_batches(db_path, last_timestamp, config, es, batch_size)
    
    if total_indexed > 0:
        print(f"Successfully indexed {total_indexed} documents to Elasticsearch")
        
        # Update timestamp with current time to mark completion
        update_timestamp(config)
    else:
        print("No new records found, timestamp not updated")

if __name__ == "__main__":
    main()
