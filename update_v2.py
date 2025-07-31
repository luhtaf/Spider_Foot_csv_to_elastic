from datetime import datetime
from elasticsearch import Elasticsearch
import time, sys, yaml
import pandas as pd

# 1. Baca CSV


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

config = load_config()
username = config.get('username_elastic', '')
passw = config.get('password_elastic', '')
url_elastic = config.get('url_elastic', 'http://localhost:9200')
index_name = config.get('elastic_index', 'nasional_cve')

csv_source = config.get('csv_source', 'cve_data.csv')
df = pd.read_csv("pemda_pempus.csv", sep=';')
version = int(config.get('version', 1))

es = Elasticsearch(url_elastic, basic_auth=(username, passw), verify_certs=False)


while True:
    query = {
        "query": {
            "bool": {
                "should": [
                    {"range": {"versi": {"lt": version}}},
                    {"bool": {"must_not": {"exists": {"field": "versi"}}}}
                ]
            }
        }
    }

    resp = es.search(index=f"{index_name}*", body=query, size=1000, from_=0)
    hits = resp['hits']['hits']
    if not hits:
        print("✅ Tidak ada data lagi. Berhenti.")
        break
    for i in hits:
        data={"version": version}
        try:
            result = df.loc[df['Nama'] == i['_source']['Organisasi'], 'Subsektor'].values[0]
            data['Subsektor'] = result
        except Exception as e:
            print(e)
            data['Subsektor'] = ""
        index=i['_index']
        _id=i['_id']
        es.update(index=index, id=_id, body={"doc": data})

    
    time.sleep(1)