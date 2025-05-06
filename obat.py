from elasticsearch import Elasticsearch
es=Elasticsearch('https://admin:admin123@10.12.20.213:9200', verify_certs=False)
global cache
cache={}
import re
import json

def extract_cve(data):
    """
    Extract CVE identifiers from data using regex
    
    Args:
        data: String or dictionary containing CVE information
        
    Returns:
        list: List of CVE identifiers found
    """
    # Convert dict to string if needed
    if isinstance(data, dict):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    
    # Pattern for CVE identifiers: CVE followed by year (4 digits) and ID (1-7 digits)
    cve_pattern = r'CVE-\d{4}-\d{1,7}'
    
    # Find all matches
    cve_matches = re.findall(cve_pattern, data_str)
    
    return cve_matches[0]
def update_cache(cve, cache):
        if cve not in cache:
            index='list-cve-*'
            search_body = {
                "query": {
                    "term": {
                        "_id": cve
                    }
                }
            }
            cve_data=es.search(index=index, body=search_body)
            cache[cve]=cve_data['hits']['hits'][0]['_source']
        return cache
def lookup(masukan, cache):
    try:
        data={}
        data['Vuln']=extract_cve(masukan['_source']['Vuln'])
        cache=update_cache(data['Vuln'], cache)
        try:
            data['Score']=cache[data['Vuln']]['v3']['score']
        except:
            try:
                data['Score']=cache[data['Vuln']]['v2']['score']
            except:pass
        try:
            data['Severity']=cache[data['Vuln']]['v3']['sev']
        except:
            try:
                data['Severity']=cache[data['Vuln']]['v2']['sev']
            except:pass
    except:
        data['Score']=0.0
        data['Severity']='N/A'
    return data, cache

ind='nasional_cve*'
search_body = {
    "term": {
        "Score": 0
    }
}

count=es.count(index=ind, query=search_body)['count']
print(count)
size=100
dari=0  
urutan=1
while dari<count:
    print(f"Mulai urutan ke-{urutan}")
    print(f"data proses {dari}/{count}")
    cve_data=es.search(index=ind, query=search_body, size=size, from_=dari)
    for cve in cve_data['hits']['hits']:
        print(cve)
        new_cve,cache=lookup(cve, cache)
        print(new_cve)
        body={"doc":new_cve}
        es.update(index=cve['_index'], id=cve['_id'], body=body)
    urutan=urutan+1
    dari=dari+size