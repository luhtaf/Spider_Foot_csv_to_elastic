from elasticsearch import Elasticsearch
url_elastic='https://10.12.20.213:9200'
es = Elasticsearch(url_elastic,basic_auth=("admin", "admin123"),verify_certs=False)

index='list-cve-*'
id='CVE-1999-0695'
search_body = {
    "query": {
        "term": {
            "_id": id
        }
    }
}

cve_data=es.search(index=index, body=search_body)
print(cve_data['hits']['hits'][0])