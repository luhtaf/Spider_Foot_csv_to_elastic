class SpiderfootToElastic:
    def __init__(this):
        from elasticsearch import Elasticsearch
        import custom_library,os,re
        from datetime import datetime
        from glob import glob
        from pygrok import Grok
        this._grok=Grok
        this._datetime=datetime
        this._glob=glob
        this._os=os
        this._re=re
        
        this._custom_library=custom_library
        this._konfigurasi=custom_library.load_yaml('./fim_config.yaml')
        this._tipe_tidak_terpakai=this._konfigurasi['tipe_tidak_terpakai']
        this._modul_tidak_terpakai=this._konfigurasi['modul_tidak_terpakai']
        username=this._konfigurasi['username_elastic']
        passw=this._konfigurasi['password_elastic']
        this._tipe=this._konfigurasi['type']
        url_elastic=this._konfigurasi['url_elastic']
        this._es = Elasticsearch(url_elastic,basic_auth=(username, passw),verify_certs=False)
        this._cache={}
        this._target=[]
        this._init_target()
    def _init_target(this):
        target=this._konfigurasi['path_file']
        for i in target:
            if i.endswith("*"):
                this._get_wildcard_file(i)
            else:
                this._target.append(i)
    def _get_sektor_organisasi_from_string(this,input_string):
        pattern='%{DATA:case}_sektor_%{DATA:sektor}_organisasi_%{DATA:organisasi}_target_%{GREEDYDATA:target}'
        grok = this._grok(pattern)
        hasil=grok.match(input_string)
        case_value=hasil['case'].replace('_',' ').title()
        sector_value=hasil['sektor'].replace('_',' ').title()
        organisasi_value=hasil['organisasi'].replace('_',' ').title()
        target_value=hasil['target']
        return case_value,sector_value,organisasi_value,target_value
    def _get_wildcard_file(this,input_string):
        path = this._os.path.split(input_string)[0]  # Get only the path
        csv_filenames = this._glob(this._os.path.join(path, "*.csv"))  # Search for all .csv files
        filtered_csv_filenames = [filename for filename in csv_filenames if filename.startswith(input_string.replace("*",""))]  # Filter if needed
        if filtered_csv_filenames:
            for filename in filtered_csv_filenames:
                this._target.append(filename)
    def _update_cache(this,cve):
        if cve not in this._cache:
            index='list-cve-*'
            search_body = {
                "query": {
                    "term": {
                        "_id": cve
                    }
                }
            }
            cve_data=this._es.search(index=index, body=search_body)
            this._cache[cve]=cve_data['hits']['hits'][0]['_source']
        return this._cache[cve]
    def _read_dir(this):
        this._os.listdir()
    def _process_one_file(this,target):
        readed_target=open(target,"r", errors='ignore')
        lines=readed_target.readlines()
        for urutan in range(len(lines)):
            data={}
            line=lines[urutan]
            terpisah=line.replace("\n","").split(',')
            if "organisasi" in line:
                if urutan>0:
                    data['Scan Name']=terpisah[0]
                    data['Updated']=terpisah[1]
                    data['Type']=terpisah[2]
                    data['Module']=terpisah[3]
                    data['Source']=terpisah[4]
                    data_kosong = True if data['Source']== '"' else False
                    tidak_terpakai = True if data['Type'] in this._tipe_tidak_terpakai else False
                    tidak_terpakai = True if data['Module'] in this._modul_tidak_terpakai else False
                    if not tidak_terpakai and not data_kosong:
                        lewati=False
                        try:
                            this.FP=int(terpisah[5])                      
                        except:
                            this.FP=0
                        data['F/P']=this.FP
                        try:
                            data['Data']=terpisah[6].replace('"','')
                        except:
                            print(f"error saat parsing data ke {urutan}, datanya {str(terpisah)}")
                            lewati=True
                        if not lewati:
                            try:
                                data['Case'],data['Sektor'],data['Organisasi'],data['Target']=this._get_sektor_organisasi_from_string(data['Scan Name'])
                            except Exception as e:
                                print(e)
                                data['error']=f"Format Scan Name Salah, gagal mengambil data Case, Sektor, Organisasi, dan Target: {data['Scan Name']}"
                            updated_time = this._datetime.strptime(data['Updated'], "%Y-%m-%d %H:%M:%S").isoformat(sep="T") + f".{0:03d}+07:00"
                            data['@timestamp'] = updated_time
                            if 'CVE' in data['Data']:
                                data['Vuln']=data['Data']
                                try:
                                    this._update_cache(data['Data'])
                                    try:
                                        data['Score']=this._cache[data['Data']]['v3']['score']
                                    except:
                                        try:
                                            data['Score']=this._cache[data['Data']]['v2']['score']
                                        except:pass
                                    try:
                                        data['Severity']=this._cache[data['Data']]['v3']['sev']
                                    except:
                                        try:
                                            data['Severity']=this._cache[data['Data']]['v2']['sev']
                                        except:pass
                                except:
                                    data['Score']='N/A'
                                    data['Severity']='N/A'
                            timestamp=data['Updated'].split(" ")[0].replace("-",".")
                            if this._tipe=='production':
                                this._es.index(index=f"nasional_cve-{timestamp}",body=data)
    def start(this):
        for target in this._target:
            this._process_one_file(target)
            pass

es=SpiderfootToElastic()

es.start()