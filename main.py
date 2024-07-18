class SpiderfootToElastic:
    def __init__(this):
        from elasticsearch import Elasticsearch
        import custom_library,os,re
        from datetime import datetime
        from glob import glob
        this._datetime=datetime
        this._glob=glob
        this._os=os
        this._re=re
        this._custom_library=custom_library
        this._fim_config=custom_library.load_yaml('./fim_config.yaml')
        username=this._fim_config['username_elastic']
        passw=this._fim_config['password_elastic']
        url_elastic=this._fim_config['url_elastic']
        this._es = Elasticsearch(url_elastic,basic_auth=(username, passw),verify_certs=False)
        this._es2 = Elasticsearch('https://10.12.20.204:9200',basic_auth=("th", "threathunt"),verify_certs=False)
        this._cache={}
        this._target=[]
        this._init_target()
    def _init_target(this):
        target=this._fim_config['path_file']
        for i in target:
            if i.endswith("*"):
                this._get_wildcard_file(i)
            else:
                this._target.append(i)
    def _get_sektor_organisasi_from_string(this,input_string):
        case_value=input_string.split("_sektor")[0].replace("_"," ").title()
        # Extract the "sektor" value
        sector_pattern = r"sektor_(.*)"
        sector_match = this._re.search(sector_pattern, input_string.split("_organisasi")[0])
        if sector_match:
            sector_value = sector_match.group(1).replace("_"," ").title()  # Capitalize the first letter

        organisasi_pattern = r"organisasi_(.*)"
        organisasi_match = this._re.search(organisasi_pattern, input_string.split("_target")[0])
        if organisasi_match:
            organisasi_value = organisasi_match.group(1).replace("_"," ").title()
        
        target_pattern = r"target_(.*)"
        target_match = this._re.search(target_pattern, input_string)
        if target_match:
            target_value = target_match.group(1).replace("_"," ").title()
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
            tahun=this._get_tahun(cve)
            index=f'list-cve-{tahun}'
            cve_data=this._es2.get(index=index, id=cve)
            this._cache[cve]=cve_data['_source']
        return this._cache[cve]
    def _get_tahun(this,cve):
        return cve.split('-')[1]
    def _read_dir(this):
        this._os.listdir()
    def _process_one_file(this,target):
        readed_target=open(target,"r")
        # scan_name=target.split("\\")
        # scan_name=scan_name[len(scan_name)-1].replace(".csv","")
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
                    try:
                        this.FP=int(terpisah[5])                      
                    except:
                        this.FP=0
                    data['F/P']=this.FP
                    data['Data']=terpisah[6].replace('"','')
                    data['Case'],data['Sektor'],data['Organisasi'],data['Target']=this._get_sektor_organisasi_from_string(data['Scan Name'])
                    updated_time = this._datetime.strptime(data['Updated'], "%Y-%m-%d %H:%M:%S").isoformat(sep="T") + f".{0:03d}+07:00"
                    data['@timestamp'] = updated_time
                    if 'CVE' in data['Data']:
                        data['Vuln']=data['Data']
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
                    timestamp=data['Updated'].split(" ")[0].replace("-",".")
                    this._es.index(index=f"nasional_cve-{timestamp}",body=data)
    def start(this):
        for target in this._target:
            this._process_one_file(target)
            pass

es=SpiderfootToElastic()
es.start()