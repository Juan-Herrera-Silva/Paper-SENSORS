import json
import os
import pandas as pd
import uuid
import numpy as np
from functools import reduce
from glob import glob

df_dataset = pd.DataFrame()

def list_tofeature(values, name):
    global df_dataset
    df_dataset = pd.concat([df_dataset,pd.DataFrame(pd.Series(values),columns=[name])],axis=1)

def empty_category(list):
    for x in list:
        list_tofeature([],x)

def procmemory(features, data):
    available = ['file','urls','proc_pid']
    if not 'procmemory' in data:
        empty_category(list(set(available).intersection(features)))
        return
    category = data['procmemory']
    selected = list(set(available).intersection(features))
    for x in selected:
        procmemory_feature = []
        for c in category:
            if x in c:
                procmemory_feature.append(c[x])
            elif x=='proc_pid' and 'pid' in c:
                procmemory_feature.append(c['pid'])
        if procmemory_feature:
            if x == 'proc_pid':
                list_tofeature(procmemory_feature,'proc_pid')
            elif x == 'urls':
                list_tofeature(reduce(lambda x,y: x+y,procmemory_feature),x)
            else:
                list_tofeature(procmemory_feature,x)
        else:
            list_tofeature([],x)

def procmemory_extracted(features, data):
    available = ['name','type','ext_urls','path']
    if not 'procmemory' in data:
        empty_category(list(set(available).intersection(features)))
        return
    procmemory = data['procmemory']
    selected = list(set(available).intersection(features))
    for x in selected:
        extracted_feature = []
        for item in procmemory:
            if 'extracted' in item:
                extracted_general = item['extracted']
                if extracted_general:
                    for extracted in extracted_general:
                        if x in extracted:
                            extracted_feature.append(extracted[x])
                        elif x=='ext_urls' and 'urls' in extracted:
                            extracted_feature.append(extracted['urls'])
        if extracted_feature:
            if x=='ext_urls':
                list_tofeature(reduce(lambda x,y: x+y,extracted_feature),x)
            else:
                list_tofeature(extracted_feature,x)
        else:
            list_tofeature([],x)


def behavior_processes(features, data):
    available = ['pid','process_name','ppid'] 
    if not 'behavior' in data:
        empty_category(['proc'])
        return
    else:
        if not 'processes' in data['behavior']:
            empty_category(['proc'])
            return
    category = data['behavior']['processes']
    beh_process_groups = []
    selected = list(set(available).intersection(features))
    for item in category:
        beh_process_group = {}
        for esc in selected:
            if esc in item:
                    beh_process_group[esc] = item[esc]
            else:
                    beh_process_group[esc] = ''
        beh_process_groups.append(beh_process_group)
    list_tofeature(beh_process_groups,'proc')

def behavior_processes_single_feature(features, data):
    available = ['process_path','beh_command_line'] 
    if not 'behavior' in data:
        empty_category(list(set(available).intersection(features)))
        return
    else:
        if not 'processes' in data['behavior']:
            empty_category(list(set(available).intersection(features)))
            return
    category = data['behavior']['processes']
    selected = list(set(available).intersection(features))
    for x in selected:
        process_feature = []
        for c in category:
            if x in c:
                process_feature.append(c[x])
            elif x=='beh_command_line' and 'command_line' in c:
                process_feature.append(c['command_line'])
        if process_feature:
            list_tofeature(process_feature,x)
        else:
            list_tofeature([],x)

def behavior_processes_set(features, data):
    available = ['call_category','status','call_stacktrace','call_arguments','tid'] 
    if not 'behavior' in data:
        empty_category(list(set(available).intersection(features)))
        return
    else:
        if not 'processes' in data['behavior']:
            empty_category(list(set(available).intersection(features)))
            return
    processes = data['behavior']['processes']
    selected = list(set(available).intersection(features))
    for feature in selected:
        process_feature = []
        for process in processes:
            if 'calls' in process:
                calls = process['calls']
                for call in calls:
                    if feature in call:
                        process_feature.append(call[feature])
                    elif feature=='call_category' and 'category' in  call:
                        process_feature.append(call['category'])
                    elif feature=='call_stacktrace' and 'stacktrace' in  call:
                        process_feature.append(call['stacktrace'])
                    elif feature=='call_arguments' and 'arguments' in  call:
                        process_feature.append(call['arguments'])
        if process_feature:
            if feature == 'call_stacktrace':
                list_tofeature(reduce(lambda x,y: x+y,process_feature),feature)
            else:
                list_tofeature(process_feature,feature)
        else:
            list_tofeature([],feature)
    
def behavior_processtree(features, data): 
    available = ['tree_process_name','tree_command_line','children'] 
    if not 'behavior' in data:
        empty_category(list(set(available).intersection(features)))
        return
    else:
        if not 'processtree' in data['behavior']:
            empty_category(list(set(available).intersection(features)))
            return
    processes = data['behavior']['processtree']
    selected = list(set(available).intersection(features))
    for feature in selected:
        process_feature = []
        for tree in processes:
            if feature in tree:
                process_feature.append(tree[feature])
            elif feature=='tree_process_name' and 'process_name' in  tree:
                process_feature.append(tree['process_name'])
            elif feature=='tree_command_line' and 'command_line' in  tree:
                process_feature.append(tree['command_line'])
        if process_feature:
            if feature == 'children':
                list_tofeature(reduce(lambda x,y: x+y,process_feature),feature)
            else:
                list_tofeature(process_feature,feature)
        else:
            list_tofeature([],feature)


def behavior_summary(features, data):
    available = ['file_created','dll_loaded','regkey_opened','command_line','regkey_read','regkey_written', 'wmi_query', 'file_read','directory_enumerated']
    if not 'behavior' in data:
        empty_category(list(set(available).intersection(features)))
        return
    else:
        if not 'summary' in data['behavior']:
            empty_category(list(set(available).intersection(features)))
            return
    selected = list(set(available).intersection(features))
    category = data['behavior']['summary']
    for x in selected:
        if x in category:
            clean_category = [s.replace(';', '') for s in category[x]]
            list_tofeature(clean_category,x)
        else:
            list_tofeature([],x)

def behavior_apistats(features, data):
    available = ['apistats']
    if not 'behavior' in data:
        empty_category(list(set(available).intersection(features)))
        return
    behavior = data['behavior']
    if 'apistats' in behavior:
        apistats = behavior['apistats']
        keys = apistats.keys()
        main_list = list()
        for key in keys:
            main_list.append(list(apistats[key].items()))
        if main_list:
            reduced = reduce(lambda x,y: x+y,main_list)    
            list_tofeature(reduced,'apistats')
        else:
            empty_category(list(set(available).intersection(features)))
            return
    else:
        empty_category(list(set(available).intersection(features)))
        return

def network(features, data):
    available = ['udp', 'tcp', 'hosts', 'request', 'domains','dns_servers','dead_hosts','mitm']
    if not 'network' in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = list(set(available).intersection(features))
    for x in selected:
        category = data['network']
        if x in category:
            list_tofeature(category[x],x)
        elif x=='request':
            if 'dns' in category:
                network_dns_requests = []
                for item in data['network']['dns']:
                    network_dns_requests.append(item['request'])
                list_tofeature(network_dns_requests,'requests')
            else:
                list_tofeature([],x)	
        else:
            list_tofeature([],x)

def extracted(features, data):
    available = ['info','program']
    if not 'extracted' in data:
        empty_category(list(set(available).intersection(features)))
        return
    extracted = data['extracted']
    selected =  set(available).intersection(features)
    for x in selected:
        extracted_feature = []
        for y in extracted:
            if x in y:
                extracted_feature.append(y[x])
        if extracted_feature:
            list_tofeature(extracted_feature,x)
        else:
            list_tofeature([],x)

def virustotal(features, data):
    available = ['positives']
    if not 'virustotal' in data:
        empty_category(available)
        return
    virustotal = data['virustotal']
    if not 'summary' in virustotal:
        empty_category(available)
        return
    summary = virustotal['summary']
    if not 'positives' in summary:
        empty_category(available)
        return
    else:
        list_tofeature([summary['positives']],'positives')

def signatures(features, data):
    available = ['families','description','sign_name'] 
    if not 'signatures' in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = set(available).intersection(features)
    signatures = data['signatures']
    for x in selected:
        signature_feature = []
        for y in signatures:
            if x in y:
                signature_feature.append(y[x])
            elif x=='sign_name' and 'name' in y:
                signature_feature.append(y['name'])
        if signature_feature:
            if x=='families':
                list_tofeature(reduce(lambda x,y: x+y,signature_feature),x)
            else:
                list_tofeature(signature_feature,x)
        else:
            list_tofeature([],x)


def signatures_call(features, data):
    available = ['category','sign_stacktrace', 'api','arguments'] 
    if not 'signatures' in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = set(available).intersection(features)
    signatures = data['signatures']
    for x in selected:
        signature_feature = []
        for item in signatures:
            if 'marks' in item:
                marks_general = item['marks']
                if marks_general:
                    for mark in marks_general:
                        if 'call' in mark:
                            if x in mark['call']:
                                signature_feature.append(mark['call'][x])
                            elif x=='sign_stacktrace' and 'stacktrace' in mark['call']:
                                signature_feature.append(mark['call']['stacktrace'])
        if signature_feature:
            if x=='sign_stacktrace':
                list_tofeature(reduce(lambda x,y: x+y,signature_feature),x)
            else:
                list_tofeature(signature_feature,x)
        else:
            list_tofeature([],x)

def static_direct(features, data):
    available = ['imported_dll_count']
    if not 'static' in data:
        empty_category(list(set(available).intersection(features)))
        return
    static = data['static']
    for x in available:
        if x in static:
            list_tofeature([static[x]],x)
        else:
            list_tofeature([],x)

def static_direct_set(features, data):
    sets = {'pe_imports':['dll'],
            'pe_resources':['pe_res_name','filetype'], #pe_res_name = pe_resources -> name
            'pe_sections':['pe_sec_name','entropy']} #pe_sec_name = pe_sections -> name
    if not 'static' in data:
        selected = []
        for att in sets.values():
            selected = [ x for x in att if x in features] + selected
        empty_category(selected)
        return
    static = data['static']
    selected_keys = set(list(sets.keys())).intersection(features)
    for key in selected_keys:
        selected = [ x for x in sets[key] if x in features]
        if key in static:
            for feature in selected:
                static_feature = []
                for item in static[key]:
                    if feature in item:
                        static_feature.append(item[feature])
                    elif feature=='pe_res_name' and 'name' in item and key=='pe_resources':
                        static_feature.append(item['name'])
                    elif feature=='pe_sec_name' and 'name' in item and key=='pe_sections':
                        static_feature.append(item['name'])
                if static_feature:
                    list_tofeature(static_feature,feature)
                else:
                    list_tofeature([],feature)
        else:
            empty_category(selected)

def debug(features, data):
    available = ['action','errors','log']
    if not 'debug' in data:
        empty_category(list(set(available).intersection(features)))
        return
    selected = list(set(available).intersection(features))
    debug = data['debug']
    for x in selected:
        if x in debug:
            list_tofeature(debug[x],x)
        else:
            list_tofeature([],x)

def process(PATH, features, isMemory, isAF):
    separator = "/" if os.name=="posix" else "\\"
    import time
    start = time.time()
    id = str(uuid.uuid4())
    SAVE_PATH = '.'+separator+id+'.csv'
    result = [y for x in os.walk(PATH) for y in glob(os.path.join(x[0], '*.json'))]
    dataframes = list()
    for report in result:
        with open(report) as f:
            data  = json.load(f)
        print("Processing: " + str(report))
        global df_dataset
        df_dataset = pd.DataFrame()
        if 'procmemory' in features:
            procmemory(features,data)
            if 'procm_extracted' in features:
                procmemory_extracted(features,data)
        if 'extracted' in features:
            extracted(features,data)
        if 'virustotal' in features:
            virustotal(features,data)
        if 'signatures' in features:
            signatures(features,data)
            if 'call' in features:
                signatures_call(features,data)
        if 'static' in features:
            if 'imported_dll_count' in features:
                static_direct(features,data)
            if 'pe_imports' or 'pe_resources' or 'pe_sections' in features:
                static_direct_set(features,data)
        if 'network' in features:
            network(features,data)
        if 'behavior' in features:
            if 'processes' in features:
                if 'pid' or 'process_name' or 'ppid' in features:
                    behavior_processes(features,data)
                behavior_processes_single_feature(features,data)
                #if 'calls' in features:
                #    behavior_processes_set(features, data) #This generates too much data (approx. 5 times the original size of a file)
                if 'processtree' in features:
                    behavior_processtree(features, data)
            if 'summary' in features:
                behavior_summary(features,data)
            if 'apistats' in features:
                behavior_apistats(features, data)
        if 'debug' in features:
            debug(features,data)
        df_dataset.fillna(np.nan,inplace=True)
        row_df: pd.DataFrame = pd.DataFrame([df_dataset.count()])
        if isAF:
            #Family
            df_dataset.insert(0,'family','')
            if 'Goodware' in report:
                df_dataset['family'] = report.split('Analisis'+separator)[1][0]
            else:
                df_dataset['family'] = report.split('Ransomware'+separator)[1][0]
            #Artifact
            df_dataset.insert(0,'artifact','')
            df_dataset['artifact'] = report.split(separator+'Experimento')[0].split(separator)[-1]    
            row_df.insert(0,"family",df_dataset.iloc[0]['family'])
            row_df.insert(0,"artifact",df_dataset.iloc[0]['artifact'])    
        if isMemory:
            dataframes.append(row_df) #This may lead to excessive data in memory at runtime
        else:
            with open(SAVE_PATH, 'a') as f: #This leads to 'n' write operations
                row_df.to_csv(f, header=f.tell()==0, index=False)

    if isMemory:
        general = pd.concat(dataframes)
        general.to_csv(SAVE_PATH, index=False)
        print('(1) Number of rows:'+str(len(general)))
    end = time.time()
    print('(1) Runtime:'+str(end - start))


