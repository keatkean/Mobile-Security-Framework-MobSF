#!/usr/bin/env python
# MobSF automated analysis scripts

import argparse
import ast
import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import requests
import time
from bs4 import BeautifulSoup

# logging 
logging.basicConfig(level=logging.INFO)

# relative file paths
current_dir = os.path.dirname(os.path.abspath(__file__))
output_folder = os.path.join(current_dir,"../mobsf/uploads/{}/dynamic_report.json")
static_output_folder = os.path.join(current_dir,"../mobsf/uploads/{}/static_report.json")
script_path = os.path.join(current_dir,"../mobsf/DynamicAnalyzer/tools/frida_scripts/others")

# check if server is up
def is_server_up(url):
    try:
        urllib.request.urlopen(url, timeout=5)
        return True
    except urllib.error.URLError:
        pass
    return False

# file upload
def file_upload(server_url, apikey, file):
    # accepted file extensions
    mimes = {
        '.apk': 'application/octet-stream',
        '.ipa': 'application/octet-stream',
        '.appx': 'application/octet-stream',
        '.zip': 'application/zip',
    }
    
    filename = os.path.basename(file)
    _, ext = os.path.splitext(file)
    if ext in mimes:
        files = {'file': (filename, open(file, 'rb'), mimes[ext], {'Expires': '0'})}
        response = requests.post(server_url + 'api/v1/upload', files=files, headers={'AUTHORIZATION': apikey})
        if response.status_code == 200 and 'hash' in response.json():
            logging.info('[OK] Upload Complete - {}'.format(file))
            upload_response_json=response.json()
            upload_response=ast.literal_eval(response.text)
            hashvalue = upload_response["hash"]
            static_analysis(server_url, apikey, file, upload_response_json)
            return upload_response, hashvalue
        else:
            logging.error('[Error] Performing Upload - {}'.format(file))

# static analysis
def static_analysis(server_url, apikey, file, upload_response_json):
    logging.info('Running Static Analysis - {}'.format(file))
    response = requests.post(
    server_url + 'api/v1/scan',
    data=upload_response_json,
    headers={'AUTHORIZATION': apikey})
    if response.status_code == 200:
        logging.info('[OK] Static Analysis Complete - {}'.format(file))
    else:
        logging.error('[Error] Performing Static Analysis - {}'.format(file))

# dynamic analysis
def dynamic_analysis(server_url, apikey, hashvalue, upload_response, androidactivites):
    logging.info('Running Dynamic Analysis')
    api_path = server_url + 'api/v1/dynamic/start_analysis'
    header = "hash={}".format(hashvalue)
    response = subprocess.Popen(['curl', '-X', 'POST', '--url', api_path, '--data', header, '-H', 'Authorization:'+apikey],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.stdout.flush()  
    error = response.communicate()
    if response.returncode != 0:
        print(error)
        logging.error(f"[Error] Error starting dynamic analysis" + error.decode('utf-8'))

    else:
        logging.info("[OK] Dynamic analysis has successfully started")
        if androidactivities == 1:
            test_activities(hashvalue)
        frida_instrumentation(hashvalue, "compiled.js")
        #time.sleep() to allow frida instrumentation to run before analysis
        time.sleep(30)
        stop_analysis(hashvalue)
        generate_static_report(hashvalue)
        generate_report(hashvalue)
        report_links(hashvalue, upload_response)

# android activities
def test_activities(hash):
    api_path = server_url + 'api/v1/android/activity'
    exported_header = 'hash={}&test=exported'.format(hash)
    activity_header = 'hash={}&test=activity'.format(hash)
    exported = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', exported_header, '-H', 'Authorization:'+apikey],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error_exported = exported.communicate()
    if exported.returncode != 0:
        logging.error("[Error] Error with testing exported activities" + error_exported.decode('utf-8'))
    else:
        logging.info("[OK] Successfully tested exported activties")
        activity = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', activity_header, '-H', 'Authorization:'+apikey],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error_activity = activity.communicate()
        if activity.returncode != 0 :
            logging.error("[Error] Error in testing for activties" + error_activity.decode('utf-8'))
        else:
            logging.info("[OK] Successfully tested for activities")

# frida scripts
def frida_instrumentation(hash, script_name):
    api_path = server_url + 'api/v1/frida/instrument'
    full_script_path = script_path + '/' + script_name
    file = open(full_script_path, "r")
    script_contents = file.read()
    file.close()
    parsed_script_contents = urllib.parse.quote_plus(script_contents)
    header = "hash={}&default_hooks=api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass&auxiliary_hooks=enum_class,string_catch,string_compare,enum_methods,search_class,trace_class&class_name=java.io.File&class_search=ssl&class_trace=javax.net.ssl.TrustManager&frida_code={}".format(hash,parsed_script_contents)
    response = subprocess.Popen(['curl', '-X', 'POST', '--url', api_path, '--data', header, '-H', 'Authorization:'+apikey],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.error("[Error] Frida script instrumentation unsuccessful.\nError: " + error.decode('utf-8'))
    else:
        logging.info("[OK] Frida script instrumentation successful")

def stop_analysis(hash):
    api_path = server_url + 'api/v1/dynamic/stop_analysis'
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', header, '-H', 'Authorization:'+ apikey],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.info("[Error] Stopping of dynamic analysis is unsuccessful" + error.decode('utf-8'))
    else:
        logging.info("[OK] Stopping of dynamic analysis is successful")

# generate dynamic report
def generate_report(hash):
    api_path = server_url + 'api/v1/dynamic/report_json'
    logging.info('Generating dynamic analysis report')
    output_full_path = output_folder.format(hash)
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', header, '-H', 'Authorization:'+apikey, '--output', output_full_path],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.error("[Error] Dynamic JSON report generation is unsuccessful")
    else:
        logging.info("[OK] Dynamic JSON report generation is successful")

# generate static report
def generate_static_report(hash):
    api_path = server_url + 'api/v1/report_json'
    logging.info('Generating static analysis report')
    static_output_full_path = static_output_folder.format(hash)
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', header, '-H', 'Authorization:'+apikey, '--output', static_output_full_path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.error("[Error] Static JSON report generation is unsuccessful")
    else:
        logging.info("[OK] Static JSON report generation is successful")
        permission_list(hash, static_output_full_path)

# obtain list of permissions used from static report
def permission_list(hash, static_output_full_path):
    # get static report
    f = open(static_output_full_path, 'r')
    jsonString = f.read()
    f.close()

    # list of permissions used by the application
    static_details = json.loads(jsonString)
    permissions = (static_details['permissions'])
    keys = list(permissions.keys())
    for i in range(len(keys)):
        cropped = keys[i].replace("'", "")
        cropped = cropped.replace("android.permission.", "")
        keys[i] = cropped

    # list of all permissions
    permission_path = os.path.join(current_dir,'../mobsf/all_permissions.txt')
    f = open(permission_path, 'r')
    allPermissions = list(f.read().split(', '))
    f.close()

    # file to store the input for AI scoring
    perm_score = os.path.join(current_dir,'../mobsf/uploads/{}/perm_score.txt'.format(hash))

    # initialise the file
    f = open(perm_score,"w")
    f.write("{")
    f.close()

    # compare the permissions used by the application against the full list of permissions
    for i in allPermissions:
        f = open(perm_score,'a')
        if i in keys:
            f.write('"'+i+'": [1],')
        else:
            f.write('"'+i+'": [0],')
        f.close()

    # remove the last comma
    f = open(perm_score,'r+')
    content = f.read()
    f.seek(len(content)-1)
    f.truncate()
    f.close()

    # end the dictionary in the file
    f = open(perm_score,"a")
    f.write("}")
    f.close()

# generate links to static, dynamic, and appsec scorecard
def report_links(hash, upload_response):
    static_link = server_url + 'static_analyzer/?name=' + upload_response['file_name'] + '&checksum=' + hash + '&type=' + upload_response['scan_type']
    print("Link for Static Report: {}".format(static_link))
    dynamic_link = server_url + 'dynamic_report/' + hash
    print("Link for Dynamic Report: {}".format(dynamic_link))
    scorecard_link = server_url + 'appsec_dashboard/' + hash + '/'
    print("Link for Application Security Scorecard: {}\n".format(scorecard_link))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--type', help='')
    parser.add_argument('-s', '--server', help='IP address and Port number of a running MobSF Server. (ex: 127.0.0.1:8000)')
    parser.add_argument('-a', '--activities', help='Run android activities and capture screenshots. Value can be 1 or 0 (Default: 0)')
    parser.add_argument('-f', '--file', help='Path to the mobile app binary/zipped source code file or folder containing such files')
    args = parser.parse_args()

    if args.type and args.file and args.server:
        server = args.server
        server_url = 'http://' + server + '/'
        api_docs = BeautifulSoup(requests.get(server_url+'api_docs').text, 'html.parser')
        apikey = api_docs.select('.lead > strong')[0].get_text()
        print(apikey)
        androidactivities = args.activities
        
        if not is_server_up(server_url):
            print('MobSF REST API Server is not running at ' + server_url)
            print('Exiting!')
            exit(0)

        if os.path.exists(args.file):
            if os.path.isfile(args.file):
                file = args.file
                if args.type == 'static' or args.type == 'dynamic':
                    output = file_upload(server_url, apikey, file)
                    if output != None:
                        upload_response = output[0]
                        hashvalue = output[1]
                        if args.type == 'dynamic':
                            dynamic_analysis(server_url, apikey, hashvalue, upload_response, androidactivities)
                    else:
                        print('{} has an invalid file type for analysis'.format(file))
                else:
                    print('Invalid scan type. (static/dynamic)')
            elif os.path.isdir(args.file):
                for filename in os.listdir(args.file):
                    file = os.path.join(args.file, filename)
                    print(args.type)
                    if args.type == 'static' or args.type == 'dynamic':
                        output = file_upload(server_url, apikey, file)
                        if output != None:
                            upload_response = output[0]
                            hashvalue = output[1]
                            if args.type == 'dynamic':
                                dynamic_analysis(server_url, apikey, hashvalue, upload_response, androidactivities)
                        else:
                            print('{} has an invalid file type for analysis'.format(file))
                    else:
                        print('Invalid scan type. (static/dynamic)')
        else:
            print('File or folder {} not found. Enter a valid file or folder'.format(args.file))

        

    else:
        parser.print_help()