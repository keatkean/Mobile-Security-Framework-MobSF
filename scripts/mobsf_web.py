#!/usr/bin/env python
# MobSF automated analysis scripts

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

# logging 
logging.basicConfig(level=logging.INFO)

# relative file paths
current_dir = os.path.dirname(os.path.abspath(__file__))
output_folder = os.path.join(current_dir,"../mobsf/uploads/{}/dynamic_report.json")
static_output_folder = os.path.join(current_dir,"../mobsf/uploads/{}/static_report.json")
script_path = os.path.join(current_dir,"../mobsf/DynamicAnalyzer/tools/frida_scripts/others")
permission_path = os.path.join(current_dir,'../mobsf/all_permissions.txt')
automated_user_activities_script = os.path.join(current_dir,'automated_activities.sh')


# check if server is up
def is_server_up(url):
    try:
        urllib.request.urlopen(url, timeout=5)
        return True
    except urllib.error.URLError:
        pass
    return False

# file upload
def file_upload(server_url, apikey, file, type, androidactivities, output_logs, useractivities):
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
            analyzer = upload_response["analyzer"]
            static_analysis(server_url, apikey, file, upload_response_json)
            return upload_response, hashvalue, analyzer
        elif response.status_code == 200 and 'hash' in response.json()['results'][0]:
            for resp in response.json()['results']:
                upload_response=resp
                file = upload_response["file_name"]
                logging.info('[OK] Upload Complete - {}'.format(file))
                # upload_response=ast.literal_eval(response.text)
                hashvalue = upload_response["hash"]
                analyzer = upload_response["analyzer"]
                static_analysis(server_url, apikey, file, upload_response)
                generate_static_report(server_url, apikey, hashvalue)
                determine_dynamic(upload_response, hashvalue, analyzer, type, server_url, apikey, androidactivities, output_logs, useractivities)
            return 'ZipAnalysis'
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
def dynamic_analysis(server_url, apikey, hashvalue, androidactivities, useractivities):
    os.system("adb -s emulator-5554 emu kill")
    ## change the 'Pixel_XL_API_28' if you are using a different emulator
    subprocess.Popen(['emulator','-wipe-data','-avd','Pixel_XL_API_28', '-writable-system', '-no-snapshot'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(15)
    logging.info('Running Dynamic Analysis')
    api_path = server_url + 'api/v1/dynamic/start_analysis'
    header = "hash={}".format(hashvalue)
    response = subprocess.Popen(['curl', '-X', 'POST', '--url', api_path, '--data', header, '-H', 'Authorization:'+apikey],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.stdout.flush()  
    error = response.communicate()
    if response.returncode != 0:
        logging.error(f"[Error] Error starting dynamic analysis" + error.decode('utf-8'))

    else:
        logging.info("[OK] Dynamic analysis has successfully started")
        if androidactivities == '1':
            test_activities(server_url, apikey, hashvalue)
        if useractivities == '1':
            automated_user_activities()
        frida_instrumentation(server_url, apikey, hashvalue, "compiled.js")
        #time.sleep() to allow frida instrumentation to run before analysis
        time.sleep(20)
        stop_analysis(server_url, apikey, hashvalue)
        generate_report(server_url, apikey, hashvalue)

# android activities
def test_activities(server_url, apikey, hash):
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
def frida_instrumentation(server_url, apikey, hash, script_name):
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

def stop_analysis(server_url, apikey, hash):
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
def generate_report(server_url, apikey, hash):
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
def generate_static_report(server_url, apikey, hash):
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
    if static_details['permissions'] != None:
        permissions = (static_details['permissions'])
        keys = list(permissions.keys())
    else:
        keys = []
    for i in range(len(keys)):
        cropped = keys[i].replace("'", "")
        cropped = cropped.replace("android.permission.", "")
        keys[i] = cropped

    # list of all permissions
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
def report_links(server_url, hash, upload_response, type, output_logs, analyzer):
    static_link = server_url + analyzer + '/?name=' + upload_response['file_name'] + '&checksum=' + hash + '&type=' + upload_response['scan_type']
    print("Link for Static Report: {}".format(static_link))
    output_logs.append("Link for Static Report: {}".format(static_link))
    if type == 'dynamic':
        dynamic_link = server_url + 'dynamic_report/' + hash
        print("Link for Dynamic Report: {}".format(dynamic_link))
        output_logs.append("Link for Dynamic Report: {}".format(dynamic_link))
    scorecard_link = server_url + 'appsec_dashboard/' + hash + '/'
    print("Link for Application Security Scorecard: {}\n".format(scorecard_link))
    output_logs.append("Link for Application Security Scorecard: {}\n".format(scorecard_link))
    output_logs.append("\n")


def determine_dynamic(upload_response, hashvalue, analyzer, type, server_url, apikey, androidactivities, output_logs, useractivities):
    dynamic_scan_types = ["apk", "xapk"]
    if type == "dynamic" and upload_response["scan_type"] in dynamic_scan_types:
        dynamic_analysis(server_url, apikey, hashvalue, androidactivities, useractivities)
        report_links(server_url, hashvalue, upload_response, type, output_logs, analyzer)
    else:
        report_links(server_url, hashvalue, upload_response, "static", output_logs, analyzer)


def automated_user_activities():
    os.system(automated_user_activities_script)


def AutomatedAnalysis(type, server_url, androidactivities, filepath, apikey, useractivities):
    output_logs = []
    if os.path.exists(filepath):
        if os.path.isfile(filepath):
            file = filepath
            output_logs.append("Analysis results - {}".format(file))
            if type == 'static' or type == 'dynamic':
                output = file_upload(server_url, apikey, file, type, androidactivities, output_logs, useractivities)
                if output == 'ZipAnalysis':
                    output_logs.append("Completed Zip Analysis")
                    output_logs.append("\n")
                    return "ZipAnalysis"
                elif output != None:
                    upload_response = output[0]
                    hashvalue = output[1]
                    analyzer = output[2]
                    generate_static_report(server_url, apikey, hashvalue)
                    determine_dynamic(upload_response, hashvalue, analyzer, type, server_url, apikey, androidactivities, output_logs, useractivities)
                else:
                    print('{} has an invalid file type for analysis'.format(file))
                    output_logs.append('{} has an invalid file type for analysis'.format(file))
            else:
                print('Invalid scan type. (static/dynamic)')
                output_logs.append('Invalid scan type. (static/dynamic)')
        elif os.path.isdir(filepath):
            for filename in os.listdir(filepath):
                file = os.path.join(filepath, filename)
                if type == 'static' or type == 'dynamic':
                    file_upload(server_url, apikey, file, type, androidactivities, output_logs, useractivities)

            for filename in os.listdir(filepath):
                file = os.path.join(filepath, filename)
                output_logs.append("Analysis results - {}".format(file))
                if type == 'static' or type == 'dynamic':
                    output = file_upload(server_url, apikey, file, type, androidactivities, output_logs, useractivities)
                    if output == 'ZipAnalysis':
                        output_logs.append("Completed Zip Analysis")
                        output_logs.append("\n")
                    elif output != None:
                        upload_response = output[0]
                        hashvalue = output[1]
                        analyzer = output[2]
                        generate_static_report(server_url, apikey, hashvalue)
                        determine_dynamic(upload_response, hashvalue, analyzer, type, server_url, apikey, androidactivities, output_logs, useractivities)
                    else:
                        print('{} has an invalid file type for analysis'.format(file))
                        output_logs.append('{} has an invalid file type for analysis'.format(file))
                        output_logs.append("\n")
                else:
                    print('Invalid scan type. (static/dynamic)')
                    output_logs.append('Invalid scan type. (static/dynamic)')
    else:
        print('File or folder {} not found. Enter a valid file or folder'.format(filepath))
        output_logs.append('File or folder {} not found. Enter a valid file or folder'.format(filepath))
    return output_logs
