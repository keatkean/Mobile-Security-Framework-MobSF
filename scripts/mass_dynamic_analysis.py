#!/usr/bin/env python
# Mass Dynamic Analysis
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

logging.basicConfig(level=logging.INFO)
current_dir = os.path.dirname(os.path.abspath(__file__))
output_folder = os.path.join(current_dir,"../mobsf/uploads/{}/dynamic_report.json")
static_output_folder = os.path.join(current_dir,"../mobsf/uploads/{}/static_report.json")
script_path = os.path.join(current_dir,"../mobsf/DynamicAnalyzer/tools/frida_scripts/others")


def is_server_up(url):
    try:
        urllib.request.urlopen(url, timeout=5)
        return True
    except urllib.error.URLError:
        pass
    return False


def start_scan(directory, server_url, apikey, rescan='0'):
    print('\nLooking for Android/iOS/Windows binaries or source code: ' + directory)
    logging.info('Uploading to MobSF Server\n')
    uploaded = []
    mimes = {
        '.apk': 'application/octet-stream',
        '.ipa': 'application/octet-stream',
        '.appx': 'application/octet-stream',
        '.zip': 'application/zip',
    }


    for filename in os.listdir(directory):
        file = os.path.join(directory, filename)
        _, ext = os.path.splitext(file)
        if ext in mimes:
            files = {'file': (filename, open(file, 'rb'), mimes[ext], {'Expires': '0'})}
            response = requests.post(server_url + 'api/v1/upload', files=files, headers={'AUTHORIZATION': apikey})
            if response.status_code == 200 and 'hash' in response.json():
                logging.info('[OK] Upload Complete - {}'.format(file))
                upload_response_json=response.json()
                uploaded.append(response.json())
                upload_response=ast.literal_eval(response.text)
                hash = upload_response["hash"]
                #run static analysis
                logging.info('Running Static Analysis - {}'.format(file))
                response = requests.post(
                server_url + 'api/v1/scan',
                data=upload_response_json,
                headers={'AUTHORIZATION': apikey})
                if response.status_code == 200:
                    logging.info('[OK] Static Analysis Complete - {}'.format(file))
                else:
                    logging.error('[Error] Performing Static Analysis - {}'.format(file))
            else:
                logging.error('[Error] Performing Upload - {}'.format(file))

            logging.info('Running Dynamic Analysis - {}'.format(file))
            api_path = server_url + 'api/v1/dynamic/start_analysis'
            header = "hash={}".format(hash)
            response = subprocess.Popen(['curl', '-X', 'POST', '--url', api_path, '--data', header, '-H', 'Authorization:'+apikey],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sys.stdout.flush()  
            error = response.communicate()
            if response.returncode != 0:
                print(error)
                logging.error(f"[Error] Error starting dynamic analysis - " + file + error.decode('utf-8'))

            else:
                logging.info('[OK] Dynamic analysis has successfully started - {}'.format(file))
                test_activities(hash)
                frida_instrumentation(hash, "compiled.js")
                #time.sleep() to allow frida instrumentation to run before analysis
                time.sleep(60)
                stop_analysis(hash)
                generate_static_report(hash)
                generate_report(hash)
                report_links(hash, upload_response)
                
        else:
            logging.info('{} is not a APK/IPA/APPX/ZIP file\n'.format(file))

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

def generate_report(hash):
    api_path = server_url + 'api/v1/dynamic/report_json'
    logging.info('Generating dynamic analysis report')
    output_full_path = output_folder.format(hash)
    header = "hash={}".format(hash)
    response = subprocess.Popen(['curl','-X','POST','--url',api_path, '--data', header, '-H', 'Authorization:'+apikey, '--output', output_full_path],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = response.communicate()
    if response.returncode != 0:
        logging.error("[Error] JSON report generation is unsuccessful")
    else:
        logging.info("[OK] JSON report generation is successful")

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

def report_links(hash, upload_response):
    static_link = server_url + 'static_analyzer/?name=' + upload_response['file_name'] + '&checksum=' + hash + '&type=' + upload_response['scan_type']
    print("Link for Static Report: {}".format(static_link))
    dynamic_link = server_url + 'dynamic_report/' + hash
    print("Link for Dynamic Report: {}".format(dynamic_link))
    scorecard_link = server_url + 'appsec_dashboard/' + hash + '/'
    print("Link for Application Security Scorecard: {}\n".format(scorecard_link))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', help='Path to the directory that contains mobile app binary/zipped source code')
    parser.add_argument('-s', '--ipport', help='IP address and Port number of a running MobSF Server. (ex: 127.0.0.1:8000)')
    parser.add_argument('-k', '--apikey', help='MobSF REST API Key')
    parser.add_argument('-r', '--rescan', help='Run a fresh scan. Value can be 1 or 0 (Default: 0)')
    args = parser.parse_args()

    if args.directory and args.ipport and args.apikey:
        server = args.ipport
        directory = args.directory
        server_url = 'http://' + server + '/'
        apikey = args.apikey
        rescan = args.rescan
        if not is_server_up(server_url):
            print('MobSF REST API Server is not running at ' + server_url)
            print('Exiting!')
            exit(0)
        # MobSF is running, start scan
        start_scan(directory, server_url, apikey, rescan)
    else:
        parser.print_help()