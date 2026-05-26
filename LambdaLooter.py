import os
import json
import subprocess
import zipfile
import pathlib
from zipfile import ZipFile
from concurrent.futures import ThreadPoolExecutor, wait
import shutil
import boto3
import requests
from pprint import pprint
from time import gmtime, strftime
from datetime import datetime, timedelta


def loot(profile, lambda_client, threads, getversions, deldownloads, jsonTracker):       
    """
    Variables - 
    lambda_client: lambda client object for downloading. 
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    profile: the AWS profile lambdas are downloaded from 
    """
    downloadLambdas(profile, lambda_client, threads, getversions, deldownloads, jsonTracker)


def deleteDownload(profile):
    """
    Delete the downloaded zip
    Variables - 
    profile: name of profile to match to directory name for deleting
    """
    try:
        filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/{}".format(profile))
        shutil.rmtree(filepath, ignore_errors=True)
    
    except Exception as e:
        print("Error: {0} : {1}".format(filepath, e.strerror))


def downloadLambdas(profile, lambda_client, threads, getversions, deldownloads, jsonTracker):
    """
    Thread download lambda 'checkVersions' function
    Variables - 
    profile: the AWS profile lambdas are downloaded from
    lambda_client: lambda client object for downloading. 
    threads: number of threads for downloads
    getversions: YES or NO
    deldownloads: Should we delete data after we are done?
    """
    counter = 0
    try:
        func_paginator = lambda_client.get_paginator('list_functions')
        for func_page in func_paginator.paginate():
            continue
    except Exception as e:
        with open(f'./logs/failures.log', "a") as code:
            code.write(f"Failed, {profile}, " + str(e) + "\n")
        return 1
    for func_page in func_paginator.paginate():
        with ThreadPoolExecutor(threads) as executor:
            for func in func_page['Functions']:
                modifiedTime = datetime.strptime(func['LastModified'],'%Y-%m-%dT%H:%M:%S.%f%z')
                lastChecked = datetime.strptime(jsonTracker['LambdaLastChecked'],'%Y-%m-%d %H:%M:%S.%f%z')        
                if lastChecked < modifiedTime:
                    counter += 1     
                    futures = [executor.submit(checkVersions, profile, func['FunctionArn'], lambda_client, getversions)]                #wait for all tasks to complete
                    wait(futures)

    
    print(f'Lambda Downloaded: {counter}')
    zipEnvironmentVariableFiles(profile, deldownloads)

def zipEnvironmentVariableFiles(profile, deldownloads):

    zipDirectory = pathlib.Path("./loot/" + profile + "/env")
    zipDirectory.mkdir(exist_ok=True)
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/" + "envVariables.zip")
    counter = 0
    with zipfile.ZipFile(filepath , mode="w") as archive:
        for file_path in zipDirectory.iterdir():
            archive.write(file_path, arcname=file_path.name)
            counter += 1
            if deldownloads:
                os.remove(file_path)
    print(f'Number Environment Variables Zipped: {counter}')


def downloadExecution(profile, strFunction, lambda_client):
    """
    execute the download of the lambdas function(s) and Envionrment Varilables
    Variables - 
    profile: the AWS Profile we are looting
    lambda_client: lambda client object for downloading. 
    strFunction: arn of the lambda to download
    profile: the AWS profile lambdas are downloaded from
    """

    func_details = lambda_client.get_function(FunctionName=strFunction)
    downloadDir = "./loot/" + profile + "/lambda/lambda-" + func_details['Configuration']['FunctionName']  + "-version-" + func_details['Configuration']['Version'] + ".zip" 
    url = func_details['Code']['Location']
    
    r = requests.get(url)
    with open(downloadDir, "wb") as code:
        code.write(r.content)
    
    saveEnvFilePath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/env/lambda-env_"+ func_details['Configuration']['FunctionName'] + "-"  + func_details['Configuration']['Version'] + "-environmentVariables-loot.txt")
    env_details = lambda_client.get_function_configuration(FunctionName=strFunction)
    variables = env_details.get('Environment', {}).get('Variables', {})
    if variables:
        with open(saveEnvFilePath, 'a') as outputfile:
            outputfile.write(json.dumps(variables) + "\n")

def checkVersions(profile, strFunction, lambda_client, getversions):
    """
    check if we are downloading all versions of the lambdas function calls downloadExecution
    If we are downloading multiple versions paginate
    Variables - 
    profile: the AWS Profile we are looting
    strFunction: arn of the lambda to download
    lambda_client: lambda client object for downloading. 
    getversions: YES or NO
    """
    if getversions:
        func_paginator = lambda_client.get_paginator('list_versions_by_function')
        for func_page in func_paginator.paginate(FunctionName=strFunction):
            for func in func_page['Versions']:
                strFunction = func['FunctionArn']
                downloadExecution(profile, strFunction, lambda_client)
    else:
        downloadExecution(profile, strFunction, lambda_client)
