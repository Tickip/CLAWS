import os
import json
import argparse
import zipfile
import pathlib
from zipfile import ZipFile
import re
import glob
import importlib
import importlib.util
import subprocess
from subprocess import call
from concurrent.futures import ThreadPoolExecutor, wait
import shutil
import gc
import boto3
from boto3 import Session
import requests
import datetime
from constants import FILE_TYPES
import secretvalidation



def hunt(threads, deldownloads, getversions, profile=None):
    """
    Main function
    Sets the stage for everything!
    Variables -
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    profile: the AWS profile lambdas are downloaded from
    """


    sigs = getSigs()

    print(profile)
    if profile is None:
        # if user doesn't supply a profile, we will grab every file within /loot and search through it.
        rootdir = './loot'
        print(rootdir)
        print(glob.glob(rootdir + r'/*', recursive=False))
        for file in glob.glob(rootdir + r'/*', recursive=False):
            print(file)
            threadSecrets(threads, deldownloads, file.split('/')[-1], sigs)


    if profile is not None:
        # user supplied single aws profile, lets roll
        threadSecrets(threads, deldownloads, profile, sigs)

def getSigs():
    #
    # This will create an array of json signature objects to iterate through based on the files starting with sig_
    # In future we can add a flag to ask for the file or naming scheme of the file and have the signatures loaded that way.
    #______________________________________________________________________________
    sigs = []
    sigfiles = os.listdir(os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures"))
    for sigfile in sigfiles:
        try:
            if sigfile.startswith('sig_'):
                #pull in all sig files from the signature dir
                sigfilePath =  os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures/" + sigfile)
                jsonSigs = json.load(open(sigfilePath))
                for sigType in jsonSigs[0]["sigs"]:
                    sigs.append(sigType)
        except Exception as e:
            print("Failed to import sigfiles." + str(e))

    return(sigs)

def threadSecrets(threads, deldownloads, profile, sigs):
    """
    Variables -
    threads: number of threads for downloads
    deldownloads: YES or NO
    profile: the AWS profile to interact with
    sigs: Json values of all the signatures
    """

    print("Scanning for Secrets in " + profile)
    rootdir = './loot'
    files = glob.glob(rootdir + r'/' + profile + '/*/*.zip', recursive=True)
    files = files + glob.glob(rootdir + r'/' + profile + '/*.zip', recursive=True)
    for f in files:
        #print(f)
        checkSecrets(f, deldownloads, profile, sigs)

def regexChecker(pattern, fileread):
    #print('regexChecker()')
    returnvalue = re.finditer(pattern.encode(), fileread, re.MULTILINE | re.IGNORECASE)
    return returnvalue



def checkSecrets(f,deldownloads, profile, sigs):
    """
    Search through lambda zip for secrets based on signatures
    Variables -
    f: zip file to search through
    """
    print("checkSecrets()")


    print(f) # nice looking single line per file
    with ZipFile(f, "r") as inzip:
        for name in inzip.namelist():
            if pathlib.Path(name).suffix in FILE_TYPES:
                try:
                    with inzip.open(name) as ziptry:
                        pass
                    del ziptry
                except Exception as e:
                    with open(f'./logs/failures.log', "a") as code:
                        code.write(f"Failed to read zipfile, {profile}, {f}, " + str(e) + "\n")
                    continue
                with inzip.open(name) as zipfile:
                    try:
                        a = zipfile.read()
                    except Exception as e:
                        with open(f'./logs/failures.log', "a") as code:
                            code.write(f"Failed to read zipfile, {profile}, {f}, " + str(e) + "\n")
                        continue
                    for sigType in sigs:
                        if sigType['type'] == 'regex':
                            for outp in regexChecker(sigType['pattern'], a):
                                start = outp.span()[0]
                                line_no = a[:start].count(b"\n") + 1
                                try:
                                    output = str(outp.group(), 'UTF-8')
                                except:
                                    print("Way too ugly...moving on")
                                    #print(output)
                                secretvalidation.validate(profile, {
                                        'zip': f,
                                        'name': name,
                                        'description': sigType['caption'],
                                        'output': output.strip('"').strip("'").strip(' '),
                                        'line_no': line_no,
                                        'fileread': a,
                                        'pattern': sigType['pattern']
                                        })
                        else:
                            continue
                    del a
                    gc.collect()

    if deldownloads:
        os.remove(f)

