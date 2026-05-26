import os
import re
import json
import argparse
import subprocess
from subprocess import call
from concurrent.futures import ThreadPoolExecutor, wait
import boto3
from boto3 import Session
from time import gmtime, strftime
from datetime import datetime, timedelta
from dateutil import tz
import ec2looter
import parsing
import lambdalooter
import auth
import ssmlooter

runtime = datetime.utcnow()
# Get our default session as assume role chaining needs our current EC2 session details to be able to chain more than one session.
default_sts_client = auth.getDefault()



PROG_NAME = "CLAWS - Credential Looter AWS"
PROG_VER = 1.1
PROG_DESC = "Download AWS code and scan for secrets."
PROG_EPILOG = ""
PROG_ORIGINS = "LambdaLooter at https://github.com/StateFarmIns/LambdaLooter"



def parse_args():
    """
    Parse cmd line args
    """
    parser = argparse.ArgumentParser(prog=PROG_NAME, description=PROG_DESC, epilog=PROG_EPILOG)
    parser.add_argument("--version", action="version", version="%(prog)s v"+str(PROG_VER))

    parser.add_argument("-p", "--profile", dest="profile", help="Single AWS profile you want scan for lambda code. Defaults to credentials file.")
    parser.add_argument("-r", "--region", dest="region", default="us-east-1", help="Your aws region you want to download lambda code from. Default=us-east-1.")
    parser.add_argument("-t", "--threads", dest="threads", default=10, type=int, help="Number of threads to download functions and scan for loot. Default=10.")
    parser.add_argument("-fv", "--versions", dest="versions", action='store_true', help="Download all versions of the Lambda code. Default=False.")
    parser.add_argument("-d", "--delete", dest="deldownloads", action='store_true', help="Delete the Zip files after you are done looting. Default=False.")
    parser.add_argument("-ro", "--role", dest="role", help="Role that you will use if trying to assume role chain.")
    parser.add_argument("-hu", "--hunt", dest="hunt", action='store_true', help="Hunt through all code in /loot. Default=False.")
    #Following variable set to lambduh because 'lambda' appears to be an object or something within python and I can't use it. Sadge.
    parser.add_argument("-l", "--lambda", dest="lambduh", action='store_true', help="Download Lambda code. Default=False.")
    parser.add_argument("-e", "--ec2", dest="ec2", action='store_true', help="Download EC2 users data. Default=False.")
    parser.add_argument("-s", "--ssm", dest="ssm", action='store_true', help="Download ssm preferences. Default=False.")
    args = parser.parse_args()
    
    return args


def main(region, threads, deldownloads, getversions, hunt, ec2, lambduh, ssm, role, profile=None):       
    """
    Main function
    Sets the stage for everything!
    Variables - 
    region: aws region
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    profile: the AWS profile lambdas are downloaded from 
    """
    
    # Make sure base folders and any files you need on first run are existing.
    # Great place to check your files and see if you need to pull anything down from S3 or anywhere else you are storing your files. 
    setup()
    
    # Call to get our account list if not account is specified. 
    if profile is None:
        accounts = getAccounts()


    if ec2 or lambduh or ssm:
        if profile is None:
            if threads == 1:
                for profileCurrent in accounts:
                    awsProfileSetup(profileCurrent, region, threads, deldownloads, getversions, ec2, lambduh, ssm, role)
            else:    
                with ThreadPoolExecutor(threads) as executor:
                    futures = [executor.submit(awsProfileSetup, profileCurrent, region, threads, deldownloads, getversions, ec2, lambduh, ssm, role) for profileCurrent in accounts]
                    #wait for all tasks to complete
                    wait(futures)
    
        if profile is not None:
            awsProfileSetup(profile, region, threads, deldownloads, getversions, ec2, lambduh, ssm, role)
    


    if hunt:
        if profile is None:
            for profileCurrent in accounts:
                parsing.hunt(threads, deldownloads, getversions, profileCurrent)
        if profile is not None:
            parsing.hunt(threads, deldownloads, getversions, profile)
    print("Thanks for looting with us!")
    


# setup our folders
def setup():
    strLoot = os.path.isdir('./loot')
    if not strLoot:
        print("Making folder loot")
        os.mkdir('loot')
    strTrack = os.path.isdir('./track')
    if not strTrack:
        print("Making folder track")
        os.mkdir('track')
    strSub = os.path.isdir('./findings')
    if not strSub:
        print("Making folder findings")
        os.mkdir('findings')
    strLogs = os.path.isdir('./logs')
    if not strLogs:
        print("Making folder logs")
        os.mkdir('logs')
    
def lootDirCheck(profile, ec2, lambduh, ssm):
    # Make sure files exist if we are going to be downloading that type. 
    
    base = os.path.isdir("./loot/" + profile)
    if not base:
        os.mkdir("./loot/" + profile)
    if ec2:
        strLoot = os.path.isdir("./loot/" + profile + "/ec2")
        if not strLoot:
            os.mkdir("./loot/" + profile + "/ec2")
    if ssm:
        strLoot = os.path.isdir("./loot/" + profile + "/ssm")
        if not strLoot:
            os.mkdir("./loot/" + profile + "/ssm")
    if lambduh:
        strLoot = os.path.isdir("./loot/" + profile + "/lambda")
        if not strLoot:
            os.mkdir("./loot/" + profile + "/lambda")
        strLoot = os.path.isdir("./loot/" + profile + "/env")
        if not strLoot:
            os.mkdir("./loot/" + profile + "/env")


def _is_valid_account_id(account_id):
    return bool(re.fullmatch(r'\d{12}', account_id))

# Put in here how to ingest whatever or wherever your list is.
def getAccounts():
    accounts = []
    with open('./accounts.txt') as f:
        for line in f:
            account = line.strip()
            if _is_valid_account_id(account):
                accounts.append(account)
            elif account:
                print(f"Skipping invalid account ID: {account!r}")
    return accounts


# Track check is used to see if your tracker file exists for a specific account. If it does it will return it as a variable, if not, it will create a default tracker entry and return that. 
def trackCheck(profileID):
    print('trackCheck()')
    trackFile = os.path.exists(f'./track/{profileID}.json')
    if trackFile:
        try:
            with open(f'./track/{profileID}.json') as f:
                jsonTrack = json.load(f)
            return jsonTrack
        except Exception as e:
            print("Something went wrong and we can't load the track file. (./track.json)" + str(e))
    else:
        print("tracker file does not exist/cannot be found. Using default timeframes.")
        defaultTracker = {"LambdaLastChecked" : '1999-12-04 18:40:54.529028+00:00',
                          'ec2LastChecked' : '1999-12-04 18:40:54.529028+00:00',
                          'ssmLastChecked': '1999-12-04 18:40:54.529028+00:00'}
        with open(f'./track/{profileID}.json', "w") as code:
            code.write(json.dumps(defaultTracker))
        return defaultTracker

# Update the time in which a profile has last downloaded lambda or EC2 data. 
def trackUpdate(jsonTrack, ec2, lambduh, ssm, profileID):
    print("trackUpdate()")
    #print(jsonTrack)
    if ec2:
        jsonTrack.update({'ec2LastChecked' : str(runtime)  + "+00:00"
            })
    if lambduh:
        jsonTrack.update({'LambdaLastChecked' : str(runtime) + "+00:00"
            })
    if ssm:
        jsonTrack.update({'ssmLastChecked' : str(runtime) + "+00:00"
            })
    with open(f'./track/{profileID}.json', "w") as code:
        code.write(json.dumps(jsonTrack))



def awsProfileSetup(profileID, region, threads, deldownloads, getversions, ec2, lambduh, ssm, role):
    """
    AWS functions to interact with AWS profiles.
    Either from a file list or single specified profile
    Variables - 
    profile: the AWS profile to interact with
    region: aws region
    threads: number of threads for downloads
    deldownloads: YES or NO
    getversions: YES or NO
    ec2: YES or NO
    lambduh: YES or NO
    hunt YES or NO
    """
   
    print(f'awsProfileSetup({profileID}, {ec2}, {lambduh}, {ssm})')
    # Got our profiles tracker data. 
    jsonTracker = trackCheck(profileID)
    lootDirCheck(profileID, ec2, lambduh, ssm)
    
    #
    # Assume role to profiles in list.  
    #______________________________________________________________________________
    clients = auth.authID(profileID, region, role, default_sts_client)
    #
    # Creating the file for our profile findings and files. 
    #______________________________________________________________________________
    strExists = os.path.isdir('./loot/' + profileID)
    if not strExists:
        os.mkdir('./loot/' + profileID)
        print("Created the folder:", profileID)
    
    if ec2:
        ec2looter.loot(profileID, clients['ec2client'], deldownloads, jsonTracker)
    if lambduh:
        lambdalooter.loot(profileID, clients['lambdaclient'], threads, getversions, deldownloads, jsonTracker)
    if ssm:
        ssmlooter.loot(profileID, clients['ssmclient'], deldownloads, jsonTracker)
    # Update our tracker for the profile
    trackUpdate(jsonTracker, ec2, lambduh, ssm, profileID)
    print('')
    print('')

if __name__ == "__main__":
    args = parse_args()
    if args.profile is not None and not _is_valid_account_id(args.profile):
        print(f"Error: profile must be a 12-digit AWS account ID, got: {args.profile!r}")
        raise SystemExit(1)
    main(args.region, args.threads, args.deldownloads, args.versions, args.hunt, args.ec2, args.lambduh, args.ssm, args.role, profile=args.profile)
