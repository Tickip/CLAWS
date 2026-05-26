import os
import json
import requests
from datetime import datetime, date
import random
import string
from pprint import pprint
from hashlib import sha256
import secrethandler
import parsing

digits = string.digits

#
# This script needs to be edited to reflect your internal company and how to validate credentials. 
def validate(profile, output):
    print('validate()')
    #print(output['name'])
    #print(output['output'])
    # Check to see if we have submitted this cred before. 
    subdBefore = seenBefore(output['output'], profile, output)
    if output['output'].startswith("AKIA"):
        akiaChecker(output, profile)
    else:
        subdBefore = seenBefore(output['output'], profile, output)
        print(subdBefore)
        if not subdBefore:
            logNotValidated(profile, output)

            
# This function is specific to double checking AKIA findings do look for the secretkey tied to the AKIA. 
# IT is nested becuase it is an easy way to grab to potential key value, then get teh actual key out of inside of it. 
# If you search just for the 40 character string, lots of non-keys show up such as random base64 strings or url's, weird guid's, etc. 
def akiaChecker(output, profile):
    firstregex = "(secret|Key)['\",:]{1,5}\s?( |\"|'){1}[a-zA-Z0-9\/\+\-]{40}( |\"|'){1}"
    secretregex = "[a-zA-Z0-9\/\+\-]{40}"
    for outp in parsing.regexChecker(firstregex, output['fileread']):
        akiasecret = None
        start = outp.span()[0]
        line_no = output['fileread'][:start].count(b"\n") + 1
        try:
            akiasecret = str(outp.group(), 'UTF-8')
            print(akiasecret)
        except Exception as e:
            print("Failed:" + str(e))
        if akiasecret != None:
            for outp2 in parsing.regexChecker(secretregex, akiasecret.encode()):
                secret = None
                start = outp2.span()[0]
                line_no = akiasecret.encode()[:start].count(b"\n") + 1
                try:
                    secret = str(outp2.group(), 'UTF-8')
                    print(secret)
                except Exception as e:
                    print("Failed:" + str(e))

                if secret != None:
                    subdBefore = seenBefore(output['output'], profile, output)
                    if not subdBefore:
                        context = parseInfoOutput(profile, output)
                        exposedCredentialIdentityDetails = {}
                        exposedCredentialIdentityDetails["identity"] = output['output']
                        exposedCredentialIdentityDetails["secret"] = secret
                        exposedCredentialIdentityDetails["secret_extra"] = ''
                        exposedCredentialIdentityDetails["cred_type"] = output['description']
                        context['exposed_cred'] = exposedCredentialIdentityDetails
                        pprint(context)
                        logNotValidated(None, None, context)
                        #logSubmission(context)

def logNotValidated(profile, output, context=None):
    # if no context has been built, this can build it for us.
    # Not the greatest way but was added afterwards and is the easiest for now. 
    if profile != None and output != None:
        context = parseInfoOutput(profile, output)
        exposedCredentialIdentityDetails = {}
        exposedCredentialIdentityDetails["identity"] = ''
        exposedCredentialIdentityDetails["secret"] = output['output']
        exposedCredentialIdentityDetails["secret_extra"] = ''
        exposedCredentialIdentityDetails["cred_type"] = output['description']
        context['exposed_cred'] = exposedCredentialIdentityDetails 

    filepath = './findings/notvalidated.json'
    submittedFile = os.path.isfile(filepath)
    if submittedFile:
        with open(filepath) as f:
            subJSON = json.load(f)
        subJSON['unvalidated'].append(context)
    else:
        subJSON = {'unvalidated':[context]}
    #pprint(subJSON)
    with open(filepath, 'w') as jf:
        jf.write(json.dumps(subJSON))
    
# Checks to see if we have seen this secret before. 
def seenBefore(secret, profile, output):
    
    seen = False
    filepath = './findings/notvalidated.json'
    nonSubmittedFile = os.path.isfile(filepath)
    if nonSubmittedFile:
        with open(filepath) as f:
            subJSON = json.load(f)
        for sub in subJSON['unvalidated']:
            if sub['sha2'] == sha256(secret.encode('utf-8')).hexdigest():
                seen = True
                filepath = output['zip']
                originalaccountseen = sub['accountID']
                with open(f'./logs/duplicates.log', "a") as code:
                    code.write(f"duplicate, {profile}, {secret}, {filepath}, {originalaccountseen}\n")
    filepath = './findings/obvfalsepositive.json'
    obvfalsepositiveFile = os.path.isfile(filepath)
    if obvfalsepositiveFile:
        with open(filepath) as f:
            subJSON = json.load(f)
        for sub in subJSON['obvfalsepositive']:
            if sub['sha2'] == sha256(secret.encode('utf-8')).hexdigest():
                seen = True
                filepath = output['zip']
                originalaccountseen = sub['accountID']
                with open(f'./logs/duplicates.log', "a") as code:
                    code.write(f"duplicate, {profile}, {secret}, {filepath}, {originalaccountseen}\n")
    filepath = './findings/expiredJWT.json'
    expiredFile = os.path.isfile(filepath)
    if expiredFile:
        with open(filepath) as f:
            subJSON = json.load(f)
        for sub in subJSON['expired']:
            if sub['sha2'] == sha256(secret.encode('utf-8')).hexdigest():
                seen = True
                filepath = output['zip']
                originalaccountseen = sub['accountID']
                with open(f'./logs/duplicates.log', "a") as code:
                    code.write(f"duplicate, {profile}, {secret}, {filepath}, {originalaccountseen}\n")
    return seen


# This builds the information portion of our output.  
def parseInfoOutput(accountID, output):
    
    random_code = ''.join(random.choice(digits) for _ in range(32))
    code_with_prefix = "claws" + random_code

    datefound = date.today()
    timefound = datetime.now()

    context = {}
    #pprint(response)
    context['date_found'] = str(datefound)
    context['time_found'] = str(timefound)
    context['source'] = output['name']
    context['project_path'] = output['zip'].split('/')[-1:][0]
    context['stepFunctionId'] = code_with_prefix
    context['provider'] = 'CLAWS'
    context['visibility'] = ''
    context['sha2'] = sha256(output['output'].encode('utf-8')).hexdigest()
    context['accountID'] = accountID
    return context


if __name__ == "__main__":
    main()
