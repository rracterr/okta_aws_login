#!/usr/bin/env python3

# From https://github.com/nimbusscale/okta_aws_login
#
# Tweeked for move.com by Ben Knauss

import argparse
import base64
import configparser
import getpass
import math
import os
import sys
import time
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from os.path import expanduser
from urllib.parse import urlparse
import boto3
import requests
from bs4 import BeautifulSoup
import logging


##########################################################################
# Args

parser = argparse.ArgumentParser(
    description = "Gets a STS token to use for AWS CLI based "
                  "on a SAML assertion from Okta")

parser.add_argument(
    '--username', '-u',
    help="The username to use when logging into Okta. The username can "
         "also be set via the OKTA_USERNAME env variable. If not provided "
         "you will be prompted to enter a username."
)

parser.add_argument(
    '--profile', '-p',
    help="The name of the profile to use when storing the credentials in "
         "the AWS credentials file. If not provided then the name of "
         "the role assumed will be used as the profile name."
)

parser.add_argument(
    '--list', '-l', 
    help='List of available AWS accounts', 
    action="store_true", 
    default=False)

parser.add_argument(
    '--role', '-r',
    help='Name of the role to assume, ex: User, Admin, Dev. (case sensitive)')

parser.add_argument(
    '--setenv', '-s',
    help='Set AWS Environment variables (AWS_ACCESS_KEY, AWS_SECURITY_KEY)',
    action="store_true",
    default=False)

parser.add_argument(
    '--debug', '-d',
    action="store_true", 
    help='enable debug mode')


args = parser.parse_args()

##########################################################################

### Variables ###
# file_root: Path in which all file interaction will be relative to.
# Defaults to the users home dir.
file_root = expanduser("~")

# okta_aws_login_config_file: The file were the config parameters for the 
# okta_aws_login tool is stored
okta_aws_login_config_file = file_root + '/.aws/okta'

# aws_config_file: The file where this script will store the temp
# credentials under the saml profile.
aws_config_file = file_root + '/.aws/credentials'

# sid_cache_file: The file where the Okta sid is stored.
# only used if cache_sid is True.
sid_cache_file = file_root + '/.okta_sid'
###


def get_arns_from_assertion(assertion):
    """Parses a base64 encoded SAML Assertion and extracts the role and 
    principle ARNs to be used when making a request to STS.
    Returns a dict with RoleArn, PrincipalArn & SAMLAssertion that can be 
    used to call assume_role_with_saml"""
    # Parse the returned assertion and extract the principle and role ARNs
    root = ET.fromstring(base64.b64decode(assertion))
    urn = "{urn:oasis:names:tc:SAML:2.0:assertion}"
    urn_attribute = urn + "Attribute"
    urn_attributevalue = urn + "AttributeValue"
    role_url = "https://aws.amazon.com/SAML/Attributes/Role"
    
    arns_text = []
    principleArn = ''
    
    for saml2attribute in root.iter(urn_attribute):
        if (saml2attribute.get('Name') == role_url):
            for saml2attributevalue in saml2attribute.iter(urn_attributevalue):
                dirty_arns = saml2attributevalue.text.split(',')
                principleArn = dirty_arns[0]
                arns_text.append(dirty_arns[1])

    # Create dict to be used to call assume_role_with_saml
    arn_dict = {}
    arn_dict['PrincipalArn'] = principleArn
    arn_dict['SAMLAssertion'] = assertion
    arn_dict['RoleArn'] = arns_text
    return arn_dict


def get_saml_assertion(response):
    """Parses a requests.Response object that contains a SAML assertion.
    Returns an base64 encoded SAML Assertion if one is found"""
   # Decode the requests.Response object and extract the SAML assertion
    soup = BeautifulSoup(response.text, "html.parser")
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            return inputtag.get('value')

    if args.debug:
        print('No SAMLResponse Found in response')


def get_sid_from_file(sid_cache_file):
    """Checks to see if a file exists at the provided path. If so file is read
    and checked to see if the contents looks to be a valid sid.
    if so sid is returned"""
    if os.path.isfile(sid_cache_file) == True:
        with open(sid_cache_file) as sid_file:
            sid = sid_file.read()
            if len(sid) == 25:
                if args.debug:
                    logging.debug('SID found cached in file (%s)', sid)
                return sid

    if args.debug:
        logging.debug('No SID file found')


def get_sts_token(RoleArn,PrincipalArn,SAMLAssertion):
    """Use the assertion to get an AWS STS token using Assume Role with SAML
    returns a Credentials dict with the keys and token"""
    if args.debug:
        logging.debug('getting STS token')
    sts_client = boto3.client('sts')
    response = sts_client.assume_role_with_saml(RoleArn=RoleArn,
                                                PrincipalArn=PrincipalArn,
                                                SAMLAssertion=SAMLAssertion)
    Credentials = response['Credentials']
    return Credentials

def get_user_creds():
    """Get's creds for Okta login from the user. Retruns user_creds dict"""
    # Check to see if the username arg has been set, if so use that
    if args.username is not None:
        username = args.username
    # Next check to see if the OKTA_USERNAME env var is set
    elif os.environ.get("OKTA_USERNAME") is not None:
        username = os.environ.get("OKTA_USERNAME")
    # Otherwise just ask the user
    else:
        defaultuser = getpass.getuser()
        if args.debug:
            logging.debug('prompting for username (%s)', defaultuser)
        prompt = 'Username [' + defaultuser + '] :'
        username = input(prompt) or defaultuser

    # Set prompt to include the user name, since username could be set
    # via OKTA_USERNAME env and user might not remember.
    passwd_prompt = "Password for {}: ".format(username)
    if args.debug:
        logging.debug('prompting for password (%s)', passwd_prompt)
    password = getpass.getpass(prompt=passwd_prompt)
    if len(password) == 0:
        print( "Password must be provided")
        sys.exit(1)
    # Build dict and return in
    user_creds = {}
    user_creds['username'] = username
    user_creds['password'] = password
    return user_creds

def okta_cookie_login(sid,idp_entry_url):
    session = requests.Session()

    """Attempts a login using the provided sid cookie value. Returns a
    requests.Response object. The Response object may or may not be a
    successful login containing a SAML assertion"""
    # Create Cookie Dict and add sid value
    cookie_dict = {}
    cookie_dict['sid'] = sid

    cookie_url = idp_entry_url

    cookie_response = session.get(cookie_url,verify=True,cookies=cookie_dict)

    if args.debug:
        logging.debug('Attempted login with SID (%s, response: %d)', sid, cookie_response.status_code)

    return cookie_response

def handleApiError(response):
    send_result = json.loads(response.text)

    error_code = send_result['errorCode']
    error_summary = send_result['errorSummary']

    print("{code} - {summary}".format(code=error_code, summary=error_summary))
    exit()

def factorSMS(factor_url, factor_name, stateToken):
    session = requests.Session()
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})

    payload = {'stateToken': stateToken}

    send_response = session.post(factor_url, data=json.dumps(payload), verify=True)

    if send_response.status_code == 200:
        passcode = input("sms> Enter your {} code: ".format(factor_name))
        payload = {'stateToken': stateToken, 'passCode': passcode}

        verify_response = session.post(factor_url, data=json.dumps(payload), verify=True)

        if verify_response.status_code == 200:
            verify_result = json.loads(verify_response.text)
            return verify_result['sessionToken']
        elif verify_response.status_code in (403, 429):
            handleApiError(verify_response)
    elif send_response.status_code in (403, 429):
        handleApiError(send_response)


def factorOkta(factor_url, factor_name, stateToken):
    session = requests.Session()
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})

    passcode = input("okta> Enter your {} code: ".format(factor_name))
    payload = {'stateToken': stateToken, 'passCode': passcode}

    verify_response = session.post(factor_url, data=json.dumps(payload), verify=True)

    if verify_response.status_code == 200:
        verify_result = json.loads(verify_response.text)
        return verify_result['sessionToken']
    elif verify_response.status_code in (403, 429):
        handleApiError(verify_response)


def factorGoogle(factor_url, factor_name, stateToken):
    session = requests.Session()
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})

    payload = {'stateToken': stateToken}

    send_response = session.post(factor_url, data=json.dumps(payload), verify=True)

    if send_response.status_code == 200:
        passcode = input("google> Enter your {} code: ".format(factor_name))
        payload = {'stateToken': stateToken, 'passCode': passcode}

        verify_response = session.post(factor_url, data=json.dumps(payload), verify=True)

        if verify_response.status_code == 200:
            verify_result = json.loads(verify_response.text)
            return verify_result['sessionToken']
        elif verify_response.status_code in (403, 429):
            handleApiError(verify_response)
    elif send_response.status_code in (403, 429):
        handleApiError(send_response)

def factorPush(factor_url, factor_name, stateToken):
    session = requests.Session()
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})

    payload = {'stateToken': stateToken}

    send_response = session.post(factor_url, data=json.dumps(payload), verify=True)

    print("Please see your 2FA device")
    if send_response.status_code == 200:
        done = False
        while done == False:
            time.sleep(3)
            verify_response = session.post(factor_url, data=json.dumps(payload), verify=True)
            if verify_response.status_code == 200:
                verify_result = json.loads(verify_response.text)

                if verify_result.get('factorResult', None) is not None:
                    if verify_result['factorResult'] == 'WAITING':
                        print(".", end='', flush=True)
                    elif verify_result['factorResult'] == 'CANCELLED':
                        print("User canceled verification.")
                        exit()
                    elif verify_result['factorResult'] == 'TIMEOUT':
                        print("Timeout")
                        exit()
                if verify_result.get('status', None) is not None:
                    if verify_result['status']=='SUCCESS':
                        done=True
            elif verify_response.status_code in (403, 429):
                handleApiError(verify_response)

        return verify_result['sessionToken']

    elif send_response.status_code in (403, 429):
        handleApiError(send_response)

def getFactorName(provider, factorType):
    if (factorType=='push'):
        return 'Okta Verify (push)'
    elif (factorType=='sms'):
        return 'SMS'
    elif (factorType=='question'):
        return 'Question/Answer Not Supported'
    elif (factorType=='call'):
        return 'Okta Call'
    elif (factorType=='token:software:totp'):
        if (provider=='GOOGLE'):
            return 'Google Authenticator'
        elif (provider=='OKTA'):
            return 'Okta Verify'

def okta_mfa_login(password_login_response):
    session = requests.Session()

    authn_stateToken = password_login_response['stateToken']
    factor_list = password_login_response['_embedded']['factors']

    print("Select which MFA method would you like to use?: ")

    for count in range(0, len(factor_list)):
        name = getFactorName(factor_list[count]['provider'], factor_list[count]['factorType'])
        print(count + 1, ")", " ",   name)

    factor_id = int(input("Factor number : ")) - 1
    factor_name = factor_list[factor_id]['factorType']
    factor_provider = factor_list[factor_id]['provider']
    factor_url = factor_list[factor_id]['_links']['verify']['href']

    if factor_name == "push":
        sessionToken = factorPush(factor_url, factor_name, authn_stateToken)
    elif factor_name == "sms":
        sessionToken = factorSMS(factor_url, factor_name, authn_stateToken)
    elif factor_name == "call":
        sessionToken = factorSMS(factor_url, factor_name, authn_stateToken)
    elif factor_name == "question":
        print("Question/Answer not supported.");
    elif factor_name == "token:software:totp":
        if factor_provider == "GOOGLE":
            print("Google");
            sessionToken = factorGoogle(factor_url, factor_name, authn_stateToken)
        elif factor_provider == "OKTA":
            sessionToken = factorOkta(factor_url, factor_name, authn_stateToken)

    return sessionToken


def okta_password_login(username,password,sso_url):
    session = requests.Session()
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})

    parsedurl = urlparse(sso_url)

    authn_payload = {   'username': username,
                        'password': password,
                        'options': {
                            'multiOptionalFactorEnroll': True,
                            'warnBeforePasswordExpired': True
                        }
                    }

    authn_url = "{scheme}://{netloc}{action}".format(
                                                scheme=parsedurl.scheme,
                                                netloc=parsedurl.netloc,
                                                action="/api/v1/authn")

    # Performs the submission of the IdP login form with the above post data
    authn_response = session.post(authn_url, data=json.dumps(authn_payload), verify=True)

    if authn_response.status_code == 200:
        authn_result = json.loads(authn_response.text)
        authn_status = authn_result['status']

        if authn_status == "MFA_REQUIRED":
            sessionToken = okta_mfa_login(authn_result)
        else:
            sessionToken = authn_result['sessionToken']

        saml_url = "{url}?onetimetoken={sessiontoken}".format(
            url=sso_url,
            sessiontoken=sessionToken)

        saml_response = session.get(saml_url, verify=True)

        return saml_response
    elif authn_response.status_code in (401, 403, 429):
        handleApiError(authn_response)

def write_aws_creds(aws_config_file,profile,access_key,secret_key,token,
                    region,output):
    """ Writes the AWS STS token into the AWS credential file"""
    # Check to see if the aws creds path exists, if not create it
    creds_dir = os.path.dirname(aws_config_file)
    if os.path.exists(creds_dir) == False:
       os.makedirs(creds_dir) 
    config = configparser.RawConfigParser()
    # Read in the existing config file if it exists
    if os.path.isfile(aws_config_file):
        config.read(aws_config_file)
    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, 'output', output)
    config.set(profile, 'region', region)
    config.set(profile, 'aws_access_key_id', access_key)
    config.set(profile, 'aws_secret_access_key', secret_key)
    config.set(profile, 'aws_session_token', token)
    config.set(profile, 'aws_security_token', token)
        
    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section('default'):
        config.add_section('default')
    config.set('default', 'output', output)
    config.set('default', 'region', region)
    config.set('default', 'aws_access_key_id', access_key)
    config.set('default', 'aws_secret_access_key', secret_key)
    config.set('default', 'aws_session_token', token)
    config.set('default', 'aws_security_token', token)
    
    # Write the updated config file
    with open(aws_config_file, 'w+') as configfile:
        config.write(configfile)        


def write_sid_file(sid_file,sid):
    """Writes a given sid to a file. Returns nothing"""
    sid_cache_file = os.open(sid_file,os.O_WRONLY|os.O_CREAT,mode=0o600)
    os.write(sid_cache_file,sid.encode())
    os.close(sid_cache_file)


def main():
    print("Okta Authentication Tool");

    if args.list:
        config = configparser.RawConfigParser()
        config.read(okta_aws_login_config_file)
        print(" ")
        print("Valid AWS Profiles:")
        for section in config.sections():
            print("  ", section)
        print(" ")
        exit()

    if args.role:
        rolestr = str(args.role)
    else:
        rolestr = ''

    if not args.profile:
        print(" ")
        print("Please provide an AWS profile name")
        print(" ")
        parser.print_help()
        exit()
    else:
        profile = vars(parser.parse_args())
        if args.debug:
            logging.debug('Profile: %s', profile)
    	    
    # Check to see if config file exists, if not complain and exit
    # If config file does exist create config dict from file
    if os.path.isfile(okta_aws_login_config_file):
        config = configparser.RawConfigParser()
        config.read(okta_aws_login_config_file)
        conf_dict = dict(config[args.profile])
    else:
        print("~/.aws/okta file is needed.")
        sys.exit(1)

    # declaring a var to hold the SAML assertion. 
    assertion = None

    # see if a sid file exists
    sid = get_sid_from_file(sid_cache_file)

    # If a sid has been set from file then attempt login via the sid
    if sid is not None:
        response = okta_cookie_login(sid,conf_dict['sso_url']) #idp_entry_url
        assertion = get_saml_assertion(response)

    # if the assertion equals None, means there was no sid, the sid expired
    # or is otherwise invalid, so do a password login
    if assertion is None:
        # If sid file exists, remove it because the contained sid has expired
        if os.path.isfile(sid_cache_file):
            os.remove(sid_cache_file)

        user_creds = get_user_creds()
        response = okta_password_login(user_creds['username'],
                                       user_creds['password'],
                                       conf_dict['sso_url'])

        assertion = get_saml_assertion(response)

    # If the assertion is still none after the password login, then something
    # is wrong, complain and exit 

    if assertion is None:
        print("No valid SAML assertion retrieved!")
        sys.exit(1)

    # If cache sid enabled write sid to file
    write_sid_file(sid_cache_file,response.cookies['sid'])

    # Get arns from the assertion and the AWS creds from STS
    saml_dict = get_arns_from_assertion(assertion) 

    # Match up the role to choose from the --role param
    if args.role:
        for count in range(0, len(saml_dict['RoleArn'])):
            if rolestr == str(saml_dict['RoleArn'][count]).split(':')[5].split('/')[-1]:
                role_id = count
        if role_id == -1:
            print("No matching role found")
            exit(1)
    else:
        print("Select which role in the", profile['profile'], "account : ")
        for count in range(0, len(saml_dict['RoleArn'])):
            print( count + 1, ")", str(saml_dict['RoleArn'][count]).split(':')[5].split('/')[-1])
        role_id = int(input("Role number : ")) - 1
 
    print("Role: ", saml_dict['RoleArn'][role_id])

    selected_role = saml_dict['RoleArn'][role_id]  
    
    aws_creds = get_sts_token(selected_role,
                          saml_dict['PrincipalArn'],
                          saml_dict['SAMLAssertion'])

    # Get role name to use for the name of the profile
    # check if profile arg has been set
    if args.profile is not None:
        profile_name = args.profile
    elif conf_dict['cred_profile'] == 'role':
        profile_name = saml_dict['RoleArn'].split('/')[1]
    # if none complain and exit
    else:
        print("profile_name not set!")
        sys.exit()

    write_aws_creds(aws_config_file,
                    profile_name,
                    aws_creds['AccessKeyId'],
                    aws_creds['SecretAccessKey'],
                    aws_creds['SessionToken'],
                    conf_dict['region'],
                    'json')

    now = datetime.now(timezone.utc)
    valid_duration = aws_creds['Expiration'] - now
    valid_minutes = math.ceil(valid_duration / timedelta(minutes=1)) 
    cred_details = ("Credentials for the profile {} have been set. "
                    "They will expire in {} minutes.".format(profile_name,
                     valid_minutes)) 
    print(cred_details)

if __name__ == '__main__':
    main()

