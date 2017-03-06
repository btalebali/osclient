#
# Copyright (c) Prologue [2014-2015], All Rights Reserved.
#
# Prologue owns all intellectual property rights related to source codes and
# object codes of this file. Unless otherwise agreed in writing between user's
# company and Prologue, only object codes are given to the user. Obtaining source
# code of this file by any other way is not legal and constitutes infringement.
# Object codes use rights are expressly described in the license agreement signed
# between user's company and Prologue. Any other use without the written permission
# of Prologue is not legal and constitutes an infringement.
#
import socket
import random
import subprocess
import os
import time
import logging
import sys
import StringIO
import pypacksrc
import json

'''
def init_logger(pname):
    logger = logging.getLogger(pname)
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        logger.handlers = []
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setLevel(logging.DEBUG)
    #FORMAT="%(asctime)s %(uicbmodule)s[%(process)d:%(thread)d]: %(account)s: %(user)s: %(levelname)s: %(message)s[in %(pathname)s:%(lineno)d in %(funcName)s]"
    FORMAT="%(account)s: %(user)s: %(levelname)s: %(message)s[in %(pathname)s:%(lineno)d in %(funcName)s]"
    handler.setFormatter(logging.Formatter(FORMAT))
    #handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    requests_logger = logging.getLogger("requests.packages.urllib2")
    requests_logger.addHandler(handler)
    requests_logger.setLevel(logging.DEBUG)
    return logger

def init_extra_logger(account="undefined", user="undefined"):
    #d={'account':account,'user':user,'uicbmodule':uicbmodule}
    d={'account':account,'user':user}
    return d
'''

UiCMP = "UiCMP"
DEFAULT = "default"
PUBLIC = "public"
PRIVATE = "private"
AUTOMATIC = "automatic"
FIXED = "fixed"
WINDOWS = "windows"

class Log2string:
    def __init__(self,pname):
        self.pname = pname
        self.log_capture_string = StringIO.StringIO()
        self.logger = None
        self.extra = None

    def init_logger(self):
        logger = logging.getLogger(self.pname)
        logger.setLevel(logging.DEBUG)
        if logger.handlers:
            logger.handlers = []
        handler = logging.StreamHandler(self.log_capture_string)
        handler.setLevel(logging.INFO)
        #FORMAT="%(asctime)s %(uicbmodule)s[%(process)d:%(thread)d]: %(account)s: %(user)s: %(levelname)s: %(message)s[in %(pathname)s:%(lineno)d in %(funcName)s]"
        FORMAT="[%(process)d:%(thread)d] %(levelname)s: %(account)s: %(user)s: %(message)s[in %(pathname)s:%(lineno)d in %(funcName)s]"
        handler.setFormatter(logging.Formatter(FORMAT))
        #handler.setLevel(logging.INFO)
        logger.addHandler(handler)
        requests_logger = logging.getLogger("requests.packages.urllib2")
        requests_logger.addHandler(handler)
        requests_logger.setLevel(logging.INFO)
        self.logger = logger
        return logger

    def get_log_string(self):
        log_contents = self.log_capture_string.getvalue()
        self.log_capture_string.flush()
        self.log_capture_string.truncate(0)
        self.log_capture_string.seek(0)
        return log_contents[0:len(log_contents)-1]

    def init_extra_logger(self, account="undefined", user="undefined"):
        d={'account':account,'user':user,'uicbmodule':self.pname}
        self.extra = d
        #d = {'account':account,'user':user}
        return d


def exec_cmd(cmd, tag):
    command_exec="rtalogger -i accords -t {0} -- '{1}'".format(tag, cmd)
    try:
        #reponse_cmd = subprocess.Popen(command_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        #out_cmd, error_cmd = reponse_cmd.communicate()
        out_cmd = os.system(command_exec)
    except:
        pass

def _init_logger(pname, account_='undefined', user_='undefined'):
    logger = Log2string(pname)
    log = logger.init_logger()
    d = logger.init_extra_logger(account=account_,user=user_)
    return logger

def get_log(log):
    m = log.get_log_string()
    exec_cmd(m, log.pname)
    return m

def generate_password():
    element = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    elementm = "abcdefghijklmnopqrstuvwxyz"
    elementn = "0123456789"
    passwd = ""
    for i in range(4):
        passwd = passwd + element[random.randint(0, len(element) - 1)]
    for i in range(6):
        passwd = passwd + elementm[random.randint(0, len(elementm) - 1)]
    for i in range(3):
        passwd = passwd + elementn[random.randint(0, len(elementn) - 1)]
    return passwd

def get_vm_name(hostname, name, label):
    if hostname and not(hostname.isspace()) and (hostname != name):
        return hostname
    elif label and not(label.isspace()):
        return label
    else:
        return name

def check_ssh_connection(hostname, prov, logger):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    retry = True
    connection = False
    check = 0
    while retry and check < 60:
        try:
            s.connect((hostname, 22))
            retry = False
            connection = True
            logger.logger.info('ssh command test ssh port(22) connection -> ?', extra=logger.extra)
            get_log(logger)
        except socket.error as e:
            time.sleep(10)
        check += 1
    s.close()
    return connection

def ssh_command(keyfile, host, username, password, command):
    logger = _init_logger("CMD", account_= accountnane,user_="undefined")
    logger.logger.info('CMD -> ?', extra=logger.extra)
    get_log(logger)
    keydir = os.path.expanduser(keyfile)
    if(check_ssh_connection(host, "CMD", logger)):
        logger.info('ssh command test port(22) connection -> OK', extra=logger.extra)
        if password.isspace() or not(password):
            command_exec = '''ssh -o StrictHostKeyChecking=no -q -i {0} {1}@{2}  "{3}"'''.format(keydir, username, host,command)
            try:
                reponse_cmd = os.system(command_sh)
                #reponse_cmd = subprocess.Popen(command_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            except OSError as e:
                logger.error('ssh command -> failure %s',str(e.error), extra=logger.extra)
                get_log(logger)
                return "failure"
            logger.info('ssh command -> OK', extra=d)
            return "succeeded"
        else:
            commandexec = "sudo -S sh -c '" + command + "'"
            command_exec = '''sshpass -p '{0}' ssh -o StrictHostKeyChecking=no -q {1}@{2} "{3} <<< '{0}'"'''.format(password,username,host,commandexec)
            reponse_cmd = subprocess.Popen(command_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            try:
                reponse_cmd = subprocess.Popen(command_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            except OSError as e:
                logger.logger.error('ssh command -> failure %s',str(e.error), extra=logger.extra)
                get_log(logger)
                return "failure"
            logger.info('ssh command -> OK', extra=logger.extra)
            get_log(logger)
            return "succeeded"
    logger.logger.error('ssh commandport(22) connection -> failure',extra=d)
    return "failure"

def upload_file_uicbdepositbucket(filepath):
    import boto3
    session = boto3.Session(aws_access_key_id=pypacksrc.s3userKey, aws_secret_access_key=pypacksrc.s3userSecretKey, region_name="eu-west-1")
    s3 = session.resource('s3')
    bucket = s3.Bucket(pypacksrc.s3uicbDeposit)
    key = "tmp"
    filename = os.path.basename(filepath)
    filekey = key + "/" + filename
    bucket.upload_file(filename, filekey, ExtraArgs={'ACL': 'public-read'})
    url =  bucket.meta.client.meta.endpoint_url + "/" + pypacksrc.s3uicbDeposit + "/" + filekey
    ime.sleep(20)
    return url  

def delete_file_uicbdepositbucket(filepath):
    import boto3
    session = boto3.Session(aws_access_key_id=pypacksrc.s3userKey, aws_secret_access_key=pypacksrc.s3userSecretKey, region_name="eu-west-1")
    s3 = session.resource('s3')
    bucket = s3.Bucket(pypacksrc.s3uicbDeposit)
    filename = os.path.basename(filepath)
    filekey = "tmp/" + filename
    resp = bucket.meta.client.delete_object(Bucket=pypacksrc.s3uicbDeposit,Key=filekey)
    os.remove(filepath)
    return "succeeded"

def unicode2str(value):
    if not(value):
        return " "
    elif isinstance(value,unicode):
        return str(value.encode('ascii', 'ignore'))
    else:
        return str(value)

def is_json(mjson):
    if not(mjson):
        return False
    try:
        json_object = json.loads(mjson)
    except ValueError, e:
        return False
    return True