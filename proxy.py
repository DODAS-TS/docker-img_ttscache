#!/usr/bin/env python
#-*- coding: utf-8 -*-
"""This script requires the following environment variables:

  - IAM_TOKEN
  - IAM_REFRESH_TOKEN
  - IAM_CLIENT_ID
  - IAM_CLIENT_SECRET
  - MARATHON_USER (used if Marathon cache manager is selected)
  - MARATHON_PASSWD (used if Marathon cache manager is selected)
  - ZOOKEEPER_HOST_LIST (used if Zookeeper cache manager is selected)
  - CACHE_MANAGER [ZOOKEEPER, MARATHON, MEMORY]

"""
from __future__ import print_function

import json
import logging
import os
import subprocess
import sys
import time
from StringIO import StringIO

import requests
from urllib3._collections import HTTPHeaderDict

import pycurl
from cache import MarathonCache, MemoryCache, ZookeeperCache

if sys.version_info.major == 2:
    from urlparse import urlsplit
else:
    from urllib.parse import urlsplit


CONFIG_FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "proxy_config.json"
)


class Container(object):

    """Simple object container to simulate JSON obj access."""

    def __getattr__(self, name):
        setattr(self, name, None)
        return getattr(self, name)

    def __repr__(self):
        return str(vars(self))


class ProxyManager(object):

    """Manager of tokens."""

    def __init__(self, env, cache_manager=None):
        # Get all environment variables
        self.iam = Container()
        self.iam.token = env.get('IAM_TOKEN')
        self.iam.client_id = env.get('IAM_CLIENT_ID')
        self.iam.client_secret = env.get('IAM_CLIENT_SECRET')

        self.marathon = Container()
        self.marathon.user = env.get('MARATHON_USER'),
        self.marathon.passwd = env.get('MARATHON_PASSWD')
        # CACHE
        self.cache_dir = '/tmp'
        if cache_manager == 'ZOOKEEPER':
            self.cache = ZookeeperCache(env.get('ZOOKEEPER_HOST_LIST'))
        elif cache_manager == 'MARATHON':
            self.cache = MarathonCache(
                self.marathon.user, self.marathon.passwd)
        else:
            self.cache = MemoryCache()

        # LOAD PROXY CONFIG FILE
        with open(CONFIG_FILE_PATH) as config_file:
            proxy_config = json.load(config_file)

        # Configuration containers
        self.config = Container()
        self.config.local_cache = Container()
        self.config.lock_file = Container()
        self.config.tts = Container()
        self.config.iam = Container()
        self.config.user = Container()

        # Configuration variables
        self.config.local_cache.expiration_time = proxy_config.get(
            'local_cache_expiration_time')
        self.config.audience = proxy_config.get('audience')

        self.config.lock_file.age = proxy_config.get('lock_file_age')
        self.config.lock_file.path = "{}/lock".format(self.cache_dir)

        self.config.tts.url = proxy_config.get('tts')
        self.config.tts.output_data = '{}/output.json'.format(self.cache_dir)

        self.config.iam.endpoint = proxy_config.get('iam_endpoint')
        self.config.iam.token_endpoint = self.config.iam.endpoint + 'token'
        self.config.iam.introspect_endpoint = self.config.iam.endpoint + 'introspect'
        self.config.iam.credential_endpoint = proxy_config.get(
            'credential_endpoint')

        self.config.user.cert = "{}/usercert.crt".format(self.cache_dir)
        self.config.user.key = "{}/userkey.key".format(self.cache_dir)
        self.config.user.passwd = "{}/userpasswd.txt".format(self.cache_dir)
        self.config.user.proxy = "{}/userproxy.pem".format(self.cache_dir)

        self.exchanged_token = ""

    def check_tts_data(self):
        """Checks and refresh tts data.

        .. note::
            Workflow:

            - Check tts output data file
                - if YES -> Check if expired
                    - if YES -> get_tts_data(True)
                    - if NO  -> Token OK
                - if NO -> get_exchange_token()
                    - if OK [returns (str) exchange_token] 
                        - get_tts_data(exchange_token)
                    - if FAILS [returns int] -> Check CACHE for refresh token
                        - if YES -> get_tts_data(True) [True to use refresh token]
                        - if NO  -> ERROR

        """
        logging.debug("Check tts output data: %s", self.config.tts.output_data)
        if os.path.exists(self.config.tts.output_data):
            ctime = os.stat(self.config.tts.output_data).st_ctime
            since = time.time() - ctime
            logging.debug("Check expiration time: %s > %s",
                          since, self.config.local_cache.expiration_time)
            if since > self.config.local_cache.expiration_time:
                logging.debug("Token about to expire. Get tts data...")
                tts_data = self.get_tts_data(True)
            else:
                logging.debug("Token OK.")
                return True
        else:
            logging.debug("Token not exist, get exchange token...")
            self.exchanged_token = self.get_exchange_token()
            if isinstance(self.exchanged_token, int):
                logging.error("Get exchange token error: %s",
                              self.exchanged_token)
                if self.cache.refresh_token.value == None:
                    logging.error("Problem with Token Server")
                    return False
                else:
                    logging.error("Exchange with refresh token")
                    tts_data = self.get_tts_data(True)
            else:
                logging.debug("Token OK.")
                tts_data = self.get_tts_data(self.exchanged_token)

        return tts_data

    def get_certificate(self):
        """Retrieve the certificate.

        :returns: The given tts token
        :raises requests.exceptions: possible on redirect
        :raises pycurl.exceptions: during the call of iam credential endpoint

        .. todo::
            Manage controls (gestisci controlli)

        """
        data = json.dumps({"service_id": "x509"})

        logging.debug("Create headers and buffers")
        headers = StringIO()
        buffers = StringIO()

        logging.debug("Prepare CURL")
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, bytes(self.config.iam.credential_endpoint))
        curl.setopt(pycurl.HTTPHEADER, [
            'Authorization: Bearer {}'.format(
                str(self.exchanged_token).split('\n', 1)[0]),
            'Content-Type: application/json'
        ])
        curl.setopt(pycurl.POST, 1)
        curl.setopt(pycurl.POSTFIELDS, data)
        curl.setopt(curl.WRITEFUNCTION, buffers.write)
        curl.setopt(curl.HEADERFUNCTION, headers.write)
        curl.setopt(curl.VERBOSE, True)

        try:
            logging.debug("Perform CURL call")
            curl.perform()
            status = curl.getinfo(curl.RESPONSE_CODE)
            logging.debug("Result status: %s", status)
            logging.debug("Close CURL")
            curl.close()
            logging.debug("Get body content")
            body = buffers.getvalue()
            logging.debug("Body: %s", body)

            if str(status) != "303":
                logging.error(
                    "On 'get redirected with curl': http error: %s", str(status))
                return False
        except pycurl.error as error:
            errno, errstr = error
            logging.error('A pycurl error n. %s occurred: %s', errno, errstr)
            return False

        logging.debug("Manage redirect")
        for item in headers.getvalue().split("\n"):
            if "location" in item:
                # Example item
                #   "location: https://watts-dev.data.kit.edu/api/v2/iam/credential_data/xxx"
                logging.debug("Item url: %s", item)
                url_path = urlsplit(item.strip().split()[1]).path
                redirect = self.config.tts.url + url_path
                logging.debug("Redirect location: %s", redirect)

                headers = {'Authorization': 'Bearer ' +
                           self.exchanged_token.strip()}
                response = requests.get(redirect, headers=headers)

                try:
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    # Whoops it wasn't a 200
                    logging.error(
                        "Error in get certificate redirect: %s", str(err))
                    return False

                with open('/tmp/output.json', 'w') as outf:
                    outf.write(response.content)

                cur_certificate = json.loads(response.content)
                cert_id = cur_certificate['credential']['id']
                logging.debug("Certificate id: '%s'", cert_id)
                if self.revoke_cert(cert_id):
                    logging.debug("Certificate '%s' revoked", cert_id)
                else:
                    logging.error("Certificate '%s' NOT REVOKED", cert_id)
            else:
                logging.error("No location in redirect response")

        return True

    def revoke_cert(self, cert_id):
        """Revoke a certificate.
        
        :param cert_id: str
        :returns: bool, the end status of the operation
        :raises requests.exceptions: possible on redirect
        :raises pycurl.exceptions: during the call of iam credential endpoint

        """
        logging.debug("Create buffers")
        buffers = StringIO()

        logging.debug("Prepare CURL to revoke cert '%s'", cert_id)
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, bytes(
            "{}/{}".format(self.config.iam.credential_endpoint, cert_id))
        )
        curl.setopt(pycurl.HTTPHEADER, [
            'Authorization: Bearer {}'.format(
                str(self.exchanged_token).split('\n', 1)[0]),
        ])
        curl.setopt(pycurl.CUSTOMREQUEST, "DELETE")
        curl.setopt(curl.WRITEFUNCTION, buffers.write)
        curl.setopt(curl.VERBOSE, True)

        try:
            logging.debug("Perform CURL call to DELETE '%s'", cert_id)
            curl.perform()
            status = curl.getinfo(curl.RESPONSE_CODE)
            logging.debug("Result status: %s", status)
            logging.debug("Close CURL")
            curl.close()
            logging.debug("Get body content")
            body = buffers.getvalue()
            logging.debug("Body: %s", body)
            body_dict = json.loads(body)
            if body_dict['result'] != "ok":
                return False
        except pycurl.error as error:
            errno, errstr = error
            logging.error(
                'A pycurl error n. %s occurred on DELETE: %s', errno, errstr)
            return False
        return True

    def get_exchange_token(self):
        """Retrieve the access token.

        Exchange the access token with the given client id and secret.
        The refresh token in cached and the exchange token is kept in memory.

        .. todo::
            Add controls (aggiungi controlli)

        """

        logging.debug("Prepare header")

        data = HTTPHeaderDict()
        data.add('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange')
        data.add('audience', self.config.audience)
        data.add('subject_token', self.iam.token)
        data.add('scope', 'openid profile offline_access')

        logging.debug("Call get exchanged token with data: '%s'", str(data))

        response = requests.post(self.config.iam.token_endpoint, data=data, auth=(
            self.iam.client_id, self.iam.client_secret), verify=True)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            # Whoops it wasn't a 200
            logging.error("Error in get exchange token: %s", err)
            return response.status_code

        result = json.loads(response.content)
        logging.debug("Result: %s", result)

        logging.debug("Override refresh token")
        with open('/tmp/refresh_token', 'w') as outf:
            outf.write(result["refresh_token"])
            self.cache.refresh_token.value = result["refresh_token"]

        return result["access_token"]

    def introspection(self, iam_client_id, iam_client_secret, exchanged_token):
        """Get info through introspection with the given client id, secret and token.

        .. todo::
            Add controls (aggiungi controlli)

        :param iam_client_id:
        :param iam_client_secret:
        :param exchanged_token: 

        """

        iam_client_id = self.iam.client_id
        iam_client_secret = self.iam.client_secret

        data = HTTPHeaderDict()
        data.add('token', exchanged_token)

        response = requests.post(self.config.iam.introspect_endpoint, data=data, auth=(
            iam_client_id, iam_client_secret), verify=False)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            # Whoops it wasn't a 200
            logging.error("Error in introspection: %s", err)
            logging.error("HTTP error. Response status: %s",
                          response.status_code)
            return response.status_code

        with open('/tmp/introspection', 'w') as outf:
            outf.write(response.content)

    def refresh_token(self, refresh_token):
        """Request with refresh token.

        .. todo::
            Manage result out of the function (gestisci result fuori dalla funzione)

        :param refresh_token: 

        """
        data = HTTPHeaderDict()
        data.add('client_id', self.iam.client_id)
        data.add('client_secret', self.iam.client_secret)
        data.add('grant_type', 'refresh_token')
        data.add('refresh_token', refresh_token)

        logging.debug("Refresh token. data: '%s'", str(data))

        response = requests.post(
            self.config.iam.token_endpoint, data=data, verify=True)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            # Whoops it wasn't a 200
            logging.error("Error in refresh_token: %s", err)
            logging.error("HTTP error. Response status: %s",
                          response.status_code)
            return response.status_code

        logging.debug("Response content: %s", response.content)
        result = json.loads(response.content)
        return result["access_token"]

    def get_tts_data(self, exchange=False):
        """Get TTS data using a lock procedure.

        Phases:
            - get lock
            - retrieve_tts_data
            - release lock

        :param exchange: Bool (Default value = False)

        """
        logging.debug("Check lock file %s", self.config.lock_file.path)
        if os.path.exists(self.config.lock_file.path):
            ctime = os.stat(self.config.lock_file.path).st_ctime
            age = time.time() - ctime
            logging.debug("Check age of %s: %s < %s",
                          self.config.lock_file.path, age, self.config.lock_file.age)
            if age < self.config.lock_file.age:
                logging.debug("Update in progres. Go to sleep...")
                time.sleep(self.config.lock_file.age - age)
            else:
                logging.debug("Stale lock file. Removing %s...",
                              self.config.lock_file.path)
                os.remove(self.config.lock_file.path)
        logging.debug("Update last use time of %s", self.config.lock_file.path)
        open(self.config.lock_file.path, 'w+').close()

        if exchange:
            logging.debug("Exchange /tmp/refresh_token")
            if self.cache.refresh_token.value == None:
                with file('/tmp/refresh_token') as refresh_t_file:
                    refresh_token = refresh_t_file.read()
                    logging.debug("Refresh token")
                    self.exchanged_token = self.refresh_token(
                        refresh_token.strip())
                    if isinstance(self.exchanged_token, int):
                        logging.error("Error in refresh_token")
            else:
                self.exchanged_token = self.refresh_token(
                    self.cache.refresh_token.value)
                if isinstance(self.exchanged_token, int):
                    logging.error("Error in refresh_token with Zookeeper")
                else:
                    with open('/tmp/refresh_token', 'w') as outf:
                        outf.write(self.cache.refresh_token.value)

        logging.debug("Refresh token")
        if self.get_certificate():

            logging.debug("Load json and prepare objects")
            with open('/tmp/output.json') as tts_data_file:
                tts_data = json.load(tts_data_file)

            with open(self.config.user.cert, 'w+') as cur_file:
                cur_file.write(
                    str(tts_data['credential']['entries'][0]['value']))

            with open(self.config.user.key, 'w+') as cur_file:
                cur_file.write(
                    str(tts_data['credential']['entries'][1]['value']))

            with open(self.config.user.passwd, 'w+') as cur_file:
                cur_file.write(
                    str(tts_data['credential']['entries'][2]['value']))

            try:
                logging.debug("Change user key mod")
                os.chmod(self.config.user.key, 0o600)
            except OSError as err:
                logging.error(
                    "Permission denied to chmod passwd file: %s", err)
                return False

            logging.debug("Remove lock")
            os.remove(self.config.lock_file.path)

            return True

        return False

    def generate_proxy(self):
        """Generates proxy with grid-proxy-init only if there are not errors."""

        if self.check_tts_data():
            logging.debug("Generating proxy for %s", self.exchanged_token)

            command = "grid-proxy-init -valid 160:00 -key {} -cert {} -out {} -pwstdin ".format(
                self.config.user.key, self.config.user.cert, self.config.user.proxy
            )
            with open(self.config.user.passwd) as my_stdin:
                my_passwd = my_stdin.read()
            proxy_init = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )

            logging.debug("Execute proxy")
            proxy_out, proxy_err = proxy_init.communicate(input=my_passwd)

            logging.debug("Proxy result: %s", proxy_init.returncode)
            if proxy_init.returncode > 0:
                logging.error("grid-proxy-init failed for token %s",
                              self.exchanged_token)
                logging.error("grid-proxy-init failed stdout %s", proxy_out)
                logging.error("grid-proxy-init failed stderr %s", proxy_err)
            else:
                return self.config.user.proxy
        else:
            logging.error("Error occured in check_tts_data!")


def get():
    """Execute the get_proxy routine."""
    logging.info("CALLING GET PROXY")

    # imports tokens, id and secret
    environment = {
        'IAM_TOKEN': os.environ.get("IAM_TOKEN", None),
        'IAM_REFRESH_TOKEN': os.environ.get("IAM_REFRESH_TOKEN", None),
        'IAM_CLIENT_ID': os.environ.get("IAM_CLIENT_ID", None),
        'IAM_CLIENT_SECRET': os.environ.get("IAM_CLIENT_SECRET", None),
        'MARATHON_USER': os.environ.get("MARATHON_USER", None),
        'MARATHON_PASSWD': os.environ.get("MARATHON_PASSWD", None),
        'ZOOKEEPER_HOST_LIST': os.environ.get("ZOOKEEPER_HOST_LIST", None),
        'CACHE_MANAGER': os.environ.get("CACHE_MANAGER", False)
    }

   # Open proxy config
    with open(CONFIG_FILE_PATH) as config_file:
        proxy_config = json.load(config_file)

    # Check for env variables to override
    for key in proxy_config:
        cur_key = "proxy_{}".format(key)
        cur_var = os.environ.get(cur_key.upper(), False)
        if cur_var:
            if isinstance(proxy_config[key], int):
                proxy_config[key] = int(cur_var)
            elif isinstance(proxy_config[key], float):
                proxy_config[key] = float(cur_var)
            else:
                proxy_config[key] = str(cur_var)

    # Store environment in config file
    proxy_config['environment'] = environment
    with open(CONFIG_FILE_PATH, "w") as config_file:
        json.dump(proxy_config, config_file)

    # Logging environment
    logging.info("IAM_TOKEN = %s", environment.get('IAM_TOKEN'))
    logging.info("IAM_REFRESH_TOKEN = %s",
                 environment.get('IAM_REFRESH_TOKEN'))
    logging.info("IAM_CLIENT_= %s", environment.get('IAM_CLIENT_ID'))
    logging.info("IAM_CLIENT_SECRET = %s",
                 environment.get('IAM_CLIENT_SECRET'))
    logging.info("MARATHON_USER = %s", environment.get('MARATHON_USER'))
    logging.info("MARATHON_PASSWD = %s", environment.get('MARATHON_PASSWD'))
    logging.info("ZOOKEEPER_HOST_LIST = %s",
                 environment.get('ZOOKEEPER_HOST_LIST'))
    logging.info("CACHE_MANAGER = %s", environment.get('CACHE_MANAGER'))

    cache_manager = None

    if environment.get('CACHE_MANAGER') == 'ZOOKEEPER' and environment.get('ZOOKEEPER_HOST_LIST') is not None:
        cache_manager = 'ZOOKEEPER'
    elif environment.get('CACHE_MANAGER') == 'MARATHON' and environment.get('MARATHON_USER') is not None and environment.get('MARATHON_PASSWD') is not None:
        cache_manager = 'MARATHON'
    elif environment.get('CACHE_MANAGER'):
        # CACHE MANAGER is set and is not recognized
        raise Exception("Unknown CACHE MANAGER")

    proxy_manager = ProxyManager(environment, cache_manager)
    proxy_file = proxy_manager.generate_proxy()

    if proxy_file is not None:
        header = {
            'Content-Type': "application/octet-stream",
            'filename': ".pem"
        }
        with open(proxy_file, 'rb') as file_:
            data = file_.read()
        return header, data

    logging.error("Cannot find Proxy file: '%s'", proxy_file)
    header = {
        'Content-Type': "text/html"
    }
    return header, "<p>grid-proxy-info failed</p>"
