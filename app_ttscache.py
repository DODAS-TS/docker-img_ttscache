#!/usr/bin/env python
#-*- coding: utf-8 -*-
from io import BytesIO
import os
import requests
import json
import logging
from urllib3._collections import HTTPHeaderDict

from flask import Flask, request, send_file, make_response

from proxy import get as get_proxy

APP = Flask(__name__)


@APP.route('/get_dn_map', methods=['GET'])
def get_dn_map():
    """ Get users in iam group and generate DN-user map
    """

    endpoint = os.environ.get("PROXY_IAM_ENDPOINT")
    id = os.environ.get("IAM_MAP_CLIENT_ID")
    secret = os.environ.get("IAM_MAP_CLIENT_SECRET")
    group = os.environ.get("IAM_MAP_GROUP")

    logging.debug("Prepare header")

    data = {
        'client_id': id,
        'client_secret': secret,
        'grant_type': 'client_credentials', 'scope': 'scim:read'}

    logging.debug("Call get exchanged token with data: '%s'", str(data))

    response = requests.post(endpoint+"token", allow_redirects=True, data=data, verify=True)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        # Whoops it wasn't a 200
        logging.error("Error in get exchange token: %s", err)
        return response.status_code
    result = json.loads(response.content)
    logging.debug("Result: %s", result)

    d = HTTPHeaderDict()
    d.add('Authorization', 'Bearer '+str(result["access_token"]))
    response = requests.get(endpoint+"scim/Groups", allow_redirects=True, headers=d, verify=True)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        # Whoops it wasn't a 200
        logging.error("Error in get the user list: %s", err)
        return response.status_code
    result = json.loads(response.content)

    userTuples = []
    for grp in result['Resources']:
        if grp['displayName'] == group:
            logging.debug(grp)
            userTuples = [(x['display'], x['value']) for x in grp['members']]
            break
        elif group == "ALL":
            logging.debug(grp)
            for usr in grp['members']:
                userTuples.append((usr['display'], usr['value']))

    logging.debug("Send response")
    response = make_response(json.dumps({'userMap': userTuples}))
    response.headers['Content-Type'] = 'application/json'
    return response, 200


@APP.route('/get_proxy', methods=['GET'])
@APP.route('/cgi-bin/get_proxy', methods=['GET'])
def ttscache_get_proxy():
    """Get the proxy.


    :returns: the get_proxy content.

    """
    if request.method == 'GET':
        logging.debug("GET request")
        header, body = get_proxy()
        if 'filename' in header:
            logging.debug("Send certificate file")
            return send_file(
                BytesIO(body),
                attachment_filename=header.get('filename'),
                mimetype=header.get('Content-Type')
            )
        else:
            logging.debug("Send response")
            response = make_response(body)
            response.headers['Content-Type'] = header.get('Content-Type')
            return response, 500


@APP.route('/health', methods=['GET'])
def health():
    """Check app health."""
    return "OK", 200


if __name__ == '__main__':
    logging.basicConfig(filename='/var/log/ttscache/app.log',
                        format='[%(asctime)s][%(levelname)s][%(filename)s@%(lineno)d]->[%(message)s]',
                        level=logging.DEBUG)
    APP.logger.setLevel(logging.DEBUG)
    get_proxy()
    APP.run(host="0.0.0.0", port=80)
