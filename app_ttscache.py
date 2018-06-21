#!/usr/bin/env python
#-*- coding: utf-8 -*-
from io import BytesIO
import logging

from flask import Flask, request, send_file, make_response

from proxy import get as get_proxy

APP = Flask(__name__)


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
            return response


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
