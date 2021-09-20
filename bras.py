# -*- coding: utf8 -*-

import json
import logging
import requests
import sys
import traceback

from bs4 import BeautifulSoup
from js2py import EvalJs
from logging.handlers import SysLogHandler
from typing import Dict

data = {
    'username': 'MG2133xxxx',
    'password': 'passwooord'
}

encrypt_url = r'https://authserver.nju.edu.cn/authserver/custom/js/encrypt.js'
info_url = r'http://p.nju.edu.cn/api/portal/v1/getinfo'
auth_url = r'http://p.nju.edu.cn/cas/'

logging.basicConfig()
logger = logging.getLogger('BrasPy')
logger.setLevel(level=logging.INFO)
logger.addHandler(SysLogHandler())


def authenticate(session: requests.session) -> None:
    global data
    for key in ['username', 'password']:
        if key not in data:
            raise Exception('{} does not exist'.format(key))
    username = data['username']
    password = data['password']

    response = session.get(encrypt_url)
    if response.status_code != 200:
        raise IOError('Cannot get encrypt js (code={})'.format(response.status_code))
    context = EvalJs()
    context.execute(js=response.text)

    response = session.get(auth_url, allow_redirects=False)
    if response.status_code != 302:
        raise IOError('CAS login returned code {} instead of 302'.format(response.status_code))
    login_url = response.headers['Location']
    if login_url.startswith('http://'):
        login_url = 'https' + login_url[4:]
    
    response = session.get(login_url)
    if response.status_code != 200:
        raise IOError('Cannot get login page (code={})'.format(response.status_code))
    try:
        soup = BeautifulSoup(response.text, features='html.parser')
        salt = soup.select_one("#casLoginForm #pwdDefaultEncryptSalt").attrs['value']
        data = {
            'username': username,
            'password': context.encryptAES(password, salt),
            'lt': soup.select_one('#casLoginForm [name="lt"]').attrs['value'],
            'dllt': soup.select_one('#casLoginForm [name="dllt"]').attrs['value'],
            'execution': soup.select_one('#casLoginForm [name="execution"]').attrs['value'],
            '_eventId': soup.select_one('#casLoginForm [name="_eventId"]').attrs['value'],
            'rmShown': soup.select_one('#casLoginForm [name="rmShown"]').attrs['value']
        }
    except Exception:
        raise
    
    response = session.post(login_url, data, allow_redirects=False)
    if response.status_code != 302:
        raise IOError('Cannot post login page (code={}): {}'.format(response.status_code, repr(data)))
    callback_url = response.headers['Location']

    response = session.get(callback_url, allow_redirects=False)
    if response.status_code != 302:
        raise IOError('CAS callback returned code {} instead of 302'.format(response.status_code))
    logger.debug('CAS login success')


def fetch_info(session: requests.session) -> Dict[str, Dict]:
    response = session.get(info_url)
    if response.status_code != 200:
        raise IOError('Cannot get info api (code={})'.format(response.status_code))
    result = json.loads(response.text)
    if 'reply_code' not in result:
        raise IOError('Invalid info api response {}'.format(response.text))
    return result


def main() -> None:
    session = requests.session()

    info = fetch_info(session)
    if info['reply_code'] == 404:
        logger.debug('not authenticated')
        authenticate(session)
        info = fetch_info(session)

    for row in info['results']['rows']:
        ipv4 = '.'.join(map(lambda x: str((row['user_ipv4'] & (0xff << x)) >> x), [24, 16, 8, 0]))
        logger.info('{}\t{}\t{}'.format(row['mac'], ipv4, row['user_ipv6']))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info('*** interrupted ***')
        sys.exit(0)
    except Exception as e:
        trace = '\n'.join(['  ' + line for line in str(traceback.format_exc()).splitlines()])
        logger.critical('*** unhandled exception ***')
        logger.critical('Error: {}\n{}'.format(e, trace))
