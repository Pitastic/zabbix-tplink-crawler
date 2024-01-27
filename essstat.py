#!/usr/bin/env python3
# coding: utf-8
"""Parsing Stats via HTTP Request from a TP LINK Switch"""


__author__ = "Peter Smode"
__copyright__ = "Copyright 2021, Peter Smode"
__credits__ = "Peter Smode"
__license__ = "GPL 3.0"
__version__ = "0.6.0"
__maintainer__ = "Peter Smode"
__email__ = "psmode@kitsnet.us"
__status__ = "Beta"


import argparse
import pprint
import re
import sys
import json
from datetime import datetime
import requests
from bs4 import BeautifulSoup


def fetch_text(
        username: str, password: str, url: str, debug: bool = False) -> [BeautifulSoup, bool]:
    """Getting the HTML cpontent from the Switch"""
    if debug:
        print(f"Credentials are: {username} - {password} - {url}")

    s = requests.Session()

    data = {"logon": "Login", "username": username, "password": password}
    headers = {'Referer': f'{url}/Logout.htm'}
    try:
        r = s.post(f'{url}/logon.cgi', data=data, headers=headers, timeout=5)
    except requests.exceptions.Timeout as _:
        sys.exit("ERROR: Timeout Error at login")
    except requests.exceptions.RequestException as err:
        sys.exit("ERROR: General error at login: "+str(err))

    headers = {'Referer': f'{url}/',
               'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               'Upgrade-Insecure-Requests': "1"}
    r = s.get(f'{url}/PortStatisticsRpm.htm', headers=headers, timeout=6)

    soup = BeautifulSoup(r.text, 'html.parser')

    # TL-SG1016DE and TL-SG108E models have a script before the HEAD block
    convoluted = (soup.script == soup.head.script)

    if debug:
        pprint.pprint(convoluted)

        if convoluted:
            # This is the 24 port TL-SG1024DE model with the stats
            # in a different place (and convoluted coding)
            pprint.pprint(soup.head.find_all("script"))
            pprint.pprint(soup.body.script)

        else:
            # This should be a TL-SG1016DE or a TL-SG108E
            pprint.pprint(soup.script)

    if r.status_code != 200:
        sys.exit("ERROR: Login failure - bad credentials?")

    return soup, convoluted


def parse_text(soup: BeautifulSoup, debug: bool = False,
               mode_convoluted: bool = False) -> dict:
    """Parse the given text for port statistics"""

    pattern = re.compile(r"var (max_port_num) = (.*?);$", re.MULTILINE)

    if debug:

        if mode_convoluted:
            print(pattern.search(str(soup.head.find_all("script"))).group(0))
            print(pattern.search(str(soup.head.find_all("script"))).group(1))
            print(pattern.search(str(soup.head.find_all("script"))).group(2))

        else:
            print(pattern.search(str(soup.script)).group(0))
            print(pattern.search(str(soup.script)).group(1))
            print(pattern.search(str(soup.script)).group(2))

    if mode_convoluted:
        max_port_num = int(pattern.search(
            str(soup.head.find_all("script"))).group(2))

    else:
        max_port_num = int(pattern.search(str(soup.script)).group(2))

    if mode_convoluted:

        i1 = re.compile(
            r'tmp_info = "(.*?)";$',
            re.MULTILINE | re.DOTALL
        ).search(str(soup.body.script)).group(1)

        i2 = re.compile(
            r'tmp_info2 = "(.*?)";$',
            re.MULTILINE | re.DOTALL
        ).search(str(soup.body.script)).group(1)

        # We simulate bug for bug the way the variables are loaded on the "normal" switch models.
        # In those, each data array has two extra 0 cells at the end. To remain compatible with
        # the balance of the code here, we need to add in these redundant entries so they can
        # be removed later. (smh)
        script_vars = ('tmp_info:[' + i1.rstrip() +
                       ' ' + i2.rstrip() + ',0,0]').replace(" ", ",")

    else:
        script_vars = re.compile(
            r"var all_info = {\n?(.*?)\n?};$",
            re.MULTILINE | re.DOTALL
        ).search(str(soup.script)).group(1)

    if debug:
        print(script_vars)

    entries = re.split(",?\n+", script_vars)

    if debug:
        pprint.pprint(entries)

    edict = {}
    drop2 = re.compile(r"\[(.*),0,0]")
    for entry in entries:
        e2 = re.split(":", entry)
        edict[str(e2[0])] = drop2.search(e2[1]).group(1)

    if debug:
        pprint.pprint(edict)

    if mode_convoluted:
        e3 = {}
        e4 = {}
        e5 = {}
        ee = re.split(",", edict['tmp_info'])

        for x in range(0, max_port_num):
            e3[x] = ee[(x*6)]
            e4[x] = ee[(x*6)+1]
            e5[(x*4)] = ee[(x*6)+2]
            e5[(x*4)+1] = ee[(x*6)+3]
            e5[(x*4)+2] = ee[(x*6)+4]
            e5[(x*4)+3] = ee[(x*6)+5]

    else:
        e3 = re.split(",", edict['state'])
        e4 = re.split(",", edict['link_status'])
        e5 = re.split(",", edict['pkts'])

    return {'entry_dict': edict, 'entries': [e3, e4, e5], 'max_port_num': max_port_num}


def output_parsed(stats: dict, debug: bool = False,
                  o_statsonly: bool = False,
                  o_oneline: bool = False,
                  o_json: bool = False,
                  o_discover: bool = False) -> None:
    """Generate Script Output to stdout"""

    current_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not (o_statsonly or o_oneline or o_json or o_discover):
        print(current_dt)
        print(f"max_port_num={stats.get('max_port_num')}")

    if not o_json:

        if o_oneline:
            print(f"{current_dt},{stats.get('max_port_num')},", end="")
            output_format = "{0:d},{1:s},{2:s},{3:s},{4:s},{5:s},{6:s}"
            my_end = ","

        else:
            output_format = "{0:d};{1:s};{2:s};{3:s},{4:s},{5:s},{6:s}"
            my_end = "\n"

    pdict = {}
    jlist = []
    tp_state = {'0': 'Disabled', '1': 'Enabled'}
    tp_link_status = {
        '0': "Link Down",
        '1': "LS 1",
        '2': "10M Half",
        '3': "10M Full",
        '4': "LS 4",
        '5': "100M Full",
        '6': "1000M Full"
    }

    for x in range(1, stats.get('max_port_num')+1):

        if o_discover:
            state = stats.get('entries')[0][x-1]
            jlist.append({
                "{#PORTNUMBER}": x,
                "{#PORTSTATE}": state,
            })
            continue

        pdict[x] = {}

        if (o_oneline or o_json):
            pdict[x]['state'] = tp_state.get(
                stats.get('entries')[0][x-1],
                'unknown'
            )
            pdict[x]['link_status'] = tp_link_status.get(
                stats.get('entries')[1][x-1],
                'unknown'
            )

        else:
            pdict[x]['state'] = tp_state.get(
                stats.get('entries')[0][x-1],
                'unknown'
            )
            pdict[x]['link_status'] = tp_link_status.get(
                stats.get('entries')[1][x-1],
                'unknown'
            )

        pdict[x]['TxGoodPkt'] = stats.get('entries')[2][((x-1)*4)]
        pdict[x]['TxBadPkt'] = stats.get('entries')[2][((x-1)*4)+1]
        pdict[x]['RxGoodPkt'] = stats.get('entries')[2][((x-1)*4)+2]
        pdict[x]['RxBadPkt'] = stats.get('entries')[2][((x-1)*4)+3]

        if x == stats.get('max_port_num'):
            my_end = "\n"

        if o_json:
            z = {**{"port": x}, **pdict[x]}
            jlist.append(z)
            continue

        # Stats only
        print(output_format.format(x,
                                   pdict[x]['state'],
                                   pdict[x]['link_status'],
                                   pdict[x]['TxGoodPkt'],
                                   pdict[x]['TxBadPkt'],
                                   pdict[x]['RxGoodPkt'],
                                   pdict[x]['RxBadPkt']), end=my_end)

    if o_json or o_discover:

        json_object = json.dumps(jlist)
        print(json_object)

    if debug:
        pprint.pprint(pdict)

    return


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='TP-Link Easy Smart Switch port statistics.')
    parser.add_argument('target', metavar='TPhost',
                        help='IP address or hostname of switch')
    parser.add_argument('-1', '--1line', action='store_true',
                        help='output in a single line')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='activate debugging output')
    parser.add_argument('-j', '--json', action='store_true',
                        help='output in JSON format')
    parser.add_argument('-p', '--password', metavar='TPpswd',
                        required=True, help='password for switch access')
    parser.add_argument('-s', '--statsonly', action='store_true',
                        help='output post statistics only')
    parser.add_argument('-u', '--username', metavar='TPuser', required=False,
                        default='admin', help='username for switch access')
    parser.add_argument('-c', '--discover', action='store_true',
                        help='Zabbix Discovery mode outputs a list of ports only')
    args = vars(parser.parse_args())

    url = args['target']
    if not url.startswith('http'):
        url = "http://"+args['target']

    TPLstatsonly = args['statsonly']

    soup_instance, is_convoluted = fetch_text(args['username'], args['password'], url,
                                              debug=args['debug'])

    parsed = parse_text(soup_instance, mode_convoluted=is_convoluted,
                        debug=args['debug'])

    output_parsed(parsed,
                  o_statsonly=args['statsonly'],
                  o_oneline=args['1line'],
                  o_json=args['json'],
                  o_discover=args['discover'])
