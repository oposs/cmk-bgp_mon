#!/usr/bin/env python3	
# Copyright (C) 2023 OETIIKER+PARTNER AG – License: GNU General Public License v2

"""
Special agent for monitoring bgp Sessions with Check_MK.
"""

import argparse
import logging
import sys
import traceback
import os
import json
import base64
import urllib3
urllib3.disable_warnings()
import requests
from cmk.utils.password_store import replace_passwords
from pprint import pprint
import re
from datetime import datetime, timedelta
import time
import xml.etree.ElementTree as ET

LOGGER = logging.getLogger(__name__)


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-u", "--username", required=True, type=str, help="user name")
    parser.add_argument(
        "-p", "--password", required=True, type=str, help="user password"
    )
    parser.add_argument(
        "-r", "--driver", required=True, type=str, help="communication driver name"
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Debug mode: raise Python exceptions"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        help="Be more verbose (use twice for even more)",
    )
    parser.add_argument("hostaddress", help="bgp_mon host name")

    args = parser.parse_args(argv)


    if args.verbose and args.verbose >= 2:
        fmt = "%(asctime)s %(levelname)s: %(name)s: %(filename)s: Line %(lineno)s %(message)s"
        lvl = logging.DEBUG
    elif args.verbose:
        fmt = "%(asctime)s %(levelname)s: %(message)s"
        lvl = logging.INFO
    else:
        fmt = "%(asctime)s %(levelname)s: %(message)s"
        lvl = logging.WARNING

    if args.debug:
        lvl = logging.DEBUG

    logging.basicConfig(level=lvl, format=fmt)

    return args


class ciscoFetcher:
    def __init__(self, hostaddress, username, password, driver) -> None:  # type:ignore[no-untyped-def]
        self._username = username
        self._password = password
        self._host = hostaddress
        self._driver = driver
        self._endpoint = ( "http://%s/ins" if driver == 'cisco_http' else "https://%s/ins" ) % self._host
        self._headers = {"content-type": "application.json-rpc"}

    def __duration_string_to_seconds(self,duration_str):
        # Define a regular expression for extracting components
        pattern = re.compile(r'P(?:([0-9]+)Y)?(?:([0-9]+)M)?(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+)S)?)?')

        # Extract components from the duration string
        match = pattern.match(duration_str)
        years, months, days, hours, minutes, seconds = map(int, match.groups(default=0))

        # Get the current date and time
        current_date = datetime.now()

        # Use mktime to directly convert the adjusted date to epoch seconds
        epoch_seconds = int(time.mktime((
            current_date.year - years,
            current_date.month - months,
            current_date.day - days,
            current_date.hour - hours,
            current_date.minute - minutes,
            current_date.second - seconds,
            -1, -1, -1
        )))

        # Calculate the difference from the current time
        difference = int(datetime.now().timestamp()) - epoch_seconds

        return difference

    def fetch(self):
        # if host is test and file is readable
        if self._host == "test" and os.access("/tmp/cisco_bgp_data.json", os.R_OK):        
            with open("/tmp/cisco_bgp_data.json") as f:
                return self.__postprocess(json.load(f))

        response = requests.post(
            self._endpoint,
            headers=self._headers,
            auth=(self._username, self._password),
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "cli",
                    "params": {
                        "cmd": "show bgp vrf all all summary",
                        "version": 1
                    },
                    "id": 1,
                }
            ),
            verify=False,  # nosec
        )

        if response.status_code != 200:
            LOGGER.warning("response status code: %s", response.status_code)
            LOGGER.warning("response : %s", response.text)
            raise RuntimeError("Failed to fetch data")
        else:
            LOGGER.debug("success! response: %s", response.text)
            
        try:
            return self.__postprocess(response.json())
        except Exception as e:
            LOGGER.warning("error processing response: %s", e)
            LOGGER.warning("response : %s", response.text)
            raise ValueError("Got invalid data from host")

    def __postprocess(self, data):
        result = []
        # it seems results from different cisco devices are not necessarily
        # consistant
        if ("bgp_parameters" in data):
            data = data["bgp_parameters"]["value"]
        for vrf in data["result"]["body"]["TABLE_vrf"][
            "ROW_vrf"
        ]:
            if ("TABLE_af" not in vrf 
                or "ROW_af" not in vrf["TABLE_af"]):
                continue
            for af in vrf["TABLE_af"]["ROW_af"]:
                if ("TABLE_saf" not in af 
                    or "ROW_saf" not in af["TABLE_saf"]):
                    continue
                saf = af["TABLE_saf"]["ROW_saf"]
                if ("TABLE_neighbor" not in saf
                    or "ROW_neighbor" not in saf["TABLE_neighbor"]):
                    continue
                neighbors = saf["TABLE_neighbor"]["ROW_neighbor"]
                if isinstance(neighbors,dict):
                    neighbors = [neighbors]
                for neighbor in neighbors:
                        if ("vrf-name-out" in vrf
                            and "af-name" in saf
                            and "neighborid" in neighbor
                            and "neighboras" in neighbor
                            and "state" in neighbor):
                            nb = {
                                    "vrf-name-out": vrf["vrf-name-out"],
                                    "af-name": saf["af-name"],
                                    "neighbourid": neighbor["neighborid"],
                                    "neighbouras": neighbor["neighboras"],
                                    "state": neighbor["state"],
                                }
                            if "time" in neighbor:
                                nb["uptime"] = self.__duration_string_to_seconds(neighbor["time"])
                            result.append(nb)                        
        return result

class paloaltoFetcher:
    def __init__(self, args) -> None:  # type:ignore[no-untyped-def]
        self._username = args.username
        self._password = args.password
        self._host = args.hostaddress
        self._endpoint = "https://%s/api/"  % self._host
        self._debug = args.debug
        self._verbose = args.verbose

    def fetch(self):
        # if host is test and file is readable
        if self._host == "test" and os.access("/tmp/paloalto_bgp_data.xml", os.R_OK):        
            with open("/tmp/paloalto_bgp_data.xml") as f:
                return self.__postprocess(f.read())

        kg_response = requests.get(self._endpoint, {
                'type': "keygen",
                'user': self._username,
                'password': self._password,
            },
            verify=False,  # nosec
        )

        if kg_response.status_code != 200:
            LOGGER.warning("response status code: %s", response.status_code)
            LOGGER.warning("response : %s", response.text)
            raise RuntimeError("Failed to fetch key")
        else:
            LOGGER.debug("success! response: %s", response.text)

        kg_key = self.__getKey(kg_response.text)
        
        op_response = requests.get(self._endpoint, {
                'type': "op",
                'key': kg_key,
                'cmd': "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>",
            },
            verify=False,  # nosec
        )

        if op_response.status_code != 200:
            LOGGER.warning("response status code: %s", response.status_code)
            LOGGER.warning("response : %s", response.text)
            raise RuntimeError("Failed to fetch bgp status")
        else:
            LOGGER.debug("success! response: %s", response.text)
                    
        try:
            return self.__postprocess(response.text)
        except Exception as e:
            LOGGER.warning("error processing response: %s", e)
            LOGGER.warning("response : %s", response.text)
            raise ValueError("Got invalid data from host")

    def __getKey(self,xml):
        root = ET.fromstring(xml)
        status = root.attrib.get('status')
        if status != 'success':
            LOGGER.warning("Request failed. Got %s", xml)
            raise ValueError("Got no auth key")

        # Find the 'key' element
        key_element = root.find('.//key')
        if key_element is not None:
            LOGGER.debug("Got auth key: %s",key_element.text)
            return key_element.text
 
        LOGGER.warning("Failed to extract key from: %s");
        raise ValueError("Got no auth key")

    def __postprocess(self, xml):
        root = ET.fromstring(xml)
        status = root.attrib.get('status')

        if status != 'success':
            LOGGER.warning("Request failed. Got %s", xml)
            raise ValueError("Got no bgp status information")

        result = []
        for entry in root.findall('./result/entry'):
            vrf_name_out = entry.get('vr')            
            af_name = entry.find('./prefix-counter/entry').get('afi-safi')
            neighbourid = entry.find('peer-router-id').text
            state = entry.find('status').text
            uptime = entry.find('status-duration').text

            result.append({
                'vrf-name-out': vrf_name_out,
                'af-name': af_name,
                'neighbourid': neighbourid,
                'state': state,
                'uptime': int(uptime),
            })
            
        return result

class huaweiFetcher:
    # make sure to run 
    #  pip3 install pexpect
    # in the checkmk instance where this plugin is installed
    import pexpect
    timeout = 30

    def __init__(self, args) -> None:  # type:ignore[no-untyped-def]
        self._username = args.username
        self._password = args.password
        self._host = args.hostaddress
        self._debug = args.debug
        self._verbose = args.verbose
        
    def __more(self,cmd):
        # LOGGER.debug('sending: %s', cmd)
        self._child.sendline(cmd)
        index = 0
        output = ""
        while index == 0:
            index = self._child.expect(['---- More ----','<.+?>'],timeout=self.timeout)
            line = self._child.before
            # LOGGER.debug("got: %s",line)
            output += line
            if index == 0:
                self._child.send(' ')
        
        return re.sub(r"^.*\x1b\[42D","",output,flags=re.MULTILINE)

    def fetch(self):
        if self._host == "test":
            with open("/tmp/huawei_bgp_data.txt",'r',encoding='utf-8') as f:
                return self.__postprocess(f.read())
        # Initiate SSH session
        self._child = child = self.pexpect.spawn(f"ssh {self._username}@{self._host}", encoding='utf-8')
        password_prompt = ".*assword:"
        ssh_newkey = "Are you sure you want to continue connecting"
        output = ""
        try:
            # Handle initial connection prompt
            index = child.expect([ssh_newkey, password_prompt],timeout=self.timeout)
            if index == 0:
                child.sendline("yes")
                index = child.expect([password_prompt],timeout=self.timeout)
            # Handle authentication prompts
            if index == 1:
                child.sendline(self._password)
            # Expect switch prompt and execute command
            child.expect("<.+?>",timeout=self.timeout)
            output += self.__more("display bgp vpnv4 all peer verbose")
            output += self.__more("display bgp vpnv6 all peer verbose")
            child.sendline("exit")
        except:
            LOGGER.debug("failed to read data: %s", str(self._child))
            raise RuntimeError("Failed to fetch data "+str(self._child))

        try:
            LOGGER.debug("Sending output to postprocessing")
            return self.__postprocess(output)
        except:
            LOGGER.debug("failed to parse output")
            LOGGER.debug("response : %s", output)
            raise ValueError("Got invalid data from host")


    def __duration_string_to_seconds(self,duration_str):
        # Define a regular expression for extracting components
        pattern = re.compile(r'(?:([0-9]+)d)?(?:([0-9]+)h)?(?:([0-9]+)m)?(?:([0-9]+)s)?')

        # Extract components from the duration string
        match = pattern.match(duration_str)
        days, hours, minutes, seconds = map(int, match.groups(default=0))

        # Get the current date and time
        current_date = datetime.now()

        # Use mktime to directly convert the adjusted date to epoch seconds
        epoch_seconds = int(time.mktime((
            current_date.year,
            current_date.month,
            current_date.day - days,
            current_date.hour - hours,
            current_date.minute - minutes,
            current_date.second - seconds,
            -1, -1, -1
        )))

        # Calculate the difference from the current time
        difference = int(datetime.now().timestamp()) - epoch_seconds

        return difference


    def __postprocess(self, data):
        LOGGER.debug("Got data for postprocessing (%i bytes)", len(data))
        LOGGER.debug("DATA ============================\n%s", base64.encodebytes(data.encode('ascii')).decode('utf-8'))
        result = []
        pattern = r"""
            (family\sfor\sVPN\sinstance:\s+(?P<vrf_name_out>\S+))?\s+
            BGP\sPeer\sis\s(?P<neighbourid>[^\s,]+),\s+
                remote\sAS\s(?P<neighbouras>\S+).{0,190}
            BGP\scurrent\sstate:\s(?P<state>[^\s,]+)
                (?:,\sUp\sfor\s+(?P<uptime>\S+))?\s*\n
        """
        ip_pattern = re.compile(r"\d+\.\d+\.\d+\.\d+")
        for match in re.finditer(pattern, data, re.VERBOSE | re.DOTALL | re.IGNORECASE ):
            LOGGER.debug("Found Match --------------------\n%s",match.group(0));
            uptime = match.group("uptime")
            nb = {
                "vrf-name-out": match.group("vrf_name_out"),
                "af-name": "ipv4" if ip_pattern.search(match.group("neighbourid")) else "ipv6",
                "neighbourid": match.group("neighbourid"),
                "neighbouras": match.group("neighbouras"),
                "state": match.group("state"),
                "uptime": None if uptime is None else self.__duration_string_to_seconds(uptime)
            }
            result.append(nb)

        LOGGER.debug("Returning postprocessed data")
        return result

def main(argv=None):
    replace_passwords()
    args = parse_arguments(argv or sys.argv[1:])
    sys.stdout.write("<<<bgp_mon_sessions:sep(0)>>>\n")
    try:
        if args.driver == "cisco_http" or args.driver == "cisco_https":
            for session in ciscoFetcher(
                args.hostaddress, args.username, args.password,args.driver,
            ).fetch():
                # turn the session content into a single line json string
                sys.stdout.write(json.dumps(session,sort_keys=True,separators=(',', ':')) + "\n")
        elif args.driver == "huawei":
            for session in huaweiFetcher(args).fetch():
                # turn the session content into a single line json string
                sys.stdout.write(json.dumps(session,sort_keys=True,separators=(',', ':')) + "\n")
        elif args.driver == "paloalto":
            for session in paloaltoFetcher(args).fetch():
                # turn the session content into a single line json string
                sys.stdout.write(json.dumps(session,sort_keys=True,separators=(',', ':')) + "\n")
        else:
            raise RuntimeError("Unknown driver")
    except Exception as e:
        formatted_traceback = traceback.format_exc()
        print(formatted_traceback)
        print(f"Error: {e}")
        sys.exit(1)

    sys.exit(0)
