#!/usr/bin/env python3
# Copyright (C) 2023 OETIIKER+PARTNER AG – License: GNU General Public License v2

"""
Special agent for monitoring bgp Sessions with Check_MK.
"""

import argparse
import logging
import sys
import os
import json
import urllib3
urllib3.disable_warnings()
import requests
from cmk.utils.password_store import replace_passwords
from pprint import pprint
import re
from datetime import datetime
import time


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


def main(argv=None):
    replace_passwords()
    args = parse_arguments(argv or sys.argv[1:])
    sys.stdout.write("<<<bgp_mon_sessions:sep(0)>>>\n")
    try:
        if args.driver == "cisco_http" or args.driver == "cisco_https":
            for session in ciscoFetcher(
                args.hostaddress, args.username, args.password, args.driver,
            ).fetch():
                # turn the session content into a single line json string
                sys.stdout.write(json.dumps(session,sort_keys=True,separators=(',', ':')) + "\n")
        else:
            raise RuntimeError("Unknown driver")
    except Exception as e:
        sys.stdout.write(f"Error: {e}")
        sys.exit(1)
    sys.exit(0)
