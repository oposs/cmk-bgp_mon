#!/usr/bin/env python3
# Copyright (C) 2023 OETIKER+PARTNER AG – License: GNU General Public License v2

import json
from typing import Any, Mapping
from pprint import pprint
from collections import namedtuple

from cmk.utils import debug
from cmk.base.plugins.agent_based.agent_based_api.v1 import register, Result, Metric, Service, State
from cmk.base.plugins.agent_based.agent_based_api.v1.type_defs import (
    CheckResult,
    DiscoveryResult,
    StringTable,
)

Section = Mapping[str, Any]


def parse_bgp_mon_sessions(string_table: StringTable) -> Section:
    bgp_class = namedtuple('bgp_class',['inventory','result'])
    parsed = bgp_class(inventory=[],result={})
    for row in string_table:
        data=json.loads(row[0])
        service = 'AS' + data['neighbouras'] + ' ' + data['neighbourid']
        parsed.inventory.append(service)
        parsed.result[service] = data
    return parsed

def discover_sessions(section: Section) -> DiscoveryResult:
    if debug.enabled():
        print("DEBUG Discover Section:")
        pprint(section)
    for service in section.inventory:
        yield Service(
            item=service,
            parameters=section.result[service],
        )


def check_bgp_mon_sessions(item: Any, section: Section) -> CheckResult:
    result = section.result.get(item, {})
    if debug.enabled():
        print("DEBUG Check Section:")
        pprint(item)
        pprint(result)
    session_status = result.get("state", "").lower()
    for key in ['vrf-name-out', 'af-name', 'neighbourid', 'neighbouras']:
        yield Result(state=State.OK, summary=f"{key}: {result.get(key,'n/a')}")

    if "uptime" in result and result["uptime"] is not None:
        yield Metric(
            name="uptime",
            value=float(result["uptime"]),
        )

    yield Result(
        state=State.OK if session_status == 'established' else
        State.CRIT if session_status == 'idle' else
        State.WARN,
        summary=f"state: {result.get('state','n/a')}",
    )


register.agent_section(
    name="bgp_mon_sessions",
    parse_function=parse_bgp_mon_sessions,
)

register.check_plugin(
    name="bgp_mon_sessions",
    service_name="BGP %s",
    discovery_function=discover_sessions,
    check_function=check_bgp_mon_sessions,
)