#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.


from cmk.gui.i18n import _
from cmk.gui.plugins.wato.special_agents.common import RulespecGroupDatasourcePrograms
from cmk.gui.plugins.wato.utils import (
    HostRulespec,
    MigrateToIndividualOrStoredPassword,
    rulespec_registry,
)
from cmk.gui.valuespec import Dictionary, DropdownChoice, TextInput

def _valuespec_special_agents_bgp_mon():
    return Dictionary(
        elements=[
            (
                "username", 
                TextInput(
                    title=_("Username"),
                    allow_empty=False)
            ),
            (
                "password",
                MigrateToIndividualOrStoredPassword(
                    title=_("Password"),
                    allow_empty=False,
                ),
            ),
            (
                "driver",
                DropdownChoice(
                    title=_("Driver"),
                    choices=[
                        ("cisco_http", _("Cisco Nexus 9000 HTTP")),
                        ("cisco_https", _("Cisco Nexus 9000 HTTPS")),
                        ("huawei", _("Huawei Sx700 SSH")),
                    ],
                    default="cisco_http",
                ),
            ),
        ],
        required_keys=["username", "password", "driver"],
        title=_("BGP Monitor"),
        help=_("This rule selects the bgp_mon special agent for an existing Checkmk host"),
    )


rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupDatasourcePrograms,
        name="special_agents:bgp_mon",
        valuespec=_valuespec_special_agents_bgp_mon,
    )
)
