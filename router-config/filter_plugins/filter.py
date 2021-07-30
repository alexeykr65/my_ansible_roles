#!/usr/bin/env python
"""
Author: Alexey
"""

import re
import ipaddress


class FilterModule(object):
    """
    Defines a filter module object.
    """

    @staticmethod
    def filters():
        """
        Return a list of hashes where the key is the filter
        name exposed to playbooks and the value is the function.
        """
        return {
            "ios_run_conf_nat": FilterModule.ios_run_conf_nat,
            "ios_run_conf_routing": FilterModule.ios_run_conf_routing,
        }

    @staticmethod
    def ios_run_conf_nat(text, flDel=False):
        if flDel:
            prefix_cmd = 'no '
        else:
            prefix_cmd = ''
        intrf_pattern = r"""
            \n(?P<intrf_name>interface\s+.*)\n(?P<intrf_cont>[^!]*)
        """
        intrf_cmd_pattern = r"""
            \n(?P<intrf_cmd>\s+ip\s+nat\s+.*)
        """
        router_cmd_pattern = r"""
            \n(?P<router_cmd>ip\snat.*)
        """
        reg_cmd = re.compile(router_cmd_pattern, re.VERBOSE)
        ret = ""
        items_routers = [match.groupdict() for match in reg_cmd.finditer(text)]
        for rt in items_routers:
            ret = f'{ret}{prefix_cmd}{rt["router_cmd"]}\n'

        reg_intrf = re.compile(intrf_pattern, re.VERBOSE)
        items_intrf = [match.groupdict() for match in reg_intrf.finditer(text)]
        reg_cmd = re.compile(intrf_cmd_pattern, re.VERBOSE)
        for intrf in items_intrf:
            if re.search('nat', intrf['intrf_cont'], re.MULTILINE):
                items_cmd = [match.groupdict() for match in reg_cmd.finditer(intrf['intrf_cont'])]
                cmd_cont = ""
                for cmd in items_cmd:
                    cmd_cont = f'{cmd_cont} {prefix_cmd}{cmd["intrf_cmd"]}\n'
                ret = f'{ret}{intrf["intrf_name"]}\n{cmd_cont}'
        return ret

    @staticmethod
    def ios_run_conf_routing(text, flDel=False):
        if flDel:
            prefix_cmd = 'no '
        else:
            prefix_cmd = ''
        router_cmd_pattern = r"""
            \n(?P<router_cmd>ip\sroute.*)
        """
        reg_cmd = re.compile(router_cmd_pattern, re.VERBOSE)
        ret = ""
        items_routers = [match.groupdict() for match in reg_cmd.finditer(text)]
        for rt in items_routers:
            ret = f'{ret}{prefix_cmd}{rt["router_cmd"]}\n'

        return ret
