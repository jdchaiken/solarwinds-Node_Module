#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Jarett D. Chaiken <jdc@salientcg.com>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community',
}

DOCUMENTATION = '''
---
module: orion_node
short_description: Created/Removes/Edits Nodes in Solarwinds Orion NPM
description:
    - "Create/Remove Nodes in Orion NPM"
version_added: "2.7"
author: "Jarett D Chaiken (@jdchaiken)"
options:
    hostname:
        description:
            - Name of Orion host running SWIS service
        required: true
    username:
        description:
            - Orion Username
            - Active Directory users must use DOMAIN\\username format
        required: true
    password:
        description:
            - Password for Orion user
        required: true
    state:
        description:
            - The desired state of the node
        required: false
        choices:
            - present
            - absent
            - managed
            - unmanaged
            - muted
            - unmuted
        default:
            - managed
    node_id:
        description:
            - node_id of the node
            - Must provide either an IP address, node_id, or exact node name
        required: false
    name:
        description:
            - Name of the node
            - For Adding a node this field is required
            - For All other states field is optional and partial names are acceptable
        required: false
    ip_address:
        description:
            - IP Address of the node
            - Must provide either an IP address, node_id, or exact node name
        required: false
    unmanage_from:
        description:
            - "The date and time (in ISO 8601 UTC format) to begin the unmanage period."
            - If this is in the past, the node will be unmanaged effective immediately.
            - If not provided, module defaults to now.
            - "ex: 2017-02-21T12:00:00Z"
        required: false
    unmanage_until:
        description:
            - "The date and time (in ISO 8601 UTC format) to end the unmanage period."
            - You can set this as far in the future as you like.
            - If not provided, module defaults to 24 hours from now.
            - "ex: 2017-02-21T12:00:00Z"
        required: false
    polling_method:
        description:
            - Polling method to use
        choices:
            - external_node
            - icmp
            - snmp
            - WMI
            - agent
            - vcenter
            - meraki
        default: snmp
        required: false
    ro_community_string:
        description:
            - SNMP Read-Only Community string
            - "Note: Required if using snmp polling"
        required: false
    rw_community_string:
        description:
            - SNMP Read-Write Community string
        required: false
    snmp_version:
        description:
            - SNMPv2c is used by default
            - SNMPv3 not support at this time
        choices:
            - 2
        default: 'snmpv2c'
        requried: false
    snmp_port:
        description:
            - port that SNMP server listens on
        required: false
        default: '161'
    snmp_allow_64:
        description:
            - Set true if device supports 64-bit counters
        type: bool
        default: true
        required: false
    wmi_credential:
        description:
            - 'Credential Name already configured in NPM  Found under "Manage Windows Credentials" section of the Orion website (Settings)'
            - "Note: creation of credentials are not supported at this time"
            - Required if using WMI polling
        required: false
    polling_engine:
        description:
            - ID of polling engine that NPM will use to poll this device
        required: false
    custom_properties:
        description:
            - A list of custom properties and their values
        required: false
requirements:
    - orionsdk
    - datetime
    - requests
    - traceback        
'''

EXAMPLES = '''
---

- name:  Remove a node from Orion
  orion_node:
	hostname: "<Hostname of orion server>"
	username: Orion Username
	password: Orion Password
	name: servername
	state: absent
'''

import traceback
from datetime import datetime, timedelta
import string
import re
from dateutil.parser import parse
import requests
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
try:
    from orionsdk import SwisClient
    HAS_ORION = True
except Exception as e:
    HAS_ORION = False

__SWIS__ = None

requests.urllib3.disable_warnings()


def run_module():
    '''
    Module Main Function
    '''
    global __SWIS__

    module_args = {
        'hostname': {'required': True},
        'username': {'required': True, 'no_log': True},
        'password': {'required': True, 'no_log': True},
        'state': {
            'required': False,
            'choices': [
                'present',
                'absent',
                'managed',
                'unmanaged',
                'muted',
                'unmuted',
            ],
            'default': 'managed'
        },
        'node_id': {'required': False},
        'ip_address': {'required': False},
        'name': {'required': False},
        'unmanage_from': {'required': False, 'default': None},
        'unmanage_until': {'required': False, 'default': None},
        'polling_method': {
            'required': False,
            'choices': [
                'External',
                'ICMP',
                'SNMP',
                'WMI',
                'Agent'],
            'default': 'SNMP'
        },
        'ro_community_string': {'required': False, 'no_log': True},
        'rw_community_string': {'required': False, 'no_log': True},
        'snmp_version': {'required': False, 'default': '2'},
        'snmp_port': {'required': False, 'default': '161'},
        'snmp_allow_64': {'required': False, 'default': True},
        'wmi_credential': {'required': False, 'no_log': True},
        'polling_engine': {'required': False},
        'custom_properties': {'required': False, 'default': {}}

    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_ORION:
        module.fail_json(msg='orionsdk required for this module')

    options = {
        'hostname': module.params['hostname'],
        'username': module.params['username'],
        'password': module.params['password'],
    }

    __SWIS__ = SwisClient(**options)

    try:
        __SWIS__.query('SELECT uri FROM Orion.Environment')
    except Exception as e:
        module.fail_json(
            msg='Failed to query Orion. '
                'Check Hostname, Username, and/or Password: {0}'.format(str(e))
            )

    if module.params['state'] == 'present':
        add_node(module)
    elif module.params['state'] == 'absent':
        remove_node(module)
    elif module.params['state'] == 'managed':
        remanage_node(module)
    elif module.params['state'] == 'unmanaged':
        unmanage_node(module)

def _get_node(module):
    node = {}
    if module.params['node_id'] is not None:
        results = __SWIS__.query(
            'SELECT NodeID, Caption, Unmanaged, UnManageFrom, UnManageUntil, Uri  FROM Orion.Nodes WHERE NodeID = '
            '@node_id',
            node_id=module.params['node_id']
            )
    elif module.params['ip_address'] is not None:
        results = __SWIS__.query(
            'SELECT NodeID, Caption, Unmanaged, UnManageFrom, UnManageUntil, Uri  FROM Orion.Nodes WHERE IPAddress = '
            '@ip_address',
            ip_address=module.params['ip_address']
        )
    elif module.params['name'] is not None:
        results = __SWIS__.query(
            "SELECT NodeID, Caption, Unmanaged, UnManageFrom, UnManageUntil, Uri "
            "FROM Orion.Nodes WHERE Caption like "
            "@name",
            name='%'+module.params['name']+'%'
        )
    else:
        # No Id provided
        module.fail_json(msg='You must provide either a node_id, ip_address, or name')

    if results['results']:
        node['nodeid'] = results['results'][0]['NodeID']
        node['caption'] = results['results'][0]['Caption']
        node['netobjectid'] = 'N:{}'.format(node['nodeid'])
        node['unmanaged'] = results['results'][0]['Unmanaged']
        node['unmanagefrom'] = parse(results['results'][0]['UnManageFrom']).isoformat()
        node['unmanageuntil'] = parse(results['results'][0]['UnManageUntil']).isoformat()
        node['uri'] = results['results'][0]['Uri']
    return node

def _validate_fields(module):
    # Setup properties for new node
    props = {
        'IPAddress': module.params['ip_address'],
        'Caption': module.params['name'],
        'ObjectSubType': module.params['polling_method'].upper(),
        'Community': module.params['ro_community_string'],
        'RWCommunity': module.params['rw_community_string'],
        'SNMPVersion': module.params['snmp_version'],
        'AgentPort':  module.params['snmp_port'],
        'Allow64BitCounters': module.params['snmp_allow_64'],
        'EngineID': module.params['polling_engine'],
        'External': lambda x: True if module.params['polling_method'] =='EXTERNAL' else False,
    }

    # Validate required fields
    if not props['IPAddress']:
        module.fail_json(msg='IP Address Parameter is required')

    if not props['External']:
      if not props['Caption']:
          module.fail_json(msg='Node name is required to add a node')

    if not props['ObjectSubType']:
        module.fail_json(msg='Polling Method is required [External, SNMP, ICMP, WMI, Agent]')
    elif props['ObjectSubType'] == 'SNMP':
        if not props['ro_community_string']:
            module.fail_json(msg='Read-Only Community String is required')
    elif props['ObjectSubType'] == 'WMI':
        if not props['wmi_credential']:
            module.fail_json(msg='WMI Credential is required')
    elif props['ObjectSubType'] == 'EXTERNAL':
        props['ObjectSubType'] = 'ICMP'

    if not props['SNMPVersion']:
        props['SNMPVersion'] = 2
    if not props['AgentPort']:
        props['AgentPort'] = 161
    if not props['Allow64BitCounters']:
        props['Allow64BitCounters'] = True

    if not props['EngineID']:
        props['EngineID'] = 1

    return props

def _add_wmi_credentials(module, node, **props):

    # Check if passed credential is valid
    cred = __SWIS__.query(
          "SELECT ID FROM Orion.Credential WHERE Name = "
          "@wmi_credential",
          wmi_credential= module.params['wmi_credential'])

    if cred['ID']:  # Valid credential passed - Add to Orion.NodeSettings
        nodesettings = {
            'nodeid': node['nodeid'],
            'SettingName': 'WMICredential',
            'SettingValue': str(cred['ID']),
        }
        __SWIS__.create('Orion.NodeSettings', **nodesettings)
    else:  # Invalid Credential
        module.fail_json(msg='Invalid Credential id {0}'.format(module.params['wmi_credential']), **cred)

def _add_pollers(module, node, external):

    pollers_enabled = {
        'N.Status.ICMP.Native': True,
        'N.Status.SNMP.Native': False,
        'N.ResponseTime.ICMP.Native': True,
        'N.ResponseTime.SNMP.Native': False,
        'N.Details.SNMP.Generic': True,
        'N.Uptime.SNMP.Generic': True,
        'N.Cpu.SNMP.HrProcessorLoad': True,
        'N.Memory.SNMP.NetSnmpReal': True,
        'N.AssetInventory.Snmp.Generic': True,
        'N.Topology_Layer3.SNMP.ipNetToMedia': False,
        'N.Routing.SNMP.Ipv4CidrRoutingTable': False
    }

    if not external:
      pollers = []
      for k in pollers_enabled:
          pollers.append(
              {
                  'PollerType': k,
                  'NetObject': 'N:' + node['nodeid'],
                  'NetObjectType': 'N',
                  'NetObjectID': node['nodeid'],
                  'Enabled': pollers_enabled[k]
              }
          )

      for poller in pollers:
          print("Adding poller type: {} with status {}...".format(poller['PollerType'], poller['Enabled']), end="")
          try:
              __SWIS__.create('Orion.Pollers', **poller)
          except Exception:
              module.fail_json(**poller)

def add_node(module):

    # Check if node already exists
    node = _get_node(module)

    if node:
        module.exit_json(changed=False, ansible_facts=node)

    ## Validate Fields
    props = _validate_fields(module)

    # Add Node
    try:
        __SWIS__.create('Orion.Nodes', **props)
        node['changed'] = True
    except Exception as e:
        module.fail_json(msg='Failed to add {}'.format(str(e)), **props)

    #### If Node is a WMI node, assign credential
    if props['ObjectSubType'] == 'WMI':
      _add_wmi_credentials(module, node, **props)


    ## Add Pollers
    _add_pollers(module, node, lambda x: True if props['External'] else False)


    ## Add Custom Properties
    custom_properties = lambda x: module.params['custom_properties'] if module.params['custom_properties'] else {},

    if not props['External']:
      try:
          node = _get_node(module)
      except Exception as e:
          module.fail_json(msg='Error adding Custom properties {}'.format(str(e)))

      if type(custom_properties) is dict:
        for k in custom_properties.keys():
            try:
                __SWIS__.update(node['Uri'] + '/CustomProperties', k=custom_properties[k])
                module.exit_json(mgs="{0} has been added".format(node['caption']), **node)

            except Exception as e:
                module.fail_json(msg='Failed to add custom properties',**node)

    module.exit_json()

def remove_node(module):
    node = _get_node(module)
    if not node:
        module.exit_json(changed=False)

    try:
        __SWIS__.delete(node['uri'])
        node['changed'] = True
        module.exit_json(**node)
    except Exception as e:
        module.fail_json(msg='Error removing node {}'.format(str(e)), **node)

def remanage_node(module):
    node = _get_node(module)
    if not node:
        module.fail_json(msg='Node not found')
    elif not node['unmanaged']:
        module.exit_json(changed=False)

    try:
        __SWIS__.invoke('Orion.Nodes', 'Remanage', node['netobjectid'])
        module.exit_json(changed=True, msg="{0} has been remanaged".format(node['caption']))
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

def unmanage_node(module):
    now = datetime.utcnow()
    tomorrow = now + timedelta(days=1)

    node = _get_node(module)

    unmanage_from = module.params['unmanage_from']
    unmanage_until = module.params['unmanage_until']

    if not unmanage_from:
        unmanage_from = now
    if not unmanage_until:
        unmanage_until = tomorrow

    if not node:
        module.fail_json(msg='Node not found')
    elif node['unmanaged']:
        if unmanage_from == node['unManageFrom'] and unmanage_until == node['unManageUntil']:
            module.exit_json(changed=False)

    try:
        __SWIS__.invoke(
               'Orion.Nodes',
               'Unmanage',
               node['netobjectid'],
               unmanage_from,
               unmanage_until,
               False  # use Absolute Time
        )
        msg = "{0} will be unmanaged from {1} until {2}".format(
            node['nodeid'],
            unmanage_from,
            unmanage_until
        )
        module.exit_json(changed=True,  msg=msg)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

def mute_node(module):
    
    #Check if Node exists 
    node = _get_node(module)

    if not node:
        module.fail_json(msg='Node not found')

    # Check if already muted
    suppressed = __SWIS__.invoke('Orion.AlertSuppression','GetAlertSuppressionState',[node['uri']])
    
    # If already muted, check if parameters changed
    if suppressed['suppressFrom'] == module.params['unmanage_from'] and suppressed['suppressUntil'] == module.params['unmanage_until']:
        node['changed']=False
        module.exit_json(changed=True, ansible_facts=node)

    # Otherwise Mute Node with given parameters
    try:
        __SWIS__.invoke(
            'Orion.AlertSuppression',
            'SuppressAlerts', 
            EntityUris=[node['uri']], 
            suppressFrom=module.params['unmanage_from'],
            suppressUntil =  module.params['unmanage_until']
        )    
        node['changed'] = True
        module.exit_json(changed=True, ansible_facts=node)
    except:
        module.fail_json(msg="Unable to mute {0}".format(node['caption']), ansible_facts=node)

    

    
def unmute_node(module):
    
    node = _get_node(module)
    if not node:
        module.fail_json(msg='Node not found')
    
    # Check if already muted
    suppressed = __SWIS__.invoke('Orion.AlertSuppression','GetAlertSuppressionState',[node['uri']])
    
    if not suppressed:
        node['changed'] = False
        module.exit_json(changed=False, ansible_facts=node)
    else:
        __SWIS__.invoke('Orion.AlertSuppression', 'ResumeAlerts', entityUris=[node['uri']])
        node['changed'] = True
        module.exit_json(changed=True, ansible_facts=node)


def main():
    run_module()

if __name__ == "__main__":
    main()
