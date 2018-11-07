#!/usr/bin/python
# Copyright: (c) 2018 Digital Energy Cloud Solutions LLC
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)

#
# Author: Sergey Shubin (sergey.shubin@digitalenergy.online)
#

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: decs_vm
short_description: Manage virtual data centers (aka protected private network segments) in DECS cloud
description: >
     This module can be used to create a virtual data center in Digital Energy cloud platform, modify its 
     characteristics, enable/disable its external network link, configure network port forwarding rules and 
     delete a virtual data center.
version_added: "2.2"
author:
     - Sergey Shubin <sergey.shubin@digitalenergy.online>
requirements:
     - python >= 2.6
     - PyJWT
     - decs_utils library module
notes:
     - Environment variables can be used to pass selected parameters to the module, see details below.
     - Specified Oauth2 provider must be trusted by the DECS cloud controller on which JWT will be used.
     - 'Similarly, JWT supplied in I(authenticator=jwt) mode should be received from Oauth2 provider trusted by
       the DECS cloud controller on which this JWT will be used.'
options:
    app_id:
        description:
        - 'Application ID for authenticating to the DECS controller when I(authenticator=oauth2).'
        - 'Required if I(authenticator=oauth2).'
        - 'If not found in the playbook or command line arguments, the value will be taken from DECS_APP_ID 
           environment variable.'
        required: no
    app_secret:
        description:
        - 'Application API secret used for authenticating to the DECS controller when I(authenticator=oauth2).'
        - This parameter is required when I(authenticator=oauth2) and ignored in other modes.
        - 'If not found in the playbook or command line arguments, the value will be taken from DECS_APP_SECRET 
           environment variable.'
        required: no
    authenticator:
        description:
        - Authentication mechanism to be used when accessing DECS controller and authorizing API call.
        default: jwt
        choices: [ jwt, oauth2, legacy ]
        required: yes
    controller_url:
        description:
        - URL of the DECS controller that will be contacted to manage the VM according to the specification.
        - 'This parameter is always required regardless of the specified I(authenticator) type.'
        required: yes
    datacenter:
        description:
        - Name of the data center where a new VDC to accommodate a VM being created should be provisioned first.
        - This parameter is required when creating VM and a non-existent target VDC is specified by name.
        - Name of the data center should be exactly as defined in the target DECS controller.
        - This parameter is case sensitive.
        required: no
    jwt:
        description:
        - 'JWT (access token) for authenticating to the DECS controller when I(authenticator=jwt).'
        - 'This parameter is required if I(authenticator=jwt) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECS_JWT environment variable.
        required: no
    oauth2_url:
        description:
        - 'URL of the oauth2 authentication provider to use when I(authenticator=oauth2).'
        - 'This parameter is required when when I(authenticator=oauth2).'
        - If not specified in the playbook, the value will be taken from DECS_OAUTH2_URL environment variable.
    password:
        description:
        - 'Password for authenticating to the DECS controller when I(authenticator=legacy).'
        - 'This parameter is required if I(authenticator=legacy) and ignored in other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECS_PASSWORD environment variable.
        required: no
    port_forwards:
        description:
        - List of port forwarding rules for the VM.
        - 'Each rule is a dictionary with the following keys:'
        - ' - I(ext_port) (integer) - external port number;'
        - ' - I(int_port) (integer) - internal port number;'
        - ' - I(proto) (string) - protocol name, valid values are C(tcp) and C(udp).'
        - 'If I(port_forwards) is specified for an existing VM and requested I(state) is one of C(present), C(paused),
          C(poweredoff) or C(poweredon), then for each port forwarding rule specified:'
        - ' - If the rule is not yet configured for the VM, it will be created;'
        - ' - If the rule already exists for this VM, no action will be done;'
        - ' - If some rule exists for this VM but not listed in the specified rules, it will be deleted.'
        required: no
    quotas:
        description:
        - Dictionary that defines resource quotas to be set on a newly created VDC.
        - 'This parameter is optional and only used when creating new VDC. It is ignored for any operations on an 
          existing VDC.'
        - 'The following keys are valid to set the resource quotas:'
        - ' - I(cpu) (integer) - limit on the total number of CPUs that can be consumed by VMs in this VDC.'
        - ' - I(ram) (integer) - limit on the total amount of RAM in GB that can be consumed by VMs in this VDC.'
        - ' - I(disk) (integer) - limit on the total volume of disk space in GB that can be consumed by VMs 
          in this VDC'
        - ' - I(ext_ips) (integer) - maximum number of external IP addresses that can be allocated to the VMs in
          this VDC'
        - 'Each of the above keys is optional. For example, you may specify I(cpu) and I(ram) while omitting the 
        other two keys. Then the quotas will be set on RAM and CPU leaving disk volume and the number of external 
        IP addresses unlimited.'
        required: no
    state:
        description:
        - Specify the desired state of the virtual data center at the exit of the module.
        - 'Regardless of I(state), if VDC exists and is in one of [DEPLOYING, DESTROYING, MIGRATING, ] states, 
          do nothing.'
        - 'If desired I(state=present):'
        - ' - VDC does not exist or is in DESTROYED state, create it according to the specifications.'
        - ' - VDC is in one of [VIRTUAL, DEPLOYED] states, change quotas if necessary, change VFW state if necessary.'
        - ' - VDC is in DELETED state, restore it and change quotas if necessary.'
        - ' - VDC is in DISABLED state, enable VFW and change quotas if necessary.'
        - 'If desired I(state=enabled):'
        - ' - VDC does not exist or is in DESTROYED state, create it according to the specifications.'
        - ' - VDC is in VIRTUAL state, deploy VFW, change quotas if necessary.'
        - ' - VDC is in DEPLOYED state, change quotas if necessary.'
        - ' - VDC is in DELETED state, restore it, change quotas if necessary.'
        - 'If desired I(state=absent):'
        - ' - VDC is in one of [VIRTUAL, DEPLOYED, DELETED] states, destroy it.'
        - 'If desired I(state=disabled):'
        - ' - VDC does not exist or is in one of [DELETED, DESTROYED] state, abort with an error.'
        - ' - VDC is in one of [VIRTUAL, DISABLED] states, change quotas if necessary.'
        - ' - VDC is in DEPLOYED state, change quotas if necessary and disable the VFW.'
        default: present
        choices: [ absent, disabled, enabled, present ]
    tenant:
        description:
        - 'Name of the tenant under which the VDC will be deployed (for new VDCs) or is located (if identifying an
          existing VDC by I(vdc_name)).'
        - 'This parameter is required for creating a new VDC.'
        - 'This parameter is ignored if an existing VDC is located by I(vdc_id).'
        required: no
    user:
        description:
        - 'Name of the legacy user for authenticating to the DECS controller when I(authenticator=legacy).'
        - 'This parameter is required when I(authenticator=legacy) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECS_USER environment variable.
        required: no
    vdc_id:
        description:
        - ID of the VDC to manage.
        - 'Either I(vdc_id) or a pair of I(vdc_name) and I(tenant) is required to locate and manage VDC.'
        - 'If both I(vdc_id) and I(vdc_name) are specified, I(vdc_name) will be ignored.'
        required: no
    vdc_name:
        description:
        - Name of the VDC where the VM will be deployed (for new VMs) or can be found (for existing VMs).
        - 'If both I(vdc_id) and I(vdc_name) are specified, I(vdc_name) will be ignored.'
        required: no
    workflow_callback:
        description:
        - 'Callback URL that represents an application, which invokes this module (e.g. up-level orchestrator or 
          end-user portal) and may except out-of-band updates on progress / exit status of the module run.'
        - API call at this URL will be used to relay such information to the application.
        - 'API call payload will include module-specific details about this module run and I(workflow_context).'
        required: no
    workflow_context:
        description:
        - 'Context data that will be included into the payload of the API call directed at I(workflow_callback) URL.'
        - 'This context data is expected to uniquely identify the task carried out by this module invocation so 
           that up-level orchestrator could match returned information to the its internal entities.'
        required: no
'''

EXAMPLES = '''
- name: create a VM named "SimpleVM" in the OVC cloud along with VDC named "ANewVDC" if it does not exist yet.
    decs_vdc:
      authenticator: oauth2
      app_id: {{ MY_APP_ID }}
      app_secret: {{ MY_APP_SECRET }}
      controller_url: "https://ds1.digitalenergy.online"
      vdc_name: SimpleVDC
      quotas:
        cpu: 16
        ext_ips: 4
      state: present
      tenant: "GreyseDevelopment"
    delegate_to: localhost
    register: simple_vdc
'''

RETURN = '''
vdc_facts:
    description: facts about the virtual machine 
    returned: always
    type: dict
    sample: None
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

from ansible.module_utils.decs_utility import *

def decs_vdc_parameters():
    """Build and return a dictionary of parameters expected by decs_vdc module in a form accepted
    by AnsibleModule utility class."""

    return dict(
        app_id=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECS_APP_ID'])),
        app_secret=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECS_APP_SECRET'])),
        authenticator=dict(type='str',
                           required=True,
                           choices=['legacy', 'oauth2', 'jwt']),
        controller_url=dict(type='str', required=True),
        datacenter=dict(type='str', required=False, default=''),
        # iconf
        jwt=dict(type='str',
                 required=False,
                 fallback=(env_fallback, ['DECS_JWT'])),
        oauth2_url=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECS_OAUTH2_URL'])),
        password=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECS_PASSWORD'])),
        # port_forwards=dict(type='list', default=[], required=False),
        quotas=dict(type='dict', required=False),
        state=dict(type='str',
                   default='present',
                   choices=['absent', 'disabled', 'enabled', 'present']),
        tenant=dict(type='str', required=False, default=''),
        user=dict(type='str',
                  required=False,
                  fallback=(env_fallback, ['DECS_USER'])),
        vdc_id=dict(type='int', default=0),
        vdc_name=dict(type='str', default=""),
        # wait_for_ip_address=dict(type='bool', required=False, default=False),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

# Workflow digest:
# 1) authenticate to DECS controller & validate authentication by issuing API call - done when creating DECSController
# 2) check if the VDC with the specified id or vdc_name:name exists
# 3) if VDC does not exist -> deploy
# 4) if VDC exists: check desired state, desired configuration -> initiate action accordingly
# 5) report result to Ansible

def main():
    module_parameters = decs_vdc_parameters()

    amodule = AnsibleModule(argument_spec=module_parameters,
                            supports_check_mode=True,
                            mutually_exclusive=[
                                ['oauth2', 'password'],
                                ['password', 'jwt'],
                                ['jwt', 'oauth2'],
                            ],
                            required_together=[
                                ['app_id', 'app_secret'],
                                ['user', 'password'],
                            ],
                            required_one_of=[
                                ['vdc_id', 'vdc_name'],
                            ],
                            )

    decon = DECSController(amodule,
                           amodule.params['authenticator'], amodule.params['controller_url'],
                           amodule.params['jwt'],
                           amodule.params['app_id'], amodule.params['app_secret'], amodule.params['oauth2_url'],
                           amodule.params['user'], amodule.params['password'],
                           amodule.params['workflow_callback'], amodule.params['workflow_context'])

    # Check if the VDC with the specified parameters already exists
    vdc_id, vdc_facts = decon.vdc_find(arg_vdc_id=amodule.params['vdc_id'],
                                       arg_vdc_name=amodule.params['vdc_name'],
                                       arg_check_state=False)
    vdc_should_exist = True

    if vdc_id:
        if vdc_facts['status'] in ("DEPLOYING", "DESTROYING", "MIGRATING"):
            # nothing to do for an existing VDC in the listed states regardless of the requested state
            decon.result['failed'] = False
            decon.result['changed'] = False
            decon.result['msg'] = ("No change can be done for existing VDC ID {} because of its current "
                                   "status '{}'").format(vdc_id, vdc_facts['status'])
        elif vdc_facts['status'] == "VIRTUAL":
            if amodule.params['state'] == 'absent':
                decon.vdc_delete(arg_vdc_id=vdc_id, arg_permanently=True)
                vdc_should_exist = False
            elif amodule.params['state'] in ('present', 'disabled'):
                decon.vdc_quotas(vdc_facts, amodule.params['quotas'])
            elif amodule.params['state'] == 'enabled':
                decon.vdc_quotas(vdc_facts, amodule.params['quotas'])
                decon.vdc_vfwstate(vdc_facts, 'deploy')
        elif vdc_facts['status'] == "DISABLED":
            if amodule.params['state'] == 'absent':
                decon.vdc_delete(arg_vdc_id=vdc_id, arg_permanently=True)
                vdc_should_exist = False
            elif amodule.params['state'] in ('present', 'disabled'):
                # nop / quotas
                decon.vdc_quotas(vdc_facts, amodule.params['quotas'])
            elif amodule.params['state'] == 'enabled':
                decon.vdc_quotas(vdc_facts, amodule.params['quotas'])
                decon.vdc_vfwstate(vdc_facts, amodule.params['state'])
        elif vdc_facts['status'] == "DEPLOYED":
            if amodule.params['state'] == 'absent':
                decon.vdc_delete(arg_vdc_id=vdc_id, arg_permanently=True)
                vdc_should_exist = False
            elif amodule.params['state'] in ('present', 'enabled'):
                decon.vdc_quotas(vdc_facts, amodule.params['quotas'])
            elif amodule.params['state'] == 'disabled':
                decon.vdc_vfwstate(vdc_facts, amodule.params['state'])
                decon.vdc_quotas(vdc_facts, amodule.params['quotas'])
        elif vdc_facts['status'] == "DELETED":
            if amodule.params['state'] in ('present', 'enabled'):
                # TODO: check if restore VDC API returns the new VDC ID of the restored VDC instance.
                decon.vdc_restore(arg_vdc_id=vdc_id)
                # TODO: Not sure what to do with the quotas after VDC is restored. May need to update vdc_facts.
                vdc_should_exist = True
                pass
            elif amodule.params['state'] == 'absent':
                # nop
                decon.result['failed'] = False
                decon.result['changed'] = False
                decon.result['msg'] = ("No state change required for VDC ID {} because of "
                                       "its current status '{}'").format(vdc_id, vdc_facts['status'])
                vdc_should_exist = False
            elif amodule.params['state'] == 'disabled':
                # error
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for VDC ID {} in the "
                                       "current status '{}'").format(vdc_id,
                                                                     amodule.params['state'],
                                                                     vdc_facts['status'])
        elif vdc_facts['status'] == "DESTROYED":
            if amodule.params['state'] in ('present', 'enabled'):
                # need to re-provision VDC
                decon.check_amodule_argument('tenant')  # each of the following calls will abort if argument is missing
                decon.check_amodule_argument('datacenter')
                decon.check_amodule_argument('vdc_name')
                # try to find tenant by name and get its ID
                tenant_id, _ = decon.tenant_find(amodule.params['tenant'])
                if tenant_id:
                    # now that we have tenant ID we can create VDC and get vdc_id on success
                    vdc_id = decon.vdc_provision(tenant_id, amodule.params['datacenter'],
                                                 amodule.params['vdc_name'], decon.decs_username,
                                                 amodule.params['quotas'])
                    vdc_should_exist = True
                else:
                    decon.result['failed'] = True
                    decon.result['msg'] = ("Current user does not have access to the requested tenant "
                                           "name '{}' or non-existent tenant specified.").format(
                        amodule.params['tenant'])
            elif amodule.params['state'] == 'absent':
                decon.result['failed'] = False
                decon.result['changed'] = False
                decon.result['msg'] = ("No state change required for VDC ID {} because of its "
                                       "current status '{}'").format(vdc_id,
                                                                     vdc_facts['status'])
                vdc_should_exist = False
            elif amodule.params['state'] == 'disabled':
                decon.result['failed'] = True
                decon.result['changed'] = False
                decon.result['msg'] = ("Invalid target state '{}' requested for VM ID {} in the "
                                       "current status '{}'").format(vdc_id,
                                                                     amodule.params['state'],
                                                                     vdc_facts['status'])
    else:
        # Preexisting VDC was not found.
        vdc_should_exist = False  # we will change it back to True if VDC is explicitly created or restored
        # If requested state is 'absent' - nothing to do
        if amodule.params['state'] == 'absent':
            decon.result['failed'] = False
            decon.result['changed'] = False
            decon.result['msg'] = ("Nothing to do as target state 'absent' was requested for "
                                   "non-existent VDC name '{}'").format(amodule.params['name'])
        elif amodule.params['state'] in ('present', 'enabled'):
            # Target VDC does not exist yet - create it and store the returned ID in vdc_id variable for later use
            # To create VDC we need tenant name (to obtain ist ID), datacenter name and new VDC name - check
            # that these parameters are present and proceed.
            decon.check_amodule_argument('tenant')  # each of the following calls will abort if argument is missing
            decon.check_amodule_argument('datacenter')
            decon.check_amodule_argument('vdc_name')
            # try to find tenant by name and get its ID
            tenant_id, _ = decon.tenant_find(amodule.params['tenant'])
            if tenant_id:
                # now that we have tenant ID we can create VDC and get vdc_id on success
                vdc_id = decon.vdc_provision(tenant_id, amodule.params['datacenter'],
                                             amodule.params['vdc_name'], decon.decs_username,
                                             amodule.params['quotas'],)
                vdc_should_exist = True
            else:
                # we failed to find a tenant with the specified name - no way to create VDC without tenant
                decon.result['failed'] = True
                decon.result['msg'] = ("Current user does not have access to the requested tenant "
                                       "name '{}' or non-existent tenant specified.").format(amodule.params['tenant'])
        elif amodule.params['state'] == 'disabled':
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("Invalid target state '{}' requested for non-existent "
                                   "VDC name '{}' ").format(amodule.params['state'],
                                                            amodule.params['vdc_name'])
    #
    # conditional switch end - complete module run
    if decon.result['failed']:
        amodule.fail_json(**decon.result)
    else:
        # prepare VDC facts to be returned as part of decon.result and then call exit_json(...)
        if vdc_should_exist and not amodule.check_mode:
            # If we arrive here, there is a good chance that the VDC is present - get fresh VDC facts from
            # the cloud by VDC ID.
            # Otherwise, VDC facts from previous call (when the VDC was still in existence) will be returned.
            _, decon.result['vdc_facts'] = decon.vdc_find(arg_vdc_id=vdc_id)
        amodule.exit_json(**decon.result)


if __name__ == "__main__":
    main()
