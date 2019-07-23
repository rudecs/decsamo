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
module: decs_gpu
short_description: Manage on-demand GPU resources for virtual machines in DECS cloud
description: >
     This module can be used to manage on-demand GPU (graphical processor unit) resource allocation to
     a virtual machine in Digital Energy cloud platform and deallocation of previously allocated GPU 
     thus releasing corresponding resources back to a free pool.
version_added: "2.2"
author:
     - Sergey Shubin <sergey.shubin@digitalenergy.online>
requirements:
     - python >= 2.6
     - PyJWT module
     - requests module
     - decs_utils library module
notes:
     - This module will always put target VM into HALTED state before attempting to manipulate GPU resources.
     - To control VM state on module's exit use I(vm_state) parameter.
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
    gpu_config:
        description:
        - GPU specification provided as a dictionary.
        - This parameter is required when I(state=present) and igonred when I(state=absent).
        - 'Valid keys are:'
        - ' - I(type) (string) - desired type of GPU resource. Valid types are C(nvidia), C(amd), C(intel). In 
              the current implementation only C(nvidia) GPU type is supported. The module will convert the supplied
              string to uppercase when passing GPU type to upstream DECS API.'
        - ' - I(mode) (string) - desired mode of GPU resource. Valid modes are C(passthrough), C(virtual). The 
              module will convert the supplied string to uppercase when passing GPU type to upstream DECS API.
              In the current implementation only C(passthrough) mode is supported.'
        - ' - I(profile) (int) - desired virtual profile of GPU resource. Relevant for NVIDIA virtual GPUs only.
              Not supported in the current implementation.'
        - ' - I(ram) (int) - desired volume of FB RAM for the GPU resource. Relevant for AMD virtual GPUs only.
              Not supported in the current implementation.'
        - ' - I(count) (int) - how many instances of the specified GPU resource to allocate to the target VM. 
              Default is 1. Zero or negative values are invalid.'
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
    state:
        description:
        - Specify the desired state of the GPU resource(s) at the exit of the module.
        - 'If desired I(state=present):'
        - ' - there are no GPU resource(s) are currently allocated to the target VM - create them according
              to the I(gpu_config) specifications.'
        - ' - there already are some GPU resources allocated to the target VM, but they are of different 
              type & mode - delete all previously allocated resources and create the new one(s) according to
              the I(gpu_config) specification.'
        - ' - there already are some GPU resources allocated to the target VM exactly of the same type & mode,
              as specified in I(gpu_config) - make sure that the actual count of GPU resources matches the
              specification by adding or deleting as necessary.'
        - 'If desired I(state=absent), all GPU resources allocated to the target VM will be destroyed (if any).'
        default: present
        choices: [ present, absent ]
    user:
        description:
        - 'Name of the legacy user for authenticating to the DECS controller when I(authenticator=legacy).'
        - 'This parameter is required when I(authenticator=legacy) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECS_USER environment variable.
        required: no
    vdc_id:
        description:
        - ID of the VDC where the target VM can be found.
        - 'This parameter may be required when locating VM by I(vm_name).'
        - 'This parameter is not required when locating VM I(vm_id).'
        required: no
    vdc_name:
        description:
        - Name of the VDC where the target VM can be found.
        - 'This parameter may be required when locating VM by I(vm_name).'
        - 'If both I(vdc_id) and I(vdc_name) are specified, I(vdc_name) will be ignored.'
        required: no
    verify_ssl:
        description:
        - 'Controls SSL verification mode when making API calls to DECS controller. Set it to False if you
         want to disable SSL certificate verification. Intended use case is when you run module in a trusted
         environment that uses self-signed certificates. Note that disabling SSL verification in any other
         scenario can lead to security issues, so please know what you are doing.'
        default: True
        required: no
    vm_id:
        description:
        - ID of the VM for which GPU resource will be managed. VM must exist prior to calling this module.
        - 'Either I(vm_id) or a combination of VM name I(vm_name) and VDC related parameters (either I(vdc_id) or a pair of
           I(tenant) and I(vdc_name) is required.'
        - 'If the VM is identified by I(vm_id), then I(vm_name), I(vdc_name) or I(vdc_id) parameters will be ignored.'
        required: no
    vm_name:
        description:
        - Name of the VM for which GPU resources will be managed.
        - 'To manage VM by I(vm_name) you also need to specify either I(vdc_id) or a pair of I(vdc_name) and I(tenant).'
        - 'If both I(vm_name) and I(vm_id) are specified, I(vm_name) will be ignored and I(vm_id) used to locate the VM.'
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
- name: attach one GPU of type NVIDIA and mode PASSTHROUGH to VM "AITrainer" located in "Env01".
    decs_gpu:
      vm_name: "AITrainer"
      gpu_config:
        type: nvidia
        mode: passthrough
        count: 1
      state: present
      authenticator: oauth2
      app_id: {{ MY_APP_ID }}
      app_secret: {{ MY_APP_SECRET }}
      controller_url: "https://ds1.digitalenergy.online"
      vdc_name: "Env01"
    delegate_to: localhost
    register: aitrainer_gpu

- name: detach all GPUs (if any) from VM "AITrainer", located in "Env01".
    decs_gpu:
      vm_name: "AITrainer"
      state: absent
      authenticator: oauth2
      app_id: {{ MY_APP_ID }}
      app_secret: {{ MY_APP_SECRET }}
      controller_url: "https://ds1.digitalenergy.online"
      vdc_name: "Env01"
    delegate_to: localhost
'''

RETURN = '''
gpu_facts:
    description: list of GPU object IDs associated with the target VM on module's completion
    returned: always
    type: list
    sample:
      gpu_facts:
        - 101
        - 102
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.decs_utility import *

def gpu_build_parameters():
    """Build and return a dictionary of parameters expected by DECSAmo decs_gpu module in a form
    accepted by AnsibleModule utility class.
    This dictionary is then used y AnsibleModule class instance to parse and validate parameters
    passed to the module from the playbook.
    """

    return dict(
        app_id=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECS_APP_ID'])),
        app_secret=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECS_APP_SECRET']),
                        no_log=True),
        authenticator=dict(type='str',
                            required=True,
                            choices=['legacy', 'oauth2', 'jwt']),
        controller_url=dict(type='str', required=True),
        gpu_config=dict(type='dict', required=False),
        # count=dict(type='int', required=False, default=1),
        jwt=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECS_JWT']),
                    no_log=True),
        name=dict(type='str'),
        oauth2_url=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECS_OAUTH2_URL'])),
        password=dict(type='str',
                        required=False,
                        fallback=(env_fallback, ['DECS_PASSWORD']),
                        no_log=True),
        port_forwards=dict(type='list', default=[], required=False),
        state=dict(type='str',
                    default='present',
                    choices=['absent', 'present']),
        user=dict(type='str',
                    required=False,
                    fallback=(env_fallback, ['DECS_USER'])),
        vdc_id=dict(type='int', default=0),
        vdc_name=dict(type='str', default=""),
        vm_id=dict(type='int'),
        vm_name=dict(type='string'),
        vm_start=dict(type='bool', required=False, default=True),
        verify_ssl=dict(type='bool', required=False, default=True),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

#
# Workflow digest:
# 1) authenticate to DECS controller & validate authentication by issuing API call - done when creating DECSController
# 2) validate module arguments:
#       - check that VM identification is possible (vm_id, or vm_name plus on of tenant & vdc_name or vdc_id are specified)
#       - check if specified VM exists
#       - check that type is either NVIDIA or DUMMY and mode is PASSTHROUGH
# 3) Check if VM does have any GPUs currently attached
# 4) Proceed according to state value (present/absent) and characteristics of currently attached GPUs (if any)
# 5) report result to Ansible
#

def main():
    module_parameters = gpu_build_parameters()

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
                                ['vm_id', 'vm_name'],
                            ],
                            )

    # create DECS Controller instance - this will also validate authentication parameters and 
    # set up context for subsequent calls to DECS API
    decon = DECSController(amodule,
                           amodule.params['authenticator'], amodule.params['controller_url'],
                           amodule.params['jwt'],
                           amodule.params['app_id'], amodule.params['app_secret'], amodule.params['oauth2_url'],
                           amodule.params['user'], amodule.params['password'],
                           amodule.params['workflow_callback'], amodule.params['workflow_context'])

    vm_id, vm_info, _ = decon.vm_find(arg_vm_id=amodule.params['vm_id'],
                                      arg_vm_name=amodule.params['vm_name'],
                                      arg_vdc_id=amodule.params['vdc_id'],
                                      arg_vdc_name=amodule.params['vdc_name'],
                                      arg_check_state=True)

    def sure_halt_vm():
        """This is a convenience method that makes sure the VM is in HALTED state.
        As we require VM to be in HALTED state for GPU manipulation, this method will
        be used throughout the below code to facilitate such checks.

        Note: this method will abort module execition if the HALTED state is not reached
        within the specified amount of time (by default it is 6 attempts with 5 sec interval). 
        """
        decon.vm_powerstate(vm_info, 'poweredoff')
        if not decon.vm_wait4state(vm_id, 'HALTED'):
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("Failed to put VM ID {} to 'HALTED' state within the specified timeout.").format(vm_id)
            amodule.exit_json(**decon.result)
        return

    if not vm_id:
        decon.result['failed'] = True
        decon.result['changed'] = False
        decon.result['msg'] = ("Cannot find the specified VM: VM ID {}, VM name '{}', "
                               "VDC ID {}, VDC name '{}'.").format(amodule.params['vm_id'], amodule.params['vm_name'],
                                                                 amodule.params['vdc_id'], amodule.params['vdc_name'])
        amodule.fail_json(**decon.result)

    target_state = amodule.params['state'].lower()
    gpu_type = ""
    gpu_mode = ""
    gpu_count = 0
    ret_vgpus = [] # this will be filled with vGPU IDs that are attached to the VM on successful completion

    if  target_state == "present":
        if not ('type' in amodule.params['gpu_config'] and 'mode' in amodule.params['gpu_config']):
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = "For state='present' gpu_config must have both 'type' and 'mode' keys."
            amodule.fail_json(**decon.result)

        gpu_type = amodule.params['gpu_config']['type'].upper()
        gpu_mode = amodule.params['gpu_config']['mode'].upper()
        gpu_count = amodule.params['gpu_config'].get('count', 1)

        if gpu_count == 0:
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("Invalid GPU count {} specified for state='present'. "
                                   "GPU count must be positive.").format(gpu_count)
            amodule.fail_json(**decon.result)

        if gpu_type not in ('NVIDIA', 'DUMMY'):
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("GPU type '{}' not supported. Type(s) supported by your version "
                                "are 'NVIDIA' or 'DUMMY'.").format(gpu_type)
            amodule.fail_json(**decon.result)

        if gpu_mode != 'PASSTHROUGH':
            decon.result['failed'] = True
            decon.result['changed'] = False
            decon.result['msg'] = ("GPU mode '{}' not supported. Mode(s) supported by your version "
                                "are 'PASSTHROUGH'.").format(gpu_mode)
            amodule.fail_json(**decon.result)

    existing_gpus = decon.gpu_list(vm_id)

    if target_state == 'absent':
        if len(existing_gpus) != 0:
            # GPU list is not empty - we need to detach GPU(s)
            sure_halt_vm() # Note: this call will fail module execution if HALTED state is not reached
            # detach all GPUs - gpu_detach will return on success and fail module in case of any errors
            decon.gpu_detach(vm_id, -1)
            decon.result['changed'] = True
        else:
            decon.result['changed'] = False
            decon.result['msg'] = ("Nothing to do for GPU state='absent' when there are no "
                                   "GPUs currently allocated to VM ID {}.").format(vm_id)
    else: 
        # target state 'present'
        sure_halt_vm() # Note: this call will fail module execution if HALTED state is not reached
        # detach all existing GPUs (if any) - gpu_detach will return on success and fail module in case of any errors
        if len(existing_gpus) != 0:
            decon.gpu_detach(vm_id, -1)
        decon.result['changed'] = True
        # attach new GPU(s) according to the specs
        for _ in range (0, gpu_count):
            new_vgpu_id = decon.gpu_attach(vm_id, gpu_type, gpu_mode)
            ret_vgpus.append(new_vgpu_id)

    decon.result['failed'] = False
    if decon.result['changed'] and amodule.params['vm_start']:
        # if there were changes (which is an indicator of the fact that we've been halting the VM)
        # and vm_start is set to True, restart the VM
        decon.vm_powerstate(vm_info, 'poweredon')

    # "Package" resulting GPU facts (a list of vGPU IDs) and exit the module
    decon.result['vgpus'] = ret_vgpus
    amodule.exit_json(**decon.result)
    # end of main() function

if __name__ == "__main__":
    main()
