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
short_description: Manage virtual machine in DECS cloud
description: >
     This module can be used to create a virtual machine in Digital Energy cloud platform from a specified OS image,
     modify virtual machine's CPU and RAM allocation, change its power state, configure network port forwarding rules,
     restart guest OS and delete a virtual machine thus releasing corresponding cloud resources.
version_added: "2.2"
author:
     - Sergey Shubin <sergey.shubin@digitalenergy.online>
requirements:
     - python >= 2.6
     - PyJWT module
     - requests module
     - decs_utils library module
notes:
     - Environment variables can be used to pass selected parameters to the module, see details below.
     - Specified Oauth2 provider must be trusted by the DECS cloud controller on which JWT will be used.
     - 'Similarly, JWT supplied in I(authenticator=jwt) mode should be received from Oauth2 provider trusted by
       the DECS cloud controller on which this JWT will be used.'
options:
    annotation:
        description:
        - 'Description of the VM. Valid at VM provisioning time and ignored for existing VMs.'
        required: no
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
    boot_disk:
        description:
        - Boot disk specification provided as a dictionary.
        - Boot disk cannot be removed from VM.
        - Size change is not supported by the module. Use DECS API if you need to manage existing disk size.
        - 'This parameter is required for VM creation, valid at VM creation time only and ignored for operations on
           existing VMs.'
        - 'Valid keys are:'
        - ' - I(size) (integer) - size of the disk in GB'
        - ' - I(model) (string) - model name of a storage resource provider. Valid model names are C(ovs), C(iscsi)'
        - ' - I(pool) (string) - pool from which boot disk resource will be provisioned. Pool names are storage
              model and DECS instance setup specific. If specified pool name is not found, it is expected that
              the platform will provision from C(default) pool, which must always be present.'
        required: no
    controller_url:
        description:
        - URL of the DECS controller that will be contacted to manage the VM according to the specification.
        - 'This parameter is always required regardless of the specified I(authenticator) type.'
        required: yes
    cpu:
        description:
        - Number of virtual CPUs to allocate for the VM.
        - This parameter is required for creating new VM and optional for other operations.
        - 'If you set this parameter for an existing VM, then the module will check if VM resize is necessary and do
          it accordingly. Note that resize operation on a running VM may generate errors as not OS images support
          hot resize feature.'
        required: no
    datacenter:
        description:
        - Name of the data center where a new VDC to accommodate a VM being created should be provisioned first.
        - This parameter is required when creating VM and a non-existent target VDC is specified by name.
        - Name of the data center should be exactly as defined in the target DECS controller.
        - This parameter is case sensitive.
        required: no
    data_disks:
        description:
        - The list of data disks to attach to the VM.
        - This parameter is valid at VM creation time only and is ignored for operations on existing VMs.
        - Data disks resize or removal is not supported by the module. Use DECS API to manage existing data disks.
        - 'Each data disk is specified as a dictionary with the following keys:'
        - ' - I(size) (integer) - size of the data disk in GB.'
        - ' - I(model) (string) - model name of the resource storage provider to use for disk deployment. Valid model
              names are C(ovs), C(iscsi).'
        - ' - I(pool) (string) -  pool name to deploy data disk to. Pool names are specific to storage model and
              DECS instance setup. If specified pool name is not found, it is expected that the platform will
              provision from the C(default) pool, which must always be present.'
        required: no
    ext_network:
        description:
        - Specify if an external network address should be attached to the VM.
        - Only one external network address can be attached to each VM (this limitation may be removed in the future).
        - 'It does not automatically configure virtual NIC to be associated with the attached external network
          address at the quest OS level. You need to complete setup at guest OS level by writing a corresponding task.'
        - 'To get attached IP address you would typically check vm_facts["interfaces"][1]["ipAddress"] - a string
          formatted like "123.45.67.89/24"'
        - 'To get the default gateway address for the attached external IP address you would typically check
          vm_facts["interfaces"][1]["params"] - a string formatted like "gateway:123.45.67.1 externalnetworkid:1"'
        default: absent
        choices: [ present, absent ]
    ext_network_id:
        description:
        - 'Specify network ID from which the external IP address will be taken when external network assignment
          is requested.'
        - 'This parameter is optional and valid for creating external network assignment only, i.e. when
          I(ext_network=present).'
        - 'If no I(ext_network_id) is specified, the external IP address will be taken from default network'
        required: no
    id:
        description:
        - ID of the VM.
        - 'Either I(id) or a combination of VM name I(name) and VDC related parameters (either I(vdc_id) or a pair of
           I(tenant) and I(vdc_name) is required to manage an existing VM.'
        - 'This parameter is not required (and ignored) when creating new VM as VM ID is assigned by cloud platform
           automatically and cannot be changed afterwards. If existing VM is identified by I(id), then I(tenant),
           I(vdc_name) or I(vdc_id) parameters will be ignored.'
        required: no
    image_id:
        description:
        - ID of the OS image to use for VM provisioning.
        - 'This parameter is valid at VM creation time only and is ignored for operations on existing VMs.'
        - 'You need to know image ID, e.g. by extracting it with decs_imageid module and storing
           in a variable prior to calling decs_vm.'
        - 'If both I(image_id) and I(image_name) are specified, I(image_name) will be ignored.'
        required: no
    image_name:
        description:
        - Name of the OS image to use for a new VM provisioning.
        - 'This parameter is valid at VM creation time only and is ignored for operations on existing VMs.'
        - 'The specified image name will be looked up in the target DECS controller and error will be generated if
          no matching image is found.'
        - 'If both I(image_id) and I(image_name) are specified, I(image_name) will be ignored.'
        required: no
    jwt:
        description:
        - 'JWT (access token) for authenticating to the DECS controller when I(authenticator=jwt).'
        - 'This parameter is required if I(authenticator=jwt) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECS_JWT environment variable.
        required: no
    name:
        description:
        - Name of the VM.
        - 'To manage VM by I(name) you also need to specify either I(vdc_id) or a pair of I(vdc_name) and I(tenant).'
        - 'If both I(name) and I(id) are specified, I(name) will be ignored and I(id) used to locate the VM.'
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
    ram:
        description:
        - Size of RAM in MB to allocate to the VM.
        - This parameter is required for creating new VM and optional for other operations.
        - 'If you set this parameter for an existing VM, then the module will check if VM resize is necessary and do
          it accordingly. Note that resize operation on a running VM may generate errors as not all OS images support
          hot resize feature.'
        required: no
    ssh_key:
        description:
        - 'SSH public key to be deployed on to the new VM for I(ssh_key_user). If I(ssh_key_user) is not specified,
          the key will not be deployed, and a warning is generated.'
        - This parameter is valid at VM creation time only and ignored for any operation on existing VMs.
        required: no
    ssh_key_user:
        description:
        - User for which I(ssh_key) should be deployed.
        - If I(ssh_key) is not specified, this parameter is ignored and a warning is generated.
        - This parameter is valid at VM creation time only and ignored for any operation on existing VMs.
        required: no
    state:
        description:
        - Specify the desired state of the virtual machine at the exit of the module.
        - 'Regardless of I(state), if VM exists and is in one of [MIGRATING, DESTROYING, ERROR] states, do nothing.'
        - 'If desired I(state=check):'
        - ' - Just check if VM exists in any state and return its current specifications.'
        - ' - If VM does not exist, fail the task.'
        - 'If desired I(state=present):'
        - ' - VM does not exist, create the VM according to the specifications and start it.'
        - ' - VM in one of [RUNNING, PAUSED, HALTED] states, attempt resize if necessary, change network if necessary.'
        - ' - VM in DELETED state, restore and start it.'
        - ' - VM in DESTROYED state, recreate the VM according to the specifications and start it.'
        - 'If desired I(state=poweredon):'
        - ' - VM does not exist, create it according to the specifications.'
        - ' - VM in RUNNING state, attempt resize if necessary, change network if necessary.'
        - ' - VM in one of [PAUSED, HALTED] states, attempt resize if necessary, change network if necessary, next
              start the VM.'
        - ' - VM in DELETED state, restore it.'
        - ' - VM in DESTROYED state, create it according to the specifications.'
        - 'If desired I(state=absent):'
        - ' - VM in one of [RUNNING, PAUSED, HALTED] states, destroy it.'
        - ' - VM in one of [DELETED, DESTROYED] states, do nothing.'
        - 'If desired I(state=paused):'
        - ' - VM in RUNNING state, pause the VM, resize if necessary, change network if necessary.'
        - ' - VM in one of [PAUSED, HALTED] states, resize if necessary, change network if necessary.'
        - ' - VM in one of [DELETED, DESTROYED] states, abort with an error.'
        - 'If desired I(state=poweredoff) or I(state=halted):'
        - ' - VM does not exist, create the VM according to the specifications and leave it in HALTED state.'
        - ' - VM in RUNNING state, stop the VM, resize if necessary, change network if necessary.'
        - ' - VM in one of [PAUSED, HALTED] states, resize if necessary, change network if necessary.'
        - ' - VM in DELETED state, abort with an error.'
        - ' - VM in DESTROYED state, recreate the VM according to the specifications and leave it in HALTED state.'
        default: present
        choices: [ present, absent, poweredon, poweredoff, halted, paused, check ]
    tags:
        description:
        - String of custom tags to be assigned to the VM (This feature is not implemented yet!).
        - These tags are arbitrary text that can be used for grouping or indexing the VMs by other applications.
        required: no
    tenant:
        description:
        - 'Name of the tenant under which the VM will be deployed (for new VMs) if VM deployment also requires
          deployment of a named VDC (e.g. VDC I(vdc_name) is not found for I(tenant).'
        - 'This parameter is required for a new VM when target VDC is specified by I(vdc_name) and is not present.'
        - 'This parameter is not required for a new VM when target VDC is specified by I(vdc_id).'
        required: no
    user:
        description:
        - 'Name of the legacy user for authenticating to the DECS controller when I(authenticator=legacy).'
        - 'This parameter is required when I(authenticator=legacy) and ignored for other authentication modes.'
        - If not specified in the playbook, the value will be taken from DECS_USER environment variable.
        required: no
    vdc_id:
        description:
        - ID of the VDC where a new VM will be deployed or an existing VM can be found.
        - 'This parameter may be required when managing VM by its I(name).'
        - 'This parameter is not required when VM is located by I(id).'
        required: no
    vdc_name:
        description:
        - Name of the VDC where the VM will be deployed (for new VMs) or can be found (for existing VMs).
        - 'This parameter may be required when managing VM by its I(name).'
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
- name: create a VM named "SimpleVM" in the DECS cloud along with VDC named "ANewVDC" if it does not exist yet.
    decs_vm:
      annotation: "VM created by decs_vm module"
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://ds1.digitalenergy.online"
      name: SimpleVM
      cpu: 2
      ram: 4096
      boot_disk:
        size: 10
        model: ovs
        pool: boot
      image_name: "Ubuntu 16.04 v1.1"
      data_disks:
        - size: 50
          model: ovs
          pool: data
      port_forwards:
        - ext_port: 21022
          int_port: 22
          proto: tcp
        - ext_port: 80
          int_port: 80
          proto: tcp
      state: present
      tags: "PROJECT:Ansible STATUS:Test"
      tenant: "Development"
      vdc_name: "ANewVDC"
    delegate_to: localhost
    register: simple_vm
- name: resize the above VM to CPU 4 and remove port forward rule for port number 80.
    decs_vm:
      authenticator: jwt
      jwt: "{{ MY_JWT }}"
      controller_url: "https://ds1.digitalenergy.online"
      name: SimpleVM
      cpu: 4
      ram: 4096
      port_forwards:
        - ext_port: 21022
          int_port: 22
          proto: tcp
      state: present
      tenant: "Development"
      vdc_name: "ANewVDC"
    delegate_to: localhost
    register: simple_vm
- name: stop existing VM identified by the VM ID and down size it to CPU:RAM 1:2048 along the way.
    decs_vm:
      authenticator: jwt
      jwt: "{{ MY_JWT }}"
      controller_url: "https://ds1.digitalenergy.online"
      id: "{{ TARGET_VM_ID }}"
      cpu: 1
      ram: 2048
      state: poweredoff
    delegate_to: localhost
    register: simple_vm
- name: check if VM exists and read in its specs.
    decs_vm:
      authenticator: oauth2
      app_id: "{{ MY_APP_ID }}"
      app_secret: "{{ MY_APP_SECRET }}"
      controller_url: "https://ds1.digitalenergy.online"
      name: "{{ TARGET_VM_NAME }}"
      vdc_name: "{{ TARGET_VDC_NAME }}"
      tenant: "{{ TRAGET_TENANT }}"
      state: check
    delegate_to: localhost
    register: existing_vm
'''

RETURN = '''
vm_facts:
    description: facts about the virtual machine that may be useful in the playbook
    returned: always
    type: dict
    sample:
      vm_facts:
        id: 9454
        name: TestVM
        state: RUNNING
        username: testuser
        password: Yab!tWbyPF
        int_ip: 192.168.103.253
        vdc_name: SandboxVDC
        vdc_id: 2883
        vdc_ext_ip: 185.193.143.151
        ext_ip: 185.193.143.106
        ext_netmask: 24
        ext_gateway: 185.193.143.1
        ext_mac: 52:54:00:00:1a:24
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.decs_utility import *
class decsamo_vm(DECSController):
    def __init__(self, arg_amodule):
        # call superclass constructor first
        super(decsamo_vm, self).__init__(arg_amodule,
                                         arg_amodule.params['authenticator'],
                                         arg_amodule.params['controller_url'],
                                         arg_amodule.params['jwt'],
                                         arg_amodule.params['app_id'], arg_amodule.params['app_secret'],
                                         arg_amodule.params['oauth2_url'],
                                         arg_amodule.params['user'], arg_amodule.params['password'],
                                         arg_amodule.params['workflow_callback'], arg_amodule.params['workflow_context'])

        self.vm_id, self.vm_info, self.vdc_id = self.vm_find(arg_vm_id=arg_amodule.params['id'],
                                                              arg_vm_name=arg_amodule.params['name'],
                                                              arg_vdc_id=arg_amodule.params['vdc_id'],
                                                              arg_vdc_name=arg_amodule.params['vdc_name'],
                                                              arg_check_state=False)

        self.vm_should_exist = True
        if not self.vm_id:
            self.vm_should_exist = False
        return

    def nop(self):
        """No operation (NOP) handler for VM management by DECSAMo decs_vm module.
        This function is intended to be called from the main switch construct of the module
        when current state -> desired state change logic does not require any changes to
        the actual VM state.
        """
        self.result['failed'] = False
        self.result['changed'] = False
        if self.vm_id:
            self.result['msg'] = ("No state change required for VM ID {} because of its "
                                   "current status '{}'.").format(self.vm_id, self.vm_info['status'])
        else:
            self.result['msg'] = ("No state change to '{}' can be done for "
                                  "non-existent VM.").format(self.amodule.params['state'])
        return

    def error(self):
        """Error handler for VM management by DECSAMo decs_vm module.
        This function is intended to be called when an invalid state change is requested.
        Invalid means that the current is invalid for any operations on the VM or the transition
        from current to desired state is not technically possible.
        """
        self.result['failed'] = True
        self.result['changed'] = False
        if self.vm_id:
            self.result['msg'] = ("Invalid target state '{}' requested for VM ID {} in the "
                                   "current status '{}'.").format(self.vm_id,
                                                                  self.amodule.params['state'],
                                                                  self.vm_info['status'])
        else:
            self.result['msg'] = ("Invalid target state '{}' requested for non-existent VM name '{}' "
                                   "in VDC ID {} / VDC name '{}'").format(self.amodule.params['state'],
                                                                          self.amodule.params['name'],
                                                                          self.amodule.params['vdc_id'],
                                                                          self.amodule.params['vdc_name'])
        return

    def create(self):
        """New VM creation handler for VM management by DECSAMo decs_vm module.
        This function checks for the presence of required parameters, creates specified VDC if
        necessary and then deploys a new VM into the specified VDC.

        Note that this function requires DECORT API of version 3.3.1 or higher, as it expects
        the ability of the cloud platform to create VMs in HALTED state.
        """
        # the following parameters must be present: cpu, ram, image_name, boot_disk
        # each of the following calls will abort if argument is missing
        self.check_amodule_argument('cpu')
        self.check_amodule_argument('ram')
        self.check_amodule_argument('boot_disk')
        # either image_name or image_id must be present
        if not self.check_amodule_argument('image_name', abort=False):
            if not self.check_amodule_argument('image_id', abort=False):
                # neither image_name nor image_id are set - abort the script
                self.result['failed'] = True
                self.result['msg'] = "Missing both 'image_name' and 'image_id'. You need to specify one to create a VM."
                self.amodule.fail_json(**self.result)

        start_vm = True
        if self.amodule.params['state'] in ('halted', 'poweredoff'):
            start_vm = False

        # if we get through here, all parameters required to create a VM should be set
        # create VDC if necessary
        if not self.vdc_id:
            # target VDC does not exist yet - create it and store the returned ID in vdc_id variable for later use
            # To create VDC we need tenant name (to obtain ist ID), datacenter name and new VDC name - check
            # that these parameters are present and proceed. If any such check fails, check_amodule_argument calls will
            # abort the script
            self.check_amodule_argument('tenant')
            self.check_amodule_argument('datacenter')
            self.check_amodule_argument('vdc_name')
            if self.amodule.params['tenant'] and self.amodule.params['datacenter']:
                # try to find tenant by name and get its ID
                tenant_id, _ = self.tenant_find(self.amodule.params['tenant'])
                if tenant_id:
                    # now that we have tenant ID we can create VDC and get vdc_id on success
                    self.vdc_id = self.vdc_provision(tenant_id, self.amodule.params['datacenter'],
                                                     self.amodule.params['vdc_name'], self.decs_username)
                else:
                    # we failed to get tenant ID - it means we do not have access rights to that tenant
                    self.result['failed'] = True
                    self.result['msg'] = ("Current user does not have access to the requested tenant "
                                            "name '{}' or non-existent tenant specified.").format(
                        self.amodule.params['tenant'])
            else:
                # we miss either tenant or datacenter in the parameters - creating VDC is not possible
                self.result['failed'] = True
                self.result['msg'] = ("Cannot create VDC name '{}', because either datacenter or tenant "
                                        "parameter is missing or emtpy.").format(self.amodule.params['vdc_name'])
        # find OS image ID that is specified for the new VM
        osimage_facts = None
        if not self.result['failed']:
            # no errors in the workflow thus far and we have target VDC ID - next locate requested OS image
            if self.check_amodule_argument('image_id', abort=False) and self.amodule.params['image_id'] is not None:
                # we have image ID from the module parameters - use it as is
                osimage_facts = dict(id=self.amodule.params['image_id'])
            else:
                # no image ID specified, so we rely on image_name from module params - locate OS image by name
                osimage_facts = self.image_find(self.amodule.params['image_name'], self.vdc_id)
        if not self.result['failed'] and osimage_facts is not None:
            # no errors thus far and we have: target VDC ID and requested OS image ID - we are ready to
            # provision the VM
            if self.amodule.params['ssh_key'] and self.amodule.params['ssh_key_user']:
                cloud_init_params = {'users': [
                    {"name": self.amodule.params['ssh_key_user'],
                     "ssh-authorized-keys": [self.amodule.params['ssh_key']],
                     "shell": '/bin/bash'}
                    ]}
            else:
                cloud_init_params = None
            self.vm_id = self.vm_provision(arg_vdc_id=self.vdc_id, arg_vm_name=self.amodule.params['name'],
                                        arg_cpu=self.amodule.params['cpu'], arg_ram=self.amodule.params['ram'],
                                        arg_boot_disk=self.amodule.params['boot_disk'],
                                        arg_image_id=osimage_facts['id'],
                                        arg_data_disks=self.amodule.params['data_disks'],
                                        arg_annotation=self.amodule.params['annotation'],
                                        arg_userdata=cloud_init_params,
                                        arg_start_vm=start_vm)
            self.vm_info = self.vm_facts(arg_vm_id=self.vm_id, arg_vdc_id=self.vdc_id)
            self.vm_portforwards(self.vm_info, self.amodule.params['port_forwards'])
            self.vm_extnetwork(self.vm_info,
                               self.amodule.params['ext_network'], self.amodule.params['ext_network_id'],
                               25) # specify arg_force_delay=25 sec when calling vm_extnetwork as part of VM provisioning
            # TODO - configure tags for the new VM if corresponding parameters are specified
            # if decon.check_amodule_argument('tags', abort=False):
            #
            self.vm_should_exist = True
        return

    def destroy(self):
        """VM destroy handler for VM management by DECSAMo decs_vm module.
        Note that this handler deletes the VM permanently together with all assigned disk resources.
        """
        self.vm_delete(arg_vm_id=self.vm_id, arg_permanently=True)
        self.vm_should_exist = False
        return

    def restore(self):
        """VM restore handler for VM management by DECSAMo decs_vm module.
        Note that resotring VM is only possible if VM is in DELETED state. If called on a VM
        that is in any other state, the method will throw an error and abort the execution.
        """
        self.vm_restore(arg_vm_id=self.vm_id)
        # TODO - do we need updated vm_facts to manage port forwards and size after VM is restored?
        self.vm_info = self.vm_facts(arg_vm_id=self.vm_id, arg_vdc_id=self.vdc_id)
        self.modify()
        self.vm_should_exist = True
        return

    def modify(self, arg_wait_cycles=0):
        """VM modify handler for VM management by DECSAMo decs_vm module.
        This method is a convenience wrapper that calls individual VM modification functions as
        follows:
          - modify portforwards;
          - modify presence of direct external network attachment;
          - modify boot disk size;
          - modify CPU and RAM allocations.
        """
        self.vm_portforwards(self.vm_info, self.amodule.params['port_forwards'])
        self.vm_extnetwork(self.vm_info,
                           self.amodule.params['ext_network'], self.amodule.params['ext_network_id'])
        self.vm_bootdisk_size(self.vm_info, self.amodule.params['boot_disk'])
        self.vm_size(self.vm_info,
                     self.amodule.params['cpu'], self.amodule.params['ram'],
                     wait_for_state_change=arg_wait_cycles)
        return

    def package_facts(self, arg_vdc_facts=None, arg_check_mode=False):
        """Package a dictionary of VM facts according to the decs_vm module specification. This dictionary will
        be returned to the upstream Ansible engine at the completion of the module run.

        @param arg_vdc_facts: dictionary with VDC facts as returned by API call to .../cloudspaces/get
        @param arg_check_mode: boolean that tells if this Ansible module is run in check mode

        @return: dictionary of VM facts, containing suffucient information to manage the VM in subsequent tasks.
        """

        ret_dict = dict(id=0,
                    name="none",
                    state="CHECK_MODE",
                    username="",
                    password="",
                    vdc_id=0,
                    vdc_name="",
                    vdc_ext_ip="",
                    int_ip="",
                    ext_ip="",
                    ext_netmask="",
                    ext_gateway="",
                    ext_mac=""
                    )

        if arg_check_mode or self.vm_info is None:
            # if in check mode (or void facts provided) return immediately with the default values
            return ret_dict

        if not self.vm_should_exist:
            ret_dict['state'] = "ABSENT"
            return ret_dict

        ret_dict['id'] = self.vm_info['id']
        ret_dict['name'] = self.vm_info['name']
        ret_dict['state'] = self.vm_info['status']
        # if the VM is an imported VM, then the 'accounts' list may be empty,
        # so check for this case before trying to access login and passowrd values
        if len(self.vm_info['accounts']):
            ret_dict['username'] = self.vm_info['accounts'][0]['login']
            ret_dict['password'] = self.vm_info['accounts'][0]['password']

        ret_dict['vdc_id'] = self.vm_info['cloudspaceid']
        if arg_vdc_facts is not None:
            ret_dict['vdc_name'] = arg_vdc_facts['name']
            ret_dict['vdc_ext_ip'] = arg_vdc_facts['externalnetworkip']

        ret_dict['int_ip'] = self.vm_info['interfaces'][0]['ipAddress']

        # Look up external network in the provided arg_vm_dict - select the detected 1-st record of type PUBLIC
        # NOTE that current implementation does not support multiple direct IP addresses assigned to a VM, but this
        # may change in the future.
        for item in self.vm_info['interfaces']:
            if item['type'] == "PUBLIC":
                # 'ipAddress' value comes in the form like "192.168.1.10/24", so for IP address we need to split at "/"
                # and assign resulting list items accordingly
                ret_dict['ext_ip'], ret_dict['ext_netmask'] = item['ipAddress'].split("/", 1)
                # 'params' value has form 'gateway:185.193.143.1 externalnetworkId:2', so we need to split twice:
                # first by ":" and then by " " to get external gateway address
                ret_dict['ext_gateway'] = item['params'].split(":")[1].split(" ", 1)[0]
                # and the MAC address of the direct public interface
                ret_dict['ext_mac'] = item['macAddress']
                break

        return ret_dict

    @staticmethod
    def build_parameters():
        """Build and return a dictionary of parameters expected by DECSAmo decs_vm module in a form
        accepted by AnsibleModule utility class.
        This dictionary is then used y AnsibleModule class instance to parse and validate parameters
        passed to the module from the playbook.
        """

        return dict(
            annotation=dict(type='str',
                            default='',
                            required=False),
            # allow_restart=dict(type='bool', required=False, default=False),
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
            boot_disk=dict(type='dict', required=False),
            controller_url=dict(type='str', required=True),
            # count=dict(type='int', required=False, default=1),
            cpu=dict(type='int', required=False),
            # compute_nodes=dict(type='list', required=False, default=[])
            # create_vdc=dict(type='bool', required=False, default=False),
            datacenter=dict(type='str', required=False, default=''),
            data_disks=dict(type='list', default=[], required=False),
            ext_network=dict(type='str',
                             default='absent',
                             choices=['absent', 'present']),
            ext_network_id=dict(type='int', default=0, required=False),
            id=dict(type='int'),
            image_id=dict(type='int', required=False),
            image_name=dict(type='str', required=False),
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
            ram=dict(type='int', required=False),
            ssh_key=dict(type='str', required=False),
            ssh_key_user=dict(type='str', required=False),
            state=dict(type='str',
                       default='present',
                       choices=['absent', 'paused', 'poweredoff', 'halted', 'poweredon', 'present', 'check']),
            tags=dict(type='str', required=False),
            tenant=dict(type='str', required=False, default=''),
            user=dict(type='str',
                      required=False,
                      fallback=(env_fallback, ['DECS_USER'])),
            vdc_id=dict(type='int', default=0),
            vdc_name=dict(type='str', default=""),
            verify_ssl=dict(type='bool', required=False, default=True),
            # wait_for_ip_address=dict(type='bool', required=False, default=False),
            workflow_callback=dict(type='str', required=False),
            workflow_context=dict(type='str', required=False),
        )

# Workflow digest:
# 1) authenticate to DECS controller & validate authentication by issuing API call - done when creating DECSController
# 2) check if the VM with the specified id or vdc_name:name exists
# 3) if VM does not exist, check if there is enough resources to deploy it in the target account / vdc
# 4) if VM exists: check desired state, desired configuration -> initiate action accordingly
# 5) VM does not exist: check desired state -> initiate action accordingly
#       - create VM: check if target VDC exists, create VDC as necessary, create VM
#       - delete VM: delete VM
#       - change power state: change as required
#       - change guest OS state: change as required
# 6) report result to Ansible


def main():
    module_parameters = decsamo_vm.build_parameters()

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
                                ['id', 'name'],
                            ],
                            )

    # Initialize DECS VM instance object
    # This object does not necessarily represent an existing VM
    subj = decsamo_vm(amodule)

    # handle state=check before any other logic
    if amodule.params['state'] == 'check':
        subj.result['changed'] = False
        if subj.vm_id:
            # VM is found - package facts and report success to Ansible
            subj.result['failed'] = False
            subj.vm_info = subj.vm_facts(arg_vm_id=subj.vm_id, arg_vdc_id=subj.vdc_id)
            _, vdc_facts = subj.vdc_find(arg_vdc_id=subj.vdc_id)
            subj.result['vm_facts'] = subj.package_facts(vdc_facts, amodule.check_mode)
            amodule.exit_json(**subj.result)
            # we leave the module at this point
        else:
            subj.result['failed'] = True
            subj.result['msg'] = ("Cannot locate VM name '{}'. Other arguments are: VM ID {}, VDC name '{}', "
                                  "VDC ID {}, tenant '{}'.").format(amodule.params['name'],
                                                                    amodule.params['id'],
                                                                    amodule.params['vdc_name'],
                                                                    amodule.params['vdc_id'],
                                                                    amodule.params['tenant'])
            amodule.fail_json(**subj.result)
            pass

    if subj.vm_id:
        if subj.vm_info['status'] in ("MIGRATING", "DESTROYING", "ERROR"):
            # nothing to do for an existing VM in the listed states regardless of the requested state
            subj.nop()
        elif subj.vm_info['status'] == "RUNNING":
            if amodule.params['state'] == 'absent':
                subj.destroy()
            elif amodule.params['state'] in ('present', 'poweredon'):
                # check port forwards / check size / nop
                subj.modify()
            elif amodule.params['state'] in ('paused', 'poweredoff', 'halted'):
                # pause or power off the vm, then check port forwards / check size
                subj.vm_powerstate(subj.vm_info, amodule.params['state'])
                subj.modify(arg_wait_cycles=7)
        elif subj.vm_info['status'] in ("PAUSED", "HALTED"):
            if amodule.params['state'] == 'absent':
                subj.destroy()
            elif amodule.params['state'] in ('present', 'paused', 'poweredoff', 'halted'):
                subj.modify()
            elif amodule.params['state'] == 'poweredon':
                subj.modify()
                subj.vm_powerstate(subj.vm_info, amodule.params['state'])
        elif subj.vm_info['status'] == "DELETED":
            if amodule.params['state'] in ('present', 'poweredon'):
                # TODO - check if restore API returns VM ID (similarly to VM create API)
                subj.vm_restore(arg_vm_id=subj.vm_id)
                # TODO - do we need updated vm_facts to manage port forwards and size after VM is restored?
                subj.vm_info = subj.vm_facts(arg_vm_id=subj.vm_id, arg_vdc_id=subj.vdc_id)
                subj.modify()
            elif amodule.params['state'] == 'absent':
                subj.nop()
                subj.vm_should_exist = False
            elif amodule.params['state'] in ('paused', 'poweredoff', 'halted'):
                subj.error()
        elif subj.vm_info['status'] == "DESTROYED":
            if amodule.params['state'] in ('present', 'poweredon', 'poweredoff', 'halted'):
                subj.create()
                pass
            elif amodule.params['state'] == 'absent':
                subj.nop()
                subj.vm_should_exist = False
            elif amodule.params['state'] == 'paused':
                subj.error()
    else:
        # Preexisting VM was not found.
        # vm_should_exist = False  # now it is initialized in the decsamo_vm constructor
        # If requested state is 'absent' - exit immediately, as there is nothing to do
        if amodule.params['state'] == 'absent':
            subj.nop()
        elif amodule.params['state'] in ('present', 'poweredon', 'poweredoff', 'halted'):
            subj.create()
        elif amodule.params['state'] == 'paused':
            subj.error()

    if subj.result['failed']:
        amodule.fail_json(**subj.result)
    else:
        # prepare VM facts to be returned as part of decon.result and then call exit_json(...)
        vdc_facts = None
        if subj.vm_should_exist:
            if subj.result['changed']:
                # There were changes to the VM - refresh VM facts.
                subj.vm_info = subj.vm_facts(arg_vm_id=subj.vm_id, arg_vdc_id=subj.vdc_id)
            # we need to extract VDC facts regardless of 'changed' flag, as it is our source of information on
            # the VDC external IP address
            _, vdc_facts = subj.vdc_find(arg_vdc_id=subj.vdc_id)
        subj.result['vm_facts'] = subj.package_facts(vdc_facts, amodule.check_mode)
        amodule.exit_json(**subj.result)


if __name__ == "__main__":
    main()
