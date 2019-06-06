#
# Copyright: (c) 2018 Digital Energy Cloud Solutions LLC
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)

#
# Author: Sergey Shubin (sergey.shubin@digitalenergy.online)
#

"""
This is the library of utility functions and classes for managing DECS cloud platform.

These classes are made aware of Ansible module architecture and designed to be called from the main code of an Ansible
module to fulfill cloud resource management tasks.

Methods defined in this file should NOT implement complex logic like building execution plan for an
upper level Ansible module. However, they do implement necessary sanity checks and may abort upper level module
execution if some fatal error occurs. Being Ansible aware, they usually do so by calling AnsibleModule.fail_json(...)
method with properly configured arguments.
"""

import copy
import json
import jwt
import time
import requests

from ansible.module_utils.basic import AnsibleModule

#
# TODO: the following functionality to be implemented and/or tested
# 2) vdc_delete - need decision if we allow force delete (any existing VMs to be deleted)
# 4) workflow callbacks
# 5) run phase states
# 6) vm_tags - set/manage VM tags
# 7) vm_attributes - change VM attributes (name, annotation) after VM creation - do we need this in Ansible?
# 9) test vm_restore() method and execution plans that involve vm_restore()
#


class DECSController(object):
    """DECSController is a utility class that holds target controller context and handles API requests formatting
    based on the requested authentication type.
    """

    VM_RESIZE_NOT = 0
    VM_RESIZE_DOWN = 1
    VM_RESIZE_UP = 2

    def __init__(self, arg_amodule,
                 arg_authenticator, arg_controller_url,
                 arg_jwt=None,
                 arg_app_id=None, arg_app_secret=None, arg_oauth2_url=None,
                 arg_user=None, arg_password=None,
                 arg_workflow_callback=None, arg_workflow_context=None):
        """
        Instantiate DECSController() class at the beginning of any DECS module run to have the following:
        - check authentication parameters to make sure all required parameters are properly specified
        - initiate test connection to the specified DECS controller and validates supplied credentias
        - store validated authentication information for later use by DECC API calls
        - store AnsibleModule class instance to keep handy reference to the module context

        If any of the required parameters are missing or supplied authentication information is invalid, an error
        message will be generated and execution aborted in a way, that lets Ansible to pick this information up and
        relay it upstream.
        """

        self.amodule = arg_amodule  # AnsibleModule class instance

        # Note that the value for 'changed' key is by default set to 'False'. If you plan to manage value of 'changed'
        # key outside of DECSController() class, make sure you only update to 'True' when you really change the state
        # of the object being managed.
        # The rare cases to reset it to False again will usually involve either module running in "check mode" or
        # when you detect and error and are about to call exit_json() or fail_json()
        self.result = {'failed': False, 'changed': False, 'waypoints': "Init"}

        self.authenticator = arg_authenticator.lower()
        self.controller_url = arg_controller_url

        self.jwt = arg_jwt
        self.app_id = arg_app_id
        self.app_secret = arg_app_secret
        self.oauth2_url = arg_oauth2_url
        self.password = arg_password
        self.user = arg_user
        self.session_key = ''
        # self.iconf = arg_iconf
        self.verify_ssl = arg_amodule.params['verify_ssl']
        self.workflow_callback_present = False
        self.workflow_callback = arg_workflow_callback
        self.workflow_context = arg_workflow_context
        if arg_workflow_callback != "":
            self.workflow_callback_present = True

        # The following will be initialized to the name of the user in DECS controller, who corresponds to
        # the credentials supplied as authentication information parameters.
        self.decs_username = ''

        # self.run_phase may eventually be deprecated in favor of self.results['waypoints']
        self.run_phase = "Run phase: Initializing DECSController instance."

        if self.authenticator == "jwt":
            if not arg_jwt:
                self.result['failed'] = True
                self.result['msg'] = ("JWT based authentication requested, but no JWT specified. "
                                      "Use 'jwt' parameter or set 'DECS_JWT' environment variable")
                self.amodule.fail_json(**self.result)
        elif self.authenticator == "legacy":
            if not arg_password:
                self.result['failed'] = True
                self.result['msg'] = ("Legacy user authentication requested, but no password specified. "
                                      "Use 'password' parameter or set 'DECS_PASSWORD' environment variable.")
                self.amodule.fail_json(**self.result)
            if not arg_user:
                self.result['failed'] = True
                self.result['msg'] = ("Legacy user authentication requested, but no user specified. "
                                      "Use 'user' parameter or set 'DECS_USER' environment variable.")
                self.amodule.fail_json(**self.result)
        elif self.authenticator == "oauth2":
            if not self.app_id:
                self.result['failed'] = True
                self.result['msg'] = ("Oauth2 based authentication requested, but no application ID specified. "
                                      "Use 'app_id' parameter or set 'DECS_APP_ID' environment variable.")
                self.amodule.fail_json(**self.result)
            if not arg_app_secret:
                self.result['failed'] = True
                self.result['msg'] = ("Oauth2 based authentication requested, but no application secret specified. "
                                      "Use 'app_secret' parameter or set 'DECS_APP_SECRET' environment variable.")
                self.amodule.fail_json(**self.result)
            if not arg_oauth2_url:
                self.result['failed'] = True
                self.result['msg'] = ("Oauth2 base authentication requested, but no Oauth2 provider URL specified. "
                                      "Use 'oauth2_url' parameter or set 'DECS_OAUTH2_URL' environment variable.")
                self.amodule.fail_json(**self.result)
        else:
            # Unknown authenticator type specified - notify and exit
            self.result['failed'] = True
            self.result['msg'] = "Error: unknown authentication type '{}' requested.".format(self.authenticator)
            self.amodule.fail_json(**self.result)

        self.run_phase = "Run phase: Authenticating to DECS controller."

        if self.authenticator == "jwt":
            # validate supplied JWT on the DECS controller
            self.validate_jwt()  # this call will abort the script if validation fails
            jwt_decoded = jwt.decode(self.jwt, verify=False)
            self.decs_username = jwt_decoded['user'] + "@" + jwt_decoded['iss']
        elif self.authenticator == "legacy":
            # obtain session id from the DECS controller and thus validate the the legacy user
            self.validate_legacy_user()  # this call will abort the script if validation fails
            self.decs_username = self.user
        else:
            # self.authenticator == "oauth2" - Oauth2 based authorization mode
            # obtain JWT from Oauth2 provider and validate on the DECS controller
            self.obtain_oauth2_jwt()
            self.validate_jwt()  # this call will abort the script if validation fails
            jwt_decoded = jwt.decode(self.jwt, verify=False)
            self.decs_username = jwt_decoded['username'] + "@" + jwt_decoded['iss']

        # self.run_phase = "Initializing DECSController instance complete."
        return

    def check_amodule_argument(self, arg_name, abort=True):
        """Checks if the argument identified by the arg_name is defined in the module parameters.

        @param arg_name: string that defines the name of the module parameter (aka argument) to check.
        @param abort: boolean flag that tells if module should abort its execution on failure to locate the
        specified argument.

        @return: True if argument is found, False otherwise (in abort=False mode).
        """

        if arg_name not in self.amodule.params:
            if abort:
                self.result['failed'] = True
                self.result['msg'] = "Missing conditionally required argument: {}".format(arg_name)
                self.amodule.fail_json(**self.result)
            else:
                return False
        else:
            return True

    def obtain_oauth2_jwt(self):
        """Obtain JWT from the Oauth2 provider using application ID and application secret provided , as specified at
         class instance init method.

        If method fails to obtain JWT it will abort the execution of the script by calling AnsibleModule.fail_json()
        method.

        @return: JWT as string.
        """

        token_get_url = self.oauth2_url + "/v1/oauth/access_token"
        req_data = dict(grant_type="client_credentials",
                        client_id=self.app_id,
                        client_secret=self.app_secret,
                        response_type="id_token",
                        validity=3600,)
        # TODO: Need standard code snippet to handle server timeouts gracefully
        # Consider a few retries before giving up or use requests.Session & requests.HTTPAdapter
        # see https://stackoverflow.com/questions/15431044/can-i-set-max-retries-for-requests-request

        # catch requests.exceptions.ConnectionError to handle incorrect oauth2_url case
        try:
            token_get_resp = requests.post(token_get_url, data=req_data, verify=self.verify_ssl)
        except requests.exceptions.ConnectionError:
            self.result['failed'] = True
            self.result['msg'] = "Failed to connect to '{}' to obtain JWT access token".format(token_get_url)
            self.amodule.fail_json(**self.result)
        except requests.exceptions.Timeout:
            self.result['failed'] = True
            self.result['msg'] = "Timeout when trying to connect to '{}' to obtain JWT access token".format(
                token_get_url)
            self.amodule.fail_json(**self.result)

        # alternative -- if resp == requests.codes.ok
        if token_get_resp.status_code != 200:
            self.result['failed'] = True
            self.result['msg'] = ("Failed to obtain JWT access token from oauth2_url '{}' for app_id '{}': "
                                  "HTTP status code {}, reason '{}'").format(token_get_url,
                                                                             self.amodule.params['app_id'],
                                                                             token_get_resp.status_code,
                                                                             token_get_resp.reason)
            self.amodule.fail_json(**self.result)

        # Common return values: https://docs.ansible.com/ansible/2.3/common_return_values.html
        self.jwt = token_get_resp.content.decode('utf8')
        return self.jwt

    def validate_jwt(self, arg_jwt=None):
        """Validate JWT against DECS controller. JWT can be supplied as argument to this method. If None supplied as
        argument, JWT will be taken from class attribute. DECS controller URL will always be taken from the class
        attribute assigned at instantiation.
        Validation is accomplished by attempting API call that lists accounts for the invoking user.

        @param arg_jwt: the JWT to validate. If set to None, then JWT from the class instance will be validated.

        @return: True if validation succeeds. If validation fails, method aborts the execution by calling
        AnsibleModule.fail_json() method.
        """

        if self.authenticator not in ('oauth2', 'jwt'):
            # sanity check - JWT is relevant in oauth2 or jwt authentication modes only
            self.result['msg'] = "Cannot validate JWT for incompatible authentication mode '{}'".format(
                self.authenticator)
            self.amodule.fail_json(**self.result)
            # The above call to fail_json will abort the script, so below return statement will never be executed
            return False

        if not arg_jwt:
            # If no JWT is passed as argument to this method, we will validate JWT stored in the class instance (if
            # any)
            arg_jwt = self.jwt

        if not arg_jwt:
            # arg_jwt is still None - it mans self.jwt is also None, so generate error and abort the script
            self.result['failed'] = True
            self.result['msg'] = "Cannot validate empty JWT."
            self.amodule.fail_json(**self.result)
            # The above call to fail_json will abort the script, so below return statement will never be executed
            return False

        req_url = self.controller_url + "/restmachine/cloudapi/accounts/list"
        req_header = dict(Authorization="bearer {}".format(arg_jwt),)

        try:
            api_resp = requests.post(req_url, headers=req_header, verify=self.verify_ssl)
        except requests.exceptions.ConnectionError:
            self.result['failed'] = True
            self.result['msg'] = "Failed to connect to '{}' while validating JWT".format(req_url)
            self.amodule.fail_json(**self.result)
            return False  # actually, this directive will never be executed as fail_json exits the script
        except requests.exceptions.Timeout:
            self.result['failed'] = True
            self.result['msg'] = "Timeout when trying to connect to '{}' while validating JWT".format(req_url)
            self.amodule.fail_json(**self.result)
            return False

        if api_resp.status_code != 200:
            self.result['failed'] = True
            self.result['msg'] = ("Failed to validate JWT access token for DECS controller URL '{}': "
                                  "HTTP status code {}, reason '{}', header '{}'").format(api_resp.url,
                                                                                          api_resp.status_code,
                                                                                          api_resp.reason, req_header)
            self.amodule.fail_json(**self.result)
            return False

        # If we fall through here, then everything went well.
        return True

    def validate_legacy_user(self):
        """Validate legacy user by obtaining a session key, which will be used for authenticating subsequent API calls
        to DECS controller.
        If successful, the session key is stored in self.session_key and True is returned. If unsuccessful for any
        reason, the method will abort.

        @return: True on successful validation of the legacy user.
        """

        if self.authenticator != 'legacy':
            self.result['failed'] = True
            self.result['msg'] = "Cannot validate legacy user for incompatible authentication mode '{}'".format(
                self.authenticator)
            self.amodule.fail_json(**self.result)
            return False

        req_url = self.controller_url + "/restmachine/cloudapi/users/authenticate"
        req_data = dict(username=self.user,
                        password=self.password,)

        try:
            api_resp = requests.post(req_url, data=req_data, verify=self.verify_ssl)
        except requests.exceptions.ConnectionError:
            self.result['failed'] = True
            self.result['msg'] = "Failed to connect to '{}' while validating legacy user".format(req_url)
            self.amodule.fail_json(**self.result)
            return False  # actually, this directive will never be executed as fail_json exits the script
        except requests.exceptions.Timeout:
            self.result['failed'] = True
            self.result['msg'] = "Timeout when trying to connect to '{}' while validating legacy user".format(req_url)
            self.amodule.fail_json(**self.result)
            return False

        if api_resp.status_code != 200:
            self.result['failed'] = True
            self.result['msg'] = ("Failed to validate legacy user access to DECS controller URL '{}': "
                                  "HTTP status code {}, reason '{}'").format(req_url,
                                                                             api_resp.status_code,
                                                                             api_resp.reason)
            self.amodule.fail_json(**self.result)
            return False

        # Assign session key to the corresponding class attribute.
        # Note that the above API call returns session key as a string with double quotes, which we need to
        # remove before it can be used as 'session=...' parameter to DECS controller API calls
        self.session_key = api_resp.content.decode('utf8').replace('"', '')

        return True

    def decs_api_call(self, arg_req_function, arg_api_name, arg_params):
        """Wrapper around DECS API calls. It uses authorization mode and credentials validated at the class
        instance creation to properly format API call and send it to the DECS controller URL.
        If connection errors are detected, it aborts execution of the script and relay error messages to upstream
        Ansible process.
        If HTTP 503 error is detected the method will retry with increasing timeout, and if after max_retries there
        still is HTTP 503 error, it will abort as above.
        If any other HTTP error is detected, the method will abort immediately as above.

        @param arg_req_function: function object to be called as part of API, e.g. requests.post or requests.get
        @param arg_api_name: a string containing the path to the API name under DECS controller URL
        @param arg_params: a dictionary containing parameters to be passed to the API call

        @return: api call response object as returned by the REST functions from Python "requests" module
        """

        max_retries = 5
        retry_counter = max_retries

        http_headers = dict()
        api_resp = None

        req_url = self.controller_url + arg_api_name

        if self.authenticator == 'legacy':
            arg_params['authkey'] = self.session_key
        elif self.authenticator in ('jwt', 'oauth2'):
            http_headers['Authorization'] = 'bearer {}'.format(self.jwt)

        while retry_counter > 0:
            try:
                api_resp = arg_req_function(req_url, params=arg_params, headers=http_headers, verify=self.verify_ssl)
            except requests.exceptions.ConnectionError:
                self.result['failed'] = True
                self.result['msg'] = "Failed to connect to '{}' when calling DECS API.".format(api_resp.url)
                self.amodule.fail_json(**self.result)
                return None  # actually, this directive will never be executed as fail_json aborts the script
            except requests.exceptions.Timeout:
                self.result['failed'] = True
                self.result['msg'] = "Timeout when trying to connect to '{}' when calling DECS API.".format(api_resp.url)
                self.amodule.fail_json(**self.result)
                return None

            if api_resp.status_code == 200:
                return api_resp
            elif api_resp.status_code == 503:
                retry_timeout = 5 + 10 * (max_retries - retry_counter)
                time.sleep(retry_timeout)
                retry_counter = retry_counter - 1
            else:
                self.result['failed'] = True
                self.result['msg'] = ("Error when calling DECS API '{}', HTTP status code '{}', "
                                      "reason '{}', parameters '{}'.").format(api_resp.url,
                                                                              api_resp.status_code,
                                                                              api_resp.reason, arg_params)
                self.amodule.fail_json(**self.result)
                return None  # actually, this directive will never be executed as fail_json aborts the script

        # if we get through here, it means that we were getting HTTP 503 while retrying - generate error
        self.result['failed'] = True
        self.result['msg'] = "Error when calling DECS API '{}', HTTP status code '{}', reason '{}'.". \
            format(api_resp.url, api_resp.status_code, api_resp.reason)
        self.amodule.fail_json(**self.result)
        return None

    def vm_bootdisk_size(self, arg_vm_dict, arg_boot_disk):
        """Manages size of the boot disk. Note that the size of the boot disk can only grow. This method will issue
        a warning if you try to reduce the size of the boot disk.

        @param arg_vm_dict: dictionary with VM facts. It identifies the VM for which boot disk size change is
        requested.
        @param arg_boot_disk: dictionary that contains boot disk parameters. Only 'size' parameter will be used by
        this method. All other keys, if any, will be ignored.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_bootdisk_size")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vm_bootdisk_size() in check mode: change boot disk size for VM ID {} "
                                  "was requested.").format(arg_vm_dict['id'])
            return

        if arg_boot_disk is None or 'size' not in arg_boot_disk:
            self.result['failed'] = False
            self.result['warning'] = ("vm_bootdisk_size(): no boot disk size specified for VM ID {}, skipping "
                                      "the changes as there is nothing to do.").format(arg_vm_dict['id'])
            return

        bdisk_id = 0
        bdisk_size = 0
        # we will look for the 1st occurence of what is expected to be a boot disk
        for disk in arg_vm_dict['disks']:
            if disk['type'] == "B" and disk['name'] == "Boot disk":
                bdisk_id = disk['id']
                bdisk_size = disk['sizeMax']
                break

        if not bdisk_id:
            self.result['failed'] = False
            self.result['warning'] = ("vm_bootdisk_size(): cannot identify boot disk of VM ID {}, skipping "
                                      "the changes.").format(arg_vm_dict['id'])
            return

        if bdisk_size >= arg_boot_disk['size']:
            self.result['failed'] = False
            self.result['msg'] = ("vm_bootdisk_size(): new boot disk size {} for VM ID {} is not greater than the "
                                  "current size {} - no changes done.").format(arg_boot_disk['size'],
                                                                               arg_vm_dict['id'],
                                                                               bdisk_size)
            return

        api_params = dict(diskId=bdisk_id,
                          size=arg_boot_disk['size'])
        self.decs_api_call(requests.post, "/restmachine/cloudapi/disks/resize", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True

        return

    def vm_delete(self, arg_vm_id, arg_permanently=False):
        """Delete a VM identified by VM ID. It is assumed that the VM with the specified ID exists.

        @param arg_vm_id: an integer VM ID to be deleted
        @param arg_permanently: a bool that tells if deletion should be permanent. If False, the VM will be
        marked as deleted and placed into a "trash bin" for predefined period of time (usually, a few days). Until
        this period passes the VM can be restored by calling 'restore' method.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vm_delete() in check mode: destroy VM ID {} was requested.".format(arg_vm_id)
            return

        api_params = dict(machineId=arg_vm_id,
                          permanently=arg_permanently,)
        self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def vm_extnetwork(self, arg_vm_dict, arg_desired_state, arg_ext_net_id=0, arg_force_delay=0):
        """Manage external network allocation for the VM.
        This method will either attach or detach external network IP address (aka direct IP address) to/from the
        specified VM.
        Only one external IP address can be present for each VM (this limitation may be removed in the future).

        @param arg_vm_dict: dictionary with VM facts. It identifies the VM for which external network IP address
        configuration is requested.
        @param arg_desired_state: specifies the desired state for the external network IP address attached to VM.
        Valid values are 'present' or 'absent'.
        @param arg_ext_net_id: specifies external network ID to get external IP address for this VM from.
        @param arg_force_delay: if not 0, it tells the method to delay external network attachment for the number
        of seconds passed in this argument. The use case for this is when external network is attached to a VM
        during its creation and we need to make sure the guest OS is already started by the moment external 
        network and corresponding vNIC are attached to the VM.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_extnetwork")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vm_extnetwork() in check mode: external network configuration change requested."
            return

        # /cloudapi/externalnetwork/list
        # accountId - required, integer
        #
        # NEW in 2.4.5+: /cloudapi/machines/listExternalNetworks
        # machineId - required
        #
        # /cloudapi/machines/attachExternalNetwork
        # machineId - required, integer
        # NEW in : externalNetworkId - optional, integer
        # Returns anything besides HTTP response?
        #
        # /cloudapi/machines/detachExternalNetwork
        # machineId - required, integer
        # NEW in :
        #

        api_params = dict(machineId=arg_vm_dict['id'])
        if arg_ext_net_id > 0:  # better check, so that only positive IDs are acted upon
                api_params['externalNetworkId'] = arg_ext_net_id

        ext_network_present = False
        # look up external network in the provided arg_vm_dict
        for item in arg_vm_dict['interfaces']:
            if item['type'] == "PUBLIC":
                if not arg_ext_net_id or (arg_ext_net_id > 0 and arg_ext_net_id == item['networkId']):
                    ext_network_present = True
                    break

        if arg_desired_state == 'present' and not ext_network_present:
            api_url = "/restmachine/cloudapi/machines/attachExternalNetwork"
        elif arg_desired_state == 'absent' and ext_network_present:
            arg_force_delay = 0 # make sure there is no delay when we detach the network
            api_url = "/restmachine/cloudapi/machines/detachExternalNetwork"
        else:
            self.result['failed'] = False
            self.result['msg'] = ("vm_extnetwork(): no change required for external IP assignment to VM ID {}, "
                                  "external IP presence flag {}, requested network ID {}, "
                                  "requested state '{}'.").format(arg_vm_dict['id'],
                                   ext_network_present, arg_ext_net_id,
                                   arg_desired_state)
            return

        if arg_force_delay > 0:
            # TODO: this is a quick fix for the case when we need guest OS started before
            # the changes to the ext network will be recognized by the cloud init scripts and
            # default gateways are reconfigured accordingly  
            time.sleep(arg_force_delay)

        self.decs_api_call(requests.post, api_url, api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def vm_facts(self, arg_vm_id=0,
                 arg_vm_name=None, arg_vdc_id=0, arg_vdc_name=None):
        """Tries to find specified VM and returns its details on success.
        Note: this method does not check if VM state is valid, so it is the responsibility of upstream code to do
        such checks if necessary.
        If VM is not found, no error is generated, just zero VM ID is returned.

        @param arg_vm_id: ID of the VM to locate. If 0 is passed as VM ID, then location will be done based on VM name
        and VDC attributes.
        @param arg_vm_name: name of the VM to locate. Locating VM by name requires that arg_vm_id is set to 0 and
        either non-zero arg_vdc_id is specified or non-empty arg_vdc_name is specified.
        @param arg_vdc_id: ID of the VDC to locate VM in. This parameter is used when locating VM by name and ignored
        otherwise.
        @param arg_vdc_name: name of the VDC to locate VM in. This parameter is used when locating VM by name and
        ignored otherwise. It is also ignored if arg_vdc_id is non-zero.

        @return: ret_vm_facts - dictionary with VM details on success, empty dictionary otherwise
        """

        _, ret_vm_facts, _ = self.vm_find(arg_vm_id, arg_vm_name,
                                          arg_vdc_id, arg_vdc_name,
                                          arg_check_state=False)

        return ret_vm_facts

    def _vm_get_by_id(self, arg_vm_id):
        """Helper function that locates VM by ID and returns VM facts.

        @param arg_vm_id: ID of the VM to find and return facts for.

        @return: VM ID, dictionary of VM facts and VDC ID where this VM is located. Note that if it fails
        to find the VM for the specified ID, it may return 0 for ID and empty dictionary for the facts. So
        it is suggested to check the return values accordingly.
        """
        ret_vm_id = 0
        ret_vm_dict = dict()
        ret_vdc_id = 0

        api_params = dict(machineId=arg_vm_id,)
        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/get", api_params)
        if api_resp.status_code == 200:
            ret_vm_id = arg_vm_id
            ret_vm_dict = json.loads(api_resp.content.decode('utf8'))
            ret_vdc_id = ret_vm_dict['cloudspaceid']
        else:
            self.result['warning'] = ("vm_get_by_id(): failed to get VM by ID {}. HTTP code {}, "
                                      "response {}.").format(arg_vm_id, api_resp.status_code, api_resp.reason)

        return ret_vm_id, ret_vm_dict, ret_vdc_id


    def vm_find(self, arg_vm_id=0,
                arg_vm_name=None, arg_vdc_id=0, arg_vdc_name=None,
                arg_check_state=True):
        """Tries to find a VM the VM with the specified parameters.
        Unlike other methods that also need to locate the VM, this method does not generate error if no VM matching
        specified parameters was found.
        On success returns VM ID and a dictionary with VM details, or 0 and emtpy dictionary on failure.
        NOTE: even if this method fails to find a VM (and returns zero VM ID) it can still return non zero VDC ID if
        it was successfully located by name.

        @param arg_vm_id: ID of the VM to locate. If 0 is passed as VM ID, then location will be done based on VM name
        and VDC attributes.
        @param arg_vm_name: name of the VM to locate. Locating VM by name requires that arg_vm_id is set to 0 and
        either non-zero arg_vdc_id is specified or non-empty arg_vdc_name is specified.
        @param arg_vdc_id: ID of the VDC to locate VM in. This parameter is used when locating VM by name and ignored
        otherwise.
        @param arg_vdc_name: name of the VDC to locate VM in. This parameter is used when locating VM by name and
        ignored otherwise. It is also ignored if arg_vdc_id is non-zero.
        @param arg_check_state: check that VM in valid state if True. Note that this check is not done if non-zero
        arg_vm_id is passed to the method.

        @return: ret_vm_id - ID of the VM on success (if the VM is found), 0 otherwise.
        @return: ret_vm_dict - dictionary with VM details on success as returned by /cloudapi/machines/get,
        empty dictionary otherwise.
        @return: ret_vdc_id - ID of the VDC where either VM was found or the ID of the VDC as requested by arguments.
        """

        VM_INVALID_STATES = ["DESTROYED", "DELETED", "ERROR", "DESTROYING"]

        ret_vm_id = 0
        ret_vm_dict = dict()
        ret_vdc_id = 0
        api_params = dict()

        if arg_vm_id:
            # locate VM by ID - if there is no VM with such ID, the below method will abort
            ret_vm_id, ret_vm_dict, ret_vdc_id = self._vm_get_by_id(arg_vm_id)
            if not ret_vm_id:
                self.result['failed'] = True
                self.result['msg'] = "vm_find(): cannot locate VM with ID {}.".format(arg_vm_id)
                self.amodule.fail_json(**self.result)
        else:
            # If no arg_vm_id specified, then we have to locate the target VDC.
            # To locate VDC we need either non zero VDC ID or non empty VDC name - do corresponding sanity check
            if not arg_vdc_id and arg_vdc_name == "":
                self.result['failed'] = True
                self.result['msg'] = ("vm_find(): cannot locate VDC when 'vdc_id' iz zero and 'vdc_name' is empty at "
                                      "the same time.")
                self.amodule.fail_json(**self.result)

            ret_vdc_id, _ = self.vdc_find(arg_vdc_id, arg_vdc_name)
            if ret_vdc_id:
                # if we have non zero arg_vdc_id at this point, try to find the VM in the corresponding VDC
                api_params['cloudspaceId'] = ret_vdc_id
                api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/list", api_params)
                if api_resp.status_code == 200:
                    vms_list = json.loads(api_resp.content.decode('utf8'))
                    for vm_record in vms_list:
                        if vm_record['name'] == arg_vm_name:
                            if not arg_check_state or vm_record['status'] not in VM_INVALID_STATES:
                                ret_vm_id = vm_record['id']
                                _, ret_vm_dict, _ = self._vm_get_by_id(ret_vm_id)
            else:
                # ret_vdc_id is still zero? - this should not happen in view of the validations we did above!
                pass

        return ret_vm_id, ret_vm_dict, ret_vdc_id

    def vm_portforwards(self, arg_vm_dict, arg_pfw_specs):
        """Manage VM port forwarding rules in a smart way. This method takes desired port forwarding rules as
        an argument and compares it with the existing port forwarding rules

        @param arg_vm_dict: dictionary with VM facts. It identifies the VM for which network configuration is
        requested.
        @param arg_pfw_specs: desired network specifications.
        """

        #
        #
        # Strategy for port forwards management:
        # 1) obtain current port forwarding rules for the target VM
        # 2) create a delta list of port forwards (rules to add and rules to remove)
        #   - full match between existing & requested = ignore, no update of pfw_delta
        #   - existing rule not present in requested list => copy to pfw_delta and mark as 'delete'
        #   - requested rule not present in the existing list => copy to pfw_delta and mark as 'create'
        # 3) provision delta list (first delete rules marked for deletion, next add rules mark for creation)
        #

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_portforwards")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vm_portforwards() in check mode: port forwards configuration change requested."
            return

        pfw_api_base = "/restmachine/cloudapi/portforwarding/"
        pfw_api_params = dict(cloudspaceId=arg_vm_dict['cloudspaceid'],
                              machineId=arg_vm_dict['id'])
        api_resp = self.decs_api_call(requests.post, pfw_api_base + "list", pfw_api_params)
        existing_pfw_list = json.loads(api_resp.content.decode('utf8'))

        if not len(arg_pfw_specs) and not len(existing_pfw_list):
            # Desired & existing port forwarding rules both empty - exit
            self.result['failed'] = False
            self.result['msg'] = ("vm_portforwards(): new and existing port forwarding lists both are empty - "
                                  "nothing to do. No change applied to VM ID {}.").format(arg_vm_dict['id'])
            return

        # pfw_delta_list will be a list of dictionaries that describe _changes_ to the port forwarding rules
        # that existed for the target VM at the moment we entered this method.
        # The dictionary has the following keys:
        #   ext_port - integer, external port number
        #   int_port - integer, internal port number
        #   proto - string, either 'tcp' or 'udp'
        #   action - string, either 'delete' or 'create'
        #   id - the ID of existing port forwarding rule that should be deleted (applicable when action='delete')
        # NOTE: not all keys may exist in the resulting list!
        pfw_delta_list = []

        # Mark all requested pfw rules as new - if we find a match later, we will mark corresponding rule
        # as 'new'=False
        for requested_pfw in arg_pfw_specs:
            requested_pfw['new'] = True

        for existing_pfw in existing_pfw_list:
            existing_pfw['matched'] = False
            for requested_pfw in arg_pfw_specs:
                # TODO: portforwarding API needs refactoring.
                # NOTE!!! Another glitch in the API implementation - .../portforwarding/list returns port numbers as strings,
                # while .../portforwarding/create expects them as integers!!!
                if (int(existing_pfw['publicPort']) == requested_pfw['ext_port'] and
                        int(existing_pfw['localPort']) == requested_pfw['int_port'] and
                        existing_pfw['protocol'] == requested_pfw['proto']):
                    # full match - existing rule stays as is:
                    # mark requested rule spec as 'new'=False, existing rule spec as 'macthed'=True
                    requested_pfw['new'] = False
                    existing_pfw['matched'] = True

        # Scan arg_pfw_specs, find all records that have been marked 'new'=True, then copy them the pfw_delta_list
        # marking as action='create'
        for requested_pfw in arg_pfw_specs:
            if requested_pfw['new']:
                pfw_delta = dict(ext_port=requested_pfw['ext_port'],
                                 int_port=requested_pfw['int_port'],
                                 proto=requested_pfw['proto'],
                                 action='create')
                pfw_delta_list.append(pfw_delta)

        # Scan existing_pfw_list, find all records that have 'matched'=False, then copy them to pfw_delta_list
        # marking as action='delete'
        for existing_pfw in existing_pfw_list:
            if not existing_pfw['matched']:
                pfw_delta = dict(ext_port=int(existing_pfw['publicPort']),
                                 int_port=int(existing_pfw['localPort']),
                                 proto=existing_pfw['protocol'],
                                 action='delete')
                pfw_delta_list.append(pfw_delta)

        if not len(pfw_delta_list):
            # nothing to do
            self.result['failed'] = False
            self.result['msg'] = ("vm_portforwards() no difference between current and requested port "
                                  "forwarding rules found. No change applied to VM ID {}.").format(arg_vm_dict['id'])
            return

        # Need VDC facts to extract VDC external IP - it is needed to create new port forwarding rules
        # Note that in a scenario when VM and VDC are created in the same task we may arrive to here
        # when VDC is still in DEPLOYING state. Attempt to configure port forward rules in this will generate
        # an error. So we have to check VDC status and loop for max ~60 seconds here so that the newly VDC
        # created enters DEPLOYED state 
        max_retries = 5
        retry_counter = max_retries
        while retry_counter > 0:
            _, vdc_facts = self.vdc_find(arg_vdc_id=arg_vm_dict['cloudspaceid'])
            if vdc_facts['status'] == "DEPLOYED":
                break
            retry_timeout = 5 + 10 * (max_retries - retry_counter)
            time.sleep(retry_timeout)
            retry_counter = retry_counter - 1

        if vdc_facts['status'] != "DEPLOYED":
            # We still cannot manage port forwards due to incompatible VDC state. This is not necessarily an
            # error that should lead to the task failure, so we register this fact in the module message and
            # return from the method.
            #
            # self.result['failed'] = True
            self.result['msg'] = ("vm_portforwards(): target VDC ID {} is still in '{}' state, "
                                  "setting port forwarding rules is not possible.").format(arg_vm_dict['cloudspaceid'],
                                                                                           vdc_facts['status'])
            return

        # Iterate over pfw_delta_list and first delete port forwarding rules marked for deletion,
        # next create the rules marked for creation.
        sorted_pfw_delta_list = sorted(pfw_delta_list, key=lambda i: i['action'], reverse=True)
        for pfw_delta in sorted_pfw_delta_list:
            if pfw_delta['action'] == 'delete':
                pfw_api_params = dict(cloudspaceId=arg_vm_dict['cloudspaceid'],
                                      publicIp=vdc_facts['externalnetworkip'],
                                      publicPort=pfw_delta['ext_port'],
                                      proto=pfw_delta['proto'])
                self.decs_api_call(requests.post, pfw_api_base + 'deleteByPort', pfw_api_params)
                # On success the above call will return here. On error it will abort execution by calling fail_json.
            elif pfw_delta['action'] == 'create':
                pfw_api_params = dict(cloudspaceId=arg_vm_dict['cloudspaceid'],
                                      publicIp=vdc_facts['externalnetworkip'],
                                      publicPort=pfw_delta['ext_port'],
                                      machineId=arg_vm_dict['id'],
                                      localPort=pfw_delta['int_port'],
                                      protocol=pfw_delta['proto'])
                self.decs_api_call(requests.post, pfw_api_base + 'create', pfw_api_params)
                # On success the above call will return here. On error it will abort execution by calling fail_json.

        self.result['failed'] = False
        self.result['changed'] = True
        return

    def vm_powerstate(self, arg_vm_dict, arg_target_state, force_change=True):
        """Manage VM power state transitions or its guest OS restart

        @param arg_vm_dict: dictionary with VM facts. It identifies the VM for which power state change is
        requested.
        @param arg_target_state: string that describes the desired power state of the VM.
        @param force_change: boolean flag that tells if it is allowed to force power state transition for certain
        cases (e.g. for transition into 'stop' state).

        NOTE: this method may return before the actual change of target VM power state occurs.
        """

        # @param wait_for_change: integer number that tells how many 5 seconds intervals to wait for the power state
        # change before returning from this method.

        NOP_STATES_FOR_POWER_CHANGE = ["MIGRATING", "DELETED", "DESTROYING", "DESTROYED", "ERROR"]

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_powerstate")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vm_powerstate() in check mode. Power state change of VM ID {} "
                                  "to '{}' was requested.").format(arg_vm_dict['id'], arg_target_state)
            return

        if arg_vm_dict['status'] in NOP_STATES_FOR_POWER_CHANGE:
            self.result['failed'] = False
            self.result['msg'] = ("vm_powerstate(): no power state change possible for VM ID {} "
                                  "in current state '{}'.").format(arg_vm_dict['id'], arg_vm_dict['status'])
            return

        powerstate_api = ""  # this string will also be used as a flag to indicate that API call is necessary
        api_params = dict(machineId=arg_vm_dict['id'])

        if arg_vm_dict['status'] == "RUNNING":
            if arg_target_state == 'paused':
                powerstate_api = "/restmachine/cloudapi/machines/pause"
            elif arg_target_state == 'poweredoff':
                powerstate_api = "/restmachine/cloudapi/machines/stop"
                api_params['force'] = force_change
            elif arg_target_state == 'restarted':
                powerstate_api = "/restmachine/cloudapi/machines/reboot"
        elif arg_vm_dict['status'] == "PAUSED" and arg_target_state in ('poweredon', 'restarted'):
            powerstate_api = "/restmachine/cloudapi/machines/resume"
        elif arg_vm_dict['status'] == "HALTED" and arg_target_state in ('poweredon', 'restarted'):
            powerstate_api = "/restmachine/cloudapi/machines/start"
        else:
            # VM seems to be in the desired power state already - do not call API
            pass

        if powerstate_api != "":
            self.decs_api_call(requests.post, powerstate_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
        else:
            self.result['failed'] = False
            self.result['msg'] = ("vm_powerstate(): no power state change required for VM ID {} its from current "
                                  "state '{}' to desired state '{}'.").format(arg_vm_dict['id'],
                                                                              arg_vm_dict['status'],
                                                                              arg_target_state)
        return

    def vm_provision(self, arg_vdc_id, arg_vm_name,
                     arg_cpu, arg_ram,
                     arg_boot_disk, arg_image_id,
                     arg_data_disks=None,
                     arg_annotation="",
                     arg_userdata=None):
        """Manage VM provisioning.
        To remove VM use vm_remove method.
        To resize VM use vm_size, to manage VM power state use vm_powerstate method.

        @param arg_vdc_id: integer ID of the VDC where the VM will be provisioned.
        @param arg_vm_name: string that specifies the name of the VM.
        @param arg_cpu: integer count of virtual CPUs to allocate.
        @param arg_ram: integer volume of RAM to allocate, specified in MB (i.e. pass 4096 to allocate 4GB RAM).
        @param arg_boot_disk: dictionary with boot disk specifications.
        @param arg_image_id: integer ID of the OS image to be deployed on the VM.
        @param arg_data_disks: list of additional data disk sizes in GB. Pass empty list if no data disks needed.
        @param arg_annotation: string that specified the description for the VM.
        @param arg_userdata: additional paramters to pass to cloud-init facility of the guest OS.

        @return ret_vm_id: integer value that specifies the VM ID of provisioned VM. In check mode it will return 0.
        """

        #
        # TODO - add support for different types of boot & data disks
        # Currently type attribute of boot & data disk specifications are ignored until new storage provider types
        # are implemented into the cloud platform.
        #

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_provision")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vm_provision() in check mode. Provision VM '{}' in VDC ID {} "
                                  "was requested.").format(arg_vm_name, arg_vdc_id)
            return 0

        # Extract data disk parameters in case the list was supplied in arg_data_disks argument
        data_disk_sizes = []
        if arg_data_disks:
            for ddisk in arg_data_disks:
                # TODO - as new storage resource providers are added, this algorithms will be reworked
                data_disk_sizes.append(ddisk['size'])

        api_params = dict(cloudspaceId=arg_vdc_id,
                          name=arg_vm_name,
                          description=arg_annotation,
                          vcpus=arg_cpu, memory=arg_ram,
                          imageId=arg_image_id,
                          disksize=arg_boot_disk['size'],
                          datadisks=data_disk_sizes,)
        if arg_userdata:
            api_params['userdata'] = json.dumps(arg_userdata)  # we need to pass a string object as "userdata" 
        
        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/create", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        ret_vm_id = int(api_resp.content)
        return ret_vm_id

    def vm_resize_vector(self, arg_vm_dict, arg_cpu, arg_ram):
        """Check if the VM size parameters passed to this function are different from the current VM configuration.
        This method is intended to be called to see if the VM would be resized in the course of module run, as
        sometimes resizing may happen implicitly (e.g. when state = present and the specified size is different
        from the current configuration of per-existing target VM.

        @param arg_vm_dict: dictionary of the VM parameters as returned by previous call to vm_facts.
        @param arg_cpu: requested (aka new) CPU count.
        @param arg_ram: requested RAM size in MBs.

        @return: VM_RESIZE_NOT if no change required, VM_RESIZE_DOWN if sizing VM down (this will required VM to be in
        one of the stopped states), VM_RESIZE_UP if sizing VM up (no guest OS restart is generally required for most
        of the modern OS).
        """

        # NOTE: This method may eventually be deemed as redundant and as such may be removed.

        if arg_vm_dict['vcpus'] == arg_cpu and arg_vm_dict['memory'] == arg_ram:
            return DECSController.VM_RESIZE_NOT

        if arg_vm_dict['vcpus'] < arg_cpu or arg_vm_dict['memory'] < arg_ram:
            return DECSController.VM_RESIZE_UP

        if arg_vm_dict['vcpus'] > arg_cpu or arg_vm_dict['memory'] > arg_ram:
            return DECSController.VM_RESIZE_DOWN

        return DECSController.VM_RESIZE_NOT

    def vm_resource_check(self):
        """Check available resources (in case limits are set on the target VDC and/or account) to make sure that
        the requested VM can be deployed.

        @return: True if enough resources, False otherwise.
        @return: Dictionary of remaining resources estimation after the specified VM would have been deployed.
        """

        # self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_resource_check")

        #
        # TODO - This method is under construction
        #

        return

    def vm_restore(self, arg_vm_id):
        """Restores a deleted VM identified by VM ID.

        @param arg_vm_id: integer value that defines the ID of a VM to be restored.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vm_restore() in check mode: restore VM ID {} was requested.".format(arg_vm_id)
            return

        api_params = dict(machineId=arg_vm_id,
                          reason="Restored on user request by Ansible DECS module.",)
        self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def vm_size(self, arg_vm_dict, arg_cpu, arg_ram, wait_for_state_change=0):
        """Resize existing VM.

        @param arg_vm_dict: dictionary with the current specification of the VM to be resized.
        @param arg_cpu: integer new vCPU count.
        @param arg_ram: integer new RAM size in GB.
        @param wait_for_state_change: integer number that tells how many 5 seconds intervals to wait for VM power state to
        change so that the resize operation can be carried out. Set this to non zero value if you expect that
        the state of VM will change shortly (usually, when you call this method after vm_powerstate(...))
        """

        #
        # TODO: need better cooperation from OS image attributes as returned by API "images/list".
        # Now it is assumed that VM hot resize up is always possible, while hot resize down is not.
        #

        INVALID_STATES_FOR_HOT_DOWNSIZE = ["RUNNING", "MIGRATING", "DELETED"]

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vm_size")

        # We need to handle a situation when either of 'cpu' or 'ram' parameter was not supplied. This is acceptable
        # when we manage state of the VM or request change to only one parameter - cpu or ram.
        # In such a case take the "missing" value from the current configuration of the VM.
        if not arg_cpu and not arg_ram:
            # if both are 0 or Null - return immediately, as user did not mean to manage size
            self.result['failed'] = False
            return

        if not arg_cpu:
            arg_cpu = arg_vm_dict['vcpus']
        elif not arg_ram:
            arg_ram = arg_vm_dict['memory']

        # stupid hack?
        if arg_ram > 1 and arg_ram < 512:
            arg_ram = arg_ram*1024

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vm_size() in check mode: resize of VM ID {} from CPU:RAM {}:{} to {}:{} requested."
                                  "was requested.").format(arg_vm_dict['id'],
                                                           arg_vm_dict['vcpus'], arg_vm_dict['memory'],
                                                           arg_cpu, arg_ram)
            return

        if arg_vm_dict['vcpus'] == arg_cpu and arg_vm_dict['memory'] == arg_ram:
            # no need to call API in this case, as requested size is not different from the current one
            self.result['failed'] = False
            return

        if ((arg_vm_dict['vcpus'] > arg_cpu or arg_vm_dict['memory'] > arg_ram) and
                arg_vm_dict['status'] in INVALID_STATES_FOR_HOT_DOWNSIZE):
            while wait_for_state_change:
                time.sleep(5)
                fresh_vm_dict = self.vm_facts(arg_vm_id=arg_vm_dict['id'])
                if fresh_vm_dict['status'] not in INVALID_STATES_FOR_HOT_DOWNSIZE:
                    break
                wait_for_state_change = wait_for_state_change - 1
            if not wait_for_state_change:
                self.result['failed'] = True
                self.result['msg'] = ("vm_size() downsize of VM ID {} from CPU:RAM {}:{} to {}:{} was requested, "
                                      "but VM is in the state '{}' incompatible with down size operation").\
                    format(arg_vm_dict['id'],
                           arg_vm_dict['vcpus'], arg_vm_dict['memory'],
                           arg_cpu, arg_ram, arg_vm_dict['status'])
                return

        api_resize_params = dict(machineId=arg_vm_dict['id'],
                                 memory=arg_ram,
                                 vcpus=arg_cpu,)
        self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/resize", api_resize_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def image_find(self, arg_osimage_name, arg_vdc_id, arg_tenant_id=0):
        """Locates image specified by name and returns its facts as dictionary.
        Primary use of this function is to obtain the ID of the image identified by its name

        @param arg_os_image: string that contains the name of the OS image
        @param arg_vdc_id: ID of the VDC to use as a reference when listing OS images
        @param arg_tenant_id: ID of the tenant for which the image will be looked up. If set to 0, the tenant ID
        will be obtained from the specified VDC's facts

        @return: dictionary with image specs. If no image found by the specified name, it returns emtpy dictionary
        and sets self.result['failed']=True.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "image_find")

        if arg_tenant_id == 0:
            _, vdc_facts = self._vdc_get_by_id(arg_vdc_id)
            arg_tenant_id = vdc_facts['accountId']
        
        # api_params = dict(cloudspaceId=arg_vdc_id)
        api_params = dict(accountId=arg_tenant_id)

        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/images/list", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        image_list = json.loads(api_resp.content.decode('utf8'))
        for image_record in image_list:
            if image_record['name'] == arg_osimage_name and image_record['status'] == "CREATED":
                return image_record

        self.result['failed'] = True
        self.result['msg'] = "Failed to find OS image by name '{}' for tenant ID '{}'.".format(arg_osimage_name,
                                                                                               arg_tenant_id)
        return None

    def vdc_delete(self, arg_vdc_id, arg_permanently=False):
        """Deletes specified VDC.

        @param arg_vdc_id: integer value that identifies the VDC to be deleted.
        @param arg_permanently: a bool that tells if deletion should be permanent. If False, the VDC will be
        marked as deleted and placed into a trash bin for predefined period of time (usually, a few days). Until
        this period passes the VDC can be restored by calling the corresponding 'restore' method.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_delete")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vdc_delete() in check mode: delete VDC ID {} was requested.".format(arg_vdc_id)
            return

        #
        # TODO: need decision if deleting a VDC with VMs in it is allowed (aka force=True) and implement accordingly.
        #

        api_params = dict(cloudspaceId=arg_vdc_id,
                          permanently=arg_permanently,)
        self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True

        return

    def _vdc_get_by_id(self, arg_vdc_id):
        """Helper function that locates VDC by ID and returns VM facts.

        @param arg_vdc_id: ID of the VDC to find and return facts for.

        @return: VDC ID and a dictionary of VDC facts as provided by cloudspaces/get API call. Note that if it fails
        to find the VDC for the specified ID, it may return 0 for ID and empty dictionary for the facts. So
        it is suggested to check the return values accordingly.
        """
        ret_vdc_id = 0
        ret_vdc_dict = dict()

        api_params = dict(cloudspaceId=arg_vdc_id,)
        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/get", api_params)
        if api_resp.status_code == 200:
            ret_vdc_id = arg_vdc_id
            ret_vdc_dict = json.loads(api_resp.content.decode('utf8'))
        else:
            self.result['warning'] = ("vdc_get_by_id(): failed to get VDC by ID {}. HTTP code {}, "
                                      "response {}.").format(arg_vdc_id, api_resp.status_code, api_resp.reason)

        return ret_vdc_id, ret_vdc_dict

    def vdc_find(self, arg_vdc_id=0, arg_vdc_name="", arg_check_state=True):
        """Returns non zero VDC ID and a dictionary with VDC details on success, 0 and empty dictionary otherwise.
        This method does not fail the run if VDC cannot be located by its name (arg_vdc_name), because this could be
        an indicator of the requested VDC never existed before.
        However, it does fail the run if VDC cannot be located by arg_vdc_id (if non zero specified) or if API errors
        occur.

        @param arg_vdc_id: integer ID of the VDC to be found.
        @param arg_vdc_name: string that defines the name of VDC to be found. This parameter is case sensitive.
        @param arg_check_state: boolean that tells the method to report VDCs in valid states only.

        @return: VDC ID of the VDC, if present. Zero otherwise.
        @return: dictionary with VDC facts as provided by .../cloudspaces/get API call if VDC is present. Empty
        dictionary otherwise.
        """

        # Cloud space can be in one of the following states:
        # VIRTUAL, DEPLOYING, DESTROYED, DEPLOYED, DESTROYING, MIGRATING, DISABLED, DELETED
        #

        VDC_INVALID_STATES = ["DESTROYED", "DELETED", "DESTROYING"]

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_find")

        ret_vdc_id = 0
        api_params = dict()
        ret_vdc_dict = dict()

        if arg_vdc_id:
            ret_vdc_id, ret_vdc_dict = self._vdc_get_by_id(arg_vdc_id)
            if not ret_vdc_id:
                self.result['failed'] = True
                self.result['msg'] = "vdc_find(): cannot locate VDC with VDC ID {}.".format(arg_vdc_id)
                self.amodule.fail_json(**self.result)
        elif arg_vdc_name != "":
            # try to locate VDC by name - start with listing all VDCs available to the current user
            api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/list", api_params)
            if api_resp.status_code == 200:
                # Parse response to see if a VDC matching arg_vdc_name is found in the output
                # If it is found, assign its ID to the return variable
                vdcs_list = json.loads(api_resp.content.decode('utf8'))
                for vdc_record in vdcs_list:
                    if vdc_record['name'] == arg_vdc_name:
                        if not arg_check_state or vdc_record['status'] not in VDC_INVALID_STATES:
                            ret_vdc_id, ret_vdc_dict = self._vdc_get_by_id(vdc_record['id'])
            # Note: we do not fail the run if VDC cannot be located by its name, because it could be a new VDC
            # that never existed before. In this case ret_vdc_id=0 and empty ret_vdc_dict will be returned.
        else:
            # Both arg_vdc_id and arg_vdc_name are empty - there is no way to locate VDC in this case
            self.result['failed'] = True
            self.result['msg'] = "vdc_find(): cannot locate VDC when VDC ID is zero and VDC name is empty string."
            self.amodule.fail_json(**self.result)

        return ret_vdc_id, ret_vdc_dict

    def vdc_portforwards(self):
        """Manage port forwarding rules at the VDC level"""
        #
        # TODO - not implemented yet - need use case for this method to decide if it should be implemented at all
        #

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_portforwards")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            # self.result['msg'] = ("vdc_portforwards() in check mode: port forwards configuration for VDC name '{}' "
            #                      "was requested.").format(arg_vdc_name)
            return

        return

    def vdc_provision(self, arg_tenant_id, arg_datacenter, arg_vdc_name, arg_username, arg_quota={}):
        """Provision new VDC according to the specified arguments.
        If critical error occurs the embedded call to API function will abort further execution of the script
        and relay error to Ansible.
        On success this method returns either 0 (if in check_mode) or the ID of the newly created VDC.

        @param arg_tenant_id: the non-zero ID of the tenant under which the new VDC will be created.
        @param arg_datacenter: the name of datacanter under the DECS controller where VDC will be created.
        @param arg_vdc_name: the name of the VDC to be created.
        @param arg_username: the name of the user under DECS controller, who will have primary access to the newly
        created VDC.
        @param arg_quota: dictionary that defines quotas to set on the VDC to be created. Valid keys are: cpu, ram,
        disk and ext_ips.

        @return: integer ID of the newly created VDC.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_provision")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vdc_provision() in check mode: provision VDC name '{}' was "
                                  "requested.").format(arg_vdc_name)
            return 0

        api_params = dict(accountId=arg_tenant_id,
                          location=arg_datacenter,
                          name=arg_vdc_name,
                          access=arg_username,
                          maxMemoryCapacity=-1, maxVDiskCapacity=-1,
                          maxCPUCapacity=-1, maxNumPublicIP=-1,)
        if arg_quota:
            if 'ram' in arg_quota:
                api_params['maxMemoryCapacity'] = arg_quota['ram']
            if 'disk' in arg_quota:
                api_params['maxVDiskCapacity'] = arg_quota['disk']
            if 'cpu' in arg_quota:
                api_params['maxCPUCapacity'] = arg_quota['cpu']
            if 'ext_ips' in arg_quota:
                api_params['maxNumPublicIP'] = arg_quota['ext_ips']

        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/create", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        # API /restmachine/cloudapi/cloudspaces/create returns ID of the newly created VDC on success
        self.result['failed'] = False
        self.result['changed'] = True
        ret_vdc_id = int(api_resp.content.decode('utf8'))
        return ret_vdc_id

    def vdc_quotas(self, arg_vdc_dict, arg_quotas):
        """Manage quotas for an existing VDC

        @param arg_vdc_dict: dictionary with VDC facts as returned by vdc_find(...) method or .../cloudspaces/get API
        call to obtain the data.
        @param arg_quotas: dictionary with quota settings. Valid keys are cpu, ram, disk and ext_ips. Not all keys must
        be present. Current quota settings for the missing keys will be retained on the VDC.
        """

        #
        # TODO: what happens if user requests quota downsize, and what is currently deployed turns above the new quota?
        #

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_quotas")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vdc_quotas() in check mode: setting quotas on VDC ID {}, VDC name '{}' was "
                                  "requested.").format(arg_vdc_dict['id'], arg_vdc_dict['name'])
            return

        # One more inconsistency in API keys:
        # - when setting resource limits, the keys are in the form 'max{{ RESOURCE_NAME }}Capacity'
        # - when quering resource limits, the keys are in the form of cloud units (CU_*)
        query_key_map = dict(cpu='CU_C',
                             ram='CU_M',
                             disk='CU_D',
                             ext_ips='CU_I',)
        set_key_map = dict(cpu='maxCPUCapacity',
                           ram='maxMemoryCapacity',
                           disk='maxVDiskCapacity',
                           ext_ips='maxNumPublicIP',)
        api_params = dict(cloudspaceId=arg_vdc_dict['id'],)
        quota_change_required = False

        for new_limit in ('cpu', 'ram', 'disk', 'ext_ips'):
            if arg_quotas:
                if new_limit in arg_quotas:
                    # If this resource type limit is found in the desired quotas, check if the desired setting is
                    # different from the current settings of VDC. If it is different, set the new one.
                    if arg_quotas[new_limit] != arg_vdc_dict['resourceLimits'][query_key_map[new_limit]]:
                        api_params[set_key_map[new_limit]] = arg_quotas[new_limit];
                        quota_change_required = True
                else:
                    # This resource type limit not found in the desired quotas. It means that no limit for this
                    # resource type - reset VDC limit for this resource type regardless of the current VDC settings.
                    api_params[set_key_map[new_limit]] = -1
                    quota_change_required = True
            else:
                # if quotas dictionary is None, it means that no quotas should be set - reset the limits
                api_params[set_key_map[new_limit]] = -1
                quota_change_required = True

        if quota_change_required:
            self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/update", api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True

        return

    def vdc_restore(self, arg_vdc_id):
        """Restores a deleted VDC identified by VDC ID. For restore to succeed the VDC must be in 'DELETED' state.

        @param arg_vdc_id: integer that defines the ID of a VDC to be restored.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_restore")

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vdc_restore() in check mode: restore VDC ID {} was requested.".format(arg_vdc_id)
            return

        api_params = dict(cloudspaceId=arg_vdc_id,
                          reason="Restored on user request by Ansible DECS module.",)
        self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/restore", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def vdc_vfwstate(self, arg_vdc_dict, arg_desired_state):
        """Manage state of the Virtual Firewall (aka VFW) associated with the VDC.

        @param arg_vdc_dict: dictionary with the target VDC facts as returned by vdc_find(...) method or
        .../cloudspaces/get API call to obtain the data.
        @param arg_desired_state: the desired state of the VFW. Valid states are 'enabled', 'disabled' or 'deploy'.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_vfwstate")

        NOP_STATES_FOR_VFW_CHANGE = ["MIGRATING", "DELETED", "DESTROYING", "DESTROYED", "DEPLOYING"]
        VALID_STATES_FOR_VFW_CHANGE = ["enabled", "disabled", "deploy"]

        if arg_vdc_dict['status'] in NOP_STATES_FOR_VFW_CHANGE:
            self.result['failed'] = False
            self.result['msg'] = ("vm_vfwstate(): no state change possible for VFW of VDC ID {} "
                                  "in its current state '{}'.").format(arg_vdc_dict['id'], arg_vdc_dict['status'])
            return

        if arg_desired_state not in VALID_STATES_FOR_VFW_CHANGE:
            self.result['failed'] = False
            self.result['warning'] = ("vm_vfwrstate(): unrecognized desired state '{}' requested "
                                      "for VDC ID {}. No VFW state change will be done.").format(arg_desired_state,
                                                                                                 arg_vdc_dict['id'])
            return

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vdc_vfwstate() in check mode: setting VFW state of VDC ID {}, VDC name '{}' to "
                                  "'{}' was requested.").format(arg_vdc_dict['id'], arg_vdc_dict['name'],
                                                                arg_desired_state)
            return

        vfwstate_api = ""  # this string will also be used as a flag to indicate that API call is necessary
        api_params = dict(cloudspaceId=arg_vdc_dict['id'],
                          reason='Changed by decs_vdc module, decs_vfwstate method.')

        if arg_vdc_dict['status'] == "VIRTUAL" and arg_desired_state in ('deploy', 'enabled'):
            vfwstate_api = "/restmachine/cloudapi/cloudspaces/deploy"
        elif arg_vdc_dict['status'] == "DEPLOYED" and arg_desired_state == 'disabled':
            vfwstate_api = "/restmachine/cloudapi/cloudspaces/disable"
        elif arg_vdc_dict['status'] == "DISABLED" and arg_desired_state in ('deploy', 'enabled'):
                vfwstate_api = "/restmachine/cloudapi/cloudspaces/enable"

        if vfwstate_api != "":
            self.decs_api_call(requests.post, vfwstate_api, api_params)
            # On success the above call will return here. On error it will abort execution by calling fail_json.
            self.result['failed'] = False
            self.result['changed'] = True
        else:
            self.result['failed'] = False
            self.result['msg'] = ("vm_vfwrstate(): no state change required for VFW in VDC ID {} from current "
                                  "state '{}' to desired state '{}'.").format(arg_vdc_dict['id'],
                                                                              arg_vdc_dict['status'],
                                                                              arg_desired_state)
        return

    def vdc_vms_list(self, arg_vdc_id=0, arg_vdc_name=""):
        """List virtual machines in the specified VDC.
        VDC can be identified either by its ID or by a combination of VDC name and tenant name.

        @param arg_vdc_id: ID the VDC to list VMs from.
        @param arg_vdc_name: name of the VDC to list VMs from.

        @returns: dictionary of VMs from the specified VDC. Please note that it may return an emtpy dictionary
        if no VMs are currently present in the VDC.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "vdc_vms_list")

        vdc_id, _ = self.vdc_find(arg_vdc_id, arg_vdc_name)

        if not vdc_id:
            self.result['failed'] = True
            self.result['msg'] = "vm_vms_list(): cannot find VDC by ID {} or name '{}'".format(arg_vdc_id, arg_vdc_name)

        api_params = dict(cloudspaceId=vdc_id)
        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/list", api_params)
        if api_resp.status_code == 200:
            vms_list = json.loads(api_resp.content.decode('utf8'))

        return vms_list


    def tenant_find(self, arg_tenant_name):
        """Find cloud tenant specified by the name and return facts about the tenant. Tenant is required for certain
        cloud resource management tasks (e.g. creating new VDC).

        @param arg_tenant_name: name of the tenant to find.

        Returns non zero tenant ID and a dictionary with tenant details on success, 0 and empty dictionary otherwise.
        """

        self.result['waypoints'] = "{} -> {}".format(self.result['waypoints'], "tenant_find")

        if arg_tenant_name == "":
            self.result['failed'] = True
            self.result['msg'] = "Cannot find tenant if tenant name is empty."
            self.amodule.fail_json(**self.result)

        api_params = dict()

        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/accounts/list", api_params)
        if api_resp.status_code == 200:
            # Parse response to see if a tenant matching arg_tenant_name is found in the output
            # If it is found, assign its ID to the return variable and copy dictionary with the facts
            tenants_list = json.loads(api_resp.content.decode('utf8'))
            for tenant_record in tenants_list:
                if tenant_record['name'] == arg_tenant_name:
                    return tenant_record['id'], tenant_record

        return 0, None

    def workflow_cb_set(self, arg_workflow_callback, arg_workflow_context=None):
        """Set workflow callback and workflow context value.
        """

        self.workflow_callback = arg_workflow_callback
        if arg_workflow_callback != "":
            self.workflow_callback_present = True
        else:
            self.workflow_callback_present = False

        if arg_workflow_context != "":
            self.workflow_context = arg_workflow_context
        else:
            self.workflow_context = ""

        return

    def workflow_cb_call(self):
        """Invoke workflow callback if it was specified earlyer with workflow_cb_set(...) method.
        """
        #
        # TODO: under construction
        #
        if self.workflow_callback_present:
            pass
        return

    def run_phase_set(self, arg_phase_name):
        """Set run phase name for module run progress reporting"""
        self.run_phase = arg_phase_name
        return
