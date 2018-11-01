#
# Copyright: (c) 2018 Digital Energy Cloud Solutions LLC
# Apache License 2.0 (see http://www.apache.org/licenses/LICENSE-2.0.txt)

#
# Author: Sergey Shubin (sergey.shubin@digitalenergy.online)
#

import copy
import json
import jwt
import time
import requests

from ansible.module_utils.basic import AnsibleModule

"""
This is the library of utility functions and classes for managing DECS cloud platform.

These classes are made aware of Ansible module architecture and designed to be called from the main code of an Ansible 
module to fulfill cloud reource management tasks.

Methods defined in this file should NOT implement complex logic like building execution plan for an
upper level Ansible module. However, they do implement necessary sanity checks and may abort upper level module 
execution if some fatal error occurs. Being Ansible aware, they usually do so by calling AnsibleModule.fail_json(...)
method with properly configured arguments.
"""


#
# TODO: the following functionality to be implemented
# 1) vm_ext_network - direct IP allocation to VM
# 2) vdc_delete - need decision if we allow force delete (any exising VMs to be deleted)
# 3) vdc_portforwards (?) - do we need to manage it separate from VMs?
# 4) workflow callbacks
# 5) run phase states
# 6) vm_tags - set/manage VM tags
# 7) vm_attributes - change VM attributes (name, annotation) after VM creation - do we need this in Ansible?
# 8) verify that result['changed'] value is set correctly
# 9) pylint and code style review.
#

class DECSController():

    VM_RESIZE_NOT = 0
    VM_RESIZE_DOWN = 1
    VM_RESIZE_UP = 2

    def __init__(self, arg_amodule,
                 arg_authenticator, arg_controller_url,
                 arg_jwt=None,
                 arg_app_id=None, arg_app_secret=None, arg_oauth2_url=None,
                 arg_user=None, arg_password=None,
                 arg_workflow_callback=None, arg_workflow_context=None):
        """DECSController is a utility class that holds target controller context and handles API requests formatting
        based on the requested authentication type.
        Instantiate this class at the beginning of any DECS module run to have the following:
        - check authentication parameters to make sure all required parameters are properly specified
        - initiate test connection to the specified DECS controller and validates supplied credentias
        - store validated authentication information for later use by DECC API calls
        - store AnsibleModule class instance to keep handy reference to the module context

        If any of the required parameters are missing or supplied authentication information is invalid, an error
        message will be generated and execution aborted in way, that is lets Ansible to pick this information up and
        relay it upstream.
        """

        self.amodule = arg_amodule  # AnsibleModule class instance

        # Note that 'changed' is by default set to 'False'. If you plan to manage value of 'changed' key outside ot
        # DECSController() class, make sure you only update to 'True' when you really change the state of the object
        # being managed.
        # The rare case when you will set it to False will usually be either module running in "check mode" or
        # when you are about to call exit_json() or fail_json()
        self.result = {'failed': False, 'changed': False}

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
        self.workflow_callback_present = False
        self.workflow_callback = arg_workflow_callback
        self.workflow_context = arg_workflow_context
        if arg_workflow_callback != "":
            self.workflow_callback_present = True

        # The following will be initialized to the name of the user in DECS controller, that corresponds to
        # the credentials supplied as authentication information parameters
        self.decs_username = ''

        self.run_phase = "Run phase: Initializing DECSController instance."

        if self.authenticator == "jwt":
            if not arg_jwt:
                self.result['failed'] = True
                self.result['msg'] = ("JWT based authentication requested, but no JWT specified. "
                                      "Use 'jwt' parameter or set 'DECS_JWT' environment variable")
                self.amodule.fail_json(**self.result)
        elif self.authenticator == "user":
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
        elif self.authenticator == "user":
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
        specified argyument.

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
         class instance init,.

        If method fails to obtain JWT it will abort the execution of the script by calling AnsibleModule.fail_json()
        method

        @return: JWT as string.
        """

        token_get_url = self.oauth2_url + "/v1/oauth/access_token"
        req_data = dict(grant_type="client_credentials",
                        client_id=self.app_id,
                        client_secret=self.app_secret,
                        response_type="id_token",
                        validity=3600,
                        )
        # TODO: Need standard code snippet to handle server timeouts gracefully
        # Consider a few retries before giving up or use requests.Session & requests.HTTPAdapter
        # see https://stackoverflow.com/questions/15431044/can-i-set-max-retries-for-requests-request

        # catch requests.exceptions.ConnectionError to handle incorrect oauth2_url case
        try:
            token_get_resp = requests.post(token_get_url, data=req_data)
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
                                  "HTTP status code {}, reason '{}'").format(
                token_get_url, self.amodule.params['app_id'],
                token_get_resp.status_code, token_get_resp.reason)
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
            self.result['msg'] = "Cannot validate JWT for incompatible authentication mode '{}'".format(self.authenticator)
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
        req_header = dict(Authorization="bearer {}".format(arg_jwt),
                          )

        try:
            api_resp = requests.post(req_url, headers=req_header)
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
                                  "HTTP status code {}, reason '{}', header '{}'").format(
                api_resp.url,
                api_resp.status_code, api_resp.reason, req_header)
            self.amodule.fail_json(**self.result)
            return False

        # If we fall through here, then everything went well.
        return True

    def validate_legacy_user(self):
        """Validate legacy user by obtaining a session key, which will be used for authenticating subsequent API calls
        to DECS controller.
        If successful, the session key is stored in self.session_key and True is returned. If unsuccessful for any
        reason, the method will exit.

        @return: True on successful validation of the legacy user.
        """

        if self.authenticator != 'user':
            self.result['failed'] = True
            self.result['msg'] = "Cannot validate legacy user for incompatible authentication mode '{}'".format(
                self.authenticator)
            self.amodule.fail_json(**self.result)
            return False

        req_url = self.controller_url + "/restmachine/cloudapi/users/authenticate"
        req_data = dict(username=self.user,
                        password=self.password,
                        )

        try:
            api_resp = requests.post(req_url, data=req_data)
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
                                  "HTTP status code {}, reason '{}'" ).format(req_url,
                                                                              api_resp.status_code,
                                                                              api_resp.reason)
            self.amodule.fail_json(**self.result)
            return False

        self.session_key = api_resp.content.decode('utf8')

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

        if self.authenticator == 'user':
            arg_params['authkey'] = self.session_key
        elif self.authenticator == 'jwt' or self.authenticator == 'oauth2':
            http_headers['Authorization'] = 'bearer {}'.format(self.jwt)

        while retry_counter > 0:
            try:
                api_resp = arg_req_function(req_url, params=arg_params, headers=http_headers)
            except requests.exceptions.ConnectionError:
                self.result['failed'] = True
                self.result['msg'] = "Failed to connect to '{}' when calling DECS API.".format(req_url)
                self.amodule.fail_json(**self.result)
                return None  # actually, this directive will never be executed as fail_json aborts the script
            except requests.exceptions.Timeout:
                self.result['failed'] = True
                self.result['msg'] = "Timeout when trying to connect to '{}' when calling DECS API.".format(req_url)
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
                                      "reason '{}', parameters '{}'.").format(req_url,
                                                                              api_resp.status_code,
                                                                              api_resp.reason, arg_params)
                self.amodule.fail_json(**self.result)
                return None  # actually, this directive will never be executed as fail_json aborts the script

        # if we get through here, it means that we were getting HTTP 503 while retrying - generate error
        self.result['failed'] = True
        self.result['msg'] = "Error when calling DECS API '{}', HTTP status code '{}', reason '{}'.". \
            format(req_url, api_resp.status_code, api_resp.reason)
        self.amodule.fail_json(**self.result)
        return None

    def _vm_get_by_id(self, arg_vm_id):
        """Helper function that locates VM by ID and returns VM facts.

        @param arg_vm_id: ID of the VM to find and return facts for.

        @return: VM ID, dictionary of VM facts and VDC ID where this VM is located. Note that if it fails
        to find the VM for the specified ID, it may retunrn 0 for ID and empty dictionary for the facts. So
        it is suggested to check the return values accordingly.
        """
        ret_vm_id = 0
        ret_vm_dict = dict()
        ret_vdc_id = 0

        api_params = dict(machineId=arg_vm_id,
                          )
        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/get", api_params)
        if api_resp.status_code == 200:
            ret_vm_id = arg_vm_id
            ret_vm_dict = copy.deepcopy(json.loads(api_resp.content.decode('utf8')))
            ret_vdc_id = ret_vm_dict['cloudspaceid']

        return ret_vm_id, ret_vm_dict, ret_vdc_id

    def vm_delete(self, arg_vm_id, arg_permanently=False):
        """Delete a VM identified by VM ID. It is assumed that the VM with the specified ID exists.

        @param arg_vm_id: an integer VM ID to be deleted
        @param arg_permanently: a bool that tells if deletion should be permanent. If False, the VM will be
        marked as deleted and placed into a trash bin for predefined period of time (usually, a few days). Until
        this period passes the VM can be restored by calling 'restore' method.
        """

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vm_delete() in check mode: destroy VM ID {} was requested.".format(arg_vm_id)
            return

        api_params = dict(machineId=arg_vm_id,
                          permanently=arg_permanently,
                          )
        self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/delete", api_params)
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

        @return: ret_vm_id - ID of the VM on success (if the VM is found), 0 otherwise
        @return: ret_vm_facts - dictionary with VM details on success, empty dictionary otherwise
        """

        ret_vm_id, ret_vm_facts, _ = self.vm_find(arg_vm_id, arg_vm_name,
                                                  arg_vdc_id, arg_vdc_name,
                                                  arg_check_state=False)

        return ret_vm_facts

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
                # if non zero arg_vdc_id is specified, try to find the VM in the corresponding VDC
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
        """Manage VM port forwarding rules in a smart way. This method takes desried port forwarding rules as
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
        #   - existing not present in requested => copy to pfw_delta and mark as 'delete'
        #   - requested not present in the existing => copy to pfw_delta and mark as 'create'
        # 3) provision delta list (remove first, add next)
        #

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
            # self.result['changed'] = self.result['changed'] or False
            self.result['msg'] = ("vm_portforwards(): new and existing port forwarding lists both are empty - "
                                  "nothing to do. No change applied to VM ID {}.").format(arg_vm_dict['id'])
            return

        # pfw_delta_list will be a list of dictionaries that describe _changes_ to the port forwarding rules
        # that existed for the target VM at the moment we entered this method.
        # The dictionary has the following keys:
        #   ext_port -
        #   int_port -
        #   proto -
        #   action - either 'delete' or 'create'
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
                # NOTE!!! Another glitch in the API implementation - .../portforwarding/list returns ports as strings,
                # while .../portforwarding/create expects them as integers!!!
                if (int(existing_pfw['publicPort']) == requested_pfw['ext_port'] and
                        int(existing_pfw['localPort']) == requested_pfw['int_port'] and
                        existing_pfw['protocol'] == requested_pfw['proto']):
                    # full match - existing rule stays:
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

        self.result['pfw_debug_out'] = "{}".format(pfw_delta_list)

        if not len(pfw_delta_list):
            # nothing to do
            self.result['failed'] = False
            # self.result['changed'] = self.result['changed'] or False
            self.result['msg'] = ("vm_portforwards() no difference between current and requested port "
                                  "forwarding rules found. No change applied to VM ID {}.").format(arg_vm_dict['id'])
            return

        # need VDC facts to extract VDC external IP - it is needed to create new port forwarding rules
        _, vdc_facts = self.vdc_find(arg_vdc_id=arg_vm_dict['cloudspaceid'])

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

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = ("vm_powerstate() in check mode. Power state change of VM ID {} "
                                  "to '{}' was requested.").format(arg_vm_dict['id'], arg_target_state)
            return

        if arg_vm_dict['status'] in NOP_STATES_FOR_POWER_CHANGE:
            self.result['failed'] = False
            # self.result['changed'] = self.result['changed'] or False
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
            # self.result['changed'] = self.result['changed'] or False
            self.result['msg'] = ("vm_powerstate(): no power state change required for VM ID {} its from current "
                                  "state '{}' to desired state '{}'.").format(arg_vm_dict['id'],
                                                                              arg_vm_dict['status'],
                                                                              arg_target_state)
        return

    def vm_provision(self, arg_vdc_id, arg_vm_name,
                     arg_cpu, arg_ram,
                     arg_boot_disk, arg_image_id,
                     arg_data_disks=None,
                     arg_annotation=""
                     ):
        """Manage VM provisioning.
        To remove VM use vm_remove method.
        To resize VM use vm_size, to manage VM power state use vm_powerstate method.

        @return ret_vm_id: integer value that specifies the VM ID of provisioned VM. In check mode it will return 0.
        """

        #
        # TODO - add support for different types of boot & data disks
        # Currently type attribute of boot & data disk specifications is ignored until new storage provider types
        # are implemented into the cloud platform.
        #

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
                          datadisks=data_disk_sizes
                          )
        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/create", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        ret_vm_id = int(api_resp.content)
        return ret_vm_id

    def vm_resize_vector(self, arg_vm_dict, arg_cpu, arg_ram):
        """Check if the VM size parameters passed to this function are different from the current VM configuration.
        This method is usually called to see if the VM needs to be resized in the course of module run, as
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

        #
        # TODO - This method is under construction
        #

        return

    def vm_restore(self, arg_vm_id):
        """Restores a deleted VM identified by VM ID.

        @param arg_vm_id: integer value that defines the ID of a VM to be restored.
        """

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vm_restore() in check mode: restore VM ID {} was requested.".format(arg_vm_id)
            return

        api_params = dict(machineId=arg_vm_id,
                          reason="Restored on user request by Ansible DECS module.",
                          )
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

        # We need to handle a situation when either of 'cpu' or 'ram' parameter was not supplied. This is acceptable
        # when we manage state of the VM or request change to only one parameter - cpu or ram.
        # In such a case take the "missing" value from the current configuration of the VM.
        if not arg_cpu and not arg_ram:
            # if both are 0 or Null - return immediately, as user did not mean to manage size
            self.result['failed'] = False
            # self.result['changed'] = self.result['changed'] or False
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
            # self.result['changed'] = self.result['changed'] or False
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
                # self.result['changed'] = self.result['changed'] or False
                self.result['msg'] = ("vm_size() downsize of VM ID {} from CPU:RAM {}:{} to {}:{} was requested, "
                                      "but VM is in the state '{}' incompatible with down size operation").format(
                    arg_vm_dict['id'],
                    arg_vm_dict['vcpus'], arg_vm_dict['memory'],
                    arg_cpu, arg_ram, arg_vm_dict['status'])
                return

        api_resize_params = dict(machineId=arg_vm_dict['id'],
                                 memory=arg_ram,
                                 vcpus=arg_cpu,
                                 )
        self.decs_api_call(requests.post, "/restmachine/cloudapi/machines/resize", api_resize_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True
        return

    def image_find(self, arg_osimage_name, arg_vdc_id):
        """Locates image specified by name and returns its facts as dictionary.
        Primary use of this function is to obtain the ID of the image identified by its name

        @param arg_os_image: string that contains the name of the OS image

        @return: dictionary with image specs. If no image found by the specified name, it returns emtpy dictionary
        and sets self.result['failed']=True.
        """
        ret_image_facts = dict()
        api_params = dict(cloudspaceId=arg_vdc_id)

        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/images/list", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        image_list = json.loads(api_resp.content.decode('utf8'))
        for image_record in image_list:
            if image_record['name'] == arg_osimage_name and image_record['status'] == "CREATED":
                ret_image_facts = copy.deepcopy(image_record)
                return ret_image_facts

        self.result['failed'] = True
        self.result['msg'] = "Failed to find OS image by name '{}'.".format(arg_osimage_name)
        return None

    def vdc_delete(self, arg_vdc_id, arg_permanently=False):
        """Deletes specified VDC.

        @param arg_vdc_id: integer value that identifies the VDC to be deleted.
        @param arg_permanently: a bool that tells if deletion should be permanent. If False, the VDC will be
        marked as deleted and placed into a trash bin for predefined period of time (usually, a few days). Until
        this period passes the VDC can be restored by calling the corresponding 'restore' method.
        """

        if self.amodule.check_mode:
            self.result['failed'] = False
            self.result['changed'] = False
            self.result['msg'] = "vdc_delete() in check mode: delete VDC ID {} was requested.".format(arg_vdc_id)
            return

        #
        # TODO: need decision if deleting a VDC with VMs in it is allowed (aka force=True)

        api_params = dict(cloudspaceId=arg_vdc_id,
                          permanently=arg_permanently,
                          )
        self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/delete", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        self.result['failed'] = False
        self.result['changed'] = True

        return

    def vdc_find(self, arg_vdc_id=0, arg_vdc_name="", arg_check_state=True):
        """Returns non zero VDC ID and a dictionary with VDC details on success, 0 and empty dictionary otherwise.
        """

        VDC_INVALID_STATES = ["DESTROYED", "DELETED", "DESTROYING"]

        ret_vdc_id = 0
        api_params = dict()
        ret_vdc_dict = dict()

        if arg_vdc_id:
            api_params['cloudspaceId'] = arg_vdc_id
            api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/get", api_params)
            if api_resp.status_code == 200:
                ret_vdc_id = arg_vdc_id
                ret_vdc_dict = copy.deepcopy(json.loads(api_resp.content.decode('utf8')))
            else:
                self.result['failed'] = True
                # self.result['changed'] = self.result['changed'] or False
                self.result['msg'] = ("vdc_find(): cannot locate VDC with VDC ID {}. HTTP code {}, "
                                      "response {}.").format(arg_vdc_id, api_resp.status_code, api_resp.reason)
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
                            ret_vdc_id = vdc_record['id']
                            ret_vdc_dict = copy.deepcopy(vdc_record)
                            ret_vdc_ip = ret_vdc_dict['externalnetworkip']
        else:
            # Both arg_vdc_id and arg_vdc_name are empty - there is no way to locate VDC in this case
            self.result['failed'] = True
            # self.result['changed'] = self.result['changed'] or False
            self.result['msg'] = "vdc_find(): cannot locate VDC when VDC ID is zero and VDC name is empty string."
            self.amodule.fail_json(**self.result)

        return ret_vdc_id, ret_vdc_dict

    def vdc_portforwards(self):
        #
        # TODO - not implemented yet
        #
        return

    def vdc_provision(self, arg_tenant_id, arg_datacenter, arg_vdc_name, arg_username):
        """Provision new VDC according to the specified arguments.
        If critical error occurs the embedded call to API function will abort further execution of the script
        and relay error to Ansible.
        On success this method returns either 0 (if in check_mode) or the ID of the newly created VDC.

        @param arg_tenant_id: the non-zero ID of the tenant under which the new VDC will be created.
        @param arg_datacenter: the name of datacanter under the DECS controller where VDC will be created.
        @param arg_vm_name: the name of the VDC to be created.
        @param arg_username: the name of the user under DECS controller, who will have primary access to the newly
        created VDC.

        @return: integer ID of the newly created VDC.
        """

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
                          maxMemoryCapacity=-1, maxVDiskCapcity=-1,
                          maxCPUCapacity=-1, maxNumPublicIP=-1,
                          )
        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/cloudspaces/create", api_params)
        # On success the above call will return here. On error it will abort execution by calling fail_json.
        # API /restmachine/cloudapi/cloudspaces/create returns ID of the newly created VDC on success
        self.result['failed'] = False
        self.result['changed'] = True
        ret_vdc_id = int(api_resp.content)
        return ret_vdc_id

    def tenant_find(self, arg_tenant_name):
        """Find cloud tenant specified by the name anr return facts about the tenant. Tenant is required for certain
        cloud resource management tasks (e.g. creating new VDC).
        Returns non zero tenant ID and a dictionary with tenant details on success, 0 and empty dictionary otherwise.
        """

        ret_tenant_id = 0
        ret_tenant_dict = dict()

        if arg_tenant_name == "":
            self.result['failed'] = True
            # self.result['changed'] = self.result['changed'] or False
            self.result['msg'] = "Cannot find tenant by empty tenant name"
            self.amodule.fail_json(**self.result)

        api_resp = self.decs_api_call(requests.post, "/restmachine/cloudapi/accounts/list", None)
        if api_resp.status_code == 200:
            # Parse response to see if a tenant matching arg_tenant_name is found in the output
            # If it is found, assign its ID to the return variable and copy dictionary with the facts
            tenants_list = json.loads(api_resp.content.decode('utf8'))
            for tenant_record in tenants_list:
                if tenant_record['name'] == arg_tenant_name:
                    ret_tenant_id = tenant_record['id']
                    ret_tenant_dict = copy.deepcopy(tenant_record)

        return ret_tenant_id, ret_tenant_dict

    def workflow_cb_set(self, arg_workflow_callback, arg_workflow_context=None):
        self.workflow_callback = arg_workflow_callback
        if arg_workflow_callback != "":
            self.workflow_callback_present = True
        else:
            self.workflow_callback_present = False

        if arg_workflow_context:
            self.workflow_context = arg_workflow_context
        else:
            self.workflow_context = ""

        return

    def workflow_cb_call(self):
        #
        # TODO: under construction
        #
        if self.workflow_callback_present:
            pass
        return

    def run_phase_set(self, arg_phase_name):
        self.run_phase = arg_phase_name
        return