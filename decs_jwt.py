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
module: decs_jwt
short_description: Obtain access token to be used for authentication to DECS cloud controller
description:
     - Obtain JWT (Json Web Token) from the specified Oauth2 provider. This JWT can be used in subsequent DECS modules
       invocations to authenticate them to the DECS cloud controller.
version_added: "1.0"
author: "Sergey Shubin (sergey.shubin@digitalenergy.online)"
notes:
     - Environment variables can be used to pass parameters to the module
     - Specified Oauth2 provider must be trusted by the DECS cloud controller on which JWT will be used.
     - If you register module output as my_jwt, the JWT value is accessed as my_jwt.jwt
requirements:
     - "python >= 2.6"
'''

EXAMPLES = '''
- name: Obtain JWT and store it as my_jwt for authenticating subsequent task to DECS cloud controller
  decs_jwt:
    app_id: "{{ my_app_id }}"
    app_secret: "{{ my_app_secret }}"
    oauth2_url: https://sso.decs.online
    delegate_to: localhost
    register: my_jwt
'''

RETURN = '''
jwt:
    description: JSON web token that can be used to access DECS cloud controller
    returned: always
    type: string
    sample: None
'''

import requests

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

def decs_jwt_parameters():
    """Build and return a dictionary of parameters expected by decs_jwt module in a form accepted
    by AnsibleModule utility class"""

    return dict(
        app_id=dict(type='str',
                    required=True,
                    fallback=(env_fallback, ['DECS_APP_ID'])),
        app_secret=dict(type='str',
                        required=True,
                        fallback=(env_fallback, ['DECS_APP_SECRET'])),
        oauth2_url=dict(type='str',
                        required=True,
                        fallback=(env_fallback, ['DECS_OAUTH2_URL'])),
        workflow_callback=dict(type='str', required=False),
        workflow_context=dict(type='str', required=False),
    )

def main():
    module_parameters = decs_jwt_parameters()

    amodule = AnsibleModule(argument_spec=module_parameters,
                            supports_check_mode=True,
                            )

    result = {'failed': False, 'changed': False}

    token_get_url = amodule.params['oauth2_url'] + "/v1/oauth/access_token"
    req_data = dict(grant_type="client_credentials",
                    client_id=amodule.params['app_id'],
                    client_secret=amodule.params['app_secret'],
                    response_type="id_token",
                    validity=1200,
                    )
    # TODO: Need standard code snippet to handle server timeouts gracefully
    # Consider a few retries before giving up or use requests.Session & requests.HTTPAdapter
    # see https://stackoverflow.com/questions/15431044/can-i-set-max-retries-for-requests-request

    # catch requests.exceptions.ConnectionError to handle incorrect oauth2_url case
    try:
        token_get_resp = requests.post(token_get_url, data=req_data)
    except requests.exceptions.ConnectionError:
        result.update(failed=True)
        result['msg'] = "Failed to connect to {}".format(token_get_url)
        amodule.fail_json(**result)
    except requests.exceptions.Timeout:
        result.update(failed=True)
        result['msg'] = "Timeout when trying to connect to {}".format(token_get_url)
        amodule.fail_json(**result)

    # alternative -- if resp == requests.codes.ok
    if token_get_resp.status_code != 200:
        result.update(failed=True)
        result['msg'] = "Failed to obtain JWT access token from oauth2_url {} for app_id {}: {} {}".format(
            token_get_url, amodule.params['app_id'],
            token_get_resp.status_code, token_get_resp.reason)
        amodule.fail_json(**result)

    # Common return values: https://docs.ansible.com/ansible/2.3/common_return_values.html
    result['jwt'] = token_get_resp.content.decode('utf8')
    amodule.exit_json(**result)

if __name__ == '__main__':
    main()