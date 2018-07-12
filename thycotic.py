#!/usr/bin/python

# (c) 2018 Kami Gerami <kami.gerami@codelabs.se>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: thycotic
short_description: Get username and password from a thycotic server REST endpoint.
description:
    - The module interacts with the API of the thycotic server.
    - This module works by searching the provided folder path for a secretname and return the username and password.
version_added: "2.5"
author: "Kami Gerami (@kamigerami)"
options:
    username:
        description:
            - The username to authenticate with.
        default: "user"
    password:
        description:
            - The password to authenticate with.
        required: True
    secret_name:
        description:
            - The name of the secret that you want.
        default: "secret"
    baseurl:
        description:
            - The base url of your thycotic server.
        required: True
    folder_path:
        description:
            - The path of the folder in which you want to search for secrets in.
        required: True
    schema:
        description:
            - Use http or https connection to the server.
        choices: ['http', 'https']
        default: 'https'
    use_proxy:
        description:
            - A boolean switch to ignore proxy settings for this hosts request.
        type: bool
        default: False

'''

RETURN = '''
data:
    description: Returns username and password as a dict.
    returned: success
    type: dict
    result: '{
        "changed": false,
        "failed": false,
        "password": "secret",
        "username": "user"
    }'
'''

EXAMPLES = '''
# Get username and password for mysecret.
- thycotic:
      username: "demo"
      password: "{{ thycotic.password }}"
      secret_name: "mysecret"
      baseurl: "thycotic.domain"
      folder_path: "dev"
      schema: "http"
      use_proxy: "no"
  register: data

- debug:
      msg: "username: {{ data.username }} password: {{ data.password }}"
'''

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url


result = {}


def retrieve_token(module, username, password, url, use_proxy):
    '''Retrieve a token from the oauth2/token uri'''

    data = "username={0}&password={1}&grant_type=password".format(
            username,
            password
    )
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    response, info = fetch_url(module,
                               url,
                               data=data,
                               headers=headers,
                               method='POST',
                               use_proxy=use_proxy)
    status_code = info["status"]

    if status_code == 200:
        if module.check_mode:
            module.exit_json(changed=False,
                             msg="Successfully retrieved token from api: \
                             {0} with status code: {1}".format(
                                                                url,
                                                                status_code))

        response_body = json.loads(response.read())
        return response_body['access_token']
    # something's wrong
    else:
        result['msg'] = "Failed to retrieve token, the error was: {0}".format(
                                                                    info['msg']
                                                                    )
        module.fail_json(**result)


def get_from_uri(module, url, token, use_proxy, path,
                 secret_id=None, user=None, pw=None):
    '''Get request from provided url path'''

    data = ""
    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'bearer {0}'.format(token),
    }
    # get username only if we have a secret_id already
    if secret_id and user is True:
        url = "{0}/{1}/{2}/fields/username".format(url, path, secret_id)
    # get password only if we have a secret_id already
    elif secret_id and pw is True:
        url = "{0}/{1}/{2}/fields/password".format(url, path, secret_id)
    else:
        url = "{0}/{1}?take=10000".format(url, path)

    response, info = fetch_url(module,
                               url,
                               data=module.jsonify(data),
                               headers=headers,
                               method='GET', use_proxy=use_proxy)
    status_code = info["status"]

    if status_code == 200:
        response_body = json.loads(response.read())
        return response_body
    # something's wrong
    else:
        result['msg'] = "Failed to retrieve {0}, the error was: {1}".format(
                                                            path, info['msg']
                                                            )
        module.fail_json(**result)


def main():
    module = AnsibleModule(
             argument_spec=dict(
                                username=dict(required=True),
                                password=dict(required=True, no_log=True),
                                secret_name=dict(required=True),
                                baseurl=dict(required=True),
                                folder_path=dict(required=True),
                                schema=dict(default='https',
                                            choices=['http', 'https']),
                                use_proxy=dict(default=False, type='bool'),
                                ),
             supports_check_mode=True)

    # normalize params
    username = module.params['username']
    password = module.params['password']
    secret_name = module.params['secret_name']
    baseurl = module.params['baseurl']
    folder_path = module.params['folder_path']
    schema = module.params['schema']
    token_url = '%s://%s/oauth2/token' % (schema, baseurl)
    api_url = '%s://%s/api/v1' % (schema, baseurl)
    use_proxy = module.params['use_proxy']

    # Retrieve token
    token = retrieve_token(module, username, password, token_url, use_proxy)
    # Get folders records
    folders = get_from_uri(module, api_url, token,
                           use_proxy, 'folders')['records']
    # Get secrets records
    secrets = get_from_uri(module, api_url, token,
                           use_proxy, 'secrets')['records']
    # Loop through folders and secrets to match for folder_path and secret_name
    folder_id = None
    secret_id = None
    for fp in folders:
        # compare against lowercase string
        if folder_path.lower() in fp['folderPath'].lower():
            # save id
            folder_id = fp['id']
    # we did not find a folder_id so fail
    if folder_id is None:
        result['msg'] = "Failed to find {0}".format(folder_path)
        module.fail_json(**result)

    for sc in secrets:
        if secret_name in sc['name'] and folder_id == sc['folderId']:
            # save id
            secret_id = sc['id']
    # we did not find a secret_id so fail
    if secret_id is None:
        result['msg'] = "Failed to find {0}".format(secret_name)
        module.fail_json(**result)

    # get username using secret_id we fetched earlier
    usern = get_from_uri(module, api_url, token, use_proxy,
                         'secrets', secret_id, user=True)
    # get password using secret_id we fetched earlier
    passw = get_from_uri(module, api_url, token, use_proxy,
                         'secrets', secret_id, pw=True)
    # save to result dict
    result['username'] = usern
    result['password'] = passw
    module.exit_json(**result)


if __name__ == '__main__':
    main()
