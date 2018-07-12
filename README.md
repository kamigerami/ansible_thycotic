### Ansible Thycotic (SecretServer) Module

The module interacts with the API of the thycotic server. 

This module works by searching the provided folder path for a secretname and return the username and password.


##### USAGE:

Place the thycotic module in your ansible module path ./library

or by specifying the `--module-path=MODULE_PATH flag -M` 

when running `ansible-playbook -M MODULE_PATH`


##### OPTIONS (= is mandatory):

```
= baseurl
        The base url of your thycotic server.


= folder_path
        The path of the folder in which you want to search for secrets in.


= password
        The password to authenticate with.


- schema
        Use http or https connection to the server.
        (Choices: http, https)[Default: https]

- secret_name
        The name of the secret that you want.
        [Default: secret]

- use_proxy
        A boolean switch to ignore proxy settings for this hosts request.
        [Default: False]
        type: bool

- username
        The username to authenticate with.
        [Default: user]


AUTHOR: Kami Gerami (@kamigerami)
        METADATA:
          status:
          - preview
          supported_by: community
```

##### EXAMPLES:
```
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
```

##### RETURN VALUES:

```
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
``` 
