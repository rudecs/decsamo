# decsamo
Ansible modules for managing DECS cloud resources.

You can find modules under Modules directory and some examples under Examples.

To install the modules for a particular playbook, do the following (assume your playbook is located in ./myfolder):
1) create a directory to hold modules as ./myfolder/library
2) copy decs_vm.py, decs_vdc.py and decs_jwt.py to 
3) create a directory to hold utilities code that supports DECS Ansible modules as ./myfolder/module_utils
4) copy decs_utility.py to ./myfolder/module_utils

The above layout is recommended by Ansible. More details can be found at https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html#directory-layout

Alternatively, you can setup the modules globally on your Ansible host.
For Ansible 2.6+ on Ubuntu do the following as root:
1) copy decs_vm.py to /usr/share/ansible/plugins/modules/ 
2) copy utility library decs_utility.py to /usr/lib/python2.7/dist-packages/ansible/module_utils/)

If you have installed the modules globally, you can check module documentation and examples by running the following command:

ansible-doc -t module decs_vm

Please note that this module is still under testing and development, so bear with possible flaws and glitches for a time being (and especially if planning to use it for production right now).
