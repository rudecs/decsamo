# decsamo Ver 1.5 (GPU enabled)

ВНИМАНИЕ: если вы используете облачную платформу версии 3.4.2 или выше, то вам необходимо использовать новый модуль DECORT (https://github.com/rudecs/decort-ansible)

Ansible-модуль для управления ресурсами облачной платформы DECS

Документация на русском языке: https://github.com/rudecs/decsamo/wiki

Ansible modules for managing DECS cloud resources.

NOTE: if you are using cloud platform version 3.4.2 or above, please use new module DECORT (https://github.com/rudecs/decort-ansible)

You can find modules under Modules directory and some examples under Examples.

To install the modules for a particular playbook, do the following (assume your playbook is located in ./myfolder):
1) create a directory to hold modules as ./myfolder/library
2) copy decs_vm.py, decs_vdc.py and decs_jwt.py to 
3) create a directory to hold utilities code that supports DECS Ansible modules as ./myfolder/module_utils
4) copy decs_utility.py to ./myfolder/module_utils

The above layout is recommended by Ansible. More details on this layout can be found at 
https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html#directory-layout

Alternatively, you can setup the modules globally on your Ansible host.
For Ansible 2.6+ on Ubuntu do the following as root:
1) copy decs_vm.py to /usr/share/ansible/plugins/modules/ 
2) copy utility library decs_utility.py to /usr/lib/python2.7/dist-packages/ansible/module_utils/)

If you have installed the modules globally, you can check module documentation and examples by running the following command:

ansible-doc -t module decs_vm

