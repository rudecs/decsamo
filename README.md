# decsamo
Ansible modules for managing DECS cloud resources.

You can find modules under Modules directory and some examples under Examples.

Once you deploy this modules to your local Ansible host (e.g. for Ansible 2.6 on Ubuntu, by placing the module decs_vm.py under /usr/share/ansible/plugins/modules/ and utility library decs_utility.py under /usr/lib/python2.7/dist-packages/ansible/module_utils/), check module documentation and examples by running the following command:

ansible-doc -t module decs_vm

Please note that this module is still under testing and development, so bear with possible flaws and glitches for a time being (and especially if planning to use it for production right now).
