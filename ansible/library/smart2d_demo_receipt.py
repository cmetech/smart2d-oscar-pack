"""Minimal Ansible library module bundled with the Smart2D pack."""

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(argument_spec={})
    module.exit_json(changed=False, message="Smart2D Ansible library example ran")


if __name__ == "__main__":
    main()
