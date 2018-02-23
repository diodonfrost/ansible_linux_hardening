# Ansible linux_hardening

This repository provides Ansible modules for hardening CentOS 7.

## Requirements

*   Ansible 2.4
*   CentOS 7

## Role Variables

Available variables are listed below, along with default values (see vars/.yml):

Apply pci-dss compliance:
```
security_standard: "pci-dss"
```

Apply stig redhat 7 compliance:
```
security_standard: "stig-rhel7"
```

Apply cloud provider compliance:
```
security_standard: "rht-ccp"
```


## Dependencies

None.

## Example Playbook


```
- hosts: localhost
  vars:
    security_standard: "pci-dss"

  roles:
    - ansible_linux_hardening
```

## License
GNU GPL 3
