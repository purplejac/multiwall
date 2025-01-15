# multiwall

[![Puppet Forge](https://img.shields.io/puppetforge/v/purplejac/multiwall.svg)](https://forge.puppetlabs.com/purplejac/multiwall)
[![Puppet Forge - downloads](https://img.shields.io/puppetforge/dt/purplejac/multiwall.svg)](https://forge.puppetlabs.com/purplejac/multiwall)
[![puppetmodule.info docs](http://www.puppetmodule.info/images/badge.png)](http://www.puppetmodule.info/m/purplejac-sysctl)
[![Apache-2.0 License](https://github.com/purplejac/multiwall/blob/main/LICENSE)](LICENSE)

Universal firewall abstraction module

## Table of Contents

1. [Description](#description)
1. [Setup - The basics of getting started with multiwall](#setup)
    * [What multiwall affects](#what-multiwall-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with multiwall](#beginning-with-multiwall)
1. [Usage - Configuration options and additional functionality](#usage)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)

## Description


This module abstracts firewall resources based on the structure of resource 
declarations applied on [puppetlabs/firewall](https://forge.puppet.com/modules/puppetlabs/firewall)

The module is designed with modularisation and expandability in mind. The thought is to
abstract firewall resources to create a simple, agnostic, drop-in-replace set of resource
types to be used in replacing the firewall and firewallchain resources provided by 
puppetlabs/firewall

The longer-term view is to allow for the relatively simple expansion adding
other firewall types to the module, mapping content and features independently
with rules defined in module hiera.
Initially, the nftables conversion relies on defined types based on the resources
offered by the Vox Pupuli [nftables](https://forge.puppet.com/modules/puppet/nftables)

## Setup

### Setup Requirements

Module dependencies currently exist for puppetlabs/firewall, puppet/nftables
and their underlying dependencies.
Any initial setup will require at least two Puppet runs for idempotency, as the first run
sets up supported/expected firewall targets and the second applies proper rule enforcement.

### Beginning with multiwall

Initial setup/configuation of multiwall itself can be done with a simple 'include' on the multiwall
resource. The module will attempt to auto-resolve the underlying module choice, 
based on the default firewall for the OS-family and version.

```puppet
include multiwall
```

Chains can then be defined using multiwall::chain resources:
```puppet
multiwall::chain { 'INPUT:filter:IPv4':
  ensure => present,
  policy => drop,
  before => undef,
}
```

## Usage

Include usage examples for common use cases in the **Usage** section. Show your
users how to use your module to solve problems, and be sure to include code
examples. Include three to five examples of the most important or common tasks a
user can accomplish with your module. Show users how to accomplish more complex
tasks that involve different types, classes, and functions working in tandem.

## Reference

This section is deprecated. Instead, add reference information to your code as
Puppet Strings comments, and then use Strings to generate a REFERENCE.md in your
module. For details on how to add code comments and generate documentation with
Strings, see the [Puppet Strings documentation][2] and [style guide][3].

If you aren't ready to use Strings yet, manually create a REFERENCE.md in the
root of your module directory and list out each of your module's classes,
defined types, facts, functions, Puppet tasks, task plans, and resource types
and providers, along with the parameters for each.

For each element (class, defined type, function, and so on), list:

* The data type, if applicable.
* A description of what the element does.
* Valid values, if the data type doesn't make it obvious.
* Default value, if any.

For example:

```
### `pet::cat`

#### Parameters

##### `meow`

Enables vocalization in your cat. Valid options: 'string'.

Default: 'medium-loud'.
```

## Limitations

In the Limitations section, list any incompatibilities, known issues, or other
warnings.

## Development

In the Development section, tell other users the ground rules for contributing
to your project and how they should submit their work.

## Release Notes/Contributors/Etc. **Optional**

If you aren't using changelog, put your release notes here (though you should
consider using changelog). You can also add any additional sections you feel are
necessary or important to include here. Please use the `##` header.

[1]: https://puppet.com/docs/pdk/latest/pdk_generating_modules.html
[2]: https://puppet.com/docs/puppet/latest/puppet_strings.html
[3]: https://puppet.com/docs/puppet/latest/puppet_strings_style.html
