#lint:ignore:140chars
# @summary Generic firewall chain resource to abstract the chain creation based on the parameters used for puppetlabs/firewall
#
# @param ensure 
# Data type: Enum[present, absent, 'present', 'absent']
# Standard ensure parameter stating the expected state of the resource
#
# @param ignore_foreign
# Data type: Boolean
# Ignore rules that do not match the puppet title pattern "^\d+[[:graph:][:space:]]" when purging unmanaged firewall rules in this chain.
# This can be used to ignore rules that were not put in by puppet. Beware that nothing keeps other systems from configuring firewall rules
# with a comment that starts with digits, and is indistinguishable from puppet-configured rules.
# Not currently enforced for nftables...
#
# @param purge
# Data type: Boolean
# Whether or not to purge unmanaged rules in this chain
# Not currently enforced for nftables...
#
# @param type
# Data type: Optional[Enum['filter', 'nat', 'route']] 
# Type setting for nftables base chain. Will fail if hook and priority are not also set.
# non-iptables setting
#
# @param hook Optional[Enum[input, forward, output, prerouting, postrouting]]
# Kernel hook to connect the chain when creating an nftables base chain.
# requires type and priority to be set, otherwise compilation will fail with an error.
#
# @oaram priority
# Data type: Optional[Integer]
# Chain/hook priority setting. Fails without hook and type set
# non-iptables setting
#
# @param target_firewall
# Data type: String
# Name of the targeted firewall to be used, if overwriting the default firewall choice
# non-iptables setting
#
# @param ignore
# Data type: Optional[Variant[String[1], Array[String[1]]]]
# Regex to perform on firewall rules to exempt unmanaged rules from purging.
# This is matched against the output of `iptables-save`.
# Not currently enforced for nftables...
#
# @param policy
# Data type: Optional[Enum['accept', 'drop', 'queue', 'return']]
# This action to take when the end of the chain is reached.
# This can only be set on inbuilt chains (i.e. INPUT, FORWARD, OUTPUT, PREROUTING, POSTROUTING)
# Not currently enforced for nftables...
#
# A description of what this defined type does
#
# @example
#   multiwall::chain { 'namevar': }
#
define multiwall::chain (
  Enum[present, absent, 'present', 'absent']                                $ensure,
  Boolean                                                                   $ignore_foreign  = false,
  Boolean                                                                   $purge           = false,
  Optional[Enum['filter', 'nat', 'route']]                                  $type           = undef,
  Optional[Enum['input', 'forward', 'output', 'prerouting', 'postrouting']] $hook           = undef,
  Optional[Integer]                                                         $priority       = undef,
  Optional[String]                                                          $target_firewall = undef,
  Optional[Variant[String[1], Array[String[1]]]]                            $ignore          = undef,
  Optional[Enum['accept', 'drop', 'queue', 'return']]                       $policy          = undef,
) {
  #
  # Check if the firewall setting has been overwritten and enforce, if-so, otherwise
  # assume the firewall type based on the default target for each OS
  #
  if $target_firewall {
    $firewall = $target_firewall
  } else {
    case $facts['os']['family'] {
      'RedHat': {
        if ($facts['os']['name'] != 'Fedora' and $facts['os']['release']['major'] < '8') or ($facts['os']['release']['major'] < '29') {
          $firewall = 'iptables'
        } else {
          $firewall = 'nftables'
        }
      }
      'Debian': {
        if ($facts['os']['name'] != 'Ubuntu' and $facts['os']['release']['major'] < '10') or (versioncmp($facts['os']['release']['major'], '21.10') < 1) {
          $firewall = 'iptables'
        } else {
          $firewall = 'nftables'
        }
      }
      'Suse': {
        if $facts['os']['release']['major'] > '15' {
          $firewall = 'nftables'
        } else {
          $firewall = 'iptables'
        }
      }
      default: {
        $firewall = 'nftables'
      }
    }
  }

#
# Construct the standardised hash for the chain declaration to be realised, using the appropriate chain type
# as defined witgh the firwall variable
#
  if $firewall == 'iptables' {
    $fw_chain = {
      $name => {
        ensure         => $ensure,
        ignore_foreign => $ignore_foreign,
        purge          => $purge,
        ignore         => $ignore,
        policy         => $policy,
      },
    }
  } else {
    $fw_chain = {
      $name => {
        ensure         => $ensure,
        ignore_foreign => $ignore_foreign,
        purge          => $purge,
        ignore         => $ignore,
        policy         => $policy,
        type           => $type,
        hook           => $hook,
        priority       => $priority,
      },
    }
  }

  create_resources("multiwall::${firewall}::chain", $fw_chain)
# lint:endignore
}
