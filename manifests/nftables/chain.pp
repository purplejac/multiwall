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
# This can be used to ignore rules that were not put in by puppet. Beware that nothing keeps other systems from configuring firewall rules with a comment that starts with digits, and is indistinguishable from puppet-configured rules.
# Not currently enforced for nftables...
#
# @param purge
# Data type: Boolean
# Whether or not to purge unmanaged rules in this chain
# Not currently enforced for nftables...
#
# @param use_inet
# Data type: Boolean
# Deciding whether to use the shared inet table in nftables, over specifying the protocol-version (IPv4/IPv6)
# 
# @param type
# Data type: Optional[Enum['filter', 'nat', 'route']] 
# Type setting for nftables base chain. Will fail if hook and priority are not also set.
#
# @param hook Optional[Enum[input, forward, output, prerouting, postrouting]]
# Kernel hook to connect the chain when creating an nftables base chain.
# requires type and priority to be set, otherwise compilation will fail with an error.
#
# @oaram priority
# Data type: Optional[Integer]
# Chain/hook priority setting. Fails without hook and type set
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
# nftables only allows enforcement on base chains, so will result in failure if type, hook and priority are not also set.
#
# A description of what this defined type does
#
# @example
#   multiwall::nftables::chain { 'namevar': }
define multiwall::nftables::chain (
  Enum[present, absent, 'present', 'absent']                                $ensure,
  Boolean                                                                   $ignore_foreign = false,
  Boolean                                                                   $purge          = false,
  Boolean                                                                   $use_inet       = true,
  Optional[Enum['filter', 'nat', 'route']]                                  $type           = undef,
  Optional[Enum['input', 'forward', 'output', 'prerouting', 'postrouting']] $hook           = undef,
  Optional[Integer]                                                         $priority       = undef,
  Optional[Variant[String[1], Array[String[1]]]]                            $ignore         = undef,
  Optional[Enum['accept', 'drop', 'queue', 'return']]                       $policy         = undef,
) {
  $chain_config = $name.split(/:/)

  #
  # nftables defaults to a joint table for ipv4 and ipv6, therefore this type will do the same,
  # allowing for the setting to be specifically overwritten if required.
  #
  if $use_inet {
    $protocol = 'inet'
  } else {
    case $chain_config[2] {
      'IPv6': {
        $protocol = 'ip6'
      }
      'IPv4': {
        $protocol = 'ip'
      }
      default: {
        $protocol = $chain_config[2].downcase()
      }
    }
  }

  #
  # Convert the table name to match the nftables::chain type
  #
  $table = "${protocol}-${chain_config[1]}"

  if ($type or $priority or $policy) {
    unless $hook {
      fail('Cannot set type, priority or default-policy on non-base chains in nftables.')
    } else {
      unless $type and $priority and $policy {
        fail('Cannot create a base chain without setting type, priority and policy.')
      } else {
        concat::fragment { "nftables-${table}-chain-${chain_config[0]}-settings":
          target  => "nftables-${table}-chain-${chain_config[0]}",
          order   => '01',
          content => "type ${type} hook ${hook} priority ${String($priority)}",
        }

        if $policy {
          concat::fragment { "nftables-${table}-chain-${chain_config[0]}-policy":
            target  => "nftables-${table}-chain-${chain_config[0]}",
            order   => '02',
            content => "policy ${policy}",
          }
        }
      }
    }
  }

  #
  # Realise the resource with the provided settings
  #
  nftables::chain { $name:
    table => $table,
    chain => $chain_config[0],
  }
}
#lint:endignore
