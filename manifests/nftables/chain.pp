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
#   multiwall::nftables::chain { 'namevar': }
define multiwall::nftables::chain (
  Enum[present, absent, 'present', 'absent']          $ensure,
  Boolean                                             $ignore_foreign = false,
  Boolean                                             $purge          = false,
  Boolean                                             $use_inet       = true,
  Optional[Variant[String[1], Array[String[1]]]]      $ignore         = undef,
  Optional[Enum['accept', 'drop', 'queue', 'return']] $policy         = undef,
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

  #
  # Realise the resource with the provided settings
  #
  nftables::chain { $name:
    table  => $table,
    chain => $chain_config[0],
  }
}
