# @summary firewall chain resource to implement the firewallchain resource from puppetlabs/firewall
#
# @param ensure
# Data type: Enum[present, absent, 'present', 'absent']
# Standard ensure parameter stating the expected state of the resource
#
# @param ignore_foreign
# Data type: Boolean
# Ignore rules that do not match the puppet title pattern "^\d+[[:graph:][:space:]]" when purging unmanaged firewall rules in this chain.
# This can be used to ignore rules that were not put in by puppet. Beware that nothing keeps other systems from configuring firewall rules with a comment that starts with digits, and is indistinguishable from puppet-configured rules.
#
# @param purge
# Data type: Boolean
# Whether or not to purge unmanaged rules in this chain
#
# @param ignore
# Data type: Optional[Variant[String[1], Array[String[1]]]]
# Regex to perform on firewall rules to exempt unmanaged rules from purging.
# This is matched against the output of `iptables-save`.
#
# @param policy
# Data type: Optional[Enum['accept', 'drop', 'queue', 'return']]
# This action to take when the end of the chain is reached.
# This can only be set on inbuilt chains (i.e. INPUT, FORWARD, OUTPUT, PREROUTING, POSTROUTING)
#
# A description of what this defined type does
# @example
#   multiwall::iptables::chain { 'namevar': }
define multiwall::iptables::chain (
    Enum[present, absent, 'present', 'absent']          $ensure,
    Boolean                                             $ignore_foreign = false,
    Boolean                                             $purge          = false,
    Optional[Variant[String[1], Array[String[1]]]]      $ignore         = undef,
    Optional[Enum['accept', 'drop', 'queue', 'return']] $policy         = undef,
) {
  #
  # Simply directly declare the firewallchain transferring the arguments directly to firewallchain
  #
  firewallchain { $name:
    ensure         => $ensure,
    ignore_foreign => $ignore_foreign,
    purge          => $purge,
    ignore         => $ignore,
    policy         => $policy,
  }
}
