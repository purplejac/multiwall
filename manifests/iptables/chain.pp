# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   multiwall::iptables::chain { 'namevar': }
define multiwall::iptables::chain (
    Enum[present, absent, 'present', 'absent']          $ensure,
    Boolean                                             $ignore_foreign = false,
    Boolean                                             $purge          = false,
    Optional[Variant[String[1], Array[String[1]]]]      $ignore         = undef,
    Optional[Enum['accept', 'drop', 'queue', 'return']] $policy         = undef,
) {
  firewallchain { $name:
    ensure         => $ensure,
    ignore_foreign => $ignore_foreign,
    purge          => $purge,
    ignore         => $ignore,
    policy         => $policy,
  }
}
