# @summary
# Wrapper class around the standard puppet-nftables module.
# Exists to allow multiwall to abstract away from the immediate module
# layer while also providing the option over set module-targeted overrides
# as a lookup hash, rather than directly to the nftables module.
# Only really includes the firewall module in preparation for use.
# 
# @example
#   include multiwall::nftables
#
# @param target_fw_features [Hash]
# A hash keyed on the parameters in the nftables module, allowing for overrides
# of the module parameters, as-required.
#
class multiwall::nftables (
  Hash  $target_fw_features = {},
) {
  if $target_fw_features == {} {
    include nftables
  } else {
    class { 'nftables':
      * => $target_fw_features,
    }
  }

  nftables::set { 'ip4dynamic':
    type  => 'ipv4_addr',
    flags => ['dynamic'],
  }
}
