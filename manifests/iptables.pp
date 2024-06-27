# @summary
# Wrapper class around the standard puppetlabs-firewall module.
# Exists to allow multiwall to abstract away from the immediate module
# layer while also providing the option over set module-targeted overrides
# as a lookup hash, rather than directly to the firewall module.
# Only really includes the firewall module in preparation for use.
# 
# @example
#   include multiwall::iptables
#
# @param target_fw_features [Hash]
# A hash keyed on the parameters in the firewall module, allowing for overrides
# of the firewall parameters, as-required.
#
class multiwall::iptables (
  Optional[Hash]  $target_fw_features = undef,
) {
  if $target_fw_features {
    class { 'firewall':
      * => $target_fw_features,
    }
  } else {
    include firewall
  }
}
