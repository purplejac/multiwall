# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   multiwall::iptables::rule { 'namevar': }
#
# @param rule_parameters [Hash]
#   The set of parameters being used to define the 'firewall' resource,
#   as outlined in the documentation for puppetlabs-firewall
#
define multiwall::iptables::rule (
  Hash $rule_parameters,
) {
  firewall { $name:
    * => $rule_parameters,
  }
}
