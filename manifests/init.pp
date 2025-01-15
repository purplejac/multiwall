# @summary
# Performs the basic tasks required to identify and action the 
# prep required for the targeted firewall to be put into use.
# Primarily exists to facilitate the translation of module-related
# settings for the required firewall modules, and to ensure that the
# modules are loaded as-needed.
#
# @example
#   include multiwall
#
# @param target_firewall [Enum['iptables', 'nftables']]
# The firewall to be targeted, to start with offering the
# options of iptables and nftables 
#
# @param target_fw_features [Hash]
# A hash of any parameters that might be relevant for the underlying 
# module. 
# The hash is fed to the underlying class and subsequently to the 
# appropriate module with a 'splat', so should match the documented
# parameters for the module in-question.
#
class multiwall (
  Enum['iptables', 'nftables']  $target_firewall = 'nftables',
  Boolean $manage_fact_dir = false,
  Boolean $strict_defaults = false,
  Hash    $target_fw_features = {},
) {
  if $manage_fact_dir {
    file { ['/etc/puppetlabs/facter', '/etc/puppetlabs/facter/facts.d']:
      ensure => 'directory',
      before => File['/etc/puppetlabs/facter/facts.d/multiwall_target.yaml'],
    }
  }

  file { '/etc/puppetlabs/facter/facts.d/multiwall_target.yaml':
    ensure  => 'file',
    content => "multiwall_target: ${target_firewall}",
  }

  if $strict_defaults {
    $unset_defaults = {
      out_ntp  => false,
      out_http => false,
      out_dns  => false,
      out_https => false,
      out_icmp => false,
      in_ssh => false,
      in_icmp => false,
    }
    $module_features = $target_fw_features + $unset_defaults
  } else {
    $module_features = $target_fw_features
  }

  class { "multiwall::${target_firewall}":
    target_fw_features => $module_features,
  }
}
