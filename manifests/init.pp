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
  Hash    $target_fw_features = {},
) {
  if $manage_fact_dir {
    file { ['/etc/puppetlabs/facter', '/etc/puppetlabs/facter/facts.d']:
      ensure => 'directory',
    }
  }

  file { '/etc/puppetlabs/facter/facts.d/multiwall_target.yaml':
    ensure  => 'file',
    content => "multiwall_target: ${target_firewall}",
  }

  if $target_fw_features == {} {
    include "multiwall::${target_firewall}"
  } else {
    class { "multiwall::${target_firewall}":
      target_fw_features => $target_fw_features,
    }
  }
}
