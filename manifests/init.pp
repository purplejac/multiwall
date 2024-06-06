# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include multiwall
class multiwall(
  Hash    $firewall_features = {},
  Hash    $nftables_features = {},
  Boolean $target_firewall = 'nftables',
){
  if $target_firewall == 'nftables' {
    if $nftables_features == {} {
      include nftables
    } else {
      class { 'nftables':
        * =>  $nftables_features,
      }
    }
  } else {
    if $firewall_features == {} {
      include nftables
    } else {
      class { 'firewall':
        * =>  $firewall_features,
      }
    }
  }
}
