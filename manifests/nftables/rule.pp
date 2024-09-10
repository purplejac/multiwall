# lint:ignore:140chars
# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   multiwall::nftables::rule { 'namevar': }
#
# @param params [Hash]
#   The set of parameters being used to define the 'firewall' resource,
#   as outlined in the documentation for puppetlabs-firewall
#
define multiwall::nftables::rule (
  Hash $params,
  Integer $high_offset = 20,
  Integer $low_offset = 10,
  Integer $mid_val = 50,
  Integer $min_point = $mid_val - 20,
) {
  if $name =~ /^(\d+)/ {
    $num_string = String($1)
    $number = scanf($num_string.regsubst(/^0/,''), "%i")[0]

    if $number < $mid_val {
      $shift_num = $number + 1
      if $shift_num < $min_point {
        if $shift_num < 10 { 
          $order_val = "0${shift_num}"
        } else {
          $order_val = "${shift_num}"
        }
      } else {
          $order_val = String($mid_val - ($low_offset - ceil($number / $low_offset)))
      }
    } else {
      $order_val = String($mid_val + (($number / $high_offset) - 1 ))
    }

    $order_param = $order_val
  } else {
    $order_param = '50'
  }
  notice($order_val)
  if 'chain' in $params {
    $chain = $params['chain'].regsubst(/-/, '_', 'G')
  } else {
    $chain = 'INPUT'
  }

  $sanitised_name = ([$chain] + [(($name.split(/[ |-]/) - $num_string)).join('_')]).join('-').regsubst(/[\.|\/]/,'_', 'G')

  if $params['ensure'] == 'absent' {
    $filtered_params = { ensure => $params['ensure'] }
  } else {
    if $params['protocol'] {
      $protocol = $params['protocol'] ? { default => 'inet', 'iptables' => 'ip', 'ip6tables' => 'ip6', 'IPv4' => 'ip', 'IPv6' => 'ip6' }
    } else {
      $protocol = 'inet'
    }

    if $params['table'] {
      $table = $params['table']
    } else {
      $table = 'filter'
    }

    $action_commands = ['ACCEPT', 'accept', 'REJECT', 'reject', 'DROP', 'drop']

    $need_meta = ['mark', 'cgroup']
    #
    # Taking the 'beg forgiveness' approach to state assignment.
    # as ctstate is largely outdated, we'll assume that if it is declared
    # it is the target to use, otherwise we'll fall back to state.
    # If neither is defined and the ct action is being taken, catalog
    # compilation will fail.
    #
    if 'ctstate' in $params {
      $ctstate = $params['ctstate']
    } elsif 'state' in $params {
      $ctstate = $params['state']
    }

    if $params['log_prefix'] {
      $log_prefix = "log prefix '${params['log_prefix'].regsubst(/(^[a-zA-Z0-9_]+$)/, '_', 'G')}'"
    } else {
      $log_prefix = undef
    }

    $jump_commands = {
      'queue'      => 'queue',
      'return'     => 'return',
      'dnat'       => "dnat ${params['todest']}",
      'snat'       => "snat ${params['tosource']}",
      'log'        => $log_prefix,
      'netmap'     => "netmap to ${params['to']}",
      'masquerade' => 'masquerade',  # TO WHAT THOUGH?
      'redirect'   => "redirect ${params['toports']}", # TO WHAT THOUGH?
      'mark'       => "meta mark set ${params['connmark']}", # ??? INVESTIGATE
      'ct'         => "ct state ${params['ctstate']}", # Need to have a think about how to get this and state to match exclusively, individually
    }

    if  'action' in $params {
      $action = $params['action'].downcase()
    } elsif ('jump' in $params) {
      if ($params['jump'] in $action_commands) {
        $action = $params['jump'].downcase()
      } else {
        $action = $jump_commands[$params['jump']]
      }
    } else {
      $action = undef
    }

    #
    # There is no direct burst parameter for nftables, instead we'll mimick by implementing by setting the rate
    # limit to 'bursts per second' and a max of one packet allowed to exceed.
    #
    if 'burst' in $params {
      $burst = "limit rate ${params['burst']}/second burst 1"
    }

    #
    # The bytecode parameter does not really translate directly for nftables, leaving a commented reminder to have a think about whether
    # to still add an option for pre-compiled rule sets, or whether to continue to ignore.
    #
    # $bytecode = "-f ${params['bytecode']}" - part of the problem here is that nftables expects a file location, rather than a code string
    #

    if 'cgroup' in $params {
      $cgroup = "meta nfproto cgroupv2 cgroup ${params['cgroup']}"
    } else {
      $cgroup = undef
    }

    #
    # Checksum fill isn't really a direct option in nftables, may need constructing - disregarding for now
    #
    # if 'checksum_fill' in $params {
    #   $checksum_fill = 
    # }
    #

    #
    # As there's no pre-defined pmtu setting we will default to 1500 but allow for it to be overridden through hiera.
    #

    #if 'pmtu' in $params {
    #  $pmtu = $params['pmtu']
    #} else {
    #  $pmtu = 1500
    #}

    #
    # We then use the set pmtu to mimic the clamp_mss_to_pmtu functionality
    #
    #$clamp_mss_to_pmtu = "tcp flags & (fin|syn|rst|ack) == syn tcp option maxseg size set ${pmtu}"

    if $params['connlimit_mask'] {
        $netmask = multiwall::cidr2netmask($params['connlimit_mask'])
        $saddr = "ip saddr & ${netmask}"
    } elsif $params['source'] {
        $saddr = "ip saddr ${params['source']}"
    } else {
      $saddr = undef
    }

    if $params['destination'] {
      $daddr = "ip daddr ${params['destination']}"
    } else {
      $daddr = undef
    }

    if $params['dport'] {
      $dport = "dport ${params['dport']}"
    } else {
      $dport = undef
    }

    if $params['sport'] {
      $sport = "sport ${params['sport']}"
    } else {
      $sport = undef
    }

    #
    # https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers outlines this as the appropriate approach to
    # clamp MSS to PMTU
    # 
    if $params['clamp_mss_to_pmtu'] {
      $clamp_mss = 'tcp option maxseg size set rt mtu'
    } else {
      $clamp_mss = ''
    }

    #
    # Mimicking cluster flag from iptables, for nftables, according to the suggestion outlined by RH using iptables-translate here:
    # https://access.redhat.com/solutions/7033787 - deliberately not checking if all three values exist, to provoke a failure if
    # one of the required parameters is not set - implemented according to available firewall settings and considering all other
    # clusterip params deprecated as per the KB
    #
    if $params['clusterip_hash_init'] or $params['clusterip_total_nodes'] or $params['clusterip_local_node'] {
      $cluster_conf = "jhash ct original saddr mod ${params['clusterip_total_nodes']} seed ${params['clusterip_hash_init']} eq ${params['clusterip_local_node']} meta pkgttype set host counter"
    } else {
      $cluster_conf = ''
    }

    if $params['connlimit_above'] {
      $connlimit_above = "ct count over ${params['connlimit_above']}"
    } else {
      $connlimit_above = ''
    }

    if $params['connlimit_upto'] {
      $connlimit_upto = "ct count under ${params['connlimit_above']}"
    } else {
      $connlimit_upto = ''
    }

    $content = "${saddr} ${daddr} ${params['proto']} ${sport} ${dport} ${log_prefix} ${clamp_mss} ${cluster_conf} ${connlimit_upto} ${connlimit_above} ${action} ${cgroup}"

    $filtered_params = {
      'ensure'  => $params['ensure'],
      'table'   => "${protocol}-${table}",
      'order'   => $order_param,
      'content' => $content,
    }
  }

  nftables::rule { $sanitised_name:
    * => $filtered_params,
  }
}
# lint:endignore
