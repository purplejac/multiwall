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
# @param fail_on_val_fail [Boolean]
#   Decides whether to fail when parameter validation fails or to just
#   create a notification resource to advice the failure but continue
#   with the implementation.
#
# @param high_offset [Integer]
#   Defines the offset for rule prioritisation to mimick the flow for
#   prioritisation from the firewall module.
#
# @param low_offset [Integer]
#   Defines the stgarting offset under which the priority is calculated
#   with the 'low value' calculation for values < low_offset
#
# @param mid_val [Integer]
#   Defines the middle offset point that is used to calculate priorfies
#   for values greater than 100
#
# @param min_point [Integer]
#   Defines the offset value under which no recalculation is performed
#   for the priorities
#
define multiwall::nftables::rule (
  Hash $params,
  Boolean $fail_on_val_fail = false,
  Integer $high_offset = 20,
  Integer $low_offset = 10,
  Integer $mid_val = 50,
  Integer $min_point = $mid_val - 20,
) {
  $param_check = multiwall::validate_nf_params($params)

  if $param_check[0] > 0 {
    $error_message = $param_check[0] ? {
      1       => "${param_check[1]} is not supported with nftables!",
      default => $param_check[1],
    }

    if $fail_on_val_fail {
      fail($error_message)
    } else {
      notify { $error_message: }
    }
  } else {
    if $name =~ /^(\d+)/ {
      $num_string = String($1)
      $number = Integer(scanf($num_string.regsubst(/^0*/,''), '%i')[0])

      if $number < $mid_val {
        $shift_num = $number + 1
        if $shift_num < $min_point {
          if $shift_num < 10 {
            $order_val = "0${shift_num}"
          } else {
            $order_val = $shift_num
          }
        } else {
          $order_val = String($mid_val - ($low_offset - ceiling($number / $low_offset)))
        }
      } else {
        $order_val = String($mid_val + (($number / $high_offset) - 1 ))
      }

      $order_param = String($order_val)
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
        #        $burst = "limit rate ${params['burst']}/second burst 1"
        $burst = lookup('mutliwall:nftables:burst')
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
      } elsif $params['source'] or $params['src_range'] or ($params['src_type'] and $params['src_type'] =~ /(blackhole|BLACKHOLE)/) {
        if $params['src_type'] and $params['src_type'] =~ /(blackhole|BLACKHOLE)/ {
          $saddr = "ip saddr ${facts['multiwall']['blackhole_targets'].join(',')}"
        }
        elsif $params['src_range'] {
          $saddr = "ip saddr ${params['src_range']}"
        } else {
          $saddr = "ip saddr ${params['source']}"
        }
      } else {
        $saddr = ''
      }

      if $params['destination'] or $params['dst_range'] or ($params['dst_type'] and $params['dst_type'] =~ /(blackhole|BLACKHOLE)/) {
        if $params['dst_type'] and $params['dst_type'] =~ /(blackhole|BLACKHOLE)/ {
          $daddr = "ip daddr ${facts['multiwall']['blackhole_targets'].join(',')}"
        }
        elsif $params['dst_range'] {
          $daddr = "ip daddr ${params['dst_range']}"
        } else {
          $daddr = "ip daddr ${params['destination']}"
        } 
      } else {
        $daddr = ''
      }

      if $params['dport'] {
        #$dport = "dport ${params['dport']}"
        $dport = lookup('multiwall:nftables:dport')
      } else {
        $dport = ''
      }

      if $params['sport'] {
        $sport = "sport ${params['sport']}"
      } else {
        $sport = ''
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

      #
      # Mimicking ctdir from iptables by converting to management of ct states established,related and using the ctdir setting to
      # decide whether to set saddr or daddr. If direction is not set correctly, will fall back to localhost target.
      #
      if $params['ctdir'] {
        unless $param_check[0] == 4 or $param_check[0] == 3 {
          $addr_command = $params['ctdir'] ? {
            /(REPLY|reply)/       => "ip daddr ${facts['networking']['ip']}",
            /(ORIGINAL|original)/ => "ip saddr ${facts['networking']['ip']}",
            default               => "ip daddr 127.0.0.1",
          }

          $ctdir = "${addr_command} ct state established,related"
        } else {
          $ctdir = ''
        }
      } else {
        $ctdir = ''
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

      #
      # There are several potential permutations of the conntract traffic management,
      # while some are more likely than others, it made sense to support them all and
      # trust the users. 
      # So management of the address and port/directional management is farmed out to 
      # the setup_ct_rule function, which will return a properly formatted string
      # of the relevant conttrack parameters
      #
      
      $conntrack = multiwall::setup_ct_rules($params)

      if $params['ctproto'] and ($params['ctorigdstport'] or $params['ctorigsrcport']) {
          $set_proto = $params['ctproto']
      } elsif $params['proto'] {
        if $params['proto'] == 'all' {
          $set_proto = '{ icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp }'
        } else {
          $set_proto = $params['proto']
        }
      } else {
        $set_proto = ''
      }

      if $set_proto  != '' and (! $params['saddr']) and (! $params['daddr']) {
        $proto = "ip protocol ${set_proto}"
      } else {
        $proto = $set_proto
      }

      if $params['ctstatus'] {
        if $params['ctstatus'] =~ Array {
          $fmt_status = $params['ctstatus'].join(',')
        } else {
          $fmt_status = $params['ctstatus']
        }

        $ctstatus = "ct status ${fmt_status.downcase()}"
      } else {
        $ctstatus = ''
      }

      if $params['date_start'] {
        $start_epoch = multiwall::time_to_epoch($params['date_start'])

        $filter_start_time = "meta time >= ${start_epoch}"
      } else {
        $filter_start_time = ''
      }

      if $params['date_stop'] {
        $stop_epoch = multiwall::time_to_epoch($params['date_stop'])

        $filter_stop_time = "meta time <= ${stop_epoch}"
      } else {
        $filter_stop_time = ''
      }

      if $params['dst_type'] or $params['src_type'] {
        $type_mgmt = multiwall::nft_format_types($params)
      } else {
        $type_mgmt = ''
      }

      if $params['gateway'] {
        $gateway = "dup to ${params['gateway']}"
      } else {
        $gateway = ''
      }

      if $params['uid'] {
        $uid = "skuid ${params['uid']}"
      } else {
        $uid = ''
      }

      if $params['gid'] {
        $gid = "skgid ${params['gid']}"
      } else {
        $gid = ''
      }

      if $params['goto'] {
        $goto = "goto ${params['goto']}"
      } else {
        $goto = ''
      }

      $all_content = [
        $saddr, $daddr, $type_mgmt, $ctdir, $proto, $sport, $dport, $uid,
        $gid, $log_prefix, $clamp_mss, $cluster_conf, $connlimit_upto,
        $connlimit_above, $conntrack, $ctstatus, $filter_start_time,
        $filter_stop_time, $gateway, $goto, $action, $cgroup
      ]

      $content = ($all_content.filter |$parameter| {
        ! $parameter.empty()
      }).join(' ')

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
}
# lint:endignore
