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
# @param param_list [Array]
#   List of parameters to be managed in the module, in the order in which
#   the nftables command should take them.
#   ONLY PARAMETERS IN THIS LIST WILL BE ENFORCED!
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
  Array $param_list,
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
      warning($error_message)
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
      $protocol = $params['protocol'] ? { default => 'inet', 'iptables' => 'ip', 'ip6tables' => 'ip6', 'IPv4' => 'ip', 'IPv6' => 'ip6' }

      if $params['table'] {
        $table = $params['table']
      } else {
        $table = 'filter'
      }

      $need_meta = ['mark', 'cgroup']
      $skip_vals = ['src_type', 'dst_type', 'todest', 'tosource', 'to', 'toports', 'connmar', 'ctstate', 'clusterip_hash_init', 'clusterip_local_node', 'conntrack']

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

      if 'connlimit_mask' in $params {
        $netmask = multiwall::cidr2netmask($params['connlimit_mask'])
      }

      if $params['source'] or $params['src_range'] or ($params['src_type'] and $params['src_type'] =~ /(blackhole|BLACKHOLE)/) {
        $source = $facts['multiwall']['blackhole_targets'].join(',')
      } elsif $params['src_range'] {
        $source = $params['src_range']
      } else {
        $source = $params['source']
      }

      if $params['destination'] or $params['dst_range'] or ($params['dst_type'] and $params['dst_type'] =~ /(blackhole|BLACKHOLE)/) {
        $destination = $facts['multiwall']['blackhole_targets'].join(',')
      } elsif $params['dst_range'] {
        $destination = $params['dst_range']
      } else {
        $destination = $params['destination']
      }

      #
      # To manage conntrack protocol overriding 'standard' protocol definition, it is set ahead
      # of reading the actual protocol settings through the params loop
      #
      if $params['ctproto'] and ($params['ctorigdstport'] or $params['ctorigsrcport']) {
        $set_proto = $params['ctproto']
      } elsif $params['proto'] {
        if $params['proto'] == 'all' {
          $set_proto = lookup('multiwall::nftables::rule::all_protocols')
        } else {
          $set_proto = $params['proto']
        }
      }

      $content = $param_list.reduce('') |$body, $parameter| {
        if $parameter in $params and ! empty($params[$parameter]) {
          $param_value = $params[$parameter]

          if $parameter == 'jump' {
            $jump_action = lookup("multiwall::nftables::rule::jump_commands.${parameter.downcase()}")
          } elsif $parameter == 'ctdir' and ! ($param_check[0] in [3, 4]) {
            $ct_direction = lookup("multiwall::nftables::rule::ctdirections.${param_value}")
          } elsif $parameter in ['proto', 'ctproto'] {
            if empty($params['saddr']) and empty($params['daddr']) {
              $proto_param = lookup('multiwall::nftables::rule::proto_no_src_dst')
            } else {
              $proto_param = lookup('multiwall::nftables::rule::proto_src_dst')
            }
          } elsif $parameter == 'ctstatus' {
            if $parameter =~ Array {
              $fmt_ct_status = $parameter.join(',').downcase()
            } else {
              $fmt_ct_status = $parameter.downcase()
            }
          } elsif $parameter in ['date_start', 'date_stop'] {
            $epoch_date = multiwall::time_to_epoch(params[$parameter])
          }

          if $parameter == 'conntrack' {
            # There are several potential permutations of the conntract traffic management,
            # while some are more likely than others, it made sense to support them all and
            # trust the users.
            # So management of the address and port/directional management is farmed out to
            # the setup_ct_rule function, which will return a properly formatted string
            # of the relevant conttrack parameters
            #
            "${body} ${multiwall::setup_ct_rules($params)}"
          } elsif $parameter in ['dst_type', 'src_type'] and $body !~ /fib [d|s]addr type/ {
            "${body} ${multiwall::nft_format_types($params)}"
          } else {
            $param_rule = lookup("multiwall::nftables::rule::${parameter}")
            "${body} ${param_rule}"
          }
        } else {
          $body
        }
      }

      #
      # The bytecode parameter does not really translate directly for nftables, leaving a commented reminder to have a think about whether
      # to still add an option for pre-compiled rule sets, or whether to continue to ignore.
      #
      # $bytecode = "-f ${params['bytecode']}" - part of the problem here is that nftables expects a file location, rather than a code string
      #

      #
      # Checksum fill isn't really a direct option in nftables, may need constructing - disregarding for now
      #
      # if 'checksum_fill' in $params {
      #   $checksum_fill = 
      # }
      #

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
