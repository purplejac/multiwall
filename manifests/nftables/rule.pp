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
# @param unsupported [Array]
#   List of unsupported parameters, normally sourced from hiera.
#   These parameters will not be converted in the current setup, but could be
#   in the future, either through this module or through removal from the unsupported
#   list and the corresponding addition of the rule in hiera.
#
define multiwall::nftables::rule (
  Hash $params,
  Array $param_list    = lookup("multiwall::nftables::rule::param_list"),
  Integer $high_offset = lookup("multiwall::nftables::rule::high_offset", { "default_value" => 20 }),
  Integer $low_offset  = lookup("multiwall::nftables::rule::low_offset", { "default_value" => 10 }),
  Integer $mid_val     = lookup("multiwall::nftables::rule::mid_val", { "default_value" => 50 }),
  Integer $min_point   = lookup("multiwall::nftables::rule::min_point", { "default_value" => $mid_val - 20 }),
  Array $unsupported   = lookup("multiwall::nftables::rule::unsupported", { "default_value" => [] }),
) {
  $sanitised_params = multiwall::validate_nf_params($params, $unsupported)

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

  if 'chain' in $sanitised_params {
    $chain = $sanitised_params['chain'].regsubst(/-/, '_', 'G')
  } else {
    $chain = 'INPUT'
  }

  $protocol = $sanitised_params['protocol'] ? { default => 'ip', 'iptables6' => 'ip6', 'IPv6' => 'ip6'}

  $sanitised_name = ([$chain] + [(($name.split(/[ |-]/) - $num_string)).join('_')]).join('-').regsubst(/[\.|\/]/,'_', 'G')
  $family = $sanitised_params['family']

  if $sanitised_params['table'] {
    $table = $sanitised_params['table']
  } else {
    $table = 'filter'
  }

  if 'connlimit_mask' in $sanitised_params {
    $netmask = multiwall::cidr2netmask($sanitised_params['connlimit_mask'])
  }

  $content = $param_list.reduce('') |$body, $parameter| {
    $body_set = $body ? { default => $body, '' => $protocol }

    if $parameter in $sanitised_params {
      $param_value = if $parameter == 'goto' { $sanitised_params[$parameter] } else { $sanitised_params[$parameter].downcase() }

      if $parameter == 'proto' { # in ['proto', 'ctproto'] {
        unless 'sport' in $sanitised_params or 'dport' in $sanitised_params {
          if $param_value == 'all' {
            $set_proto = lookup('multiwall::nftables::rule::all_protocols')
          } else {
            $set_proto = $param_value
          }

          if 'source' in $sanitised_params and 'destination' in $sanitised_params {
            $param_rule = lookup('multiwall::nftables::rule::proto_src_dst')
          } else {
            $param_rule = lookup('multiwall::nftables::rule::proto_no_src_dst')
          }

          if $body_set =~ /ip6{0,1}$/ {
            $param_rule
          } else {
            "${body_set} ${param_rule}"
          }
        } else {
          $body_set
        }
      } elsif $parameter =~ /hashlimit/ {
        #
        # For simplicity and functionality, hashlimit is only applied on the hashlimit_name
        # as it is always required for a hashlimit.
        #
        # The range of hashlimit_htable parameters are ignored in this implementation as 
        # nftables automatically manages the menory allocations around the hash table implementation,
        # so there is no true translation for those parameters.
        #
        # hashlimit_dstmask and srcmask also do not have direct implementations in nftables
        # as it relies on defined sets or groups to achieve similar functionality. As a result
        # the parameters are left unimplemented, though if set, compilation will fail with an 
        # error to ensure awareness of the change.
        #
        if $parameter != /hashlimit_name/ {
          $hashlimit = multiwall::nftables::rule::hashlimit_rule_construct($sanitised_params)
          "${body_set} ${hashlimit}"
        } else {
          $body_set
        }
      } elsif $parameter =~ 'rpfilter' and $param_value == 'accept-local' {
        nftables::simplerule { 'rpfilter_accept_local':
          action  => 'accept',
          daddr   => '127.0.0.1',
          comment => 'Allow local traffic as part of rpf config',
          before  => Nftales::Rule[$sanitised_name],
        }
      } elsif $parameter == 'conntrack' {
        # There are several potential permutations of the conntrac traffic management,
        # while some are more likely than others, it made sense to support them all and
        # trust the users.
        # So management of the address and port/directional management is farmed out to
        # the setup_ct_rule function, which will return a properly formatted string
        # of the relevant conttrack parameters
        #
        if $body_set == 'ip' {
          multiwall::setup_ct_rules($sanitised_params)
        } else {
          "${body_set} ${multiwall::setup_ct_rules($sanitised_params)}"
        }
      } elsif $parameter == 'jump' {
        $param_rule = lookup("multiwall::nftables::rule::jump_commands.${param_value}")
        "${body_set} ${param_rule}"
      } elsif $parameter =~ /^(s|d)port/ {
        $port_proto = $sanitised_params['proto']
        $param_rule = lookup("multiwall::nftables::rule::${parameter}")

        "${body_set} ${param_rule}"
      } else {
        $param_rule = lookup("multiwall::nftables::rule::${parameter}")

        if $body_set =~ /ip6{0,1}$/ and ($param_rule =~ /^(ip|fib|sk|goto)/ or $parameter =~ /^(ct|(out|in)iface)/) {
          $param_rule

        } else {
          "${body_set} ${param_rule}"
        }
      }
    } else {
      $body_set
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
    'ensure'  => $sanitised_params['ensure'],
    'table'   => "${family}-${table}",
    'order'   => $order_param,
    'content' => $content,
  }

  nftables::rule { $sanitised_name:
    * => $filtered_params,
  }
}
# lint:endignore
