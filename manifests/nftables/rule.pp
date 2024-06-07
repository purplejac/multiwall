# lint:ignore:140chars
# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   multiwall::nftables::rule { 'namevar': }
#
# @param rule_parameters [Hash]
#   The set of parameters being used to define the 'firewall' resource,
#   as outlined in the documentation for puppetlabs-firewall
#
define multiwall::nftables::rule (
  Hash $rule_parameters,
) {
  $filtered_params = {}

  if $title =~ /^(\d+)/ {
    $filtered_params = {
      'order' => $1,
    }
  }

  $sanitised_name = $title.regsubst(/(^[^a-zA-Z0-9_]+|[^a-zA-Z0-9_]+$)/, '','G').regsubst(/[^a-zA-Z0-9_]+/, '_', 'G')

  if $rule_parameters['ensure'] == 'absent' {
    $filtered_params = { ensure => $rule_parameters['ensure'] }
  } else {
    $ensure = $rule_parameters['ensure']
    $table = $rule_parameters['table']

    $protocol = $rule_parameters['protocol'] ? { 'default' => 'inet', 'iptables' => 'ip', 'ip6tables' => 'ip6', 'IPv4' => 'ip', 'IPv6' => 'ip6' }
    $chain = $rule_parameters['chain'].regsubst(/(^[a-zA-Z0-9_]+$)/, '_', 'G')

    $action_commands = ['ACCEPT', 'accept', 'REJECT', 'reject', 'DROP', 'drop']

    $need_meta = ['mark', 'cgroup']
    #
    # Taking the 'beg forgiveness' approach to state assignment.
    # as state is largely outdated, we'll assume that if it is declared
    # it is the target to use, otherwise we'll fall back to state.
    # If neither is defined and the ct action is being taken, catalog
    # compilation will fail.
    #
    if 'ctstate' in $rule_parameters {
      $ctstate = $rule_parameters['ctstate']
    } elsif 'state' in $rule_parameters {
      $ctstate = $rule_parameters['state']
    }

    $jump_commands = {
      'queue'      => 'queue',
      'return'     => 'return',
      'dnat'       => "dnat ${rule_parameters['todest']}",
      'snat'       => "snat ${rule_parameters['tosource']}",
      'log'        => "log prefix '${rule_parameters['log_prefix'].regsubst(/(^[a-zA-Z0-9_]+$)/, '_', 'G')}'",
      'nflog'      => "nflog prefix '${rule_parameters['log_prefix'].regsubst(/(^[a-zA-Z0-9_]+$)/, '_', 'G')}'",
      'netmap'     => "netmap to ${rule_parameters['to']}",
      'masquerade' => 'masquerade',  # TO WHAT THOUGH?
      'redirect'   => "redirect ${rule_parameters['toports']}", # TO WHAT THOUGH?
      'mark'       => "meta mark set ${rule_parameters['connmark']}", # ??? INVESTIGATE
      'ct'         => "ct action ${rule_parameters['ctstate']}", # Need to have a think about how to get this and state to match exclusively, individually
    }

    if  'action' in $rule_parameters {
      $action = $rule_parameters['action'].downcase()
    } elsif ('jump' in $rule_parameters) {
      if ($rule_parameters['jump'] in $action_commands) {
        $action = $rule_parameters['jump'].downcase()
      } else {
        $action = $jump_commands[$rule_parameters['jump']]
      }
    } else {
      $action = undef
    }

    #
    # There is no direct burst parameter for nftables, instead we'll mimick by implementing by setting the rate
    # limit to 'bursts per second' and a max of one packet allowed to exceed.
    #
    if 'burst' in $rule_parameters {
      $burst = "limit rate ${rule_parameters['burst']}/second burst 1"
    }

    #
    # The bytecode parameter does not really translate directly for nftables, leaving a commented reminder to have a think about whether
    # to still add an option for pre-compiled rule sets, or whether to continue to ignore.
    #
    # $bytecode = "-f ${rule_parameters['bytecode']}" - part of the problem here is that nftables expects a file location, rather than a code string
    #

    if 'cgroup' in $rule_parameters {
      $cgroup = "meta nfproto cgroupv2 cgroup ${rule_parameters['cgroup']}"
    }

    #
    # Checksum fill isn't really a direct option in nftables, may need constructing - disregarding for now
    #
    # if 'checksum_fill' in $rule_parameters {
    #   $checksum_fill = 
    # }
    #

    #
    # As there's no pre-defined pmtu setting we will default to 1500 but allow for it to be overridden through hiera.
    #

    if 'pmtu' in $rule_parameters {
      $pmtu = $rule_parameters['pmtu']
    } else {
      $pmtu = 1500
    }

    #
    # We then use the set pmtu to mimic the clamp_mss_to_pmtu functionality
    #
    $clamp_mss_to_pmtu = "tcp flags & (fin|syn|rst|ack) == syn tcp option maxseg size set ${pmtu}"

    $saddr = "ip saddr ${rule_parameters['source']}"
    $daddr = "ip saddr ${rule_parameters['destination']}"

    $dport = "dport ${rule_parameters['dport']}"
    $sport = "sport ${rule_parameters['sport']}"
  }

  $content = "${protocol} ${table} ${chain} ${saddr} ${daddr} ${rule_parameters['proto']} ${dport} ${cgroup}"

  nftables::rule { $sanitised_name:
    * => $filtered_params,
  }
}
# lint:endignore
