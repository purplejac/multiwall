# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   multiwall::rule { 'namevar': }
define multiwall::rule (
  Enum['iptables', 'nftables']                                                                                                                                                                    $target_firewall = lookup('multiwall::target_firewall',[],[], 'nftables'),
  Enum[present, absent, 'present', 'absent']                                                                                                                                                      $ensure,
  String[1]                                                                                                                                                                                       $chain,
  Enum['nat', 'mangle', 'filter', 'raw', 'rawpost', 'broute', 'security']                                                                                                                         $table,
  Enum['iptables', 'ip6tables', 'IPv4', 'IPv6']                                                                                                                                                   $protocol,
  String                                                                                                                                                                                          $jump   = $action.upcase(),
  Optional[Pattern[/^([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$/]]                                                                                                                                   $clusterip_clustermac,
  Optional[Enum['accept','reject','drop']]                                                                                                                                                        $action = undef,
  Optional[Integer[1]]                                                                                                                                                                            $burst = undef,
  Optional[String[1]]                                                                                                                                                                             $bytecode = undef,
  Optional[String[1]]                                                                                                                                                                             $cgroup = undef,
  Optional[Boolean]                                                                                                                                                                               $checksum_fill = undef,
  Optional[Boolean]                                                                                                                                                                               $clamp_mss_to_pmtu = undef,
  Optional[String[1]]                                                                                                                                                                             $clusterip_hash_init = undef,
  Optional[Enum['sourceip', 'sourceip-sourceport', 'sourceip-sourceport-destport']]                                                                                                               $clusterip_hashmode = undef,
  Optional[Integer[1]]                                                                                                                                                                            $clusterip_local_node = undef,
  Optional[Boolean]                                                                                                                                                                               $clusterip_new = undef,
  Optional[Integer[1]]                                                                                                                                                                            $clusterip_total_nodes = undef,
  Optional[String[1]]                                                                                                                                                                             $condition = undef,
  Optional[Integer]                                                                                                                                                                               $connlimit_above = undef,
  Optional[Integer[0,128]]                                                                                                                                                                        $connlimit_mask = undef,
  Optional[Integer]                                                                                                                                                                               $connlimint_upto = undef,
  Optional[Pattern[/^(?:!\s)?[a-fA-F0-9x]+$/]]                                                                                                                                                    $connmark = undef,
  Optional[Enum['REPLY', 'ORIGINAL']]                                                                                                                                                             $ctdir = undef,
  Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]                                                                                                                                                    $ctexpire = undef,
  Optional[String[1]]                                                                                                                                                                             $ctorigdst = undef,
  Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]                                                                                                                                                    $ctorigdstport = undef,
  Optional[String[1]]                                                                                                                                                                             $ctorigsrc = undef,
  Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]                                                                                                                                                    $ctorigsrcport = undef,
  Optional[Variant[Pattern[/^(?:!\s)?\d+$/],Integer]]                                                                                                                                             $ctproto = undef,
  Optional[String[1]]                                                                                                                                                                             $ctrepldst = undef,
  Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]                                                                                                                                                    $ctrepldstport = undef,
  Optional[String[1]]                                                                                                                                                                             $ctreplsrc = undef,
  Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]                                                                                                                                                    $ctreplsrcport = undef,
  Optional[Variant[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED|SNAT|DNAT)$/],
    Array[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED|SNAT|DNAT)$/]]]
  ]                                                                                                                                                                                               $ctstate = undef,
  Optional[Variant[Pattern[/^(?:!\s)?(?:EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED|NONE)$/],
    Array[Pattern[/^(?:!\s)?(?:EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED|NONE)$/]]]
  ]                                                                                                                                                                                               $ctstatus = undef,
  Optional[Pattern[/^[0-9]{4}\-(?:0[0-9]|1[0-2])\-(?:[0-2][0-9]|3[0-1])T(?:[0-1][0-9]|2[0-3])\:[0-5][0-9]\:[0-5][0-9]$/]]                                                                         $date_start = undef,
  Optional[Pattern[/^[0-9]{4}\-(?:0[0-9]|1[0-2])\-(?:[0-2][0-9]|3[0-1])T(?:[0-1][0-9]|2[0-3])\:[0-5][0-9]\:[0-5][0-9]$/]]                                                                         $date_stop = undef,
  Optional[String[1]]                                                                                                                                                                             $destination = undef,
  Optional[Variant[Array[Variant[Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/],Integer]],
    Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/],
    Integer]
  ]                                                                                                                                                                                               $dport = undef,
  Optional[Pattern[/^[A-Z]{2}(,[A-Z]{2})*$/]]                                                                                                                                                     $dst_cc = undef,
  Optional[String[1]]                                                                                                                                                                             $dst_range = undef,
  Optional[Variant[Array[Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]],
    Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]]
  ]                                                                                                                                                                                               $dst_type = undef,
  Optional[Pattern[/^(\d+.\d+.\d+.\d+|\w+:\w+::\w+)$/]]                                                                                                                                           $gateway = undef,
  Optional[Variant[String[1], Integer]]                                                                                                                                                           $gid = undef,
  Optional[String[1]]                                                                                                                                                                             $goto = undef,
  Optional[Pattern[/^\d+(?:\/(?:sec|min|hour|day))?$/]]                                                                                                                                           $hashlimit_above = undef,
  Optional[Integer[1]]                                                                                                                                                                            $hashlimit_burst = undef,
  Optional[Integer[0,32]]                                                                                                                                                                         $hashlimit_dstmask = undef,
  Optional[Integer]                                                                                                                                                                               $hashlimit_htable_expire = undef,
  Optional[Integer]                                                                                                                                                                               $hashlimit_htable_gcinterval = undef,
  Optional[Integer]                                                                                                                                                                               $hashlimit_htable_max = undef,
  Optional[Integer]                                                                                                                                                                               $hashlimit_htable_size = undef,
  Optional[Pattern[/^(?:srcip|srcport|dstip|dstport)(?:\,(?:srcip|srcport|dstip|dstport))*$/]]                                                                                                    $hashlimit_mode = undef,
  Optional[String[1]]                                                                                                                                                                             $hashlimit_name = undef,
  Optional[Integer[0,32]]                                                                                                                                                                         $hashlimit_srcmask = undef,
  Optional[Pattern[/^\d+(?:\/(?:sec|min|hour|day))?$/]]                                                                                                                                           $hashlimit_upto = undef,
  Optional[String[1]]                                                                                                                                                                             $helper = undef,
  Optional[Variant[Pattern[/^(?:!\s)?\d+$/],Integer]]                                                                                                                                             $hop_limit = undef,
  Optional[Variant[String[1],Integer]]                                                                                                                                                            $icmp = undef,
  Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+\:@]+$/]]                                                                                                                                           $iniface = undef,
  Optional[Enum['in', 'out']]                                                                                                                                                                     $ipsec_dir = undef,
  Optional[Enum['none', 'ipsec']]                                                                                                                                                                 $ipsec_policy = undef,
  Optional[Variant[Pattern[/^(?:!\s)?\w+\s(?:src|dst)(?:,src|,dst)?$/],Array[Pattern[/^(?:!\s)?\w+\s(?:src|dst)(?:,src|,dst)?$/]]]]                                                               $ipset = undef,
  Optional[Boolean]                                                                                                                                                                               $ipvs = undef,
  Optional[Boolean]                                                                                                                                                                               $isfirstfrag = undef,
  Optional[Boolean]                                                                                                                                                                               $isfragment = undef,
  Optional[Boolean]                                                                                                                                                                               $ishasmorefras = undef,
  Optional[Boolean]                                                                                                                                                                               $islastfrag = undef,
  Optional[Boolean]                                                                                                                                                                               $kernel_timezone = undef,
  Optional[Pattern[/^([0-9]+)(:)?([0-9]+)?$/]]                                                                                                                                                    $length = undef,
  Optional[Pattern[/^\d+\/(?:sec(?:ond)?|min(?:ute)?|hour|day)$/]]                                                                                                                                $limit = undef,
  Optional[String[1]]                                                                                                                                                                             $line = undef,
  Optional[Boolean]                                                                                                                                                                               $log_ip_options = undef,
  Optional[Variant[Integer[0,7], String[1]]]                                                                                                                                                      $log_level = undef,
  Optional[String[1]]                                                                                                                                                                             $log_prefix = undef,
  Optional[Boolean]                                                                                                                                                                               $log_tcp_options = undef,
  Optional[Boolean]                                                                                                                                                                               $log_tcp_sequence = undef,
  Optional[Boolean]                                                                                                                                                                               $log_uid = undef,
  Optional[Pattern[/^(?:!\s)?([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$/]]                                                                                                                           $mac_source = undef,
  Optional[Pattern[/^\d+\.\d+\.\d+\.\d+$/]]                                                                                                                                                       $mask = undef,
  Optional[Pattern[/^(?:!\s)?[a-fA-F0-9x]+$/]]                                                                                                                                                    $match_mark = undef,
  Optional[Variant[Integer[0,31], Array[Integer[0,31]]]]                                                                                                                                          $month_days = undef,
  Optional[Pattern[/^(?:!\s)?\d+(?:\:\d+)?$/]]                                                                                                                                                    $mss = undef,
  Optional[Integer[1, 65535]]                                                                                                                                                                     $nflog_group = undef,
  Optional[String]                                                                                                                                                                                $nflog_prefix = undef,
  Optional[Integer[1]]                                                                                                                                                                            $nflog_range = undef,
  Optional[Integer[1]]                                                                                                                                                                            $nflog_size = undef,
  Optional[Integer[1]]                                                                                                                                                                            $nflog_threshold = undef,
  Optional[Boolean]                                                                                                                                                                               $notrack = undef,
  Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+\:@]+$/]]                                                                                                                                           $outiface = undef,
  Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+]+$/]]                                                                                                                                              $physdev_in = undef,
  Optional[Boolean]                                                                                                                                                                               $physdev_is_bridged = undef,
  Optional[Boolean]                                                                                                                                                                               $physdev_is_in = undef,
  Optional[Boolean]                                                                                                                                                                               $physdev_is_out = undef,
  Optional[Pattern[/^(?:!\s)?[a-zA-Z0-9\-\._\+]+$/]]                                                                                                                                              $physdev_out = undef,
  Optional[Enum['unicast', 'broadcast', 'multicast']]                                                                                                                                             $pkttype = undef,
  Optional[Pattern[/^(?:!\s)?(?:ip(?:encap)?|tcp|udp|icmp|esp|ah|vrrp|carp|igmp|ipv4|ospf|gre|cbt|sctp|pim|all)$/]]                                                                               $proto = undef,
  Optional[Boolean]                                                                                                                                                                               $queue_bypass = undef,
  Optional[Integer[1]]                                                                                                                                                                            $queue_num = undef,
  Optional[Boolean]                                                                                                                                                                               $random = undef,
  Optional[Boolean]                                                                                                                                                                               $random_fully = undef,
  Optional[Boolean]                                                                                                                                                                               $rdest = undef,
  Optional[Boolean]                                                                                                                                                                               $reap = undef,
  Optional[Enum['set', 'update', 'rcheck', 'remove', '! set', '! update', '! rcheck', '! remove']]                                                                                                $recent = undef,
  Optional[Enum['icmp-net-unreachable', 'icmp-host-unreachable', 'icmp6-addr-unreachable', 'addr-unreach', 'icmp6-port-unreachable']]                                                             $reject = undef,
  Optional[Integer[1]]                                                                                                                                                                            $rhitcount = undef,
  Optional[String[1]]                                                                                                                                                                             $rname = undef,
  Optional[Variant[Enum['loose', 'validmark', 'accept-local', 'invert']]]                                                                                                                         $rpfilter = undef,
  Optional[Integer[1]]                                                                                                                                                                            $rseconds = undef,
  Optional[Boolean]                                                                                                                                                                               $rsource = undef,
  Optional[Boolean]                                                                                                                                                                               $rttl = undef,
  Optional[String[1]]                                                                                                                                                                             $set_dscp = undef,
  Optional[Enum['af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'cs5', 'cs6', 'cs7', 'ef']]                                                                                               $set_dscp_class = undef,
  Optional[Pattern[/^[a-fA-F0-9x]+(?:\/[a-fA-F0-9x]+)?$/]]                                                                                                                                        $set_mark = undef,
  Optional[Integer[1]]                                                                                                                                                                            $set_mss = undef,
  Optional[Boolean]                                                                                                                                                                               $socket = undef,
  Optional[String[1]]                                                                                                                                                                             $source = undef,
  Optional[Variant[Array[Variant[Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/], Integer]], Pattern[/^(?:!\s)?\d+(?:(?:\:|-)\d+)?$/], Integer]]                                                         $sport = undef,
  Optional[Pattern[/^[A-Z]{2}(,[A-Z]{2})*$/]]                                                                                                                                                     $src_cc = undef,
  Optional[String[1]]                                                                                                                                                                             $src_range = undef,
  Optional[Variant[Array[Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]],
    Pattern[/^(?:!\s)?(?:UNSPEC|UNICAST|LOCAL|BROADCAST|ANYCAST|MULTICAST|BLACKHOLE|UNREACHABLE|UNREACHABLE|PROHIBIT|THROW|NAT|XRESOLVE)(?:\s--limit-iface-(?:in|out))?$/]]]                      $src_type = undef,
  Optional[Integer[1]]                                                                                                                                                                            $stat_every = undef,
  Optional[Enum['nth', 'random']]                                                                                                                                                                 $stat_mode = undef,
  Optional[Integer]                                                                                                                                                                               $stat_packet = undef,
  Optional[Variant[Integer[0,1], Float[0.0,1.0]]]                                                                                                                                                 $stat_probability = undef,
  Optional[Variant[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED)$/], Array[Pattern[/^(?:!\s)?(?:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED)$/]]]]                                $state = undef,
  Optional[String[1]]                                                                                                                                                                             $string = undef,
  Optional[Enum['bm', 'kmp']]                                                                                                                                                                     $string_algo = undef,
  Optional[Integer[1]]                                                                                                                                                                            $string_from = undef,
  Optional[Pattern[/^(?:!\s)?\|[a-zA-Z0-9\s]+\|$/]]                                                                                                                                               $string_hex = undef,
  Optional[Pattern[/^(?:!\s)?((FIN|SYN|RST|PSH|ACK|URG|ALL|NONE),?)+\s((FIN|SYN|RST|PSH|ACK|URG|ALL|NONE),?)+$/]]                                                                                 $tcp_flags = undef,
  Optional[Variant[Pattern[/^(?:!\s)?(?:[0-1][0-9]{0,2}|2[0-4][0-9]|25[0-5])$/], Integer[0,255]]]                                                                                                 $tcp_option = undef,
  Optional[Boolean]                                                                                                                                                                               $time_contiguous = undef,
  Optional[Pattern[/^([0-9]|[0-1][0-9]|2[0-3])\:[0-5][0-9](?:\:[0-5][0-9])?/]]                                                                                                                    $time_start = undef,
  Optional[Pattern[/^([0-9]|[0-1][0-9]|2[0-3])\:[0-5][0-9](?:\:[0-5][0-9])?/]]                                                                                                                    $time_stop = undef,
  Optional[String[1]]                                                                                                                                                                             $to = undef,
  Optional[String[1]]                                                                                                                                                                             $todest = undef,
  Optional[Pattern[/^\d+(?:-\d+)?$/]]                                                                                                                                                             $toports = undef,
  Optional[String[1]]                                                                                                                                                                             $tosource = undef,
  Optional[Pattern[/^0x[0-9a-fA-F]+&0x[0-9a-fA-F]+=0x[0-9a-fA-F]+(?::0x[0-9a-fA-F]+)?(?:&&0x[0-9a-fA-F]+&0x[0-9a-fA-F]+=0x[0-9a-fA-F]+(?::0x[0-9a-fA-F]+)?)*$/]]                                  $u32 = undef,
  Optional[Variant[String[1], Integer]]                                                                                                                                                           $uid = undef,
  Optional[Variant[Enum['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], Array[Enum['Mon','Tue','Wed','Thu','Fri','Sat','Sun']]]]                                                                      $week_days = undef,
  Optional[Integer]                                                                                                                                                                               $zone = undef,
) {

  $firewall_params = {
    "ensure" => $ensure,
    "chain" => $chain,
    "table" => $table,
    "protocol" => $protocol,
    "clusterip_clustermac" => $clusterip_clustermac,
    "action" => $action,
    "burst" => $burst,
    "bytecode" => $bytecode,
    "cgroup" => $cgroup,
    "checksum_fill" => $checksum_fill,
    "clamp_mss_to_pmtu" => $clamp_mss_to_pmtu,
    "clusterip_hash_init" => $clusterip_hash_init,
    "clusterip_hashmode" => $clusterip_hashmode,
    "clusterip_local_node" => $clusterip_local_node,
    "clusterip_new" => $clusterip_new,
    "clusterip_total_nodes" => $clusterip_total_nodes,
    "condition" => $condition,
    "connlimit_above" => $connlimit_above,
    "connlimit_mask" => $connlimit_mask,
    "connlimint_upto" => $connlimint_upto,
    "connmark" => $connmark,
    "ctdir" => $ctdir,
    "ctexpire" => $ctexpire,
    "ctorigdst" => $ctorigdst,
    "ctorigdstport" => $ctorigdstport,
    "ctorigsrc" => $ctorigsrc,
    "ctorigsrcport" => $ctorigsrcport,
    "ctproto" => $ctproto,
    "ctrepldst" => $ctrepldst,
    "ctrepldstport" => $ctrepldstport,
    "ctreplsrc" => $ctreplsrc,
    "ctreplsrcport" => $ctreplsrcport,
    "ctstate" => $ctstate,
    "ctstatus" => $ctstatus,
    "date_start" => $date_start,
    "date_stop" => $date_stop,
    "destination" => $destination,
    "dport" => $dport,
    "dst_cc" => $dst_cc,
    "dst_range" => $dst_range,
    "dst_type" => $dst_type,
    "gateway" => $gateway,
    "gid" => $gid,
    "goto" => $goto,
    "hashlimit_above" => $hashlimit_above,
    "hashlimit_burst" => $hashlimit_burst,
    "hashlimit_dstmask" => $hashlimit_dstmask,
    "hashlimit_htable_expire" => $hashlimit_htable_expire,
    "hashlimit_htable_gcinterval" => $hashlimit_htable_gcinterval,
    "hashlimit_htable_max" => $hashlimit_htable_max,
    "hashlimit_htable_size" => $hashlimit_htable_size,
    "hashlimit_mode" => $hashlimit_mode,
    "hashlimit_name" => $hashlimit_name,
    "hashlimit_srcmask" => $hashlimit_srcmask,
    "hashlimit_upto" => $hashlimit_upto,
    "helper" => $helper,
    "hop_limit" => $hop_limit,
    "icmp" => $icmp,
    "iniface" => $iniface,
    "ipsec_dir" => $ipsec_dir,
    "ipsec_policy" => $ipsec_policy,
    "ipset" => $ipset,
    "ipvs" => $ipvs,
    "isfirstfrag" => $isfirstfrag,
    "isfragment" => $isfragment,
    "ishasmorefras" => $ishasmorefras,
    "islastfrag" => $islastfrag,
    "kernel_timezone" => $kernel_timezone,
    "length" => $length,
    "limit" => $limit,
    "line" => $line,
    "log_ip_options" => $log_ip_options,
    "log_level" => $log_level,
    "log_prefix" => $log_prefix,
    "log_tcp_options" => $log_tcp_options,
    "log_tcp_sequence" => $log_tcp_sequence,
    "log_uid" => $log_uid,
    "mac_source" => $mac_source,
    "mask" => $mask,
    "match_mark" => $match_mark,
    "month_days" => $month_days,
    "mss" => $mss,
    "nflog_group" => $nflog_group,
    "nflog_prefix" => $nflog_prefix,
    "nflog_range" => $nflog_range,
    "nflog_size" => $nflog_size,
    "nflog_threshold" => $nflog_threshold,
    "notrack" => $notrack,
    "outiface" => $outiface,
    "physdev_in" => $physdev_in,
    "physdev_is_bridged" => $physdev_is_bridged,
    "physdev_is_in" => $physdev_is_in,
    "physdev_is_out" => $physdev_is_out,
    "physdev_out" => $physdev_out,
    "pkttype" => $pkttype,
    "proto" => $proto,
    "queue_bypass" => $queue_bypass,
    "queue_num" => $queue_num,
    "random" => $random,
    "random_fully" => $random_fully,
    "rdest" => $rdest,
    "reap" => $reap,
    "recent" => $recent,
    "reject" => $reject,
    "rhitcount" => $rhitcount,
    "rname" => $rname,
    "rpfilter" => $rpfilter,
    "rseconds" => $rseconds,
    "rsource" => $rsource,
    "rttl" => $rttl,
    "set_dscp" => $set_dscp,
    "set_dscp_class" => $set_dscp_class,
    "set_mark" => $set_mark,
    "set_mss" => $set_mss,
    "socket" => $socket,
    "source" => $source,
    "sport" => $sport,
    "src_cc" => $src_cc,
    "src_range" => $src_range,
    "src_type" => $src_type,
    "stat_every" => $stat_every,
    "stat_mode" => $stat_mode,
    "stat_packet" => $stat_packet,
    "stat_probability" => $stat_probability,
    "state" => $state,
    "string" => $string,
    "string_algo" => $string_algo,
    "string_from" => $string_from,
    "string_hex" => $string_hex,
    "tcp_flags" => $tcp_flags,
    "tcp_option" => $tcp_option,
    "time_contiguous" => $time_contiguous,
    "time_start" => $time_start,
    "time_stop" => $time_stop,
    "to" => $to,
    "todest" => $todest,
    "toports" => $toports,
    "tosource" => $tosource,
    "u32" => $u32,
    "uid" => $uid,
    "week_days" => $week_days,
    "zone" => $zone,
  }

  if ($target_firewall == 'iptables')
  {
    firewall { $name:
      * => $firewall_parameters,
    }
  } else {
    "multiwall::${target_firewall}" { $name:
      params => $firewall_parameters,
    }
  }
}