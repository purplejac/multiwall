Puppet::Functions.create_function(:'multiwall::validate_nf_params') do
  dispatch :validate do
    param 'Hash', :params
    param 'Array', :unsupported
  end

  require 'date'
  def validate(params, unsupported)
    facts = closure_scope['facts']
    clusterip_keys = ['clusterip_hash_init', 'clusterip_total_node', 'clusterip_local_node']
    ctorig_port_keys = ['ctorigdstport', 'ctorigsrcport']

    cluster_check = false

    fixed_params = {}

    #
    # Check for clashing parameters and raise an error if any are encountered
    #
    [
      ['source', 'src_range'],
      ['destination', 'dst_range'],
      ['state', 'ctstate'],
      ['ctstate', 'ctdir'],
      ['log_prefix', 'nflog_prefix'],
      ['random', 'fully-random'],
      ['action', 'reject', 'goto', 'random', 'random_fully', 'queue_bypass', 'queue_num'],
    ].each do |param_set|
      set_count = []
      param_set.each do |chk_param|
        if params[chk_param]
          set_count.append(chk_param)
        end
      end
      if set_count.length > 1
        raise ArgumentError, "The following parameters cannot all be set: #{set_count.join(', ')}"
      end
    end

    #
    # Loop through the list of given parameter and create a new hash consisting only of parameters that
    # have actually been set.
    # Furthermore, do some processing to translate functionality between iptables and nftables properly.
    #
    params.each do |parameter, value|
      if value && !unsupported.include?(parameter)
        if unsupported.include?(parameter)
          raise ArgumentError, "The following parameter is unsupported in multiwall: #{parameter} - see Changelog or in-module hiera for further information."
        elsif clusterip_keys.include?(parameter) && !cluster_check && !value.nil?
          clusterip_keys.each do |param_name|
            if param_name.nil?
              raise ArgumentError, "ClusterIP parameters missing matching values for #{parameter}"
            end
          end
        elsif parameter == 'ctdir' && (!params['source'].nil? || !params['destination'].nil?)
          raise ArgumentError, 'ctdir auto-sets source/destination values for nftables to match direction. Source/Destination parameters should be unset'
        elsif ctorig_port_keys.include?(parameter) && (!params['proto']) && (!params['ctproto'])
          raise ArgumentError, 'The ctorig port parameter requires that the corresponding protocol is defined with the "proto" parameter.'
        end

        case parameter
        when 'protocol'
          # Translate the protocol parameter into the protocol command to use with nftables 'matches'
          fixed_param_name = parameter
          fixed_value = value.include('6') ? 'ip6' : 'ip'

        when 'jump'
          fixed_value = value.downcase()

        when 'length'
          fixed_value = value.sub(%r{:}, '-')

        when 'ctstatus'
          fixed_value = parameter.is_a?(Array) ? parameter.join(',').downcase : parameter.downcase

        when %r{date_.*}
          fixed_value = DateTime.parse(value).strftime('%s')

        when %r{(source|destination|(src|dst)_range)}
          # These parameters have already been checked against clashes, but are all defined with their corresponding
          # (s|d)addr keyword in nftables, so we'll do the translation here and treat them as if the source/destination
          # parameter was used.
          fixed_param_name = parameter =~ %r{(source|src_.*)} ? 'source' : 'destination'
          fixed_value = value

        when %r{(src|dst)_type}
          # traffic types don't quite match properly to iptables. the more generic types, like local and any of the casts
          # can be managed with fib, but blackhole sets would need to be defined elsewhere. To work around it, we assume
          # that the sets exist outside and rely on a fact to retrieve them and then treat them similarly to the broad source/destintion
          fixed_param_name = parameter == 'src_type' ? 'source' : 'destination'
      
          #
          # Starting by targeting only the documented type options, will circle back later to look closer at the rest.
          #
          case value
          when %r{(blackhole|BLACKHOLE)}
            fixed_value = facts['multiwall']['blackhole_targets']
          when %r{(unspec|UNSPEC)}
            # unspec effective matches on not being local or *cast. This still leaves a slight difference in that
            # it does not recognise blackhole and unreachable traffic. This should be a none-issue.
            fixed_param_name = parameter == 'src_type' ? 'type_cast_src' : 'type_cast_dst'
            fixed_value = '!= { local, broadcast, multicast, unicast }'
          when %r{(unreachable|UNREACHABLE|prohibit|PROHIBIT)}
            # The the icmp match against unreachable is much the same as iptables prohibited in the end,
            # so without a specific target type, we merge them for now
            fixed_param_name = 'type_unreachable'
            fixed_value = 'destination-unreachable'
          when 'log_level'
            log_levels = {
              '0' => 'emerg',
              'LOG_EMERG' => 'emerg',
              '1' => 'alert',
              'LOG_ALERT' => 'alert',
              '2' => 'crit',
              'LOLG_CRIT' => 'crit',
              '4' => 'err',
              'LOG_ERR' => 'err',
              '5' => 'warn',
              'LOG_WARNING' => 'warn',
              '6' => 'notice',
              'LOG_NOTICE' => 'notice',
              '7' => 'info',
              'LOG_INFO' => 'info',
              '8' => 'debug',
              'LOG_DEBUG' => 'debug',
            }
            fixed_value = log_levels[value]
          when 'log_tcp_sequence'
            # tcp options and sequence need the same setting configured in nftables, so they're unified here
            fixed_param_name = log_tcp
            fixed_value = fixed_params.include?('log_tcp') ? 'options,sequence' : value

          else
            fixed_param_name = parameter == 'src_type' ? 'type_cast_src' : 'type_cast_dst'
            fixed_value = value.downcase
          end

        when %r{^(ct)?state}
          #
          # Taking the 'beg forgiveness' approach to state assignment.
          # as ctstate is largely outdated, we'll assume that if it is declared
          # it is the target to use, otherwise we'll fall back to state.
          # If neither is defined and the ct action is being taken, catalog
          # compilation will fail.
          #
          fixed_param_name = 'ctstate'
          fixed_value = value

        when %r{^(nf)?log_prefix}
          fixed_param_name = 'log_prefix'
          fixed_value = "'#{value.gsub(%r{(^[a-zA-Z0-9_]+$)}, '_')}'"

        when %r{queue_(bypass|num)$}
          fixed_param_name = 'queue_config'
          queue_cmd = parameter == queue_bypass ? 'bypass' : "num #{value}"
          fixed_value = fixed_params.include?(fixed_param_name) ?  params[fixed_param_name] + queue_cmd : queue_cmd

        when 'reject'
          split_value = value.split('-')

          if split_value[0] =~ %r{^icmp}
            proto = split_value[0]
            split_value.delete_at(0)
          else
            proto = 'icmp6'
          end
          return_type = split_value.join('-')

          fixed_value = "#{proto} type #{return_type}"

        else
          fixed_value = value
        end

        fixed_params.merge!({fixed_param_name => fixed_value})
      end
    end
    fixed_params
  end
end
