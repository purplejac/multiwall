Puppet::Functions.create_function(:'multiwall::validate_nf_params') do
  dispatch :validate do
    param 'Hash', :params
    param 'Array', :unsupported
  end

  require 'date'
  def validate(params, unsupported)
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
      ['to', 'todest'],
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
      raise ArgumentError, "The following parameter is unsupported in multiwall: #{parameter} - see Changelog or in-module hiera for further information." if unsupported.include?(parameter)

      if value
        if clusterip_keys.include?(parameter) && !cluster_check && !value.nil?
          clusterip_keys.each do |param_name|
            raise ArgumentError, "ClusterIP parameters missing matching values for #{parameter}" if param_name.nil?
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
          fixed_param_name = parameter
          fixed_value = value.downcase

        when 'length'
          fixed_param_name = parameter
          fixed_value = value.sub(%r{:}, '-')

        when 'ctstatus'
          fixed_param_name = parameter
          fixed_value = parameter.is_a?(Array) ? parameter.join(',').downcase : parameter.downcase

        when %r{date_.*}
          fixed_param_name = parameter
          fixed_value = DateTime.parse(value).strftime('%s')

        when %r{(source|destination|(src|dst)_range)}
          # These parameters have already been checked against clashes, but are all defined with their corresponding
          # (s|d)addr keyword in nftables, so we'll do the translation here and treat them as if the source/destination
          # parameter was used.
          fixed_param_name = parameter.match?(%r{(source|src_.*)}) ? 'source' : 'destination'
          fixed_value = value

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
          fixed_param_name = parameter
          fixed_value = log_levels[value]

        when 'log_tcp_sequence'
          # tcp options and sequence need the same setting configured in nftables, so they're unified here
          fixed_param_name = log_tcp
          fixed_value = fixed_params.include?('log_tcp') ? 'options,sequence' : value

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
          queue_cmd = (parameter == queue_bypass) ? 'bypass' : "num #{value}"
          fixed_value = fixed_params.include?(fixed_param_name) ? params[fixed_param_name] + queue_cmd : queue_cmd

        when 'reject'
          split_value = value.split('-')

          fixed_param_name = parameter
          if split_value[0].match?(%r{^icmp})
            proto = split_value[0]
            split_value.delete_at(0)
          else
            proto = 'icmp6'
          end
          return_type = split_value.join('-')

          fixed_value = "#{proto} type #{return_type}"

        when 'rpfilter'
          rule_match = {
            'accept-local' => '.',
            'invert' => '. iif oif 0',
            'invert-loose' => 'oif 0',
            'invert-loose-validmark' => '. mark oif 0',
            'invert-validmark' => '. mark . iif oif =',
            'loose' => 'oif != 0',
            'loose-validmark' => '. mark oif != 0',
            'validmark' => '. mark . iif oif != 0',
          }

          fixed_param_name = parameter
          clean_value = value.is_a?(Array) ? value.delete('accept-local') : value
          lookup_key = clean_value.is_a?(Array) ? clean_value.sort.join('-') : clean_value
          fixed_value = rule_match[lookup_key]

        when 'set_mark'
          fixed_param_name = parameter
          # WRONG!
          if value.include?('/')
            (mark, mask) = value.split('/')
            fixed_value = mark & ~mask
          else
            fixed_value = value
          end

        when 'socket'
          fixed_param_name = parameter
          fixed_value = value ? '1' : '0'

        when 'stat_mode'
          if value == 'random'
            raise ArgumentError, 'stat_mode random cannot be set with stat_every and stat_packet' if params.include?('stat_every') || params.include?('stat_packet')

            fixed_param_name = 'stat_mode_random'
            fixed_value = value
          else
            fixed_param_name = 'stat_mode_nth'
            fixed_value = value
          end

        when 'stat_probability'
          fixed_param_name = parameter
          fixed_value = value.match?(%r{^0}) ? '2147483647 < 0' : '2147483647 < 2147483648'

        when 'tcp_flags'
          fixed_param_name = parameter

          all_flags = 'fin,syn,rst,psh,ack,urg,ecn,cwr'

          (val1, val2) = value.downcase.sub('all', all_flags).sub('none', '0x0').sub('! ', '').split(' ')

          fixed_value = if val2
                          (val1 == '0x0') ? '' : "#{val2} / #{val1}"
                        else
                          value.include?('!') ? "!= #{val1}" : val1
                        end

        when %r{time_}
          time_defaults = {
            'time_start' => '00:00:00',
            'time_stop' => '23:59:59',
          }

          alt_time = (parameter == 'time_start') ? 'time_stop' : 'time_start'

          unless fixed_params.include?(alt_time)
            fixed_params.merge({ alt_time => time_defaults[alt_time] })
          end

          fixed_param_name = parameter
          fixed_value = (value.count(':') == 1) ? "#{value}:00" : value

        when 'to'
          # It is preferred that 'to' isn't used, but just-in-case,
          # it will be used to replace todest if it's not set.
          fixed_param_name = 'todest'
          fixed_value = 'value'

        when 'week_days'
          # According to the nftables wiki, the days should be case-insensitive
          # this, however, is not born out in actual nft, so having to translate
          # them here.

          fixed_param_name = parameter

          day_map = {
            'Sun' => '0',
            'Mon' => '1',
            'Tue' => '2',
            'Wed' => '3',
            'Thu' => '4',
            'Fri' => '5',
            'Sat' => '6',
          }

          if value.is_a?(Array)
            target_days = value.map do |day|
              day_map[day]
            end

            fixed_value = "{#{target_days.join(',')}}"
          else
            fixed_value = day_map[value].to_s
          end

        else
          fixed_param_name = parameter
          fixed_value = value
        end

        fixed_params[fixed_param_name] = fixed_value
      end
    end
    fixed_params
  end
end
