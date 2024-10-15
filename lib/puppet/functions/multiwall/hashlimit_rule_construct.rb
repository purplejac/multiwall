#
# multiwall::hashlimit_rule_construct 
#
# Function to convert hashlimit settings from the iptables format to something useful for nftables.
# Ideally this would probably be implemented as part of a full resource, but as a first step in 
# creating multiwall, we're relying on defined types, but need a little more 'smarts' to better manage
# some of the conversions.
#
Puppet::Functions.create_function(:'multiwall::hashlimit_rule_construct') do
  dispatch :rule_construct do
    param 'Hash', :params
  end

  def rule_construct(params)
    if params['hashlimit_above'] && params['hashlimit_upto']
      raise ArgumentError, 'Cannot declare both hashlimit_above and hashlimit_upto!'
    elsif params['hashlimit_dstmask'] or params['hashlimit_srcmask']
      raise ArgumentError, 'hashlimit source and destination masks are not directly implemented in nftables, need further specification for the resource'
    end

    mode_map = [[ 'srcport', "#{params['proto']} sport"],
                [ 'dstport', "#{params['proto']} dport"],
                ['srcip', 'ip saddr'],
                ['dstip', 'ip daddr'],
    ]

    hashlimit_rule = []

    hashlimit_rule.append("meter #{params['hashlimit_name']}")

    if params['hashlimit_mode']
      mode_arguments = ''

      mode_map.each do |mode_set|
        if params['hashlimit_mode'] =~ %r{mode_set[0]}
          mode_arguments = mode_arguments + mode_set[1]
        end
      end

      hashlimit_rule.append(mode_arguments)
    end

    if params['hashlimit_table_expire']
      time_in_secs = params['hashlimit_table_expire'].to_i / 1000
      hashlimit_rule.append("timeout #{time_in_secs}s")
    end

    ['hashlimit_above', 'hashlimit_upto'].each do |hashlimit_param|
      if hashlimit_param == 'hashlimit_above'
        keyword = 'over '
      else
        keyword = ''
      end

      if params[hashlimit_param]
        if !params[hashlimit_param].match('/')
          translated_limit = "#{params[hashlimit_param]}/second"
        else
          translated_limit = params[hashlimit_param].gsub(%r{(/sec$|/s$)}, '/second').gsub(%r{(/min$|/m$)}, '/minute')
        end

        hashlimit.append("limit rate #{keyword}#{translated_limit}")
      end
    end

    if params['hashlimit_burst']
      if params['hashlimit_burst'] =~ %r{^\d+$}
        burst_value = "#{params['hashlimit_burst']} packets"
      else
        burst_value = params['hashlimit_burst']
      end
      hashlimit.append("burst #{burst_value}")
    end
  end
end
