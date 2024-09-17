Puppet::Functions.create_function(:'multiwall::format_types') do
  dispatch :format_types do
    param 'Hash', :params
  end

  def format_types(params)
    ['dst_type', 'src_type'].each do |parameter|
      next if params[parameter].nil?

      facts = closure_scope['facts']
      blackhole_rules = []
      newrule = []

      direction = parameter == 'dst_type' ? ['daddr', params['destination']] : ['saddr', params['source']]

      if params[parameter] == 'blackhole'
        facts['multiwall']['blackhole_targets'].each { |address|
          blackhole_rules.add("ip #{direction[0]} #{address} drop") 
        }
      elsif ['unicast', 'broadcast', 'multicast', 'local'].include?(params[parameter])
        newrule = ["ip #{direction[1]} fib #{direction[0]} type #{params[parameter]} #{params['jump']}"]
      end
    end
    blackhole_rules + newrule
  end
end
