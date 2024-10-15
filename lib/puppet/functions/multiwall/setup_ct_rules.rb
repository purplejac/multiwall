Puppet::Functions.create_function(:'multiwall::setup_ct_rules') do
  dispatch :setup_ct_rules do
    param 'Hash', :params
  end

  #
  # Cycles through the conntrack parameters and pieces them together
  # to cater for unexpected combinations, however unlikely.
  # Returns the parameter set as a string for Puppet to use
  #
  def setup_ct_rules(params)
    nft_command = []

    ['ctorigdst', 'ctrepldst', 'ctorigsrc', 'ctreplsrc'].each do |addrparam|
      next if params[addrparam].nil?

      p_value = params[addrparam]

      ct_addr_dir = addrparam.include?('dst') ? 'daddr' : 'saddr'
      traffic_type = addrparam.include?('orig') ? 'original' : 'reply'
      ip_arg = (params['source'].nil? && params['destination'].nil?) ? ' ip ' : ' '

      nft_command.push("ct #{traffic_type}#{ip_arg}#{ct_addr_dir} #{p_value}")
    end

    ['ctorigdstport', 'ctorigsrcport', 'ctrepldstport', 'ctreplsrcport'].each do |addrparam|
      next if params[addrparam].nil?

      p_value = params[addrparam]
      ct_port_dir = addrparam.include?('dst') ? 'proto-dst' : 'proto-src'
      traffic_type = addrparam.include?('orig') ? 'original' : 'reply'

      nft_command.push("ct #{traffic_type} #{ct_port_dir} #{p_value}")
    end
    nft_command.join(' ')
  end
end
