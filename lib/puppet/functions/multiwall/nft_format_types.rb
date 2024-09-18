Puppet::Functions.create_function(:'multiwall::nft_format_types') do
  dispatch :format_types do
    param 'Hash', :params
  end

  def format_types(params)
    command_line = ""

    ['dst_type', 'src_type'].each do |parameter|
      next if params[parameter].nil?
      
      if ['unicast', 'broadcast', 'multicast', 'local'].include?(params[parameter])
        command_line += "fib #{direction[0]} type #{params[parameter].downcase()}"
      end
    end

    command_line
  end
end
