Puppet::Functions.create_function(:'multiwall::cidr2netmask') do
  dispatch :convert_cidr do
    param 'Integer', :cidr
  end

  # Simple ruby function to convert CIDR into a netmask.
  # will strip any leading / and create a netmask based on the
  # provided CIDR.
  def convert_cidr(cidr)
    [ ((1 << 32) - 1) << (32 - cidr) ].pack('N').bytes.join('.')
  end
end
