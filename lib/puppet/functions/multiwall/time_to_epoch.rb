Puppet::Functions.create_function(:'multiwall::time_to_epoch') do
  require 'date'

  dispatch :time_to_epoch do
    param 'String', :timestamp
  end

  # Simple ruby function to convert CIDR into a netmask.
  # will strip any leading / and create a netmask based on the
  # provided CIDR.
  def time_to_epoch(timestamp)
    DateTime.parse(timestamp).strftime('%s')
  end
end
