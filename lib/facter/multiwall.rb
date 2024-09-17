# frozen_string_literal: true
#
# Build multiwall factset
#

Facter.add(:multiwall, :type => :aggregate) do
  chunk(:blackhole_route) do
    confine kernel: 'Linux'
    multiwall_info = {}

    blackhole_targets = []

    # Retrieve all blackhole routes and present the targeted addresses
    (`ip route show type blackhole`).split("\n").each { |line|
      blackhole_targets.append(line.split(' ')[1].strip())
    }
    multiwall_info['blackhole_targets'] = blackhole_targets

    #
    # According to the ip-route man page, the anycast type has
    # yet to be properly implemented for 'show'. This feature,
    # however, seems to sometimes work. So adding it for now.
    #
    anycast_targets = []

    (`ip route show type anycast`).split("\n").each { |line|
      anycast_targets.append(line).split(" ")[1].strip()
    }

    multiwall_info['anycast'] = anycast_targets

    multiwall_info
  end
end
