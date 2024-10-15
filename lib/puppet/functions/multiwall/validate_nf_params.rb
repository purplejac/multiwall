Puppet::Functions.create_function(:'multiwall::validate_nf_params') do
  dispatch :validate do
    param 'Hash', :params
  end

  def validate(params)
    unsupported = ['bytecode', 'checksum_fill', 'condition', 'ctexpire']

    clusterip_keys = ['clusterip_hash_init', 'clusterip_total_node', 'clusterip_local_node']
    ctorig_port_keys = ['ctorigdstport', 'ctorigsrcport']

    cluster_check = false

    res = [0]

    params.each do |parameter, value|
      if unsupported.include?(parameter)
        res = [1, parameter]
      end

      if clusterip_keys.include?(parameter) && !cluster_check && !value.nil?
        clusterip_keys.each do |param_name|
          if param_name.nil?
            res = [2, "ClusterIP Params missing matching values on #{parameter}"]
            break
          end
        end
      end

      if parameter == 'ctstate' && !params['ctdir'].nil?
        res = [3, 'ctstate and ctdir cannot both be set for a single rule.']
        break
      end

      if parameter == 'ctdir' && (!params['source'].nil? || !params['destination'].nil?)
        res = [4, 'ctdir auto sets source/destination values for nftables to match direction. Source/Destination parameters should be unset.']
        break
      end

      if ctorig_port_keys.include?(parameter) && (!params['proto']) && (!params['ctproto'])
        res = [5, 'ctorig port parameter requires that the corresponding protocol be defined with the "proto" parameter.']
        break
      end
    end
    res
  end
end
