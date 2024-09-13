# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::nftables::rule' do
  let(:pre_condition) { 'include nftables' }
  let(:params) do
    {
      'name' => '002 reject local traffic not on loopback interface',
      'params' => {
        'ensure' => 'present',
        'chain' => 'INPUT',
        'iniface' => '! lo',
        'proto' => 'all',
        'destination' => '127.0.0.1/8',
        'jump' => 'reject',
      }
    }
  end
  let(:title) { params['name'] }

	let(:os_check) {
		if ((facts[:os]['family'] == 'RedHat') && (facts[:os]['release']['major'].to_i > 7)) ||
			 ((facts[:os]['name'] == 'Debian') && (facts[:os]['release']['major'].to_i > 10)) ||
			 ((facts[:os]['name'] == 'Ubuntu') && facts[:os]['release']['major'] > '20.00') ||
			 ((facts[:os]['name'] == 'SLES') && (facts[:os]['release']['major'].to_i > 15)) ||
			 (facts[:os]['name'] == 'Fedora')

			 true
		else
			false
		end
	}

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
      it {
        if os_check
          is_expected.to contain_multiwall__nftables__rule(params['name']).with('params' => params['params'])
          is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with(
            'ensure' => params['params']['ensure'],
            'table' => 'inet-filter',
            'content' => %r{ip daddr 127.0.0.1/8 ip protocol { icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp }  reject},
          )
        end
      }
    end
  end
end
