# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::chain' do
  let(:pre_condition) { 'include nftables' }
  #
  # Defining a chain to test chain creation
  #
  let(:params) do
    {
      'name'   => 'TESTCHAIN:filter:IPv4',
      'ensure' => 'present',
      'policy' => 'drop',
    }
  end
  let(:title) { params['name'] }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      let(:os_check) do
        if ((facts[:os]['family'] == 'RedHat') && (facts[:os]['release']['major'].to_i > 7)) ||
           ((facts[:os]['name'] == 'Debian') && (facts[:os]['release']['major'].to_i > 10)) ||
           ((facts[:os]['name'] == 'Ubuntu') && facts[:os]['release']['major'] > '20.04') ||
           ((facts[:os]['name'] == 'SLES') && (facts[:os]['release']['major'].to_i > 15)) ||
           (facts[:os]['name'] == 'Fedora')

          true
        else
          false
        end
      end

      it { is_expected.to compile }

      it {
        if os_check
          is_expected.to contain_multiwall__nftables__chain(params['name']).with(
            'ensure' => 'present',
            'ignore_foreign' => false,
            'purge' => false,
            'policy' => 'drop',
            'use_inet' => true,
          )

          is_expected.to contain_nftables__chain(params['name']).with(
            'table' => 'inet-filter',
            'chain' => 'TESTCHAIN',
          )
        else
          is_expected.to contain_multiwall__iptables__chain(params['name']).with(
            'ensure' => 'present',
            'ignore_foreign' => false,
            'purge' => false,
            'policy' => 'drop',
          )
          is_expected.to contain_firewallchain(params['name']).with(
            'ensure' => 'present',
            'ignore_foreign' => false,
            'purge' => false,
            'policy' => 'drop',
          )
          is_expected.not_to contain_firewallchain('INPUT:filter:IPv4')
        end
      }
    end
  end
end
