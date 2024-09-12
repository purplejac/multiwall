# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::iptables::chain' do
  let(:params) do
    {
      'name'   => 'INPUT:filter:IPv4',
      'ensure' => 'present',
      'policy' => 'drop',
    }
  end
  let(:title) { params['name'] }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      # it { pp os_facts[:os] }
      let(:facts) { os_facts }

      it { is_expected.to compile }

      it {
        is_expected.to contain_firewallchain(params['name']).with(
          'ensure' => params['ensure'],
          'policy' => params['policy'],
        )
      }
    end
  end
end
