# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::nftables::chain' do
  let(:pre_condition) { 'include nftables' }
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

      it { is_expected.to compile }

      it {
        is_expected.to contain_nftables__chain(params['name']).with(
          'table' => 'inet-filter',
          'chain' => 'TESTCHAIN',
        )
      }
    end
  end
end
