# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::chain' do
  let(:pre_condition) { 'include nftables' }
  let(:title) { 'namevar' }

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

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
