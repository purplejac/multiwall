# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::iptables::chain' do
  let(:title) { 'namevar' }
  let(:params) do
    {
      'name'   => 'INPUT:filter:IPv4',
      'ensure' => 'present',
      'policy' => 'drop',
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      it { pp os_facts[:os] }
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
