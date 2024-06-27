# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::iptables::rule' do
  let(:title) { 'namevar' }
  let(:params) do
    {
      'name' => '002 reject local traffic not on loopback interface',
      'iniface' => '! lo',
      'proto' => 'all',
      'destination' => '127.0.0.1/8',
      'jump' => 'reject',
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts.merge({'testcase' => 'iptablesrule' }) }

      it { is_expected.to compile }

      it { should contain_firewall('002 reject local traffic not on loopback interface').with(
          {
            'iniface'     => '! lo',
            'proto'       => 'all',
            'destination' => '127.0.0.1/8',
            'jump'        => 'reject',
          }
        )
      }
    end
  end
end
