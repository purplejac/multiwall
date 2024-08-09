# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::iptables::rule' do
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
      },
    }
  end
  let(:title) { params['name'] }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts.merge({ 'testcase' => 'iptablesrule' }) }

      it { is_expected.to compile }

      it {
        is_expected.to contain_firewall('002 reject local traffic not on loopback interface').with(
          {
            'chain'       => params['params']['chain'],
            'iniface'     => params['params']['iniface'],
            'proto'       => params['params']['proto'],
            'destination' => params['params']['destination'],
            'jump'        => params['params']['jump'],
          },
        )
      }
    end
  end
end
