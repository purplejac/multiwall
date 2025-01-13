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
        'family' => 'inet',
        'iniface' => '! lo',
        'proto' => 'all',
        'protocol' => 'IPv4',
        'destination' => '127.0.0.1/8',
        'jump' => 'reject',
      }
    }
  end


  on_supported_os.each do |os, os_facts|
    let(:title) { params['name'] }

    let(:os_check) do
      if ((os_facts[:os]['family'] == 'RedHat') && (os_facts[:os]['release']['major'].to_i > 7)) ||
         ((os_facts[:os]['name'] == 'Debian') && (os_facts[:os]['release']['major'].to_i > 10)) ||
         ((os_facts[:os]['name'] == 'Ubuntu') && os_facts[:os]['release']['major'] > '20.00') ||
         ((os_facts[:os]['name'] == 'SLES') && (os_facts[:os]['release']['major'].to_i > 15)) ||
         (os_facts[:os]['name'] == 'Fedora')
        true
      else
        false
      end
    end
  
    let(:facts) do
      if os_check
        os_facts.merge({ multiwall: { 'blackhole_targets' => ['10.10.10.10', '20.20.20.20'] }, multiwall_target: 'nftables' })
      else
          os_facts.merge({ multiwall: { 'blackhole_targets' => ['10.10.10.10', '20.20.20.20'] }, multiwall_target: 'iptables' })
        end
    end
    
    context "on #{os} basic rule" do
      it {
        if os_check
          is_expected.to compile
          is_expected.to contain_multiwall__nftables__rule(params['name']).with('params' => params['params'])
          is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with(
            'ensure' => params['params']['ensure'],
            'table' => 'inet-filter',
            'content' => 'iifname != lo ip daddr 127.0.0.1/8 ip protocol { icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp } reject'
          )
        end
      }
    end

    context 'Testing dport parameter.' do
      let(:params) do
        {
          'name' => '050 testing dport setting with some basics',
          'params' => {
            'ensure' => 'present',
            'chain' => 'OUTPUT',
            'destination' => '10.10.10.10',
            'family' => 'inet',
            'proto' => 'tcp',
            'dport' => '8080',
            'jump' => 'accept',
          }
        }
      end
      let(:facts) { os_facts }

      it {
        if os_check
          is_expected.to compile
          is_expected.to contain_multiwall__nftables__rule(params['name'])
          is_expected.to contain_nftables__rule('OUTPUT-testing_dport_setting_with_some_basics').with(
            'name' => 'OUTPUT-testing_dport_setting_with_some_basics',
            'ensure' => 'present',
            'table' => 'inet-filter',
            'content' => 'ip daddr 10.10.10.10 tcp dport 8080 accept',
          )
        end
      }
    end
  end
end
