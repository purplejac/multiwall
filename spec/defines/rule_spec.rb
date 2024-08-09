# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::rule' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      context 'testing basic rule' do
        let(:params) do
          {
            'ensure' => 'present',
            'chain' => 'INPUT',
            'name' => '002 reject local traffic not on loopback interface',
            'iniface' => '! lo',
            'proto' => 'all',
            'destination' => '127.0.0.1/8',
            'jump' => 'reject',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }
        it {
          is_expected.to contain_multiwall__rule(params['name']).with_name('002 reject local traffic not on loopback interface')

          if (((facts[:os]['family'] == 'RedHat') && (facts[:os]['release']['major'].to_i > 7)) ||
            ((facts[:os]['name'] == 'Debian') && (facts[:os]['release']['major'].to_i > 10)) ||
            ((facts[:os]['name'] == 'Ubuntu') && facts[:os]['release']['major'] > '20.00') ||
            ((facts[:os]['name'] == 'SLES') && (facts[:os]['release']['major'].to_i > 15)) ||
            (facts[:os]['name'] == 'Fedora'))
          then
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with(
              'ensure' => 'present',
              'table' => 'inet',
              'order' => '03',
              'content' => %r{ip saddr 127.0.0.1/8 all *reject}
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_firewall('002 reject local traffic not on loopback interface').with(
              'ensure' => 'present',
              'chain' => 'INPUT',
              'table' => 'filter',
              'protocol' => 'IPv4',
              'destination' => '127.0.0.1/8',
              'iniface' => '! lo',
              'proto' => 'all',
            )
          end
          }
      end

      context 'testing absent setting' do
        let(:params) do
          {
            'name' => '002 reject local traffic not on loopback interface',
            'ensure' => 'absent',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }
        it {
          if (((facts[:os]['family'] == 'RedHat') && (facts[:os]['release']['major'].to_i > 7)) ||
            ((facts[:os]['name'] == 'Debian') && (facts[:os]['release']['major'].to_i > 10)) ||
            ((facts[:os]['name'] == 'Ubuntu') && facts[:os]['release']['major'] > '20.00') ||
            ((facts[:os]['name'] == 'SLES') && (facts[:os]['release']['major'].to_i > 15)) ||
            (facts[:os]['name'] == 'Fedora'))
          then
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with_ensure('absent')
          else
            is_expected.to contain_multiwall__iptables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_firewall('002 reject local traffic not on loopback interface').with_ensure('absent')
          end
        }
      end
    end
  end
end
