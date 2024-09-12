# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::rule' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
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
        
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'order' => '03',
              'content' => %r{ip daddr 127.0.0.1/8 all *reject},
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
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with_ensure('absent')
          else
            is_expected.to contain_multiwall__iptables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_firewall('002 reject local traffic not on loopback interface').with_ensure('absent')
          end
        }
      end

      context 'testing connlimit rule' do
        let(:params) do
          {
            'name' => '003 connlimit rule',
            'chain' => 'INPUT',
            'iniface' => 'eth0',
            'connlimit_above' => 3,
            'connlimit_mask' => 24,
            'jump' => 'reject',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name(params['name'])
            is_expected.to contain_nftables__rule('INPUT-connlimit_rule').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => %r{ip saddr & 255.255.255.0 *ct count over 3 reject},
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name']).with_name(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => 'INPUT',
              'iniface' => 'eth0',
              'table' => 'filter',
              'protocol' => 'IPv4',
              'connlimit_above' => 3,
              'connlimit_mask' => 24,
              'jump' => 'reject',
            )
          end
        }
      end

      context 'testing settings unsupported in nftables but support in iptables.' do
        let(:params) do
          {
            'name' => '004 checksum_fill for testing',
            'chain' => 'OUTPUT',
            'checksum_fill' => true,
            'iniface' => 'eth0',
            'proto' => 'all',
            'destination' => '127.0.0.1/8',
            'jump' => 'accept',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_notify('checksum_fill is not supported with nftables!')
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name'])
          end
        }
      end

      context 'testing ctdir with reply.' do 
        let(:params) do
          {
            'name' => '005 ctdir set to reply',
            'ctdir' => 'REPLY',
            'chain' => 'OUTPUT',
            'jump' => 'accept',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('OUTPUT-ctdir_set_to_reply').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => %r{ip daddr 172.16.254.254 ct state established,related *accept},
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'ctdir' => params['ctdir'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'testing ctorigdst parameter.' do
        let(:params) do
          {
            'name' => '007 ctorigdst to 127.0.0.1 and masq',
            'chain' => 'POSTROUTING',
            'table' => 'nat',
            'source' => facts[:networking]['ip'],
            'ctorigdst' => '10.10.10.10',
            'jump' => 'masquerade',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('POSTROUTING-ctorigdst_to_127_0_0_1_and_masq').with(
              'ensure' => 'present',
              'table' => "inet-#{params['table']}",
              'content' => %r{ip saddr #{facts[:networking]['ip']} *ct original daddr 10.10.10.10 masquerade},
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'table' => params['table'],
              'ctorigdst' => params['ctorigdst'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'testing ctorigsrc parameter.' do
        let(:params) do
          {
            'name' => '008 ctorigdst to 127.0.0.1 and masq',
            'chain' => 'POSTROUTING',
            'table' => 'nat',
            'destination' => facts[:networking]['ip'],
            'ctorigsrc' => '10.10.10.10',
            'jump' => 'masquerade',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }
      end

#          {
#            'name' => '008 why is it being weird',
#            'chain' => 'POSTROUTING',
#            'table' => 'nat',
#            'source' => facts[:networking]['ip'],
#            'ctorigsrc' => '10.10.10.10',
#            'jump' => 'masquerade',
#          }
#        end
#        let(:title) { params['name'] }
#
#        it { is_expected.to compile }
#
#        it {
#          if os_check
#            is_expected.to contain_multiwall__nftables__rule(params['name'])
#            is_expected.to contain_nftables__rule('POSTROUTING-ctorigsrc_from_127_0_0_1_and_masq').with(
#              'ensure' => 'present',
#              'table' => "inet-#{params['table']}",
#              'content' => %r{ip saddr #{facts[:networking]['ip']} *ct original daddr 10.10.10.10 masquerade},
#            )
#          else
#            is_expected.to contain_multiwall__iptables__rule(params['name'])
#            is_expected.to contain_firewall(params['name']).with(
#              'ensure' => 'present',
#              'chain' => params['chain'],
#              'table' => params['table'],
#              'ctorigsrc' => params['ctorigsrc'],
#              'jump' => params['jump'],
#            )
#          end
#        }
#      end
    end
  end
end
