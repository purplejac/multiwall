# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::iptables' do
  on_supported_os.each do |os, os_facts|
    if os_facts[:os]['family'] == "RedHat" and os_facts[:os]['release']['major'] > '7'
    then
      dotest = false
    else 
      dotest = true
    end

    if dotest
      context "on #{os}" do
        let(:facts) { os_facts }
        it { is_expected.to compile.with_all_deps }
      end
    end
  end
end
