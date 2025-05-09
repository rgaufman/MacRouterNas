#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe MacRouterUtils::InterfaceManager do
  let(:ifconfig_output) do
    <<~IFCONFIG
      lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
      	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
      	inet 127.0.0.1 netmask 0xff000000
      	inet6 ::1 prefixlen 128
      	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
      	nd6 options=201<PERFORMNUD,DAD>
      gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
      stf0: flags=0<> mtu 1280
      anpi1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
      	options=400<CHANNEL_IO>
      	ether ea:74:2d:ed:ab:f3
      	nd6 options=201<PERFORMNUD,DAD>
      	media: 100baseTX <full-duplex>
      	status: inactive
      en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
      	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
      	ether 60:3e:5f:35:b8:e8
      	inet6 fe80::c3a:3e02:ef44:f599%en0 prefixlen 64 secured scopeid 0xe
      	inet 192.168.3.2 netmask 0xffffff00 broadcast 192.168.3.255
      	nd6 options=201<PERFORMNUD,DAD>
      	media: autoselect
      	status: active
      en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
      	options=400<CHANNEL_IO>
      	ether ea:74:2d:ed:ab:d3
      	inet 192.168.100.1 netmask 0xffffff00 broadcast 192.168.100.255
      	nd6 options=201<PERFORMNUD,DAD>
      	media: 100baseTX <full-duplex>
      	status: active
    IFCONFIG
  end

  let(:interface_manager) { described_class.new('en5', '192.168.100.1') }

  describe '#check_lan_status' do
    context 'when interface is active with matching IP' do
      let(:active_interface) do
        <<~INTERFACE
          en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          	options=400<CHANNEL_IO>
          	ether ea:74:2d:ed:ab:d3
          	inet 192.168.100.1 netmask 0xffffff00 broadcast 192.168.100.255
          	nd6 options=201<PERFORMNUD,DAD>
          	media: 100baseTX <full-duplex>
          	status: active
        INTERFACE
      end

      it 'correctly identifies active interface with matching IP' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: active_interface })
        
        status = interface_manager.check_lan_status
        
        expect(status[:active]).to be true
        expect(status[:ip]).to eq('192.168.100.1')
        expect(status[:has_static_ip]).to be true
      end
    end

    context 'when interface is active with different IP' do
      let(:different_ip_interface) do
        <<~INTERFACE
          en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          	options=400<CHANNEL_IO>
          	ether ea:74:2d:ed:ab:d3
          	inet 192.168.100.2 netmask 0xffffff00 broadcast 192.168.100.255
          	nd6 options=201<PERFORMNUD,DAD>
          	media: 100baseTX <full-duplex>
          	status: active
        INTERFACE
      end

      it 'correctly identifies active interface with non-matching IP' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: different_ip_interface })
        
        status = interface_manager.check_lan_status
        
        expect(status[:active]).to be true
        expect(status[:ip]).to eq('192.168.100.2')
        expect(status[:has_static_ip]).to be false
      end
    end

    context 'when interface is inactive' do
      let(:inactive_interface) do
        <<~INTERFACE
          en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          	options=400<CHANNEL_IO>
          	ether ea:74:2d:ed:ab:d3
          	nd6 options=201<PERFORMNUD,DAD>
          	media: 100baseTX <full-duplex>
          	status: inactive
        INTERFACE
      end

      it 'correctly identifies inactive interface' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: inactive_interface })
        
        status = interface_manager.check_lan_status
        
        expect(status[:active]).to be false
        expect(status[:ip]).to be_nil
        expect(status[:has_static_ip]).to be false
      end
    end
  end

  describe '#check_wan_status' do
    context 'when WAN interface is active' do
      let(:active_wan) do
        <<~INTERFACE
          en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
          	ether 60:3e:5f:35:b8:e8
          	inet6 fe80::c3a:3e02:ef44:f599%en0 prefixlen 64 secured scopeid 0xe
          	inet 192.168.3.2 netmask 0xffffff00 broadcast 192.168.3.255
          	nd6 options=201<PERFORMNUD,DAD>
          	media: autoselect
          	status: active
        INTERFACE
      end

      it 'correctly identifies active WAN interface' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: active_wan })

        status = interface_manager.check_wan_status('en0')

        expect(status[:active]).to be true
        expect(status[:ip]).to eq('192.168.3.2')
      end
    end

    context 'when WAN interface is inactive' do
      let(:inactive_wan) do
        <<~INTERFACE
          en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
          	ether 60:3e:5f:35:b8:e8
          	nd6 options=201<PERFORMNUD,DAD>
          	media: autoselect
          	status: inactive
        INTERFACE
      end

      it 'correctly identifies inactive WAN interface' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: inactive_wan })

        status = interface_manager.check_wan_status('en0')

        expect(status[:active]).to be false
        expect(status[:ip]).to be_nil
      end
    end

    context 'when WAN interface is a PPP interface' do
      let(:active_ppp) do
        <<~INTERFACE
          ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
              inet 100.66.91.122 --> 203.134.4.189 netmask 0xff000000
              inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
              nd6 options=201<PERFORMNUD,DAD>
        INTERFACE
      end

      it 'correctly identifies active PPP interface' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: active_ppp })

        status = interface_manager.check_wan_status('ppp0')

        expect(status[:active]).to be true
        expect(status[:ip]).to eq('100.66.91.122')
        expect(status[:destination]).to eq('203.134.4.189')
      end

      let(:inactive_ppp) do
        <<~INTERFACE
          ppp0: flags=8050<POINTOPOINT,MULTICAST> mtu 1492
              nd6 options=201<PERFORMNUD,DAD>
        INTERFACE
      end

      it 'correctly identifies inactive PPP interface without RUNNING flag' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: inactive_ppp })

        status = interface_manager.check_wan_status('ppp0')

        expect(status[:active]).to be false
        expect(status[:ip]).to be_nil
      end

      let(:ppp_missing_ip) do
        <<~INTERFACE
          ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
              inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
              nd6 options=201<PERFORMNUD,DAD>
        INTERFACE
      end

      it 'correctly identifies PPP interface with RUNNING flag but no IP' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: ppp_missing_ip })

        status = interface_manager.check_wan_status('ppp0')

        expect(status[:active]).to be false
        expect(status[:ip]).to be_nil
      end

      let(:ppp_with_ip_without_dest) do
        <<~INTERFACE
          ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1492
              inet 100.66.91.122 netmask 0xff000000
              inet6 fe80::d211:e5ff:fe88:7787%ppp0 prefixlen 64 scopeid 0x19
              nd6 options=201<PERFORMNUD,DAD>
        INTERFACE
      end

      it 'correctly identifies active PPP interface with IP but no destination' do
        allow(interface_manager).to receive(:execute_command_with_output).and_return({ success: true, stdout: ppp_with_ip_without_dest })

        status = interface_manager.check_wan_status('ppp0')

        expect(status[:active]).to be true
        expect(status[:ip]).to eq('100.66.91.122')
        expect(status[:destination]).to be_nil
      end
    end
  end

  describe '#verify_configured' do
    context 'when interface has the expected IP' do
      it 'returns true' do
        interface_with_ip = <<~INTERFACE
          en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          	options=400<CHANNEL_IO>
          	ether ea:74:2d:ed:ab:d3
          	inet 192.168.100.1 netmask 0xffffff00 broadcast 192.168.100.255
          	nd6 options=201<PERFORMNUD,DAD>
          	media: 100baseTX <full-duplex>
          	status: active
        INTERFACE

        allow(Open3).to receive(:capture3).and_return([interface_with_ip, "", double(success?: true)])
        
        expect(interface_manager.verify_configured).to be true
      end
    end

    context 'when interface has a different IP' do
      it 'returns false' do
        interface_wrong_ip = <<~INTERFACE
          en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          	options=400<CHANNEL_IO>
          	ether ea:74:2d:ed:ab:d3
          	inet 192.168.100.2 netmask 0xffffff00 broadcast 192.168.100.255
          	nd6 options=201<PERFORMNUD,DAD>
          	media: 100baseTX <full-duplex>
          	status: active
        INTERFACE

        allow(Open3).to receive(:capture3).and_return([interface_wrong_ip, "", double(success?: true)])
        
        expect(interface_manager.verify_configured).to be false
      end
    end
  end

  describe 'regex patterns for ifconfig parsing' do
    it 'extracts IP addresses correctly' do
      ip_pattern = /inet (\d+\.\d+\.\d+\.\d+)/
      
      # Test en0 IP extraction
      en0_match = ifconfig_output.match(/en0:.*?inet (\d+\.\d+\.\d+\.\d+)/m)
      
      expect(en0_match).not_to be_nil
      expect(en0_match[1]).to eq('192.168.3.2')
      
      # Test en5 IP extraction
      en5_match = ifconfig_output.match(/en5:.*?inet (\d+\.\d+\.\d+\.\d+)/m)
      
      expect(en5_match).not_to be_nil
      expect(en5_match[1]).to eq('192.168.100.1')
    end

    it 'detects interface status correctly' do
      # Test active interface detection
      expect(ifconfig_output).to match(/en0:.*?status: active/m)
      
      # Test inactive interface detection
      expect(ifconfig_output).to match(/anpi1:.*?status: inactive/m)
    end
  end
end