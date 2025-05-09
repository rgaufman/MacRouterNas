require_relative 'spec_helper'

RSpec.describe MacRouterUtils::SysctlManager do
  let(:sysctl_manager) { MacRouterUtils::SysctlManager.new }
  
  describe '#check_status' do
    context 'when ip forwarding is enabled' do
      before do
        # Mock the macOS style output format "net.inet.ip.forwarding: 1"
        # Note: Different OS versions may output different formats:
        # - Some macOS versions use "net.inet.ip.forwarding: 1" (with a space after colon)
        # - Other systems might use "net.inet.ip.forwarding=1" (with equals sign)
        # Our implementation handles both formats
        allow(sysctl_manager).to receive(:execute_command_with_output).with("sysctl net.inet.ip.forwarding") do
          { success: true, stdout: "net.inet.ip.forwarding: 1", stderr: "" }
        end
        
        # Mock other related commands
        allow(sysctl_manager).to receive(:execute_command_with_output).with(/defaults read/) do
          { success: false, stdout: "", stderr: "Not found" }
        end
        
        allow(sysctl_manager).to receive(:execute_command_with_output).with(/sudo pfctl -s state/) do
          { success: true, stdout: "", stderr: "" }
        end
        
        allow(sysctl_manager).to receive(:execute_command_with_output).with(/sudo launchctl list/) do
          { success: false, stdout: "", stderr: "" }
        end
        
        allow(File).to receive(:exist?).and_return(false)
      end
      
      it 'correctly detects ip forwarding is enabled' do
        status = sysctl_manager.check_status
        expect(status[:enabled]).to be true
        expect(status[:effective_enabled]).to be true
      end
    end
    
    context 'when ip forwarding is disabled' do
      before do
        # Mock the macOS style output format "net.inet.ip.forwarding: 0"
        # Our implementation handles both colon and equals format
        allow(sysctl_manager).to receive(:execute_command_with_output).with("sysctl net.inet.ip.forwarding") do
          { success: true, stdout: "net.inet.ip.forwarding: 0", stderr: "" }
        end
        
        # Mock other related commands
        allow(sysctl_manager).to receive(:execute_command_with_output).with(/defaults read/) do
          { success: false, stdout: "", stderr: "Not found" }
        end
        
        allow(sysctl_manager).to receive(:execute_command_with_output).with(/sudo pfctl -s state/) do
          { success: true, stdout: "", stderr: "" }
        end
        
        allow(sysctl_manager).to receive(:execute_command_with_output).with(/sudo launchctl list/) do
          { success: false, stdout: "", stderr: "" }
        end
        
        allow(File).to receive(:exist?).and_return(false)
      end
      
      it 'correctly detects ip forwarding is disabled' do
        status = sysctl_manager.check_status
        expect(status[:enabled]).to be false
        expect(status[:effective_enabled]).to be false
      end
    end
  end
end