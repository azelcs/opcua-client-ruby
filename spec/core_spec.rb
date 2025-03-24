require 'spec_helper'

RSpec.describe OPCUAClient::Client do
  context "unconnected" do
    it "allows disconnect for unconnected clients" do
      result = new_client(connect: false).disconnect
      expect(result).to eq(0)
    end

    it "returns 0 state" do
      state = new_client(connect: false).state
      expect(state).to eq(0)
    end
  end

  context 'connected' do
    URL = 'opc.tcp://127.0.0.1:4840'
    NS = 5

    before(:each) do
      # Launch opcua test cpp server
      system('make -C tools/server/ clean all')
      pid = spawn('tools/server/opcua-test-server')
      at_exit do
        Process.kill('TERM', pid)
      end
    end

    it 'can read' do
      OPCUAClient.start(URL) do |client|
        # opcua server default values
        ec
      end
    end
  end
end
