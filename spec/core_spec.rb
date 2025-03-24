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
        # reads tools/server/server.cpp default values
        expect(client.read_int16(NS, 'int16_b')).to eq(-100)
        expect(client.read_uint16(NS, 'uint16_b')).to eq(100)
        expect(client.read_int32(NS, 'int32_b')).to eq(-1000)
        expect(client.read_uint32(NS, 'uint32_b')).to eq(1000)
        expect(client.read_float(NS, 'float_b').round(3)).to eq(123.222)
        expect(client.read_boolean(NS, 'bool_a')).to eq(true)
        expect(client.read_boolean(NS, 'bool_b')).to eq(false)
        expect(client.read_string(NS, 'string_b')).to eq('Example text')
      end
    end
  end
end
