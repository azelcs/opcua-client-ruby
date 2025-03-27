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

    # OPCUA test server (tools/server/server.cpp) default values
    let(:def_opcua_variables) do
      {
        int16_a: 0,
        int16_b: -100,
        int16_c: 100,
        int32_a: 0,
        int32_b: -1000,
        int32_c: 1000,
        uint16_a: 0,
        uint16_b: 100,
        uint16_c: 200,
        uint32_a: 0,
        uint32_b: 1000,
        uint32_c: 2000,
        bool_a: true,
        bool_b: false,
        float_a: 0,
        float_b: -123.222,
        float_c: 123.222,
        string_a: '',
        string_b: 'Example text'
      }
    end

    before(:all) do
      system('make -C tools/server/ clean all') # Compile opcua test server
    end

    around(:each) do |example|
      is_win = RUBY_PLATFORM =~ /mswin|mingw|cygwin/
      executable = is_win ? 'opcua-server.exe' : 'opcua-server'
      server_pid = spawn(File.join('tools', 'server', executable)) # Launch server
      example.run
      Process.kill('TERM', server_pid) # Stop server
    end

    context 'read' do
      xit 'can read default values' do
        OPCUAClient.start(URL) do |client|
          expect(client.read_int16(NS, 'int16_b')).to eq(def_opcua_variables[:int16_b])
          expect(client.read_uint16(NS, 'uint16_b')).to eq(def_opcua_variables[:uint16_b])
          expect(client.read_int32(NS, 'int32_b')).to eq(def_opcua_variables[:int32_b])
          expect(client.read_uint32(NS, 'uint32_b')).to eq(def_opcua_variables[:uint32_b])
          expect(client.read_boolean(NS, 'bool_a')).to eq(def_opcua_variables[:bool_a])
          expect(client.read_boolean(NS, 'bool_b')).to eq(def_opcua_variables[:bool_b])
          expect(client.read_float(NS, 'float_b').round(3)).to eq(def_opcua_variables[:float_b])
          expect(client.read_string(NS, 'string_b')).to eq(def_opcua_variables[:string_b])

          int16, uint16, int32, uint32, bool_a, bool_b, float, string = client.multi_read(NS, %w[
            int16_b uint16_b int32_b uint32_b bool_a bool_b float_b string_b]
          )

          expect(int16).to eq(def_opcua_variables[:int16_b])
          expect(uint16).to eq(def_opcua_variables[:uint16_b])
          expect(int32).to eq(def_opcua_variables[:int32_b])
          expect(uint32).to eq(def_opcua_variables[:uint32_b])
          expect(bool_a).to eq(def_opcua_variables[:bool_a])
          expect(bool_b).to eq(def_opcua_variables[:bool_b])
          expect(float.round(3)).to eq(def_opcua_variables[:float_b])
          expect(string).to eq(def_opcua_variables[:string_b])
        end
      end
    end

    context 'write' do
      it 'can write separate values and read them after' do
        OPCUAClient.start(URL) do |client|
          client.write_int16(NS, 'int16_b', -222)
          expect(client.read_int16(NS, 'int16_b')).to eq(-222)

          client.write_uint16(NS, 'uint16_b', 444)
          expect(client.read_uint16(NS, 'uint16_b')).to eq(444)

          client.write_int32(NS, 'int32_b', -2222)
          expect(client.read_int32(NS, 'int32_b')).to eq(-2222)

          client.write_uint32(NS, 'uint32_b', 4444)
          expect(client.read_uint32(NS, 'uint32_b')).to eq(4444)

          client.write_float(NS, 'float_b', 1234.123)
          expect(client.read_float(NS, 'float_b').round(3)).to eq(1234.123)

          client.write_boolean(NS, 'bool_a', false) # Opposite of default
          expect(client.read_boolean(NS, 'bool_a')).to eq(false)

          client.write_boolean(NS, 'bool_b', true) # Opposite of default
          expect(client.read_boolean(NS, 'bool_b')).to eq(true)

          client.write_string(NS, 'string_b', 'New string')
          expect(client.read_string(NS, 'string_b')).to eq('New string')
        end
      end

      it 'can multiwrite values and read them after' do
        OPCUAClient.start(URL) do |client|
          client.multi_write_int16(NS, %w[int16_a int16_b int16_c], [-123, 0, 123])
          expect(client.multi_read(NS, %w[int16_a int16_b int16_c])).to eq([-123, 0, 123])

          client.multi_write_uint16(NS, %w[uint16_a uint16_b uint16_c], [123, 456, 0])
          expect(client.multi_read(NS, %w[uint16_a uint16_b uint16_c])).to eq([123, 456, 0])

          client.multi_write_int32(NS, %w[int32_a int32_b int32_c], [-1234, 0, 1234])
          expect(client.multi_read(NS, %w[int32_a int32_b int32_c])).to eq([-1234, 0, 1234])

          client.multi_write_uint32(NS, %w[uint32_a uint32_b uint32_c], [1234, 0, 5678])
          expect(client.multi_read(NS, %w[uint32_a uint32_b uint32_c])).to eq([1234, 0, 5678])

          client.multi_write_boolean(NS, %w[bool_a bool_b], [false, true])
          expect(client.multi_read(NS, %w[bool_a bool_b])).to eq([false, true])

          client.multi_write_float(NS, %w[float_a float_b float_c], [-777.48, 0.0, 512.991])
          expect(client.multi_read(NS, %w[float_a float_b float_c]).map { |v| v.round(3) })
            .to eq([-777.48, 0.0, 512.991])

          client.multi_write_string(NS, %w[string_a string_b], ['OPCUA', 'test 123.123'])
          expect(client.multi_read(NS, %w[string_a string_b])).to eq(['OPCUA', 'test 123.123'])
        end
      end
    end
  end
end
