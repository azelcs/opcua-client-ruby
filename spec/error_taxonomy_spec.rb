require 'spec_helper'

# Specs for the error taxonomy (subclasses + structured status data) added on
# top of the single OPCUAClient::Error. Every case also asserts the failure is
# still an OPCUAClient::Error, proving `rescue OPCUAClient::Error` stays valid.
RSpec.describe 'OPCUAClient error taxonomy' do
  # `let` (not top-level constants) so these don't collide with core_spec's URL/NS.
  let(:url) { 'opc.tcp://127.0.0.1:4840' }
  let(:ns) { 5 }

  describe 'OPCUAClient.classify_status_code' do
    it 'classifies by severity bits and status family' do
      expect(OPCUAClient.classify_status_code(0x00000000)).to eq(:good)
      expect(OPCUAClient.classify_status_code(0x40000000)).to eq(:uncertain)
      expect(OPCUAClient.classify_status_code(0x80AE0000)).to eq(:connection) # BadConnectionClosed
      expect(OPCUAClient.classify_status_code(0x80340000)).to eq(:node)       # BadNodeIdUnknown
      expect(OPCUAClient.classify_status_code(0x80740000)).to eq(:type)       # BadTypeMismatch
      expect(OPCUAClient.classify_status_code(0x80010000)).to eq(:protocol)   # BadUnexpectedError
    end
  end

  context 'when nothing is listening on the endpoint' do
    it 'raises a ConnectionError that is still an OPCUAClient::Error' do
      expect do
        OPCUAClient.start('opc.tcp://127.0.0.1:4999') { |_client| }
      end.to raise_error(OPCUAClient::ConnectionError) do |e|
        expect(e).to be_a(OPCUAClient::Error) # backward compatible
        expect(e).to be_connection
        expect(e.status_code).to be_a(Integer)
        expect(e.status_name).to be_a(String)
        expect(e.node_index).to be_nil
      end
    end
  end

  context 'against a running server' do
    before(:all) do
      system('make -C tools/server/ all') # Build opcua test server if needed
    end

    around(:each) do |example|
      server_pid = spawn('tools/server/opcua-server') # Launch server
      sleep 0.3 # Give the server a moment to bind the socket before connecting
      example.run
      Process.kill('TERM', server_pid) # Stop server
    end

    it 'raises NodeError with the real status for an unknown node id' do
      OPCUAClient.start(url) do |client|
        expect { client.read_int16(ns, 'does_not_exist') }
          .to raise_error(OPCUAClient::NodeError) do |e|
            expect(e).to be_a(OPCUAClient::Error)
            expect(e).to be_node
            expect(e.status_name).to eq('BadNodeIdUnknown')
            expect(e.status_code).to eq(0x80340000)
            expect(e.node_index).to be_nil # single read, no index
          end
      end
    end

    it 'raises TypeMismatchError (client-side) when decoding a node as the wrong type' do
      OPCUAClient.start(url) do |client|
        expect { client.read_boolean(ns, 'int16_a') }
          .to raise_error(OPCUAClient::TypeMismatchError) do |e|
            expect(e).to be_a(OPCUAClient::Error)
            expect(e).to be_type_mismatch
            expect(e.status_code).to be_nil # no UA status; this is a client-side mismatch
            expect(e.status_name).to eq('UA type mismatch')
          end
      end
    end

    it 'raises TypeMismatchError (server-side) when writing an incompatible type' do
      OPCUAClient.start(url) do |client|
        expect { client.write_string(ns, 'int16_a', 'not an int') }
          .to raise_error(OPCUAClient::TypeMismatchError) do |e|
            expect(e).to be_a(OPCUAClient::Error)
            expect(e.status_code).to be_a(Integer)
            expect(e.status_name).to eq('BadTypeMismatch')
          end
      end
    end

    it 'multi_read raises NodeError carrying the failing node_index and real status' do
      OPCUAClient.start(url) do |client|
        expect { client.multi_read(ns, %w[int16_a does_not_exist int16_b]) }
          .to raise_error(OPCUAClient::NodeError) do |e|
            expect(e).to be_a(OPCUAClient::Error)
            expect(e.status_name).to eq('BadNodeIdUnknown')
            expect(e.status_code).to eq(0x80340000)
            expect(e.node_index).to eq(1) # the second node failed
          end
      end
    end

    it 'raises OPCUAClient::ArgumentError (not ::ArgumentError) for bad Ruby args' do
      OPCUAClient.start(url) do |client|
        expect { client.multi_read(ns, [123]) }
          .to raise_error(OPCUAClient::ArgumentError) do |e|
            expect(e).to be_a(OPCUAClient::Error)
            expect(e).not_to be_a(::ArgumentError) # our root, distinct from Ruby's
            expect(e.status_code).to be_nil
            expect(e.status_name).to eq('Invalid arguments')
            expect(e.node_index).to be_nil
          end
      end
    end

    it 'raises a rescuable OPCUAClient::ArgumentError (not bare ::TypeError) for wrong write types' do
      OPCUAClient.start(url) do |client|
        # Was a bare Ruby TypeError before; now a classified, rescuable error.
        expect { client.multi_write_int16(ns, %w[int16_a], ['not_an_int']) }
          .to raise_error(OPCUAClient::ArgumentError)

        expect { client.write_int16(ns, 'int16_a', 'not_an_int') }
          .to raise_error(OPCUAClient::Error)

        expect { client.multi_write_boolean(ns, %w[bool_a], ['not_a_bool']) }
          .to raise_error(OPCUAClient::ArgumentError)
      end
    end

    it 'multi_write raises TypeMismatchError carrying the failing node_index' do
      OPCUAClient.start(url) do |client|
        # node 0 (string_a) writes fine; node 1 (int16_a) rejects a string -> BadTypeMismatch
        expect { client.multi_write_string(ns, %w[string_a int16_a], %w[ok bad]) }
          .to raise_error(OPCUAClient::TypeMismatchError) do |e|
            expect(e.status_name).to eq('BadTypeMismatch')
            expect(e.node_index).to eq(1)
          end
      end
    end

    it 'raises OPCUAClient::ArgumentError (not bare ::TypeError) for a non-array argument' do
      OPCUAClient.start(url) do |client|
        expect { client.multi_read(ns, 'not_an_array') }
          .to raise_error(OPCUAClient::ArgumentError) do |e|
            expect(e).to be_a(OPCUAClient::Error)
            expect(e.status_name).to eq('Invalid arguments')
          end
      end
    end

    it 'raises OPCUAClient::ArgumentError (not bare ::TypeError) for non-numeric float/double/int64 writes' do
      OPCUAClient.start(url) do |client|
        expect { client.write_float(ns, 'float_a', 'x') }.to raise_error(OPCUAClient::ArgumentError)
        expect { client.write_double(ns, 'float_a', 'x') }.to raise_error(OPCUAClient::ArgumentError)
        expect { client.write_int64(ns, 'int16_a', 'x') }.to raise_error(OPCUAClient::ArgumentError)
        expect { client.multi_write_float(ns, %w[float_a], ['x']) }.to raise_error(OPCUAClient::ArgumentError)
        expect { client.multi_write_int64(ns, %w[int16_a], ['x']) }.to raise_error(OPCUAClient::ArgumentError)

        # An Integer is still accepted where a Float is expected (no behaviour change)
        client.write_float(ns, 'float_a', 7)
        expect(client.read_float(ns, 'float_a').round(1)).to eq(7.0)
      end
    end
  end
end
