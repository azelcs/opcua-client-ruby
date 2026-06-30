module OPCUAClient
  class << self
    def new_client
      OPCUAClient::Client.new
    end

    def start(*args)
      client = OPCUAClient::Client.new
      client.connect(*args)
      yield client
    ensure
      client.disconnect
    end
  end
end

require "opcua_client/opcua_client"
require "opcua_client/client"

module OPCUAClient
  # Error hierarchy (all defined in the C extension, all < OPCUAClient::Error so
  # any existing `rescue OPCUAClient::Error` keeps catching everything):
  #
  #   OPCUAClient::Error
  #   ├── ConnectionError    link/session/channel/transport down (robot unreachable)
  #   ├── NodeError          addressing: unknown/invalid node id, attribute, index range
  #   ├── TypeMismatchError  value/type problems (server BadTypeMismatch, or client read-type mismatch)
  #   ├── ProtocolError      everything else "Bad..." (BadUnexpectedError, BadInternalError, ...)
  #   └── ArgumentError      caller misuse from Ruby (NOT ::ArgumentError)
  #
  # Every raised error also carries #status_code (Integer or nil), #status_name
  # (String) and #node_index (Integer or nil — the failing slot in a multi_* call).
  class Error
    def connection?;    is_a?(ConnectionError);   end
    def node?;          is_a?(NodeError);          end
    def type_mismatch?; is_a?(TypeMismatchError);  end
    def protocol?;      is_a?(ProtocolError);      end
    def argument?;      is_a?(ArgumentError);      end
  end
end
