# opcua-client-ruby

Incomplete OPC-UA client library for Ruby. Wraps open62541: <https://open62541.org>.

![ci-badge](https://github.com/mak-it/opcua-client-ruby/actions/workflows/build.yml/badge.svg)

## Installation

Add it to your Gemfile:

```ruby
gem 'opcua_client'
```

## Basic usage

Use `start` helper to automatically close connections:

```ruby
require 'opcua_client'

OPCUAClient.start("opc.tcp://127.0.0.1:4840") do |client|
  # write to ns=2;s=1
  client.write_int16(2, "1", 888)
  puts client.read_int16(2, "1")
end
```

Or handle connections manually:

```ruby
require 'opcua_client'

client = OPCUAClient::Client.new
begin
  client.connect("opc.tcp://127.0.0.1:4840")
  # write to ns=2;s=1
  client.write_int16(2, "1", 888)
  puts client.read_int16(2, "1")

  client.multi_write_int16(2, (1..10).map{|x| "action_#{x}"}, (1..10).map{|x| x * 10}) # 10x writes
  client.multi_write_int32(2, (1..10).map{|x| "amount_#{x}"}, (1..10).map{|x| x * 10 + 1}) # 10x writes
ensure
  client.disconnect
end
```

### Available methods - connection:

* ```client.connect(String url)``` - raises OPCUAClient::Error if unsuccessful
* ``` client.connect(String url, String username, String password, String client_cert, String private_key)``` - authorized connection with username and password, with encryption enabled
* ```client.disconnect => Fixnum``` - returns status

### Available methods - reads and writes:

All methods raise OPCUAClient::Error if unsuccessful.

* ```client.read_int16(Fixnum ns, String name) => Fixnum```
* ```client.read_uint16(Fixnum ns, String name) => Fixnum```
* ```client.read_int32(Fixnum ns, String name) => Fixnum```
* ```client.read_uint32(Fixnum ns, String name) => Fixnum```
* ```client.read_float(Fixnum ns, String name) => Float```
* ```client.read_double(Fixnum ns, String name) => Double```
* ```client.read_boolean(Fixnum ns, String name) => true/false```
* ```client.read_string(Fixnum ns, String name) => String```
* ```client.read_byte(Fixnum ns, String name) => Byte```
* ```client.read_uint32_list(Fixnum ns, String name) => Array[Fixnum]```
* ```client.read_int32_list(Fixnum ns, String name) => Array[Fixnum]```
* ```client.multi_read(Fixnum ns, Array[String] names) => Array values```
* ```client.write_int16(Fixnum ns, String name, Fixnum value)```
* ```client.write_uint16(Fixnum ns, String name, Fixnum value)```
* ```client.write_int32(Fixnum ns, String name, Fixnum value)```
* ```client.write_uint32(Fixnum ns, String name, Fixnum value)```
* ```client.write_float(Fixnum ns, String name, Float value)```
* ```client.write_double(Fixnum ns, String name, Double value)```
* ```client.write_boolean(Fixnum ns, String name, bool value)```
* ```client.write_string(Fixnum ns, String name, String value)```
* ```client.write_uint32_list(Fixnum ns, String name, Array[Fixnum] value)```
* ```client.write_int32_list(Fixnum ns, String name, Array[Fixnum] value)```
* ```client.multi_write_int16(Fixnum ns, Array[String] names, Array[Fixnum] values)```
* ```client.multi_write_uint16(Fixnum ns, Array[String] names, Array[Fixnum] values)```
* ```client.multi_write_int32(Fixnum ns, Array[String] names, Array[Fixnum] values)```
* ```client.multi_write_uint32(Fixnum ns, Array[String] names, Array[Fixnum] values)```
* ```client.multi_write_float(Fixnum ns, Array[String] names, Array[Float] values)```
* ```client.multi_write_double(Fixnum ns, Array[String] names, Array[Double] values)```
* ```client.multi_write_boolean(Fixnum ns, Array[String] names, Array[bool] values)```
* ```client.multi_write_string(Fixnum ns, Array[String] names, Array[String] values)```
* ```client.multi_write_byte(Fixnum ns, Array[String] names, Array[Byte] values)```
* ```client.multi_write_int32_list(Fixnum ns, Array[String] names, Array[Array[Fixnum]] values)```


### Available methods - misc:

* ```client.state => Fixnum``` - client internal state
* ```OPCUAClient.human_status_code(Fixnum status) => String``` - human-readable name for a UA status code
* ```OPCUAClient.classify_status_code(Fixnum status) => Symbol``` - `:good | :uncertain | :connection | :node | :type | :protocol`

## Error handling

Every read/write/connect failure raises an `OPCUAClient::Error`. The exception
is one of the following subclasses, so you can tell *what kind* of failure it
was — and each instance also carries structured data.

```
OPCUAClient::Error  (< StandardError)
├── OPCUAClient::ConnectionError   # link/session/channel/transport down — the server is unreachable
├── OPCUAClient::NodeError         # addressing: unknown/invalid node id, bad attribute, bad index range
├── OPCUAClient::TypeMismatchError # value/type problem (server BadTypeMismatch, or a wrong-type read)
├── OPCUAClient::ProtocolError     # everything else "Bad…" (BadUnexpectedError, BadInternalError, …)
└── OPCUAClient::ArgumentError     # caller passed wrong Ruby args (NOT Ruby's ::ArgumentError)
```

Because they all inherit from `OPCUAClient::Error`, existing `rescue
OPCUAClient::Error` keeps catching everything. The subclasses are purely
additive — they let you branch on the *category* of failure (e.g. only a
`ConnectionError` should be treated as "device offline").

Each error exposes:

* ```error.status_code => Integer``` - the raw `UA_StatusCode`, or `nil` for client-side errors (bad args, wrong-type read)
* ```error.status_name => String``` - e.g. `"BadNodeIdUnknown"`, or the client-side message
* ```error.node_index  => Integer``` - index of the failing node in a `multi_*` call, otherwise `nil`

Convenience predicates: `error.connection?`, `error.node?`,
`error.type_mismatch?`, `error.protocol?`, `error.argument?`.

```ruby
begin
  client.multi_read(5, %w[temp_ok renamed_node pressure_ok])
rescue OPCUAClient::ConnectionError => e
  # the only category that means "device unreachable"
  notify_offline!(e.status_name)
rescue OPCUAClient::NodeError => e
  # a node is unknown/renamed — a schema problem, not the network
  logger.error("bad node at index #{e.node_index}: #{e.status_name}")
rescue OPCUAClient::Error => e
  # catch-all still works for everything
  logger.error("opcua failure: #{e.status_name} (#{e.status_code})")
end
```

`OPCUAClient.classify_status_code(code)` exposes the same categorizer for a raw
status code (covering `:good`/`:uncertain` too), so a consumer can map codes
without rescuing.

> **Known sharp edge:** `multi_read` returns `nil` in a result slot for a value
> whose UA type the gem does not decode (the read itself succeeded). A `nil`
> there means "undecoded", not "healthy" — don't treat it as a valid reading.

### Logging

The extension is silent by default. Set the `OPCUA_CLIENT_DEBUG` environment
variable (to any value) to print connection/diagnostic chatter to stdout.

## Subscriptions and monitoring

```ruby
cli = OPCUAClient::Client.new

cli.after_session_created do |cli|
  subscription_id = cli.create_subscription
  ns_index = 1
  node_name = "the.answer"
  cli.add_monitored_item(subscription_id, ns_index, node_name)
end

cli.after_data_changed do |subscription_id, monitor_id, server_time, source_time, new_value|
  puts("data changed: " + [subscription_id, monitor_id, server_time, source_time, new_value].inspect)
end

cli.connect("opc.tcp://127.0.0.1:4840")

loop do
  cli.connect("opc.tcp://127.0.0.1:4840") # no-op if connected
  cli.run_mon_cycle
  sleep(0.2)
end
```

### Available methods:

* ```client.create_subscription => Fixnum``` - nil if error
* ```client.add_monitored_item(Fixnum subscription, Fixnum ns, String name) => Fixnum``` - nil if error
* ```client.run_mon_cycle``` - returns status
* ```client.run_mon_cycle!``` - raises OPCUAClient::Error if unsuccessful

### Available callbacks:
* ```after_session_created```
* ```after_data_changed```

## Contribute

### Set up

```console
bundle
```

### Build and start dummy OPCUA server

```bash
make -C tools/server/ clean all # clean+all
tools/server/opcua-server # run
```

### Try out changes

```console
$ bin/rake compile
$ bin/console
pry> client = OPCUAClient::Client.new
pry> client.connect("opc.tcp://127.0.0.1:4840")
pry> client.read_uint32(5, "uint32b")
pry> client.read_uint16(5, "uint16b")
pry> client.read_bool(5, "bool_a")
```

### Test it

```console
$ bin/rake compile
$ bin/rake spec
```
