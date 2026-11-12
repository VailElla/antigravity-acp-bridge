#!/usr/bin/ruby
require_relative 'antigravity_connection_guard'

class TestAPI
  attr_accessor :leaf, :flows, :read_hook, :leaf_hook
  attr_reader :closed

  def initialize(flows = [])
    @leaf = 'node-new'
    @flows = flows
    @closed = []
  end
  def current_leaf
    @leaf_hook ? @leaf_hook.call : @leaf
  end
  def connections
    @read_hook ? @read_hook.call : @flows
  end
  def close(id)
    @closed << id
    @flows = @flows.reject { |c| c['id'] == id }
    true
  end
end

MAC_IP = '192.0.2.10'
UUID1 = '11111111-2222-3333-4444-555555555555'
UUID2 = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
TARGET = AntigravityRouterAPI::TARGET

def flow(id = UUID1, host: 'aicode.googleapis.com', source: MAC_IP,
         port: '41234', chain: ['node-old', TARGET], upload: 10, download: 20,
         network: 'tcp')
  { 'id' => id, 'metadata' => { 'host' => host, 'sourceIP' => source,
    'sourcePort' => port, 'network' => network }, 'chains' => chain,
    'upload' => upload, 'download' => download }
end

def scenario(flows = [flow], identities = [[MAC_IP, '41234']])
  api = TestAPI.new(flows)
  now = [0]
  id_source = -> { { identities: identities, region_error: false, tasks_idle: true,
                     idle_for: 1000, reporter_id: 'a' * 32, activity_epoch: 0 } }
  guard = AntigravityConnectionGuard.new(api, id_source, -> { now[0] })
  [guard, api, now, identities]
end

$assertions = 0
def assert(label, expected, actual)
  $assertions += 1
  raise "#{label}: expected #{expected.inspect}, got #{actual.inspect}" unless expected == actual
end

g, api, t, ids = scenario
assert('initial observation', :observing, g.tick)
t[0] = 44; assert('control still quiet under threshold', :observing, g.tick)
t[0] = 45; assert('stale control closed once', :closed, g.tick)
assert('only identified connection closed', [UUID1], api.closed)

g, api, t, ids = scenario([flow(host: 'daily-cloudcode-pa.googleapis.com')])
g.tick; t[0] = 179; assert('model connection gets longer window', :observing, g.tick)
t[0] = 180; assert('idle stale model connection closed', :closed, g.tick)

g, api, t, ids = scenario([flow(chain: ['node-new', TARGET])])
g.tick; t[0] = 1000; assert('current node untouched', :observing, g.tick)
assert('current never deleted', [], api.closed)

g, api, t, ids = scenario([flow(chain: ['node-old', 'example-fallback'])])
g.tick; t[0] = 45; assert('legacy Google connection can be refreshed safely', :closed, g.tick)

g, api, t, ids = scenario([flow(chain: ['node-new', 'example-fallback', TARGET])])
g.tick; t[0] = 1000; assert('current nested Google fallback is not closed', :observing, g.tick)

g, api, t, ids = scenario
g.tick; t[0] = 40; api.flows[0]['download'] = 21; g.tick
t[0] = 84; assert('traffic restarts quiet timer', :observing, g.tick)
t[0] = 85; assert('closes after subsequent quiet period', :closed, g.tick)

g, api, t, ids = scenario
g.tick; t[0] = 35; api.leaf = 'node-other'; g.tick
t[0] = 79; assert('new selection resets quiet timer', :observing, g.tick)
t[0] = 80; assert('stable new selection works', :closed, g.tick)

g, api, t, ids = scenario([flow, flow(UUID2, host: 'daily-cloudcode-pa.googleapis.com',
                                            port: '41235', chain: ['node-new', TARGET])],
                           [[MAC_IP, '41234'], [MAC_IP, '41235']])
g.tick; t[0] = 40; api.flows[1]['download'] = 21; g.tick
t[0] = 45; assert('other active Antigravity traffic blocks close', :observing, g.tick)
t[0] = 60; assert('control closes after all tracked flows quiet', :closed, g.tick)

g, api, t, ids = scenario
g.tick; t[0] = 50; ids.clear
assert('expired or empty identity feed blocks close', :observing, g.tick)
assert('no broad close without identity', [], api.closed)

[
  ['other client', [flow(source: '192.0.2.20')]],
  ['other domain', [flow(host: 'accounts.google.com')]],
  ['other group', [flow(chain: ['node-old', 'other-group'])]],
  ['udp', [flow(network: 'udp')]],
  ['bad uuid', [flow('not-an-id')]],
  ['invalid counters', [flow(upload: -1)]]
].each do |name, flows|
  g, api, t, ids = scenario(flows)
  g.tick; t[0] = 1000; g.tick
  assert(name, [], api.closed)
end

g, api, t, ids = scenario([flow(source: '2001:db8::1')], [['2001:db8::1', '41234']])
g.tick; t[0] = 45; assert('exact IPv6 tuple supported', :closed, g.tick)

g, api, t, ids = scenario([flow, flow(UUID2, port: '41235')],
                           [[MAC_IP, '41234'], [MAC_IP, '41235']])
g.tick; t[0] = 45; assert('first stale close', :closed, g.tick)
t[0] = 90; assert('cooldown limits successive close', :observing, g.tick)
t[0] = 135; assert('second stale close after cooldown', :closed, g.tick)

g, api, t, ids = scenario
g.tick; t[0] = 45
reads = 0
api.read_hook = -> do
  reads += 1
  f = Marshal.load(Marshal.dump(api.flows))
  f[0]['download'] += 1 if reads == 2
  f
end
assert('traffic race cancels close', :changed, g.tick)
assert('race leaves connection alone', [], api.closed)

g, api, t, ids = scenario
g.tick; t[0] = 45; reads = 0
api.leaf_hook = -> { reads += 1; reads == 1 ? 'node-new' : 'node-newer' }
assert('node selection race cancels close', :changed, g.tick)
assert('selection race leaves connection alone', [], api.closed)

api = TestAPI.new([flow])
t = [0]
error_feed = { identities: [[MAC_IP, '41234']], region_error: true, tasks_idle: true,
               idle_for: 1000, reporter_id: 'a' * 32, activity_epoch: 0 }
g = AntigravityConnectionGuard.new(api, -> { error_feed }, -> { t[0] })
g.tick; t[0] = 29; assert('selector still stabilizing on error', :observing, g.tick)
t[0] = 30; assert('location error can accelerate stale control', :closed, g.tick)

api = TestAPI.new([flow(host: 'daily-cloudcode-pa.googleapis.com')])
t = [0]
g = AntigravityConnectionGuard.new(api, -> { error_feed }, -> { t[0] })
g.tick; t[0] = 45; assert('location error does not accelerate model stream', :observing, g.tick)
t[0] = 180; assert('model still waits full idle interval', :closed, g.tick)

api = TestAPI.new([flow(host: 'daily-cloudcode-pa.googleapis.com')])
t = [0]
task_feed = { identities: [[MAC_IP, '41234']], region_error: false, tasks_idle: false,
              idle_for: 0, reporter_id: 'a' * 32, activity_epoch: 1 }
g = AntigravityConnectionGuard.new(api, -> { task_feed }, -> { t[0] })
g.tick; t[0] = 1000; assert('active task is never closed for network silence', :busy, g.tick)
assert('busy leaves task connection alone', [], api.closed)
task_feed[:tasks_idle] = true; task_feed[:idle_for] = 20
assert('newly idle task must settle', :busy, g.tick)
task_feed[:idle_for] = 30; g.tick
t[0] = 1179; assert('model quiet timer begins after tasks idle', :observing, g.tick)
t[0] = 1180; assert('old model connection closes after confirmed idle', :closed, g.tick)

api = TestAPI.new([flow])
t = [0]
task_feed = { identities: [[MAC_IP, '41234']], region_error: false, tasks_idle: true,
              idle_for: 1000, reporter_id: 'a' * 32, activity_epoch: 1 }
g = AntigravityConnectionGuard.new(api, -> { task_feed }, -> { t[0] })
g.tick; t[0] = 45; task_feed[:activity_epoch] = 2
assert('task that started between polls resets quiet timer', :observing, g.tick)
t[0] = 90; assert('connection closes only after new quiet window', :closed, g.tick)

api = TestAPI.new([flow])
t = [0]; calls = 0
task_feed[:activity_epoch] = 3
g = AntigravityConnectionGuard.new(api, -> {
  calls += 1
  calls == 3 ? task_feed.merge(tasks_idle: false) : task_feed
}, -> { t[0] })
g.tick; t[0] = 45
assert('task starting during revalidation cancels close', :changed, g.tick)
assert('task race leaves connection alone', [], api.closed)

class Resolver < AntigravityRouterAPI
  def initialize(table); @table = table; end
  def request(path, _method = 'GET')
    @table.fetch(path, [404, nil])
  end
  def path(name); '/proxies/' + escaped(name); end
end
r = Resolver.new({})
table = {
  r.path(TARGET) => [200, {'type' => 'Selector', 'now' => 'fallback', 'all' => ['fallback']}],
  r.path('fallback') => [200, {'type' => 'Fallback', 'now' => 'provider node', 'all' => ['provider node']}]
}
r = Resolver.new(table)
assert('nested fallback resolves provider leaf', 'provider node', r.current_leaf)
table[r.path('fallback')][1]['now'] = 'unknown'
assert('nonmember fails closed', nil, r.current_leaf)
table[r.path('fallback')][1]['now'] = 'DIRECT'
table[r.path('fallback')][1]['all'] << 'DIRECT'
assert('DIRECT fails closed', nil, r.current_leaf)

test_feed_path = "/tmp/antigravity-feed-test-#{Process.pid}-#{Time.now.to_i}"
begin
  f = File.open(test_feed_path, File::RDWR | File::CREAT | File::EXCL, 0600)
  f.write('{"version":2,"identities":[["192.0.2.10",41234],["192.0.2.20",123]],"region_error":true,"tasks_idle":true,"idle_for":45,"activity_epoch":1,"reporter_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
  f.flush
  clock = [File.mtime(f.path).to_f]
  feed = AntigravityIdentities.new(test_feed_path, -> { ['192.0.2.10'] }, -> { clock[0] })
  assert('feed only includes matching MAC neighbor',
         { identities: [[MAC_IP, '41234']], region_error: true, tasks_idle: true,
           idle_for: 45, activity_epoch: 1, reporter_id: 'a' * 32 }, feed.call)
  clock[0] += 36
  assert('stale feed fails closed', nil, feed.call)
  clock[0] -= 37
  assert('future timestamp fails closed', nil, feed.call)
  f.rewind; f.truncate(0); f.write('not valid JSON or YAML: ['); f.flush
  clock[0] = File.mtime(f.path).to_f
  assert('corrupt feed fails closed', nil, feed.call)
ensure
  f.close if f
  File.unlink(test_feed_path) if File.exist?(test_feed_path)
end

puts "guard assertions passed: #{$assertions}"
