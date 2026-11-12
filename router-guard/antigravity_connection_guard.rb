#!/usr/bin/ruby
# Narrow, fail-closed cleanup of stale Antigravity connections. No policy
# selection, rules, DNS, or other clients are modified by this service.
require 'yaml'

class AntigravityRouterAPI
  TARGET = ENV.fetch('ACP_GUARD_TARGET', 'example-antigravity')
  BLOCKED = %w[DIRECT REJECT REJECT-DROP PASS DNS COMPATIBLE].freeze
  GROUP_TYPES = %w[Selector URLTest Fallback Relay].freeze

  def initialize(config = ENV.fetch('ACP_GUARD_CONFIG', '/etc/openclash/example-config.yaml'))
    @config_path = config
    @config_version = nil
  end

  def request(path, method = 'GET')
    st = File.stat(@config_path)
    version = [st.mtime.to_f, st.size]
    if version != @config_version
      cfg = begin
        YAML.load_file(@config_path, aliases: true)
      rescue ArgumentError
        YAML.load_file(@config_path)
      end
      port = cfg.fetch('external-controller').to_s.split(':').last
      secret = cfg.fetch('secret').to_s
      raise 'invalid controller config' unless port.match?(/\A\d{1,5}\z/) &&
        port.to_i.between?(1, 65535) && !secret.match?(/[\r\n\x00]/)
      @port = port
      @secret = secret
      @config_version = version
    end
    raise 'invalid method' unless %w[GET DELETE].include?(method)
    raise 'invalid path' unless path.start_with?('/') && !path.match?(/[\r\n\x00"]/)
    # Put the local controller secret on curl's stdin, not in its arguments.
    quoted_secret = @secret.gsub(/[\\"]/) { |char| '\\' + char }
    conf = "url = \"http://127.0.0.1:#{@port}#{path}\"\n" \
           "header = \"Authorization: Bearer #{quoted_secret}\"\n"
    command = ['curl', '-sS', '--noproxy', '*', '--max-time', '4',
               '-X', method, '-w', "\n%{http_code}", '-K', '-']
    raw = IO.popen(command, 'r+', err: File::NULL) do |io|
      io.write(conf)
      io.close_write
      io.read
    end
    body, _, status = raw.rpartition("\n")
    code = status.to_i
    parsed = body.empty? ? nil : YAML.safe_load(body)
    [code, parsed]
  rescue StandardError
    [0, nil]
  end

  def escaped(value)
    value.to_s.bytes.map { |b| format('%%%02X', b) }.join
  end

  # Resolve nested fallback/URLTest groups. Provider nodes need not appear as
  # top-level /proxies entries; membership in the parent group is required.
  def current_leaf
    name = TARGET
    visited = []
    parent = nil
    8.times do
      return nil if visited.include?(name) || BLOCKED.include?(name.upcase)
      visited << name
      code, data = request('/proxies/' + escaped(name))
      return name if code == 404 && parent && Array(parent['all']).include?(name)
      return nil unless code == 200 && data.is_a?(Hash)
      type = data['type'].to_s
      return nil if type.empty? || BLOCKED.include?(type.upcase) || type == 'LoadBalance'
      return name unless GROUP_TYPES.include?(type)
      next_name = data['now']
      return nil unless next_name.is_a?(String) && !next_name.empty? &&
        Array(data['all']).include?(next_name)
      parent, name = data, next_name
    end
    nil
  end

  def connections
    code, data = request('/connections')
    return nil unless code == 200 && data.is_a?(Hash) && data['connections'].is_a?(Array)
    data['connections']
  end

  def close(id)
    return false unless id.to_s.match?(/\A[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z/)
    request('/connections/' + id, 'DELETE')[0] == 204
  end
end

class AntigravityIdentities
  FEED = '/tmp/antigravity-port-feed/current.json'
  MAC = ENV.fetch('ACP_GUARD_CLIENT_MAC', '').downcase
  MAX_AGE = 8

  def initialize(path = FEED, neighbor_source = nil, clock = nil)
    @path = path
    @neighbor_source = neighbor_source || method(:neighbor_addresses)
    @clock = clock || -> { Time.now.to_f }
  end

  def neighbor_addresses
    return nil unless MAC.match?(/\A(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\z/)
    neighbors = []
    %w[-4 -6].each do |family|
      output = IO.popen(['/sbin/ip', family, 'neigh', 'show', 'dev', 'br-lan'], &:read)
      return nil unless $?.success?
      output.each_line do |line|
        parts = line.split
        index = parts.index('lladdr')
        neighbors << parts[0].downcase if index && parts[index + 1].to_s.downcase == MAC
      end
    end
    neighbors
  end

  def call
    st = File.stat(@path)
    age = @clock.call - st.mtime.to_f
    return nil unless st.file? && st.size <= 8192 && age >= 0 && age <= MAX_AGE
    feed = YAML.safe_load(File.read(@path))
    return nil unless feed.is_a?(Hash) && feed['version'] == 2 &&
      feed['identities'].is_a?(Array) && feed['identities'].length <= 256 &&
      [true, false].include?(feed['tasks_idle']) &&
      feed['reporter_id'].is_a?(String) && feed['reporter_id'].match?(/\A[0-9a-f]{32}\z/) &&
      feed['activity_epoch'].is_a?(Integer) && feed['activity_epoch'] >= 0 &&
      feed['idle_for'].is_a?(Integer) && feed['idle_for'] >= 0
    neighbors = @neighbor_source.call
    return nil unless neighbors.is_a?(Array)
    pairs = feed['identities'].map do |pair|
      next unless pair.is_a?(Array) && pair.length == 2 && pair[0].is_a?(String)
      ip, port = pair[0].downcase, pair[1]
      next unless neighbors.include?(ip) && port.is_a?(Integer) && port.between?(1, 65535)
      [ip, port.to_s]
    end.compact.uniq
    { identities: pairs, region_error: feed['region_error'] == true,
      tasks_idle: feed['tasks_idle'], idle_for: feed['idle_for'],
      reporter_id: feed['reporter_id'], activity_epoch: feed['activity_epoch'] }
  rescue StandardError
    nil
  end
end

class AntigravityConnectionGuard
  TARGET = AntigravityRouterAPI::TARGET
  TARGETS = [TARGET, ENV.fetch('ACP_GUARD_FALLBACK', 'example-fallback')].freeze
  # The control connection is known to carry periodic project polling. Give
  # inference and relay connections a much longer quiet period.
  IDLE_SECONDS = {
    'aicode.googleapis.com' => 45,
    'daily-cloudcode-pa.googleapis.com' => 180,
    'cloudcode-pa.googleapis.com' => 180,
    'generativelanguage.googleapis.com' => 180,
    'jetski-webchannel.googleapis.com' => 180
  }.freeze
  SELECTOR_STABLE_SECONDS = 30
  ALL_CONNECTIONS_QUIET_SECONDS = 20
  ALL_TASKS_IDLE_SECONDS = 30
  ERROR_CONTROL_IDLE_SECONDS = 25
  CLOSE_COOLDOWN_SECONDS = 90
  UUID = /\A[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z/

  def initialize(api, identity_source, clock = nil)
    @api = api
    @identity_source = identity_source
    @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
    reset
    @last_close = nil
  end

  def reset
    @selected = nil
    @selected_since = nil
    @last_activity = nil
    @samples = {}
    @task_signature = nil
  end

  def relevant(connections, identities)
    return nil unless connections.is_a?(Array) && identities.is_a?(Array)
    connections.map do |c|
      next unless c.is_a?(Hash) && c['metadata'].is_a?(Hash)
      m = c['metadata']
      host = m['host'].to_s.downcase.sub(/\.$/, '')
      pair = [m['sourceIP'].to_s.downcase, m['sourcePort'].to_s]
      id = c['id'].to_s
      next unless IDLE_SECONDS.key?(host) && m['network'].to_s.downcase == 'tcp' &&
        identities.include?(pair) && id.match?(UUID) && c['chains'].is_a?(Array) &&
        c['upload'].is_a?(Integer) && c['upload'] >= 0 &&
        c['download'].is_a?(Integer) && c['download'] >= 0
      { id: id, host: host, pair: pair, chains: c['chains'],
        upload: c['upload'], download: c['download'] }
    end.compact
  end

  def signature(flow)
    [flow[:host], flow[:pair], flow[:chains], flow[:upload], flow[:download]]
  end

  def tick
    now = @clock.call
    identity_data = @identity_source.call
    unless identity_data.is_a?(Hash) && identity_data[:tasks_idle] == true &&
           identity_data[:idle_for].is_a?(Integer) && identity_data[:idle_for] >= ALL_TASKS_IDLE_SECONDS &&
           identity_data[:reporter_id].is_a?(String) && identity_data[:activity_epoch].is_a?(Integer)
      reset
      return :busy
    end
    task_signature = [identity_data[:reporter_id], identity_data[:activity_epoch]]
    if task_signature != @task_signature
      reset
      @task_signature = task_signature
    end
    identities = identity_data[:identities]
    region_error = identity_data[:region_error] == true
    leaf = @api.current_leaf
    flows = relevant(@api.connections, identities)
    unless leaf.is_a?(String) && !leaf.empty? && flows
      reset
      return :unavailable
    end
    if leaf != @selected
      @selected = leaf
      @selected_since = @last_activity = now
      @samples = {}
    end
    old_ids = @samples.keys
    current_ids = flows.map { |flow| flow[:id] }
    @last_activity = now if old_ids.sort != current_ids.sort
    @samples.delete_if { |id, _| !current_ids.include?(id) }
    flows.each do |flow|
      previous = @samples[flow[:id]]
      if previous.nil? || previous[:signature] != signature(flow)
        @samples[flow[:id]] = { signature: signature(flow), quiet_since: now }
        @last_activity = now
      end
    end
    return :observing if now - @selected_since < SELECTOR_STABLE_SECONDS ||
      now - @last_activity < ALL_CONNECTIONS_QUIET_SECONDS ||
      (@last_close && now - @last_close < CLOSE_COOLDOWN_SECONDS)

    candidates = flows.select do |flow|
      idle = IDLE_SECONDS.fetch(flow[:host])
      # Explicit, recent location errors can accelerate only the observed
      # control endpoint; model/relay streams always keep the longer window.
      idle = ERROR_CONTROL_IDLE_SECONDS if region_error && flow[:host] == 'aicode.googleapis.com'
      TARGETS.any? { |target| flow[:chains].include?(target) } && !flow[:chains].empty? &&
        flow[:chains].first != leaf &&
        now - @samples[flow[:id]][:quiet_since] >= idle
    end
    candidate = candidates.min_by { |flow| @samples[flow[:id]][:quiet_since] }
    return :observing unless candidate

    # Re-read every gate immediately before the single-connection DELETE.
    next_identity_data = @identity_source.call
    return :changed unless next_identity_data.is_a?(Hash) && next_identity_data[:tasks_idle] == true &&
      next_identity_data[:idle_for].is_a?(Integer) && next_identity_data[:idle_for] >= ALL_TASKS_IDLE_SECONDS &&
      [next_identity_data[:reporter_id], next_identity_data[:activity_epoch]] == task_signature
    next_identities = next_identity_data[:identities]
    if region_error && candidate[:host] == 'aicode.googleapis.com' &&
       now - @samples[candidate[:id]][:quiet_since] < IDLE_SECONDS.fetch(candidate[:host])
      return :changed unless next_identity_data.is_a?(Hash) && next_identity_data[:region_error] == true
    end
    return :changed unless @api.current_leaf == leaf
    next_flows = relevant(@api.connections, next_identities)
    return :changed unless next_flows
    before = flows.map { |f| [f[:id], signature(f)] }.sort_by(&:first)
    after = next_flows.map { |f| [f[:id], signature(f)] }.sort_by(&:first)
    return :changed unless before == after
    @last_close = now
    if @api.close(candidate[:id])
      quiet = (now - @samples[candidate[:id]][:quiet_since]).to_i
      @samples.delete(candidate[:id])
      puts "ANTIGRAVITY_GUARD refreshed host=#{candidate[:host]} quiet_seconds=#{quiet}"
      STDOUT.flush
      :closed
    else
      :close_failed
    end
  rescue StandardError => e
    warn "ANTIGRAVITY_GUARD retry #{e.class}"
    reset
    :unavailable
  end
end

if $PROGRAM_NAME == __FILE__
  lock = File.open('/var/lock/antigravity-connection-guard-v2.lock', File::RDWR | File::CREAT, 0600)
  exit 0 unless lock.flock(File::LOCK_EX | File::LOCK_NB)
  api = AntigravityRouterAPI.new
  guard = AntigravityConnectionGuard.new(api, AntigravityIdentities.new)
  puts 'ANTIGRAVITY_GUARD started'
  STDOUT.flush
  loop do
    guard.tick
    sleep 10
  end
end
