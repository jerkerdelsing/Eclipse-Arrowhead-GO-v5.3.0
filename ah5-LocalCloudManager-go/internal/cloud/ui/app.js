'use strict';

// Operator session (H1): every /api call needs a console login. A 401 opens the login dialog; after a successful
// login the page reloads with the session cookie (HttpOnly, SameSite=Strict).
const nativeFetch = window.fetch.bind(window);
window.fetch = async (input, init) => {
  const response = await nativeFetch(input, init);
  if (response.status === 401 && String(input).startsWith('/api/') && String(input) !== '/api/session') showLogin();
  return response;
};

function showLogin(message = '') {
  const overlay = document.getElementById('loginOverlay');
  const error = document.getElementById('loginError');
  if (!overlay) return;
  error.textContent = message;
  error.hidden = !message;
  if (overlay.hidden) {
    overlay.hidden = false;
    document.getElementById('loginPassword').focus();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('loginForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = document.getElementById('loginPassword').value;
    const response = await nativeFetch('/api/session', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }) });
    if (response.status === 204) return window.location.reload();
    const body = await response.json().catch(() => ({}));
    showLogin(body.error || `Login failed (${response.status})`);
  });
  document.getElementById('logoutButton')?.addEventListener('click', async () => {
    await nativeFetch('/api/session', { method: 'DELETE' });
    window.location.reload();
  });
});

const state = { data: null, dataManager: null, sysMonitor: null, selectedSmSystem: '', loadingSm: false, orchestration: null, activeView: 'orchestration', filter: '', registryFilter: '', selectedSeries: '', refreshTimer: null, refreshing: false, loadingData: false, loadingOrchestration: false };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
}

// Arrowhead system categories, matching the local Papyrus/SysML palette.
// Health is displayed independently through the existing state labels and dots.
function arrowheadCategory(system) {
  const name = typeof system === 'string' ? system : system?.name || system?.displayName || system?.service || system?.composeService || '';
  const key = String(name).split('.')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
  if (key === 'serviceregistry') return 'registry';
  if (['authentication', 'consumerauthorization', 'authorization'].includes(key)) return 'security';
  if (['dynamicserviceorchestration', 'simpleserviceorchestration', 'simplestoreserviceorchestration', 'serviceorchestrationdynamic', 'serviceorchestrationsimple', 'serviceorchestration'].includes(key)) return 'orchestration';
  if (['aigym', 'blacklist', 'certificateauthority', 'choreographer', 'configuration', 'datamanager', 'deviceqosevaluator', 'eventhandler', 'gatekeeper', 'gatetunnel', 'graphdbmanager', 'localcloudmanager', 'chipletlocalcloudmanager', 'onboarding', 'plantdescriptionengine', 'sysmonitor', 'timemanager', 'translationmanager'].includes(key)) return 'support';
  if (/^(mqtt|amqp|rabbitmq|mosquitto|dockerproxy|managerdockerproxy|cloudmonitorui|db$|database$)/.test(key) || /(?:database|db)$/.test(key)) return 'infrastructure';
  const declared = typeof system === 'object' ? String(system?.metadata?.arrowheadCategory || system?.metadata?.systemType || system?.category || '').toLowerCase() : '';
  if (['core', 'support', 'application', 'infrastructure'].includes(declared)) return declared;
  return 'application';
}
function arrowheadLabel(system) {
  return { registry: 'Core · registry', security: 'Core · security', orchestration: 'Core · orchestration', core: 'Core', support: 'Support', application: 'Application', infrastructure: 'Infrastructure' }[arrowheadCategory(system)];
}
function arrowheadClass(system) { return `ah-${arrowheadCategory(system)}`; }
function arrowheadBadge(system) { return `<span class="ah-category-badge ${arrowheadClass(system)}">${arrowheadLabel(system)}</span>`; }
// End Arrowhead system categories.

function shortName(name) {
  return String(name || '?').replace(/[^A-Z]/g, '').slice(0, 3) || String(name || '?').slice(0, 2).toUpperCase();
}

function formatTime(iso) {
  if (!iso) return '—';
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(iso));
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 3800);
}

function setView(view) {
  state.activeView = view;
  $$('.rail-button').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
  $$('.view').forEach((section) => {
    const active = section.id === `view-${view}`;
    section.hidden = !active;
    section.classList.toggle('active', active);
  });
  if (view === 'runtime' && state.data) {
    loadLogs($('#log-service').value);
    requestAnimationFrame(() => renderActivity(state.data.history));
  }
  if (view === 'data') {
    loadDataManager();
    requestAnimationFrame(() => {
      const series = state.dataManager?.series.find((item) => item.name === state.selectedSeries);
      if (series) renderDataChart(series);
    });
  }
  if (view === 'orchestration') loadOrchestration();
  if (view === 'sysmonitor') loadSysMonitor();
  if (view === 'intercloud') loadInterCloud();
  if (view === 'consumers') loadConsumers();
  if (view === 'plant') loadPlantDescriptions();
}

function serviceEndpoint(service) {
  const intf = service.interfaces?.[0];
  if (!intf) return '—';
  const props = intf.properties || {};
  const address = props.accessAddresses?.[0] || 'unknown';
  return `${intf.protocol || 'http'}://${address}:${props.accessPort || '—'}${props.basePath || ''}`;
}

function addressLabel(address) {
  if (typeof address === 'string') return address;
  return address?.address || address?.host || address?.value || '—';
}

function registryBadge(label, active, kind) {
  return `<span class="registry-badge ${active ? kind : 'inactive'}"><i></i>${escapeHtml(label)}</span>`;
}

function registrySystemCard(system) {
  const services = system.services || [];
  return `<article class="registry-system ${arrowheadClass(system)}">
    <div class="registry-node-head">
      <div><span class="registry-kind">${arrowheadLabel(system)}</span><strong>${escapeHtml(system.name)}</strong></div>
      <div class="registry-badges">${registryBadge('Registered', true, 'registered')}${registryBadge(system.deployed ? 'Deployed' : 'Not deployed', system.deployed, 'deployed')}</div>
    </div>
    <div class="registry-system-meta"><span>v${escapeHtml(system.version || '—')}</span><span>${escapeHtml(addressLabel(system.addresses?.[0]))}</span><span>${services.length} service${services.length === 1 ? '' : 's'}</span></div>
    <div class="registry-services">${services.map((service) => `<div class="registry-service">
      <span class="registry-service-line"><i></i><strong>${escapeHtml(service.serviceDefinition?.name || 'Unknown')}</strong></span>
      <code>${escapeHtml(service.instanceId)}</code>
      <span>${escapeHtml(service.interfaces?.[0]?.protocol || '—')} · ${escapeHtml(service.interfaces?.[0]?.policy || '—')}</span>
      ${registryBadge(service.deployed ? 'Deployed' : 'Provider offline', service.deployed, 'deployed')}
    </div>`).join('') || '<p class="registry-empty">No registered service instances.</p>'}</div>
  </article>`;
}

function renderRegistry(registry) {
  const summary = registry?.summary || {};
  $('#registry-device-count').textContent = summary.registeredDevices ?? 0;
  $('#registry-device-deployed').textContent = `${summary.deployedDevices ?? 0} deployed`;
  $('#registry-system-count').textContent = summary.registeredSystems ?? 0;
  $('#registry-system-deployed').textContent = `${summary.deployedSystems ?? 0} deployed`;
  $('#registry-service-count').textContent = summary.registeredServices ?? 0;
  $('#registry-service-deployed').textContent = `${summary.deployedServices ?? 0} deployed`;
  $('#registry-runtime-count').textContent = summary.runtimeOnly ?? 0;

  const query = state.registryFilter.trim().toLowerCase();
  const groups = (registry?.devices || []).map((device) => ({
    ...device,
    systems: (device.systems || []).filter((system) => {
      const haystack = [device.name, system.name, ...(system.services || []).flatMap((service) => [service.serviceDefinition?.name, service.instanceId])].join(' ').toLowerCase();
      return !query || haystack.includes(query);
    })
  })).filter((device) => device.systems.length || (!query && device.registered) || device.name.toLowerCase().includes(query));

  $('#registry-map').innerHTML = groups.map((device) => `<section class="registry-device">
    <div class="registry-device-head">
      <div class="registry-device-title"><span class="registry-device-icon">DV</span><div><span class="registry-kind">Device</span><h3>${escapeHtml(device.name)}</h3><small>${escapeHtml((device.addresses || []).map(addressLabel).join(', ') || 'No address published')}</small></div></div>
      <div class="registry-device-summary">${registryBadge(device.registered ? 'Registered' : 'Unassigned', device.registered, 'registered')}${registryBadge(device.deployed ? 'Deployed' : 'Not deployed', device.deployed, 'deployed')}<span>${device.systems.length} systems · ${device.serviceCount} services</span></div>
    </div>
    <div class="registry-systems">${device.systems.map(registrySystemCard).join('') || '<p class="registry-empty">This device has no registered systems.</p>'}</div>
  </section>`).join('') || '<div class="registry-map-empty"><strong>No matching registry entries</strong><span>Try a different device, system or service name.</span></div>';

  const runtimeOnly = (registry?.runtimeOnly || []).filter((entry) => !query || `${entry.name} ${entry.composeService}`.toLowerCase().includes(query));
  $('#registry-runtime-only').innerHTML = runtimeOnly.map((entry) => `<div class="registry-runtime-item">
    <div><strong>${escapeHtml(entry.name)}</strong><code>${escapeHtml(entry.composeService)}</code></div>
    ${registryBadge(entry.deployed ? 'Running' : escapeHtml(entry.runtime?.state || 'Stopped'), entry.deployed, 'deployed')}
  </div>`).join('') || '<p class="registry-empty">No deployed runtime systems are missing from ServiceRegistry.</p>';
}

function renderMetrics(data) {
  $('#metric-running').textContent = data.summary.running;
  $('#metric-containers').textContent = `of ${data.summary.containers} containers`;
  $('#metric-systems').textContent = data.summary.registeredSystems;
  $('#metric-services').textContent = data.summary.registeredServices;
  $('#metric-incidents').textContent = data.summary.incidents ?? data.summary.unhealthy;
  $('#metric-incidents').parentElement.title = data.summary.unregisteredServices?.length
    ? `Not registered: ${data.summary.unregisteredServices.join(', ')}`
    : '';
  $('#updated-at').textContent = `Updated ${formatTime(data.collectedAt)}`;
  const connection = $('#connection');
  connection.classList.toggle('online', data.cloud.registryReachable && data.cloud.dockerReachable);
  connection.lastElementChild.textContent = data.cloud.registryReachable ? 'Live telemetry' : 'Degraded';
  $('#registration-state').textContent = data.registration.registered
    ? `Manager registered · ${data.registration.instanceId}`
    : `Manager registration pending${data.registration.error ? ` · ${data.registration.error}` : ''}`;
}

function renderTopology(systems) {
  const preferred = ['DynamicServiceOrchestration', 'ConsumerAuthorization', 'ServiceRegistry', 'Onboarding', 'Gatekeeper', 'GateTunnel', 'LocalCloudManager'];
  const byName = new Map(systems.map((system) => [system.name, system]));
  const selected = preferred.map((name) => byName.get(name)).filter(Boolean);
  $('#topology').innerHTML = selected.map((system) => {
    const running = system.runtime?.state === 'running';
    const registryClass = system.name === 'ServiceRegistry' ? ' registry' : '';
    return `<button class="topology-node${registryClass} ${arrowheadClass(system)}" data-system="${escapeHtml(system.name)}">
      <span class="node-top"><span class="node-name">${escapeHtml(system.name)}</span><i class="node-state ${running ? 'up' : ''}"></i></span>
      <span class="node-role">${arrowheadLabel(system)} · ${system.serviceCount} services · ${escapeHtml(system.version || 'unknown')}</span>
    </button>`;
  }).join('');
}

function renderMessaging(data) {
  const infrastructure = data.infrastructure || [];
  $('#mqtt-infrastructure').innerHTML = infrastructure.map((item) => {
    const running = item.runtime?.state === 'running';
    return `<article class="infrastructure-card ah-infrastructure">
      <div class="infra-icon">${item.id === 'amqp-broker' ? 'AM' : 'MQ'}</div>
      <div class="infra-copy">
        <span class="node-top"><strong>${escapeHtml(item.name)}</strong><i class="node-state ${running ? 'up' : ''}"></i></span>
        <span>${escapeHtml(item.kind)}</span>
        <code>${escapeHtml(item.endpoint)}</code>
        <small>${escapeHtml(item.protocol)} · ${escapeHtml(item.security)}</small>
      </div>
      <div class="infra-actions">
        <button class="text-button" data-log="${escapeHtml(item.runtime?.service || '')}">Logs</button>
        <button class="action" data-action="restart" data-service="${escapeHtml(item.runtime?.service || '')}" ${item.runtime?.managed ? '' : 'disabled'}>Restart</button>
      </div>
    </article>`;
  }).join('') || '<p class="muted">No messaging infrastructure reported.</p>';

  $('#orchestration-flow').innerHTML = (data.orchestrations || []).map((flow) => `<article class="flow-row ${flow.active ? 'active' : ''}">
    <div class="flow-system ${arrowheadClass(flow.source)}">${escapeHtml(flow.source)}</div>
    <div class="flow-link"><span>${escapeHtml(flow.label)}</span><i></i><small>${escapeHtml(flow.protocol)}</small></div>
    <div class="flow-system ${arrowheadClass(flow.target)}">${escapeHtml(flow.target)}</div>
    <span class="flow-state">${flow.active ? 'Active' : 'Inactive'}</span>
  </article>`).join('') || '<p class="muted">No orchestration flows reported.</p>';
}

function renderActivity(history) {
  const svg = $('#activity-chart');
  const width = Math.max(svg.clientWidth || 320, 280);
  const height = Math.max(svg.clientHeight || 210, 180);
  const pad = { x: 36, y: 24 };
  const values = history.length ? history : [{ running: 0, registeredSystems: 0 }];
  const max = Math.max(1, ...values.flatMap((point) => [point.running, point.registeredSystems]));
  const x = (index) => pad.x + (values.length === 1 ? 0 : index / (values.length - 1)) * (width - pad.x * 2);
  const y = (value) => height - pad.y - (value / max) * (height - pad.y * 2);
  const line = (key) => values.map((point, index) => `${index ? 'L' : 'M'}${x(index).toFixed(1)},${y(point[key]).toFixed(1)}`).join(' ');
  const area = `${line('running')} L${x(values.length - 1)},${height - pad.y} L${x(0)},${height - pad.y} Z`;
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  const firstTime = values[0]?.at;
  const lastTime = values.at(-1)?.at;
  svg.innerHTML = `
    <line class="chart-grid" x1="${pad.x}" y1="${y(max)}" x2="${width - pad.x}" y2="${y(max)}"></line>
    <line class="chart-grid" x1="${pad.x}" y1="${y(0)}" x2="${width - pad.x}" y2="${y(0)}"></line>
    <path class="chart-area" d="${area}"></path>
    <path class="chart-running" d="${line('running')}"></path>
    <path class="chart-systems" d="${line('registeredSystems')}"></path>
    <text class="chart-label" x="${pad.x}" y="${y(max) - 7}">${max}</text>
    <text class="chart-label" x="${pad.x}" y="${height - 5}">${firstTime ? formatTime(firstTime) : '5 min ago'}</text>
    <text class="chart-label" x="${width - pad.x}" y="${height - 5}" text-anchor="end">${lastTime ? formatTime(lastTime) : 'now'}</text>`;
}

function measurementValue(entry) {
  const value = entry?.value || {};
  return value.v ?? value.vs ?? value.vb ?? value.vd ?? value.s ?? '—';
}

function renderDataChart(series, selector = '#data-chart') {
  const svg = $(selector);
  const width = Math.max(svg.clientWidth || 760, 320);
  const height = Math.max(svg.clientHeight || 310, 220);
  const pad = { left: 48, right: 20, top: 18, bottom: 30 };
  const points = series?.points || [];
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  if (!points.length) {
    svg.innerHTML = `<text class="chart-empty" x="${width / 2}" y="${height / 2}" text-anchor="middle">No numeric measurements</text>`;
    return;
  }
  const values = points.map((point) => point.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const x = (index) => pad.left + (points.length === 1 ? 0 : index / (points.length - 1)) * (width - pad.left - pad.right);
  const y = (value) => pad.top + ((max - value) / range) * (height - pad.top - pad.bottom);
  const line = points.map((point, index) => `${index ? 'L' : 'M'}${x(index).toFixed(1)},${y(point.value).toFixed(1)}`).join(' ');
  const dots = points.slice(-80).map((point, offset) => {
    const index = points.length - Math.min(points.length, 80) + offset;
    return `<circle class="data-dot" cx="${x(index)}" cy="${y(point.value)}" r="2.4"><title>${escapeHtml(point.value)} at ${escapeHtml(formatTime(point.time * 1000))}</title></circle>`;
  }).join('');
  svg.innerHTML = `
    <line class="chart-grid" x1="${pad.left}" y1="${y(max)}" x2="${width - pad.right}" y2="${y(max)}"></line>
    <line class="chart-grid" x1="${pad.left}" y1="${y(min)}" x2="${width - pad.right}" y2="${y(min)}"></line>
    <path class="data-line" d="${line}"></path>${dots}
    <text class="chart-label" x="8" y="${y(max) + 4}">${max.toFixed(1)}</text>
    <text class="chart-label" x="8" y="${y(min) + 4}">${min.toFixed(1)}</text>
    <text class="chart-label" x="${pad.left}" y="${height - 5}">${formatTime(points[0].time * 1000)}</text>
    <text class="chart-label" x="${width - pad.right}" y="${height - 5}" text-anchor="end">${formatTime(points.at(-1).time * 1000)}</text>`;
}

function renderDataManager(payload) {
  state.dataManager = payload;
  const select = $('#data-series');
  const names = payload.series.map((series) => series.name);
  if (!names.includes(state.selectedSeries)) state.selectedSeries = names[0] || '';
  select.innerHTML = payload.series.map((series) => `<option value="${escapeHtml(series.name)}">${escapeHtml(series.label || series.name)}</option>`).join('') || '<option value="">No numeric streams</option>';
  select.value = state.selectedSeries;
  const series = payload.series.find((item) => item.name === state.selectedSeries);
  const latest = series?.points.at(-1);
  $('#data-count').textContent = payload.count;
  $('#data-latest').textContent = latest?.value ?? '—';
  $('#data-unit').textContent = latest?.unit || 'unitless';
  $('#data-last-time').textContent = latest ? formatTime(latest.time * 1000) : '—';
  $('#data-chart-title').textContent = series ? (series.label || series.name) : 'No numeric streams';
  $('#data-updated').textContent = `Updated ${formatTime(payload.collectedAt)}`;
  $('#data-table').innerHTML = payload.entries.slice(0, 100).map((entry) => `<tr>
    <td>${escapeHtml(formatTime(entry.time * 1000))}</td><td><code>${escapeHtml(entry.name)}</code></td>
    <td>${escapeHtml(measurementValue(entry))}</td><td>${escapeHtml(entry.unit || '—')}</td>
  </tr>`).join('') || '<tr><td colspan="4" class="muted">DataManager contains no records.</td></tr>';
  renderDataChart(series);
}

const LIVENESS = { alive: 1, degraded: 0.5, failed: 0 };

function observationSummary(observation) {
  const value = observation?.value;
  if (!value || typeof value !== 'object') return value ?? '—';
  const keys = { echo: ['status', 'detail'], power: ['supplyType', 'state'], status: ['state', 'health'] }[observation.observationType];
  const picked = (keys || Object.keys(value)).map((key) => value[key]).filter((item) => item !== undefined && item !== null);
  return picked.length ? picked.join(' · ') : JSON.stringify(value);
}

function renderSysMonitor(payload) {
  state.sysMonitor = payload;
  state.selectedSmSystem = payload.selectedSystem;
  const select = $('#sm-system');
  select.innerHTML = payload.systems.map((item) => `<option value="${escapeHtml(item.systemName)}">${escapeHtml(item.systemName)}</option>`).join('') || '<option value="">No monitored systems</option>';
  select.value = payload.selectedSystem;
  const selected = payload.systems.find((item) => item.systemName === payload.selectedSystem);
  $('#sm-systems').textContent = payload.systems.length;
  $('#sm-stored').textContent = payload.storedObservations.toLocaleString();
  $('#sm-retention').textContent = payload.retentionDays ? `retention ${payload.retentionDays} days` : 'retention';
  $('#sm-echo').textContent = selected?.latest?.echo?.value?.status || '—';
  $('#sm-last-time').textContent = selected?.lastObservationTime ? `latest ${formatTime(selected.lastObservationTime)}` : 'latest echo';
  $('#sm-updated').textContent = `Updated ${formatTime(payload.collectedAt)}`;
  $('#sm-system-table').innerHTML = payload.systems.map((item) => `<tr data-sm-system="${escapeHtml(item.systemName)}" class="${item.systemName === payload.selectedSystem ? 'selected' : ''}">
    <td><strong>${escapeHtml(item.systemName)}</strong></td>
    <td>${escapeHtml(observationSummary(item.latest?.echo))}</td><td>${escapeHtml(observationSummary(item.latest?.power))}</td>
    <td>${escapeHtml(observationSummary(item.latest?.status))}</td>
    <td>${escapeHtml(item.lastObservationTime ? formatTime(item.lastObservationTime) : '—')}</td><td>${escapeHtml(item.observationCount)}</td>
  </tr>`).join('') || '<tr><td colspan="6" class="muted">SysMonitor has stored no observations yet.</td></tr>';
  $('#sm-chart-title').textContent = payload.selectedSystem ? `Liveness · ${payload.selectedSystem}` : 'Liveness';
  $('#sm-table').innerHTML = payload.observations.slice(0, 100).map((item) => `<tr>
    <td>${escapeHtml(formatTime(item.sourceTime))}</td><td><code>${escapeHtml(item.observationType)}</code></td>
    <td>${escapeHtml(observationSummary(item))}</td><td>${escapeHtml(item.quality || '—')}</td>
  </tr>`).join('') || '<tr><td colspan="4" class="muted">No observations stored for this system.</td></tr>';
  renderSysMonitorChart();
}

function renderSysMonitorChart() {
  const points = (state.sysMonitor?.observations || [])
    .filter((item) => item.observationType === 'echo' && item.value?.status in LIVENESS)
    .map((item) => ({ time: Date.parse(item.sourceTime) / 1000, value: LIVENESS[item.value.status], unit: '1' }))
    .reverse();
  renderDataChart({ name: 'liveness', points }, '#sm-chart');
}

function renderSysMonitorSubscriptions(payload) {
  state.smSubscriptions = payload;
  const intake = payload.intake || {};
  $('#sms-updated').textContent = `Updated ${formatTime(payload.collectedAt)} · intake ${intake.connected ? 'connected' : 'not connected'}`;
  $('#sms-note').textContent = `SysMonitor receives only the observation types selected here (AMQP queue ${intake.queue || '—'}, ${(intake.bindings || []).length} bindings). Producers without a subscription follow the default: ${payload.defaultSubscription === 'all' ? 'all observation types' : 'nothing'}.`;
  $('#sms-table').innerHTML = payload.providers.map((item) => {
    const all = item.subscription?.enabled && item.subscription.observationTypes[0] === '*';
    const chosen = new Set(item.subscribedTypes);
    const boxes = item.observationTypes.map((type) => `<label class="check"><input type="checkbox" data-sms-type="${escapeHtml(type)}" ${chosen.has(type) ? 'checked' : ''}> ${escapeHtml(type)}</label>`).join(' ');
    return `<tr data-sms-provider="${escapeHtml(item.providerSystem)}">
      <td><strong>${escapeHtml(item.providerSystem)}</strong><br><small class="muted"><code>${escapeHtml(item.baseRoutingKey)}</code></small></td>
      <td class="sms-types">${boxes} <label class="check"><input type="checkbox" data-sms-all ${all ? 'checked' : ''}> all, also future types</label></td>
      <td>${item.subscribedTypes.length ? escapeHtml(item.subscribedTypes.join(', ')) : '<span class="muted">nothing</span>'}<br><small class="muted">${escapeHtml(item.selection)}</small></td>
      <td class="actions"><button class="button small" data-sms-action="save">Subscribe</button>
        <button class="button small secondary" data-sms-action="off">Off</button>
        ${item.subscription ? '<button class="button small secondary" data-sms-action="default">Default</button>' : ''}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="4" class="muted">SysMonitor has found no authorized sysMonitor producers yet.</td></tr>';
  const orphans = payload.subscriptions.filter((item) => !item.providerFound);
  if (orphans.length) {
    $('#sms-table').insertAdjacentHTML('beforeend', orphans.map((item) => `<tr data-sms-provider="${escapeHtml(item.providerSystem)}">
      <td><strong>${escapeHtml(item.providerSystem)}</strong><br><small class="muted">not found by orchestration</small></td>
      <td>${escapeHtml(item.observationTypes.join(', '))}</td><td><span class="muted">nothing</span><br><small class="muted">subscription (kept)</small></td>
      <td class="actions"><button class="button small secondary" data-sms-action="default">Remove</button></td></tr>`).join(''));
  }
}

async function loadSysMonitorSubscriptions(silent = false) {
  try {
    const response = await fetch('/api/sysmonitor/subscriptions', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Subscription request failed (${response.status})`);
    renderSysMonitorSubscriptions(payload);
  } catch (error) {
    $('#sms-updated').textContent = error.message;
    if (!silent) showToast(error.message);
  }
}

async function changeSysMonitorSubscription(row, action) {
  const provider = row.dataset.smsProvider;
  const types = [...row.querySelectorAll('[data-sms-type]:checked')].map((box) => box.dataset.smsType);
  const all = row.querySelector('[data-sms-all]')?.checked;
  const request = action === 'default'
    ? { method: 'DELETE', headers: { 'X-Arrowhead-Action': 'confirm' } }
    : { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Arrowhead-Action': 'confirm' },
        body: JSON.stringify(action === 'off' ? { observationTypes: ['*'], enabled: false }
          : { observationTypes: all ? ['*'] : types, enabled: true }) };
  if (action === 'save' && !all && !types.length) return showToast('Select at least one observation type, or use Off.');
  try {
    const response = await fetch(`/api/sysmonitor/subscriptions/${encodeURIComponent(provider)}`, request);
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Subscription change failed (${response.status})`);
    showToast(action === 'default' ? `${provider}: back to the default subscription` : action === 'off' ? `${provider}: unsubscribed` : `${provider}: subscribed`);
  } catch (error) {
    showToast(error.message);
  }
  loadSysMonitorSubscriptions(true);
}

async function loadSysMonitor(silent = false) {
  if (state.loadingSm) return;
  state.loadingSm = true;
  if (!silent) $('#sm-updated').textContent = 'Loading…';
  try {
    const query = new URLSearchParams({ limit: '240', system: state.selectedSmSystem || '' });
    const response = await fetch(`/api/sysmonitor?${query}`, { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `SysMonitor request failed (${response.status})`);
    renderSysMonitor(payload);
    loadSysMonitorSubscriptions(silent);
  } catch (error) {
    $('#sm-updated').textContent = error.message;
    if (!silent) showToast(error.message);
  } finally {
    state.loadingSm = false;
  }
}

function renderInterCloud(payload) {
  const relays = payload.relay || {};
  const up = ['gatekeeper', 'gatetunnel'].filter((key) => relays[key]?.connected).length;
  $('#ic-cloud').textContent = payload.localCloud || '—';
  $('#ic-neighbours').textContent = payload.neighbourClouds?.length ? `neighbours ${payload.neighbourClouds.join(', ')}` : (payload.neighbourError || 'no neighbour clouds');
  $('#ic-relay').textContent = `${up} / 2 connected`;
  $('#ic-relay-detail').textContent = up === 2 ? 'Gatekeeper · GateTunnel' : 'check the relay (make -C ../Arrowhead-relay up)';
  const s = payload.sessions;
  $('#ic-sessions').textContent = s ? `${s.consumerSessions} · ${s.providerSessions}` : '—';
  $('#ic-updated').textContent = `Updated ${formatTime(payload.collectedAt)}`;
  const p = payload.producer || {};
  const rows = [
    ['Status', p.status || '—'], ['Provider', p.provider && p.providerCloud ? `${p.provider} in ${p.providerCloud}` : '—'],
    ['Endpoint (local GateTunnel)', p.endpoint || '—'], ['Published', p.publishedCount ?? '—'],
    ['Last value', p.lastValue ?? '—'], ['Last published', p.lastPublishedAt ? formatTime(p.lastPublishedAt * 1000) : '—'],
    ['Last error', p.lastError || '—']
  ];
  $('#ic-producer').innerHTML = rows.map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(String(value))}</td></tr>`).join('');
  $('#ic-relay-table').innerHTML = [['Gatekeeper', relays.gatekeeper], ['GateTunnel', relays.gatetunnel]].map(([name, r]) => `<tr>
    <td><strong>${name}</strong></td><td>${r?.connected ? 'yes' : 'no'}</td>
    <td>${escapeHtml(r?.broker || r?.error || '—')}</td><td><code>${escapeHtml(r?.inbox || '—')}</code></td></tr>`).join('');
}

async function loadInterCloud(silent = false) {
  if (state.loadingIc) return;
  state.loadingIc = true;
  if (!silent) $('#ic-updated').textContent = 'Loading…';
  try {
    const response = await fetch('/api/intercloud', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Inter-cloud request failed (${response.status})`);
    renderInterCloud(payload);
  } catch (error) {
    $('#ic-updated').textContent = error.message;
    if (!silent) showToast(error.message);
  } finally {
    state.loadingIc = false;
  }
}

async function loadDataManager(silent = false) {
  if (state.loadingData) return;
  state.loadingData = true;
  if (!silent) $('#data-updated').textContent = 'Loading…';
  try {
    const response = await fetch('/api/datamanager?limit=240', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `DataManager request failed (${response.status})`);
    renderDataManager(payload);
  } catch (error) {
    $('#data-updated').textContent = error.message;
    if (!silent) showToast(error.message);
  } finally {
    state.loadingData = false;
  }
}

function selectedProducer() {
  return state.orchestration?.catalog?.producers.find((producer) => producer.instanceId === $('#rule-producer').value);
}

function updateRuleConsumers() {
  const producer = selectedProducer();
  const consumerSelect = $('#rule-consumer');
  const previous = consumerSelect.value;
  const consumers = producer?.compatibleConsumers || [];
  const systemsByName = new Map((state.orchestration?.catalog?.consumers || []).map((consumer) => [consumer.name, consumer]));
  consumerSelect.innerHTML = consumers.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)} · ${escapeHtml(systemsByName.get(name)?.version || 'unknown')}</option>`).join('') || '<option value="">No compatible consumers</option>';
  if (consumers.includes(previous)) consumerSelect.value = previous;
  consumerSelect.disabled = !consumers.length;
  $('#create-rule').disabled = !producer || !consumers.length;
  $('#compatible-count').textContent = consumers.length;
  const interfaces = producer?.interfaces || [];
  $('#rule-producer-detail').innerHTML = producer
    ? `<strong>${escapeHtml(producer.serviceDefinition)}</strong> from ${escapeHtml(producer.provider)} · ${interfaces.map((item) => `${escapeHtml(item.templateName)} / ${escapeHtml(item.policy || 'NONE')}`).join(' · ') || 'no interfaces'}`
    : 'No eligible service producers are registered.';
}

function renderDynamicOrchestrations(payload) {
  const groups = payload.dynamic || [];
  $('#dynamic-updated').textContent = payload.dynamicError ? payload.dynamicError : `Updated ${formatTime(payload.collectedAt)}`;
  $('#dynamic-table').innerHTML = groups.map((g) => `<tr>
    <td><strong>${escapeHtml(g.consumer)}</strong></td><td><code>${escapeHtml(g.serviceDefinition)}</code></td>
    <td>${g.providers.length ? g.providers.map((p) => escapeHtml(p.cloud ? `${p.provider} in ${p.cloud}` : p.provider)).join('<br>') : `<span class="muted">${escapeHtml(g.lastMessage || '—')}</span>`}</td>
    <td>${escapeHtml(g.kind || '—')}</td><td>${escapeHtml(g.count)}</td>
    <td>${escapeHtml(g.lastAt ? formatTime(g.lastAt) : '—')}</td><td>${escapeHtml(g.lastStatus || '—')}</td></tr>`).join('')
    || '<tr><td colspan="7" class="muted">No dynamic orchestrations recorded.</td></tr>';
}

function renderConsumers(payload) {
  $('#consumers-updated').textContent = payload.errors?.length ? payload.errors.join('; ') : `Updated ${formatTime(payload.collectedAt)}`;
  $('#consumers-table').innerHTML = (payload.rows || []).map((r) => `<tr>
    <td><strong>${escapeHtml(r.provider)}</strong>${r.providerCloud !== payload.localCloud ? `<br><span class="muted">in ${escapeHtml(r.providerCloud)}</span>` : ''}</td>
    <td><code>${escapeHtml(r.serviceDefinition)}</code></td>
    <td>${r.authorized.map((a) => `${a.consumerCloud !== payload.localCloud ? `<em>from ${escapeHtml(a.consumerCloud)}:</em> ` : ''}${escapeHtml(a.consumers)}${a.scoped.length ? `<br><span class="muted">${escapeHtml(a.scoped.join(' · '))}</span>` : ''}`).join('<br>') || '<span class="muted">no policy</span>'}</td>
    <td>${r.orchestrated.map((o) => `<strong>${escapeHtml(o.consumer)}</strong>${o.consumerCloud && o.consumerCloud !== payload.localCloud ? ` <em>from ${escapeHtml(o.consumerCloud)}</em>` : ''} <span class="muted">via ${escapeHtml(o.via)}${o.count ? ` · ${escapeHtml(o.count)}×, last ${escapeHtml(formatTime(o.lastAt))}` : ''}</span>`).join('<br>') || '<span class="muted">—</span>'}</td>
  </tr>`).join('') || '<tr><td colspan="4" class="muted">No provider services found.</td></tr>';
}

async function loadConsumers(silent = false) {
  if (state.loadingConsumers) return;
  state.loadingConsumers = true;
  if (!silent) $('#consumers-updated').textContent = 'Loading…';
  try {
    const response = await fetch('/api/consumers', { cache: 'no-store', signal: AbortSignal.timeout(20000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Consumer request failed (${response.status})`);
    renderConsumers(payload);
  } catch (error) {
    $('#consumers-updated').textContent = error.message;
    if (!silent) showToast(error.message);
  } finally {
    state.loadingConsumers = false;
  }
}

function renderOrchestration(payload) {
  state.orchestration = payload;
  window.LocalCloudGraphEditor?.update(payload);
  renderDynamicOrchestrations(payload);
  const producerSelect = $('#rule-producer');
  const previous = producerSelect.value;
  const producers = payload.catalog?.producers || [];
  producerSelect.innerHTML = producers.map((producer) => `<option value="${escapeHtml(producer.instanceId)}">${escapeHtml(producer.serviceDefinition)} — ${escapeHtml(producer.provider)}</option>`).join('') || '<option value="">No interoperable producers</option>';
  if (producers.some((producer) => producer.instanceId === previous)) producerSelect.value = previous;
  producerSelect.disabled = !producers.length;
  updateRuleConsumers();

  const byInstance = new Map(producers.map((producer) => [producer.instanceId, producer]));
  const consumersByName = new Map((payload.catalog?.consumers || []).map((consumer) => [consumer.name, consumer]));
  const rules = payload.rules || [];
  const activeRules = rules.filter((rule) => byInstance.has(rule.serviceInstanceId) && consumersByName.has(rule.consumer));
  $('#active-rule-count').textContent = `${activeRules.length} active`;
  $('#orchestration-map').innerHTML = rules.map((rule) => {
    const producer = byInstance.get(rule.serviceInstanceId);
    const active = Boolean(producer && consumersByName.has(rule.consumer));
    return `<article class="rule-flow-visual ${active ? 'active' : 'stale'}">
      <div class="rule-node consumer-node ${arrowheadClass(rule.consumer)}"><small>Consumer</small><strong>${escapeHtml(rule.consumer)}</strong></div>
      <div class="rule-route"><span>${escapeHtml(producer?.serviceDefinition || rule.serviceDefinition || 'Unavailable service')}</span><i></i><small>Priority ${escapeHtml(rule.priority)}</small></div>
      <div class="rule-node producer-node ${arrowheadClass(producer?.provider || '')}"><small>Producer</small><strong>${escapeHtml(producer?.provider || 'Not registered')}</strong></div>
      <span class="rule-live"><i></i>${active ? 'Active' : 'Unavailable'}</span>
    </article>`;
  }).join('') || '<div class="rule-map-empty"><strong>No active flows</strong><span>Add a rule to visualize its consumer-to-producer route.</span></div>';
  $('#orchestration-rule-table').innerHTML = rules.map((rule) => {
    const producer = byInstance.get(rule.serviceInstanceId);
    return `<tr>
      <td><strong>${escapeHtml(rule.priority)}</strong></td>
      <td>${escapeHtml(rule.consumer)}</td>
      <td>${escapeHtml(producer?.serviceDefinition || 'Unavailable service')}<br><code>${escapeHtml(rule.serviceInstanceId)}</code></td>
      <td>${escapeHtml(producer?.provider || 'Not registered')}</td>
      <td>${escapeHtml(formatTime(rule.createdAt))}</td>
      <td><button class="rule-remove" data-remove-rule="${escapeHtml(rule.id)}">Remove</button></td>
    </tr>`;
  }).join('') || '<tr><td colspan="6" class="muted">No orchestration rules have been stored.</td></tr>';
  $('#orchestration-updated').textContent = `Updated ${formatTime(payload.collectedAt)}`;
}

async function loadOrchestration(silent = false) {
  if (state.loadingOrchestration) return;
  state.loadingOrchestration = true;
  if (!silent) $('#orchestration-updated').textContent = 'Loading…';
  try {
    const response = await fetch('/api/orchestration/rules', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Orchestration request failed (${response.status})`);
    renderOrchestration(payload);
  } catch (error) {
    $('#orchestration-updated').textContent = error.message;
    if (!silent) showToast(error.message);
  } finally {
    state.loadingOrchestration = false;
  }
}

async function createOrchestrationRule(event) {
  event.preventDefault();
  const producer = selectedProducer();
  if (!producer) return;
  const button = $('#create-rule');
  button.disabled = true;
  try {
    const response = await fetch('/api/orchestration/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Arrowhead-Action': 'confirm' },
      body: JSON.stringify({ serviceInstanceId: producer.instanceId, consumer: $('#rule-consumer').value, priority: Number($('#rule-priority').value) })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Could not create rule (${response.status})`);
    showToast('Orchestration rule added');
    await loadOrchestration(true);
  } catch (error) {
    showToast(error.message);
  } finally {
    updateRuleConsumers();
  }
}

async function removeOrchestrationRule(id) {
  if (!confirm('Remove this orchestration rule?')) return;
  try {
    const response = await fetch(`/api/orchestration/rules/${encodeURIComponent(id)}`, {
      method: 'DELETE', headers: { 'X-Arrowhead-Action': 'confirm' }
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Could not remove rule (${response.status})`);
    showToast('Orchestration rule removed');
    await loadOrchestration(true);
  } catch (error) { showToast(error.message); }
}

function systemRow(system) {
  const running = system.runtime?.state === 'running';
  return `<div class="system-row ${arrowheadClass(system)}">
    <div class="system-identity"><span class="system-glyph">${shortName(system.name)}</span><span class="system-name">${escapeHtml(system.name)}${arrowheadBadge(system)}</span></div>
    <span class="state ${running ? 'running' : ''}">${running ? 'Running' : system.runtime ? escapeHtml(system.runtime.state) : 'Registered'}</span>
    <span class="muted">${system.serviceCount} services</span>
    <span class="muted">v${escapeHtml(system.version || '—')}</span>
  </div>`;
}

function renderSystems(data) {
  $('#overview-systems').innerHTML = data.systems.slice(0, 8).map(systemRow).join('') || '<p class="muted">No registered systems.</p>';
  $('#systems-grid').innerHTML = data.systems.map((system) => {
    const running = system.runtime?.state === 'running';
    const manageable = system.runtime?.managed;
    return `<article class="system-card ${arrowheadClass(system)}">
      <div class="system-card-head"><div><p class="eyebrow">${system.composeService ? `Runtime · ${escapeHtml(system.composeService)}` : 'Registry only'}</p><h3>${escapeHtml(system.name)}</h3>${arrowheadBadge(system)}</div><span class="state ${running ? 'running' : ''}">${running ? 'Running' : system.runtime ? escapeHtml(system.runtime.state) : 'Registered'}</span></div>
      <dl><dt>Version</dt><dd>${escapeHtml(system.version || '—')}</dd><dt>Services</dt><dd>${system.serviceCount}</dd><dt>Address</dt><dd>${escapeHtml(system.addresses?.[0]?.address || '—')}</dd><dt>Health</dt><dd>${escapeHtml(system.runtime?.health || (running ? 'active' : '—'))}</dd></dl>
      <div class="card-actions">
        <button class="action" data-log="${escapeHtml(system.composeService || '')}" ${system.composeService ? '' : 'disabled'}>Logs</button>
        <button class="action" data-action="restart" data-service="${escapeHtml(system.composeService || '')}" ${manageable ? '' : 'disabled'}>Restart</button>
        <button class="action danger" data-action="${running ? 'stop' : 'start'}" data-service="${escapeHtml(system.composeService || '')}" ${manageable ? '' : 'disabled'}>${running ? 'Stop' : 'Start'}</button>
      </div>
    </article>`;
  }).join('') || '<p class="muted">No systems reported by ServiceRegistry.</p>';
}

function renderServices(services) {
  const query = state.filter.toLowerCase();
  const filtered = services.filter((service) => `${service.serviceDefinition?.name} ${service.provider?.name}`.toLowerCase().includes(query));
  $('#service-table').innerHTML = filtered.map((service) => `<tr class="microservice-row">
    <td><strong>${escapeHtml(service.serviceDefinition?.name)}</strong><br><code>${escapeHtml(service.instanceId)}</code></td>
    <td class="provider-cell ${arrowheadClass(service.provider)}">${escapeHtml(service.provider?.name)}${arrowheadBadge(service.provider)}</td>
    <td>${escapeHtml(service.version)}</td>
    <td>${escapeHtml(service.interfaces?.[0]?.protocol || '—')} · ${escapeHtml(service.interfaces?.[0]?.policy || '—')}</td>
    <td><code>${escapeHtml(serviceEndpoint(service))}</code></td>
  </tr>`).join('') || '<tr><td colspan="5" class="muted">No matching service instances.</td></tr>';
}

function renderRuntime(containers) {
  $('#container-list').innerHTML = containers.map((container) => `<div class="container-item ${arrowheadClass(container)}"><strong>${escapeHtml(container.displayName || container.service)}</strong><span class="state ${container.state === 'running' ? 'running' : ''}">${escapeHtml(container.state)}</span><span class="container-image"><code>${escapeHtml(container.service)}</code> · ${escapeHtml(container.image)}</span><span class="muted">${escapeHtml(container.health || '')}</span></div>`).join('');
  const select = $('#log-service');
  const previous = select.value;
  select.innerHTML = containers.map((container) => `<option value="${escapeHtml(container.service)}">${escapeHtml(container.displayName || container.service)} · ${escapeHtml(container.service)}</option>`).join('');
  if (containers.some((container) => container.service === previous)) select.value = previous;
}

function render(data) {
  state.data = data;
  renderMetrics(data);
  renderTopology(data.systems);
  renderMessaging(data);
  renderActivity(data.history);
  renderSystems(data);
  renderServices(data.services);
  renderRegistry(data.registryManagement);
  renderRuntime(data.containers);
  const errors = Object.values(data.errors || {}).filter(Boolean);
  if (data.summary.unregisteredServices?.length) {
    errors.push(`Running but not registered: ${data.summary.unregisteredServices.join(', ')}`);
  }
  const banner = $('#error-banner');
  banner.hidden = !errors.length;
  banner.textContent = errors.join(' · ');
}

async function refresh(silent = false) {
  if (state.refreshing) return;
  state.refreshing = true;
  const button = $('#refresh-button');
  button.disabled = true;
  try {
    const response = await fetch('/api/overview', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error(`Telemetry request failed (${response.status})`);
    render(await response.json());
    if (state.activeView === 'data') loadDataManager(true);
    if (state.activeView === 'sysmonitor') loadSysMonitor(true);
    if (state.activeView === 'intercloud') loadInterCloud(true);
    if (state.activeView === 'consumers') loadConsumers(true);
    if (state.activeView === 'orchestration') loadOrchestration(true);
    if (!silent) showToast('Telemetry refreshed');
  } catch (error) {
    $('#connection').classList.remove('online');
    $('#connection').lastElementChild.textContent = 'Disconnected';
    const banner = $('#error-banner');
    banner.hidden = false;
    banner.textContent = error.message;
  } finally {
    button.disabled = false;
    state.refreshing = false;
  }
}

async function loadLogs(service) {
  if (!service) return;
  $('#log-title').textContent = service;
  $('#logs').textContent = 'Loading logs…';
  try {
    const response = await fetch(`/api/logs?service=${encodeURIComponent(service)}&tail=180`, { cache: 'no-store' });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Could not load logs');
    $('#logs').textContent = payload.lines.join('\n') || 'No log output.';
    $('#logs').scrollTop = $('#logs').scrollHeight;
  } catch (error) {
    $('#logs').textContent = error.message;
  }
}

async function lifecycle(service, action) {
  if (!confirm(`${action[0].toUpperCase() + action.slice(1)} ${service}?`)) return;
  try {
    const response = await fetch(`/api/containers/${encodeURIComponent(service)}/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Arrowhead-Action': 'confirm' },
      body: '{}'
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Action failed (${response.status})`);
    showToast(`${service}: ${action} accepted`);
    setTimeout(() => refresh(true), 1800);
  } catch (error) { showToast(error.message); }
}

document.addEventListener('click', (event) => {
  const nav = event.target.closest('[data-view]');
  if (nav) setView(nav.dataset.view);
  const go = event.target.closest('[data-go]');
  if (go) setView(go.dataset.go);
  const node = event.target.closest('[data-system]');
  if (node) { setView('systems'); document.querySelector(`[data-log]`)?.focus(); }
  const action = event.target.closest('[data-action]');
  if (action) lifecycle(action.dataset.service, action.dataset.action);
  const log = event.target.closest('[data-log]');
  if (log?.dataset.log) {
    setView('runtime');
    $('#log-service').value = log.dataset.log;
    loadLogs(log.dataset.log);
  }
  const removeRule = event.target.closest('[data-remove-rule]');
  if (removeRule) removeOrchestrationRule(removeRule.dataset.removeRule);
});

$('#refresh-button').addEventListener('click', () => refresh());
$('#service-filter').addEventListener('input', (event) => { state.filter = event.target.value; if (state.data) renderServices(state.data.services); });
$('#registry-filter').addEventListener('input', (event) => { state.registryFilter = event.target.value; if (state.data) renderRegistry(state.data.registryManagement); });
$('#log-service').addEventListener('change', (event) => loadLogs(event.target.value));
$('#reload-logs').addEventListener('click', () => loadLogs($('#log-service').value));
$('#reload-data').addEventListener('click', () => loadDataManager());
$('#reload-sm').addEventListener('click', () => loadSysMonitor());
$('#sms-table').addEventListener('click', (event) => {
  const button = event.target.closest('[data-sms-action]');
  if (button) changeSysMonitorSubscription(button.closest('tr'), button.dataset.smsAction);
});
$('#reload-ic').addEventListener('click', () => loadInterCloud());
$('#reload-consumers').addEventListener('click', () => loadConsumers());
$('#sm-system').addEventListener('change', (event) => { state.selectedSmSystem = event.target.value; loadSysMonitor(); });
$('#sm-system-table').addEventListener('click', (event) => {
  const row = event.target.closest('[data-sm-system]');
  if (row) { state.selectedSmSystem = row.dataset.smSystem; loadSysMonitor(); }
});
$('#reload-rules').addEventListener('click', () => loadOrchestration());
$('#rule-producer').addEventListener('change', updateRuleConsumers);
$('#orchestration-form').addEventListener('submit', createOrchestrationRule);
$('#data-series').addEventListener('change', (event) => { state.selectedSeries = event.target.value; if (state.dataManager) renderDataManager(state.dataManager); });
new ResizeObserver(() => {
  if (state.data) renderActivity(state.data.history);
  if (state.dataManager) renderDataChart(state.dataManager.series.find((item) => item.name === state.selectedSeries));
  if (state.sysMonitor) renderSysMonitorChart();
}).observe(document.querySelector('main'));

refresh(true);
state.refreshTimer = setInterval(() => refresh(true), 5000);

// ---- Plant descriptions (PlantDescriptionEngine plantDescriptionManagement) ----
function emptyPlantDescription() {
  return { plantDescription: '', active: false, include: [], systems: [], connections: [] };
}

function plantModel(entry) {
  return {
    plantDescription: entry.plantDescription || '', active: Boolean(entry.active), include: [...(entry.include || [])],
    systems: (entry.systems || []).map((system) => ({
      systemId: system.systemId || '', systemName: system.systemName || '', metadata: { ...(system.metadata || {}) },
      ports: (system.ports || []).map((port) => ({ portName: port.portName || '', serviceDefinition: port.serviceDefinition || '',
        serviceInterface: port.serviceInterface || '', metadata: { ...(port.metadata || {}) }, consumer: Boolean(port.consumer) }))
    })),
    connections: (entry.connections || []).map((connection) => ({
      consumer: { systemId: connection.consumer?.systemId || '', portName: connection.consumer?.portName || '' },
      producer: { systemId: connection.producer?.systemId || '', portName: connection.producer?.portName || '' },
      priority: connection.priority ?? null
    }))
  };
}

// The request sent to the engine: empty optional members are left out.
function plantRequest(model) {
  const clean = (map) => Object.fromEntries(Object.entries(map || {}).filter(([key]) => key.trim()));
  return {
    plantDescription: model.plantDescription.trim(), active: model.active, include: model.include,
    systems: model.systems.map((system) => ({
      systemId: system.systemId.trim(), systemName: system.systemName.trim() || null, metadata: clean(system.metadata),
      ports: system.ports.map((port) => ({ portName: port.portName.trim(), serviceDefinition: port.serviceDefinition.trim(),
        serviceInterface: port.serviceInterface.trim() || null, metadata: clean(port.metadata), consumer: port.consumer }))
    })),
    connections: model.connections.map((connection) => ({ consumer: connection.consumer, producer: connection.producer,
      priority: connection.priority === null || connection.priority === '' ? null : Number(connection.priority) }))
  };
}

function metadataText(map) { return Object.entries(map || {}).map(([key, value]) => `${key}=${value}`).join(', '); }
function parseMetadata(text) {
  return Object.fromEntries(text.split(',').map((part) => part.split('=')).filter((pair) => pair[0]?.trim())
    .map(([key, ...rest]) => [key.trim(), rest.join('=').trim()]));
}

function renderPlantList(payload) {
  state.pd = { ...(state.pd || {}), ...payload };
  $('#pd-updated').textContent = `Updated ${formatTime(payload.collectedAt)}${payload.registryError ? ' · registry: ' + payload.registryError : ''}`;
  $('#pd-table').innerHTML = payload.entries.map((entry) => `<tr data-pd-id="${entry.id}" class="${state.pd.selectedId === entry.id ? 'selected' : ''}">
    <td>${entry.id}</td><td><strong>${escapeHtml(entry.plantDescription)}</strong></td>
    <td>${entry.active ? '<strong>active</strong>' : '<span class="muted">inactive</span>'}</td>
    <td>${escapeHtml((entry.include || []).join(', ') || '—')}</td><td>${(entry.systems || []).length}</td>
    <td>${(entry.connections || []).length}</td><td>${escapeHtml(formatTime(entry.updatedAt))}</td></tr>`).join('')
    || '<tr><td colspan="7" class="muted">No plant descriptions stored. Use “New plant description”.</td></tr>';
  $('#pd-system-names').innerHTML = payload.systems.map((name) => `<option value="${escapeHtml(name)}">`).join('');
  $('#pd-service-definitions').innerHTML = [...new Set(payload.services.map((s) => s.serviceDefinition))].sort()
    .map((name) => `<option value="${escapeHtml(name)}">`).join('');
  $('#pd-interfaces').innerHTML = [...new Set(payload.services.flatMap((s) => s.interfaces))].sort()
    .map((name) => `<option value="${escapeHtml(name)}">`).join('');
}

function openPlantEditor(entry) {
  state.pd.selectedId = entry ? entry.id : null;
  state.pd.model = entry ? plantModel(entry) : emptyPlantDescription();
  $('#pd-editor').hidden = false;
  $('#pd-editor-mode').textContent = entry ? `Plant description ${entry.id} · created ${formatTime(entry.createdAt)}` : 'New plant description';
  $('#pd-editor-title').textContent = entry ? entry.plantDescription : 'New plant description';
  $('#pd-delete').hidden = !entry;
  $('#pd-status').textContent = '';
  setPlantTab('form');
  renderPlantEditor();
  $$('#pd-table tr').forEach((row) => row.classList.toggle('selected', Number(row.dataset.pdId) === state.pd.selectedId));
  $('#pd-editor').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderPlantEditor() {
  const model = state.pd.model;
  $('#pd-name').value = model.plantDescription;
  $('#pd-include').value = model.include.join(', ');
  $('#pd-active').checked = model.active;
  $('#pd-systems').innerHTML = model.systems.map((system, s) => `<div class="pd-system">
    <div class="pd-system-head">
      <label class="rule-field"><span>System ID (in this plant)</span><input data-pd-field="systems.${s}.systemId" value="${escapeHtml(system.systemId)}" placeholder="sensor1"></label>
      <label class="rule-field"><span>System name</span><input data-pd-field="systems.${s}.systemName" list="pd-system-names" value="${escapeHtml(system.systemName)}" placeholder="registered system"></label>
      <label class="rule-field"><span>Metadata (key=value, …)</span><input data-pd-meta="systems.${s}" value="${escapeHtml(metadataText(system.metadata))}"></label>
      <button class="button small secondary" data-pd-remove-system="${s}" type="button">Remove system</button>
    </div>
    <table><thead><tr><th>Port</th><th>Service definition</th><th>Interface</th><th>Consumer</th><th>Metadata</th><th></th></tr></thead><tbody>
    ${system.ports.map((port, p) => `<tr>
      <td><input data-pd-field="systems.${s}.ports.${p}.portName" value="${escapeHtml(port.portName)}" placeholder="data"></td>
      <td><input data-pd-field="systems.${s}.ports.${p}.serviceDefinition" list="pd-service-definitions" value="${escapeHtml(port.serviceDefinition)}"></td>
      <td><input data-pd-field="systems.${s}.ports.${p}.serviceInterface" list="pd-interfaces" value="${escapeHtml(port.serviceInterface)}" placeholder="any"></td>
      <td><input type="checkbox" data-pd-check="systems.${s}.ports.${p}.consumer" ${port.consumer ? 'checked' : ''}></td>
      <td><input data-pd-meta="systems.${s}.ports.${p}" value="${escapeHtml(metadataText(port.metadata))}"></td>
      <td><button class="button small secondary" data-pd-remove-port="${s}.${p}" type="button">✕</button></td></tr>`).join('')}
    </tbody></table>
    <button class="button small secondary" data-pd-add-port="${s}" type="button">Add port</button>
  </div>`).join('') || '<p class="muted">No systems yet.</p>';
  renderPlantConnections();
}

function renderPlantConnections() {
  const model = state.pd.model;
  const systems = model.systems.filter((system) => system.systemId.trim());
  const systemOptions = (selected) => '<option value=""></option>' + systems.map((system) =>
    `<option value="${escapeHtml(system.systemId)}" ${system.systemId === selected ? 'selected' : ''}>${escapeHtml(system.systemId)}${system.systemName ? ' · ' + escapeHtml(system.systemName) : ''}</option>`).join('');
  const portOptions = (systemId, selected, consumer) => {
    const system = systems.find((item) => item.systemId === systemId);
    return '<option value=""></option>' + (system ? system.ports : []).filter((port) => port.portName && port.consumer === consumer)
      .map((port) => `<option value="${escapeHtml(port.portName)}" ${port.portName === selected ? 'selected' : ''}>${escapeHtml(port.portName)} · ${escapeHtml(port.serviceDefinition)}</option>`).join('');
  };
  $('#pd-connections').innerHTML = model.connections.map((connection, c) => `<tr>
    <td><select data-pd-field="connections.${c}.consumer.systemId">${systemOptions(connection.consumer.systemId)}</select></td>
    <td><select data-pd-field="connections.${c}.consumer.portName">${portOptions(connection.consumer.systemId, connection.consumer.portName, true)}</select></td>
    <td><select data-pd-field="connections.${c}.producer.systemId">${systemOptions(connection.producer.systemId)}</select></td>
    <td><select data-pd-field="connections.${c}.producer.portName">${portOptions(connection.producer.systemId, connection.producer.portName, false)}</select></td>
    <td><input type="number" min="1" step="1" data-pd-field="connections.${c}.priority" value="${connection.priority ?? ''}" placeholder="—"></td>
    <td><button class="button small secondary" data-pd-remove-connection="${c}" type="button">✕</button></td></tr>`).join('')
    || '<tr><td colspan="6" class="muted">No connections. A connection links a consumer port to a producer port.</td></tr>';
}

function setPath(target, path, value) {
  const keys = path.split('.');
  let node = target;
  keys.slice(0, -1).forEach((key) => { node = node[key]; });
  node[keys.at(-1)] = value;
}
function getPath(target, path) { return path.split('.').reduce((node, key) => node[key], target); }

function setPlantTab(tab) {
  $$('[data-pd-tab]').forEach((button) => button.classList.toggle('active', button.dataset.pdTab === tab));
  $('#pd-form').hidden = tab !== 'form';
  $('#pd-json-tab').hidden = tab !== 'json';
  if (tab === 'json') $('#pd-json').value = JSON.stringify(plantRequest(state.pd.model), null, 2);
}

async function loadPlantDescriptions(silent = false) {
  if (!silent) $('#pd-updated').textContent = 'Loading…';
  try {
    const response = await fetch('/api/plantdescriptions', { cache: 'no-store', signal: AbortSignal.timeout(20000) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Plant description request failed (${response.status})`);
    renderPlantList(payload);
  } catch (error) {
    $('#pd-updated').textContent = error.message;
    if (!silent) showToast(error.message);
  }
}

async function savePlantDescription() {
  if (!$('#pd-json-tab').hidden && !applyPlantJson()) return;
  const body = plantRequest(state.pd.model);
  if (!body.plantDescription) return showToast('Give the plant description a name.');
  const id = state.pd.selectedId;
  $('#pd-status').textContent = 'Saving…';
  try {
    const response = await fetch(id ? `/api/plantdescriptions/${id}` : '/api/plantdescriptions', {
      method: id ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json', 'X-Arrowhead-Action': 'confirm' }, body: JSON.stringify(body) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Save failed (${response.status})`);
    showToast(`Plant description ${payload.id} saved${payload.active ? ' and active' : ''}`);
    await loadPlantDescriptions(true);
    openPlantEditor(state.pd.entries.find((entry) => entry.id === payload.id) || payload);
    $('#pd-status').textContent = `Saved ${formatTime(payload.updatedAt)}`;
  } catch (error) {
    $('#pd-status').textContent = error.message;
    showToast(error.message);
  }
}

async function deletePlantDescription() {
  const id = state.pd.selectedId;
  if (!id || !window.confirm(`Delete plant description ${id}? Its orchestration rules are removed.`)) return;
  try {
    const response = await fetch(`/api/plantdescriptions/${id}`, { method: 'DELETE', headers: { 'X-Arrowhead-Action': 'confirm' } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Delete failed (${response.status})`);
    showToast(`Plant description ${id} deleted`);
    $('#pd-editor').hidden = true; state.pd.selectedId = null;
    loadPlantDescriptions(true);
  } catch (error) { showToast(error.message); }
}

function applyPlantJson() {
  try {
    state.pd.model = plantModel(JSON.parse($('#pd-json').value));
    return true;
  } catch (error) {
    showToast(`Invalid JSON: ${error.message}`);
    return false;
  }
}

$('#pd-reload').addEventListener('click', () => loadPlantDescriptions());
$('#pd-new').addEventListener('click', () => openPlantEditor(null));
$('#pd-cancel').addEventListener('click', () => { $('#pd-editor').hidden = true; state.pd.selectedId = null; $$('#pd-table tr').forEach((row) => row.classList.remove('selected')); });
$('#pd-save').addEventListener('click', savePlantDescription);
$('#pd-delete').addEventListener('click', deletePlantDescription);
$('#pd-apply-json').addEventListener('click', () => { if (applyPlantJson()) { setPlantTab('form'); renderPlantEditor(); } });
$$('[data-pd-tab]').forEach((button) => button.addEventListener('click', () => {
  if (button.dataset.pdTab === 'form' && !$('#pd-json-tab').hidden) { if (!applyPlantJson()) return; renderPlantEditor(); }
  setPlantTab(button.dataset.pdTab);
}));
$('#pd-table').addEventListener('click', (event) => {
  const row = event.target.closest('[data-pd-id]');
  if (row) openPlantEditor(state.pd.entries.find((entry) => entry.id === Number(row.dataset.pdId)));
});
$('#pd-name').addEventListener('input', (event) => { state.pd.model.plantDescription = event.target.value; });
$('#pd-include').addEventListener('input', (event) => {
  state.pd.model.include = event.target.value.split(',').map((part) => Number(part.trim())).filter((value) => Number.isInteger(value) && value > 0);
});
$('#pd-active').addEventListener('change', (event) => { state.pd.model.active = event.target.checked; });
$('#pd-add-system').addEventListener('click', () => {
  state.pd.model.systems.push({ systemId: '', systemName: '', metadata: {}, ports: [] }); renderPlantEditor();
});
$('#pd-add-connection').addEventListener('click', () => {
  state.pd.model.connections.push({ consumer: { systemId: '', portName: '' }, producer: { systemId: '', portName: '' }, priority: null });
  renderPlantConnections();
});
$('#pd-editor').addEventListener('input', (event) => {
  const field = event.target.dataset.pdField;
  if (field && event.target.tagName === 'INPUT') {
    setPath(state.pd.model, field, event.target.type === 'number' ? (event.target.value === '' ? null : Number(event.target.value)) : event.target.value);
  }
  if (event.target.dataset.pdMeta) getPath(state.pd.model, event.target.dataset.pdMeta).metadata = parseMetadata(event.target.value);
});
$('#pd-editor').addEventListener('change', (event) => {
  const target = event.target;
  if (target.dataset.pdCheck) { setPath(state.pd.model, target.dataset.pdCheck, target.checked); renderPlantConnections(); }
  if (target.dataset.pdField && target.tagName === 'SELECT') {
    setPath(state.pd.model, target.dataset.pdField, target.value);
    if (target.dataset.pdField.endsWith('.systemId')) setPath(state.pd.model, target.dataset.pdField.replace(/systemId$/, 'portName'), '');
    renderPlantConnections();
  }
  if (target.dataset.pdField && /systemId$|portName$|serviceDefinition$/.test(target.dataset.pdField) && target.tagName === 'INPUT') renderPlantConnections();
});
$('#pd-editor').addEventListener('click', (event) => {
  const model = state.pd.model;
  const { pdRemoveSystem, pdAddPort, pdRemovePort, pdRemoveConnection } = event.target.dataset;
  if (pdRemoveSystem !== undefined) { model.systems.splice(Number(pdRemoveSystem), 1); renderPlantEditor(); }
  if (pdAddPort !== undefined) {
    model.systems[Number(pdAddPort)].ports.push({ portName: '', serviceDefinition: '', serviceInterface: '', metadata: {}, consumer: false });
    renderPlantEditor();
  }
  if (pdRemovePort !== undefined) { const [s, p] = pdRemovePort.split('.').map(Number); model.systems[s].ports.splice(p, 1); renderPlantEditor(); }
  if (pdRemoveConnection !== undefined) { model.connections.splice(Number(pdRemoveConnection), 1); renderPlantConnections(); }
});

/* Shared rule-transaction editor model. Authorities own persistence; no authorization policy is changed here. */
(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.ArrowheadRuleTransactions=factory();})(typeof globalThis==='object'?globalThis:this,function(){
 'use strict';const copy=v=>JSON.parse(JSON.stringify(v)),id=r=>String(r.id??r.uuid??''),binding=r=>JSON.stringify([r.consumer,r.serviceInstanceId]),value=r=>JSON.stringify([r.consumer,r.serviceInstanceId,Number(r.priority)]),definition=r=>r.serviceDefinition||String(r.serviceInstanceId).split('|')[1];
 async function commit(api,candidate,expected){
  if(!Number.isInteger(candidate.priority)||candidate.priority<1||candidate.priority>2147483647)throw Error('Use a positive integer priority.');
  const before=await api.query(),old=expected&&before.find(r=>id(r)===id(expected));
  if(expected&&(!old||value(old)!==value(expected)))throw Error('The rule changed. Reload before saving.');
  if(old&&value(old)===value(candidate))return old;
  if(old&&binding(old)===binding(candidate)){
   await api.modify(id(old),candidate.priority,old);
   try{const rows=await api.query();const row=rows.find(r=>id(r)===id(old)&&value(r)===value(candidate))||rows.find(r=>!before.some(b=>id(b)===id(r))&&value(r)===value(candidate));if(!row||value(row)!==value(candidate))throw Error('Priority not confirmed by authority');return row;}catch(e){e.committed=true;e.message='Priority update reached the authority. Reload to confirm the current state. '+e.message;throw e;}
  }
  if(before.some(r=>binding(r)===binding(candidate)&&(!old||id(r)!==id(old))))throw Error('This consumer is already bound to that instance. Edit its existing connection.');
  const staged=copy(candidate);
  if(old&&old.consumer===candidate.consumer&&definition(old)===definition(candidate)&&Number(old.priority)===candidate.priority){
   const used=new Set(before.filter(r=>r.consumer===candidate.consumer&&definition(r)===definition(candidate)).map(r=>Number(r.priority)));staged.priority=2147483647;while(used.has(staged.priority)&&staged.priority>0)staged.priority--;if(!staged.priority)throw Error('No free staging priority.');
  }
  let created=null,removalAttempted=false,committed=false;
  try{
   const receipt=await api.create(staged);if(!old)committed=true;
   const reported=Array.isArray(receipt?.entries)?receipt.entries:[receipt];created=reported.find(r=>r&&id(r)&&value(r)===value(staged)&&!before.some(b=>id(b)===id(r)))||null;
   const current=await api.query();created=current.find(r=>!before.some(b=>id(b)===id(r))&&value(r)===value(staged))||created;
   if(!created)throw Error('Authority did not confirm a distinct new rule.');
   if(old){const fresh=current.find(r=>id(r)===id(old));if(!fresh||value(fresh)!==value(old))throw Error('The original rule changed during replacement.');removalAttempted=true;await api.remove(id(old));
    if(staged.priority!==candidate.priority)await api.modify(id(created),candidate.priority,created);committed=true;
   }
   const row=(await api.query()).find(r=>id(r)===id(created));if(!row||value(row)!==value(candidate))throw Error('Saved connection could not be confirmed.');return row;
  }catch(error){
   if(committed){error.committed=true;error.message='Save reached the authority. Reload to confirm the current state. '+error.message;throw error;}
   try{
    const current=await api.query();let originalPresent=!old||current.some(r=>id(r)===id(old)||value(r)===value(old));
    if(old&&removalAttempted&&!originalPresent){await api.create({consumer:old.consumer,serviceInstanceId:old.serviceInstanceId,priority:Number(old.priority)});originalPresent=true;}
    if(created&&originalPresent){const fresh=(await api.query()).find(r=>id(r)===id(created));if(fresh&&value(fresh)===value(staged))await api.remove(id(created));}
   }catch{error.message+=' Recovery could not finish; inspect stored rules before retrying.';}
   throw error;
  }
 }
 return{commit};
});

/* Local-cloud graphical orchestration and management-policy editor. */
(function(){
 'use strict';
 const clone=v=>JSON.parse(JSON.stringify(v)),esc=v=>escapeHtml(v),q=s=>document.querySelector(s);
 const S={payload:null,mode:'rules',consumer:'',instance:'',editing:null,priority:1,policies:[],policy:null,expected:null,scope:'',busy:false,consumerQuery:'',serviceQuery:'',policyError:'',readOnly:[],mounted:false};
 const ruleId=r=>String(r.id??r.uuid??''),ruleValue=r=>JSON.stringify([r.consumer,r.serviceInstanceId,Number(r.priority)]);
 const localName=/^[A-Za-z][A-Za-z0-9_]{0,62}$/;
 async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{'Content-Type':'application/json',...(method==='GET'?{}:{'X-Arrowhead-Action':'confirm'})},...(body===undefined?{}:{body:JSON.stringify(body)})});const v=await r.json().catch(()=>({}));if(!r.ok)throw Error(v.error||`Cloud returned ${r.status}`);return v;}
 function message(text,error=false){const n=q('#oe-message');n.textContent=text;n.hidden=!text;n.classList.toggle('error',error);}
 function producers(){const map=new Map((S.payload?.catalog?.producers||[]).map(p=>[p.instanceId,p]));for(const s of state.data?.services||[]){if(!map.has(s.instanceId))map.set(s.instanceId,{instanceId:s.instanceId,provider:s.provider?.name,serviceDefinition:s.serviceDefinition?.name,compatibleConsumers:[],interfaces:s.interfaces||[]});}if(S.mode==='policies')for(const p of [...S.policies,...(S.policy?[S.policy]:[])])if(p.targetType==='EVENT_TYPE')map.set('event:'+p.provider+':'+p.target,{instanceId:'event:'+p.provider+':'+p.target,provider:p.provider,serviceDefinition:p.target,targetType:'EVENT_TYPE',compatibleConsumers:[]});return [...map.values()].sort((a,b)=>`${a.provider}/${a.serviceDefinition}`.localeCompare(`${b.provider}/${b.serviceDefinition}`));}
 function selected(){return producers().find(p=>p.instanceId===S.instance);}
 function currentPolicy(){if(S.scope&&!Object.hasOwn(S.policy.scopedPolicies,S.scope))Object.defineProperty(S.policy.scopedPolicies,S.scope,{value:{policyType:'WHITELIST',policyList:[]},writable:true,enumerable:true,configurable:true});const p=S.scope?S.policy.scopedPolicies[S.scope]:(S.policy.defaultPolicy??={policyType:'WHITELIST',policyList:[]});p.policyList??=[];return p;}
 function chooseService(id){S.instance=id;if(S.mode==='policies'){const p=selected();if(p){const row=S.policies.find(r=>r.provider===p.provider&&r.targetType===(p.targetType||'SERVICE_DEF')&&r.target===p.serviceDefinition);S.expected=row?clone(row):null;S.policy=row?clone(row):{provider:p.provider,targetType:p.targetType||'SERVICE_DEF',target:p.serviceDefinition,cloud:'LOCAL',description:'',defaultPolicy:{policyType:'WHITELIST',policyList:[]},scopedPolicies:{}};S.policy.scopedPolicies??={};S.scope='';}}render();}
 function editRule(id){const r=(S.payload?.rules||[]).find(r=>ruleId(r)===id);if(!r)return;S.mode='rules';S.editing=clone(r);S.consumer=r.consumer;S.instance=r.serviceInstanceId;S.priority=Number(r.priority);render();message('Edit this connection and choose Save replacement.');}
 function renderGraph(){
  const allConsumers=S.payload?.catalog?.consumers||[],allProducers=producers();
  const consumers=allConsumers.filter(c=>c.name===S.consumer||c.name.toLowerCase().includes(S.consumerQuery.toLowerCase())).slice(0,100);
  const serviceRows=allProducers.filter(p=>p.instanceId===S.instance||`${p.provider} ${p.serviceDefinition}`.toLowerCase().includes(S.serviceQuery.toLowerCase())).slice(0,100);
  const height=Math.max(230,Math.max(consumers.length,serviceRows.length)*64+55),positions=new Map();consumers.forEach((c,i)=>positions.set('c:'+c.name,{x:238,y:53+i*64}));serviceRows.forEach((p,i)=>positions.set('s:'+p.instanceId,{x:555,y:53+i*64}));
  let edges='';
  if(S.mode==='rules')for(const r of S.payload?.rules||[]){const a=positions.get('c:'+r.consumer),b=positions.get('s:'+r.serviceInstanceId);if(!a||!b)continue;edges+=`<g class="oe-edge ${S.editing&&ruleId(S.editing)===ruleId(r)?'selected':''}" data-oe-rule="${esc(ruleId(r))}" tabindex="0" role="button" aria-label="Edit ${esc(r.consumer)} rule, priority ${Number(r.priority)}"><path class="oe-edge-hit" d="M${a.x},${a.y} C395,${a.y} 395,${b.y} ${b.x},${b.y}"/><path class="oe-edge-line" d="M${a.x},${a.y} C395,${a.y} 395,${b.y} ${b.x},${b.y}"/><text x="396" y="${(a.y+b.y)/2-4}" text-anchor="middle">P${Number(r.priority)}</text></g>`;}
  else if(S.policy){const target=serviceRows.find(p=>p.provider===S.policy.provider&&p.serviceDefinition===S.policy.target);const b=target&&positions.get('s:'+target.instanceId);const policy=currentPolicy();if(b)for(const c of consumers){const a=positions.get('c:'+c.name),listed=(policy.policyList||[]).includes(c.name),allow=policy.policyType==='ALL'||policy.policyType==='WHITELIST'&&listed||policy.policyType==='BLACKLIST'&&!listed;edges+=`<path class="oe-policy-edge ${allow?'allows':'denies'}" d="M${a.x},${a.y} C395,${a.y} 395,${b.y} ${b.x},${b.y}"/>`;}}
  const node=(x,y,width,label,sub,attrs,category,active)=>`<g ${attrs} class="oe-node ${category} ${active?'selected':''}" tabindex="0" role="button" aria-label="${esc(label+' '+sub)}"><rect x="${x}" y="${y}" width="${width}" height="48" rx="7"/><text x="${x+10}" y="${y+20}">${esc(label.slice(0,29))}</text><text class="oe-subtitle" x="${x+10}" y="${y+37}">${esc(sub.slice(0,32))}</text></g>`;
  q('#oe-svg').setAttribute('viewBox',`0 0 805 ${height}`);q('#oe-svg').style.height=height+'px';q('#oe-svg').innerHTML=`<text x="20" y="17" class="oe-column-title">Consumers (${consumers.length}/${allConsumers.length})</text><text x="555" y="17" class="oe-column-title">Service instances (${serviceRows.length}/${allProducers.length})</text>${edges}${consumers.map((c,i)=>node(18,29+i*64,220,c.name,'Consumer',`data-oe-consumer="${esc(c.name)}"`,arrowheadClass(c.name),S.consumer===c.name)).join('')}${serviceRows.map((p,i)=>node(555,29+i*64,230,p.serviceDefinition,p.provider,`data-oe-service="${esc(p.instanceId)}"`,'oe-service-node',S.instance===p.instanceId)).join('')}`;
 }
 function renderInspector(){const p=selected(),node=q('#oe-properties');
  if(S.mode==='rules'){const compatible=!!p?.compatibleConsumers?.includes(S.consumer);node.innerHTML=`<h3>${S.editing?'Edit connection':'New connection'}</h3><p class="section-note">Choose a consumer and a service in the graph. You can also drag from a consumer onto a service.</p><p><strong>Consumer</strong><br>${esc(S.consumer||'Select in graph')}</p><p><strong>Provider / service</strong><br>${esc(p?`${p.provider} / ${p.serviceDefinition}`:S.instance||'Select in graph')}</p><label>Priority<input id="oe-priority" type="number" min="1" max="2147483647" value="${S.priority}"></label><p class="section-note">${p&&S.consumer?compatible?'Registered catalog choice. Compatible interfaces and service authorization are still required when consuming the service.':'Not an interface-compatible catalog choice.':'Select both endpoints to continue.'}</p><div class="oe-actions"><button type="button" class="button secondary" data-oe-action="save-rule" ${!compatible||S.busy?'disabled':''}>${S.editing?'Save replacement':'Create rule'}</button>${S.editing?'<button type="button" class="action danger" data-oe-action="delete-rule">Delete rule</button>':''}</div>`;return;}
  if(!S.policy){node.innerHTML='<h3>Security policies</h3><p class="section-note">Select a service to edit its local cloud-management policy, or choose an existing policy below.</p>';return;}
  const policy=currentPolicy(),names=[...new Set([...(S.payload?.catalog?.consumers||[]).map(c=>c.name),...(policy.policyList||[])])].sort();
  node.innerHTML=`<h3>${S.expected?'Edit security policy':'New security policy'}</h3><p class="section-note">Cloud-management layer · LOCAL. Provider-owned policies are read-only and may also affect authorization.</p><p><strong>${esc(S.policy.provider)}</strong></p><label>Target type<select id="oe-target-type" ${S.expected?'disabled':''}><option value="SERVICE_DEF" ${S.policy.targetType==='SERVICE_DEF'?'selected':''}>Service definition</option><option value="EVENT_TYPE" ${S.policy.targetType==='EVENT_TYPE'?'selected':''}>Event type</option></select></label><label>Target<input id="oe-target" value="${esc(S.policy.target)}" ${S.expected?'disabled':''}></label><label>Description<input id="oe-description" maxlength="1000" value="${esc(S.policy.description||'')}"></label><label>Operation scope<select id="oe-scope"><option value="">Default policy</option>${Object.keys(S.policy.scopedPolicies||{}).map(k=>`<option ${S.scope===k?'selected':''} value="${esc(k)}">${esc(k)}</option>`).join('')}</select></label><div class="oe-scope-add"><input id="oe-new-scope" placeholder="Operation name" aria-label="New operation scope"><button type="button" class="action" data-oe-action="add-scope">Add scope</button>${S.scope?'<button type="button" class="action danger" data-oe-action="remove-scope">Remove</button>':''}</div><label>Access policy<select id="oe-policy-type">${['ALL','WHITELIST','BLACKLIST'].map(t=>`<option ${policy.policyType===t?'selected':''} value="${t}">${{ALL:'All local consumers',WHITELIST:'Allow listed consumers',BLACKLIST:'Exclude listed consumers'}[t]}</option>`).join('')}</select></label><p class="section-note">Click consumers in the graph or check them below to edit list membership.</p><div class="oe-policy-members">${names.map(n=>`<label><input type="checkbox" data-oe-member="${esc(n)}" ${(policy.policyList||[]).includes(n)?'checked':''} ${policy.policyType==='ALL'?'disabled':''}><span>${esc(n)}</span></label>`).join('')}</div><div class="oe-scope-add"><input id="oe-add-name" placeholder="Local system name" aria-label="Additional local system name"><button type="button" class="action" data-oe-action="add-member">Add</button></div><div class="oe-actions"><button type="button" class="button secondary" data-oe-action="save-policy" ${S.busy?'disabled':''}>Save policy</button>${S.expected?'<button type="button" class="action danger" data-oe-action="delete-policy">Delete policy</button>':''}</div>`;
 }
 function render(){if(!S.mounted)return;q('#oe-mode').value=S.mode;q('#oe-properties').classList.toggle('oe-busy',S.busy);renderGraph();renderInspector();q('#oe-policy-list').hidden=S.mode!=='policies';q('#oe-policy-list').innerHTML=`<label>Existing local management policy<select id="oe-existing-policy"><option value="">Select a policy…</option>${S.policies.map(p=>`<option ${S.expected?.instanceId===p.instanceId?'selected':''} value="${esc(p.instanceId)}">${esc(p.provider)} / ${esc(p.target)} (${esc(p.targetType)})</option>`).join('')}</select></label><span class="section-note">${esc(S.policyError||`${S.policies.length} editable local management policies`)}</span>${S.readOnly.length?`<details><summary>Provider-owned policies (${S.readOnly.length}, read-only)</summary>${S.readOnly.map(p=>`<p class="section-note">${esc(p.provider)} / ${esc(p.target)} · ${esc(p.defaultPolicy?.policyType||'Unknown')} · ${esc((p.defaultPolicy?.policyList||[]).join(', '))}</p>`).join('')}</details>`:''}`;}
 async function reloadPolicies(){try{const data=await api('/api/orchestration/policies');S.policies=data.entries||[];S.readOnly=data.readOnlyEntries||[];S.policyError='';}catch(e){S.policyError=e.message;}render();}
 async function reloadRules(){const data=await api('/api/orchestration/rules');renderOrchestration(data);return data;}
 async function saveRule(){
  const candidate={consumer:S.consumer,serviceInstanceId:S.instance,priority:Number(q('#oe-priority').value)};let latest=null;
  try{const saved=await window.ArrowheadRuleTransactions.commit({query:async()=>{latest=await api('/api/orchestration/rules');return latest.rules||[];},create:c=>api('/api/orchestration/rules','POST',c),remove:id=>api('/api/orchestration/rules/'+encodeURIComponent(id),'DELETE'),modify:(id,priority,expected)=>api('/api/orchestration/rules/'+encodeURIComponent(id),'PUT',{priority,expected})},candidate,S.editing);S.editing=clone(saved);S.priority=Number(saved.priority);if(latest)renderOrchestration(latest);message('Orchestration rule saved. Security policies remain separate.');}
  catch(e){await reloadRules().catch(()=>{});S.editing=null;throw e;}
 }
 async function action(name){if(S.busy)return;S.busy=true;q('#orchestration-editor').classList.add('oe-saving');q('#orchestration-editor').setAttribute('aria-busy','true');try{
  if(name==='new-rule'){S.mode='rules';S.editing=null;S.consumer='';S.instance='';S.priority=1;message('Choose or drag from a consumer to a service.');}
  else if(name==='new-policy'){const p=selected()||producers()[0];if(!p)throw Error('No registered provider is available.');S.mode='policies';S.expected=null;S.scope='';S.instance=p.instanceId;S.policy={provider:p.provider,targetType:'SERVICE_DEF',target:p.serviceDefinition,cloud:'LOCAL',description:'',defaultPolicy:{policyType:'WHITELIST',policyList:[]},scopedPolicies:{}};message('New policy draft. Choose a service or event target; existing policies are not overwritten as new.');}
  else if(name==='save-rule')await saveRule();
  else if(name==='delete-rule'&&S.editing&&confirm('Delete the selected orchestration rule?')){const current=await api('/api/orchestration/rules');if(!current.rules.some(r=>ruleId(r)===ruleId(S.editing)&&ruleValue(r)===ruleValue(S.editing)))throw Error('The rule changed; reload before deleting.');await api('/api/orchestration/rules/'+encodeURIComponent(ruleId(S.editing)),'DELETE');S.editing=null;await reloadRules();message('Rule deleted.');}
  else if(name==='reload'){await reloadRules();await reloadPolicies();if(S.mode==='policies'&&S.expected){const row=S.policies.find(p=>p.instanceId===S.expected.instanceId)||S.policies.find(p=>p.provider===S.expected.provider&&p.targetType===S.expected.targetType&&p.target===S.expected.target);S.expected=row?clone(row):null;S.policy=row?clone(row):null;if(S.policy){S.policy.scopedPolicies??={};if(!Object.hasOwn(S.policy.scopedPolicies,S.scope))S.scope='';}}if(S.mode==='rules'&&S.editing){const row=S.payload.rules.find(r=>ruleId(r)===ruleId(S.editing));S.editing=row?clone(row):null;if(row){S.consumer=row.consumer;S.instance=row.serviceInstanceId;S.priority=Number(row.priority);}}message('Rules and policies reloaded; the selected draft now reflects the cloud.');}
  else if(name==='add-scope'){const k=q('#oe-new-scope').value.trim();if(!/^[A-Za-z0-9_.:-]{1,100}$/.test(k))throw Error('Enter a valid operation name.');if(!Object.hasOwn(S.policy.scopedPolicies,k))Object.defineProperty(S.policy.scopedPolicies,k,{value:{policyType:'WHITELIST',policyList:[]},writable:true,enumerable:true,configurable:true});S.scope=k;}
  else if(name==='remove-scope'){delete S.policy.scopedPolicies[S.scope];S.scope='';}
  else if(name==='add-member'){const n=q('#oe-add-name').value.trim();if(!localName.test(n))throw Error('Use a local system name.');const p=currentPolicy();if(!p.policyList.includes(n))p.policyList.push(n);}
  else if(name==='save-policy'){S.policy.description=q('#oe-description').value;S.policy.targetType=q('#oe-target-type').value;S.policy.target=q('#oe-target').value.trim();const created=await api('/api/orchestration/policies','POST',{policy:S.policy,expected:S.expected});S.expected=clone(created);S.policy=clone(created);S.policy.scopedPolicies??={};await reloadPolicies();message('Local cloud-management policy saved.');}
  else if(name==='delete-policy'&&S.expected&&confirm('Delete this local management policy? Provider policy or default authorization may then apply.')){await api('/api/orchestration/policies/'+encodeURIComponent(S.expected.instanceId),'DELETE',{expected:S.expected});S.expected=null;S.policy=null;await reloadPolicies();message('Local management policy deleted.');}
 }catch(e){message(e.message,true);}finally{S.busy=false;q('#orchestration-editor').classList.remove('oe-saving');q('#orchestration-editor').setAttribute('aria-busy','false');render();}}
 function start(){const section=q('#view-orchestration');if(!section)return;const host=document.createElement('article');host.id='orchestration-editor';host.className='panel oe-editor';host.innerHTML=`<div class="panel-heading"><div><p class="eyebrow">Local cloud design</p><h3>Graphical orchestration & security</h3></div><div class="oe-actions"><select id="oe-mode" aria-label="Graph editing layer"><option value="rules">Orchestration rules</option><option value="policies">Security policies</option></select><button type="button" class="action" data-oe-action="new-rule">New connection</button><button type="button" class="action" data-oe-action="new-policy">New policy</button><button type="button" class="action" data-oe-action="reload">Reload</button></div></div><p class="section-note oe-note">Select a connection to edit it, or choose a consumer and service to create one. Saved rules and access policies remain separate configurations.</p><div id="oe-message" class="oe-message" role="status" hidden></div><div id="oe-policy-list" hidden></div><div class="oe-workspace"><div class="oe-graph-panel"><div class="oe-filters"><label>Consumers<input id="oe-consumer-filter" type="search" placeholder="Find a consumer"></label><label>Services<input id="oe-service-filter" type="search" placeholder="Find a provider or service"></label></div><div class="oe-graph-scroll"><svg id="oe-svg" role="application" aria-label="Orchestration graph. Choose a consumer and service; select an existing connection to edit."></svg></div><p class="section-note oe-note">System nodes retain Arrowhead colors. Service nodes are turquoise. In policy mode, green/red connections show the selected policy's allow/exclude decision, not runtime traffic.</p></div><aside id="oe-properties" class="oe-properties" aria-label="Connection and policy properties"></aside></div>`;section.insertBefore(host,section.children[1]||null);S.mounted=true;
 const old=q('.rule-map-panel');if(old)old.style.display='none';const oldForm=q('.orchestration-grid');if(oldForm){const details=document.createElement('details');details.className='oe-classic';details.innerHTML='<summary>Classic rule form</summary>';oldForm.before(details);details.append(oldForm);}
 host.addEventListener('click',e=>{const c=e.target.closest('[data-oe-consumer]'),p=e.target.closest('[data-oe-service]'),r=e.target.closest('[data-oe-rule]'),a=e.target.closest('[data-oe-action]');if(S.busy)return;if(a){action(a.dataset.oeAction);return;}if(r){editRule(r.dataset.oeRule);return;}if(p){chooseService(p.dataset.oeService);return;}if(c){S.consumer=c.dataset.oeConsumer;if(S.mode==='policies'&&S.policy){const p=currentPolicy();if(p.policyType!=='ALL'){p.policyList??=[];const i=p.policyList.indexOf(S.consumer);if(i<0)p.policyList.push(S.consumer);else p.policyList.splice(i,1);}}render();}});
 host.addEventListener('keydown',e=>{if(['Enter',' '].includes(e.key)&&e.target.closest('.oe-node,.oe-edge')){e.preventDefault();e.target.closest('.oe-node,.oe-edge').dispatchEvent(new MouseEvent('click',{bubbles:true}));}});
 host.addEventListener('input',e=>{if(e.target.id==='oe-consumer-filter'){S.consumerQuery=e.target.value;renderGraph();}else if(e.target.id==='oe-service-filter'){S.serviceQuery=e.target.value;renderGraph();}else if(e.target.id==='oe-priority')S.priority=Number(e.target.value);else if(e.target.id==='oe-description'&&S.policy)S.policy.description=e.target.value;else if(e.target.id==='oe-target'&&S.policy)S.policy.target=e.target.value;});
 host.addEventListener('change',e=>{if(S.busy)return;if(e.target.id==='oe-mode'){S.mode=e.target.value;if(S.mode==='policies'){chooseService(S.instance);reloadPolicies();}render();}else if(e.target.id==='oe-target-type'){S.policy.targetType=e.target.value;renderGraph();}else if(e.target.id==='oe-target'){S.policy.target=e.target.value.trim();renderGraph();}else if(e.target.id==='oe-scope'){S.scope=e.target.value;render();}else if(e.target.id==='oe-policy-type'){currentPolicy().policyType=e.target.value;render();}else if(e.target.dataset.oeMember){const p=currentPolicy(),name=e.target.dataset.oeMember;p.policyList??=[];p.policyList=p.policyList.filter(n=>n!==name);if(e.target.checked)p.policyList.push(name);renderGraph();}else if(e.target.id==='oe-existing-policy'){const p=S.policies.find(p=>p.instanceId===e.target.value);if(p){S.expected=clone(p);S.policy=clone(p);S.policy.scopedPolicies??={};S.scope='';const service=producers().find(s=>s.provider===p.provider&&s.serviceDefinition===p.target);S.instance=service?.instanceId||'';render();}}});
 let dragging=null;host.addEventListener('pointerdown',e=>{dragging=e.target.closest('[data-oe-consumer]')?.dataset.oeConsumer||null;});host.addEventListener('pointerup',e=>{const p=e.target.closest('[data-oe-service]');if(dragging&&p&&S.mode==='rules'){S.consumer=dragging;S.instance=p.dataset.oeService;render();}dragging=null;});
 if(state.orchestration)update(state.orchestration);else render();reloadPolicies();
 }
 function update(payload){S.payload=payload;if(S.mounted){render();for(const b of document.querySelectorAll('#orchestration-rule-table [data-remove-rule]')){if(!b.parentElement.querySelector('[data-oe-table-edit]')){const e=document.createElement('button');e.type='button';e.className='action';e.textContent='Edit graph';e.dataset.oeTableEdit=b.dataset.removeRule;e.addEventListener('click',()=>{editRule(e.dataset.oeTableEdit);q('#orchestration-editor').scrollIntoView({behavior:'smooth',block:'start'});});b.before(e);}}}}
 window.LocalCloudGraphEditor={update,state:S};if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
