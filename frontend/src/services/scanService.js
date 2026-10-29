import { get, post, patch } from './api';

export function runDiscovery(subnet) {
  return post('/api/scans/discovery', { subnet });
}

export function runPortScan(targetIp, ports) {
  return post('/api/scans/ports', { target_ip: targetIp, ports });
}

export function getScanHistory() {
  return get('/api/scans');
}

// Get devices from latest discovery scan only (default)
export function getDevices(scanId = 'latest') {
  if (scanId === 'all') return get('/api/devices');
  if (scanId === 'latest') return get('/api/devices?scan_id=latest');
  return get(`/api/devices?scan_id=${scanId}`);
}

export function getScanById(scanId) {
  return get('/api/scans/' + scanId);
}

export function compareScans(scanA, scanB) {
  return get('/api/scans/compare?scan_id_a=' + scanA + '&scan_id_b=' + scanB);
}

export function getFindings(scanId) {
  return get('/api/findings' + (scanId ? '?scan_id=' + scanId : ''));
}

export function getReport(scanId) {
  return get('/api/reports/' + scanId);
}

export function getDeviceById(deviceId) {
  return get('/api/devices/' + deviceId);
}

export function updateApproval(deviceId, status) {
  return patch('/api/devices/' + deviceId + '/approval', { approval_status: status });
}

export function getReportCsvUrl(scanId) {
  return '/api/reports/' + scanId + '/csv';
}
