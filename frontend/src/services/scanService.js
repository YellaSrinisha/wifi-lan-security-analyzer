import { get, post, patch } from './api';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export function runDiscovery(subnet) {
  return post('/api/scans/discovery', { subnet });
}

export function runPortScan(targetIp, ports) {
  return post('/api/scans/ports', { target_ip: targetIp, ports });
}

export function getScanHistory() {
  return get('/api/scans');
}

export function getDevices() {
  return get('/api/devices');
}

export function getScanById(scanId) {
  return get('/api/scans/' + scanId);
}

export function compareScans(scanA, scanB) {
  return get('/api/scans/compare?scan_a=' + scanA + '&scan_b=' + scanB);
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
  return BASE_URL + '/api/reports/' + scanId + '/csv';
}
