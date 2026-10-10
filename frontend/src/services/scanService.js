import { get, post } from './api';

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
