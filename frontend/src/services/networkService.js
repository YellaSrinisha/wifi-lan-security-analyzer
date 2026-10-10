import { get } from './api';

export function getInterfaces() {
  return get('/api/network/interfaces');
}

export function getHealth() {
  return get('/api/health');
}
