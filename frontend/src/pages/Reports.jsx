import { useState, useEffect } from 'react';
import { getScanHistory, getDevices } from '../services/scanService';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Table from '../components/Table';
import Badge from '../components/Badge';

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [s, d] = await Promise.allSettled([getScanHistory(), getDevices()]);
        if (s.status === 'fulfilled') setScans(Array.isArray(s.value) ? s.value : []);
        if (d.status === 'fulfilled') setDevices(Array.isArray(d.value) ? d.value : []);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const latestDiscovery = [...scans].reverse().find(s => s.scan_type === 'discovery');
  const latestPortScan = [...scans].reverse().find(s => s.scan_type === 'port_scan');

  const scanColumns = [
    { key: 'scan_id', label: 'Scan ID', render: (v) => v?.slice(0, 8) + '...' },
    { key: 'scan_type', label: 'Type' },
    { key: 'target', label: 'Target' },
    { key: 'status', label: 'Status', render: (v) => <Badge variant={v === 'completed' ? 'green' : 'red'}>{v}</Badge> },
    { key: 'host_count', label: 'Hosts' },
  ];

  const deviceColumns = [
    { key: 'ip_address', label: 'IP Address' },
    { key: 'mac_address', label: 'MAC' },
    { key: 'hostname', label: 'Hostname' },
    { key: 'state', label: 'State', render: (v) => <Badge variant={v === 'up' ? 'green' : 'gray'}>{v}</Badge> },
  ];

  return (
    <div>
      <PageHeader title="Reports" subtitle="Session summary and scan results" />
      <div className="flex justify-end mb-4">
        <Button variant="secondary" onClick={() => window.print()}>🖨 Print Report</Button>
      </div>
      <div className="text-sm text-blue-700 bg-blue-50 border border-blue-200 rounded-md px-3 py-2 mb-4">
        ℹ Advanced reports and CSV export will be available in Module 2.
      </div>
      {!loading && (
        <>
          <Card title="All Scans This Session" className="mb-6">
            <Table columns={scanColumns} data={[...scans].reverse()} emptyMessage="No scans yet." />
          </Card>
          <Card title="Discovered Devices" className="mb-6">
            <Table columns={deviceColumns} data={devices} emptyMessage="No devices discovered yet." />
          </Card>
          {latestDiscovery && (
            <Card title="Latest Discovery Scan" className="mb-6">
              <dl className="grid grid-cols-2 gap-2 text-sm">
                <dt className="text-gray-500">Scan ID</dt><dd className="text-gray-900 font-mono">{latestDiscovery.scan_id?.slice(0, 16)}...</dd>
                <dt className="text-gray-500">Target</dt><dd>{latestDiscovery.target}</dd>
                <dt className="text-gray-500">Status</dt><dd><Badge variant={latestDiscovery.status === 'completed' ? 'green' : 'red'}>{latestDiscovery.status}</Badge></dd>
                <dt className="text-gray-500">Hosts Found</dt><dd>{latestDiscovery.host_count ?? '—'}</dd>
                <dt className="text-gray-500">Started</dt><dd>{latestDiscovery.started_at ? new Date(latestDiscovery.started_at).toLocaleString() : '—'}</dd>
              </dl>
            </Card>
          )}
          {latestPortScan && (
            <Card title="Latest Port Scan">
              <dl className="grid grid-cols-2 gap-2 text-sm">
                <dt className="text-gray-500">Scan ID</dt><dd className="text-gray-900 font-mono">{latestPortScan.scan_id?.slice(0, 16)}...</dd>
                <dt className="text-gray-500">Target</dt><dd>{latestPortScan.target}</dd>
                <dt className="text-gray-500">Status</dt><dd><Badge variant={latestPortScan.status === 'completed' ? 'green' : 'red'}>{latestPortScan.status}</Badge></dd>
                <dt className="text-gray-500">Started</dt><dd>{latestPortScan.started_at ? new Date(latestPortScan.started_at).toLocaleString() : '—'}</dd>
              </dl>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
