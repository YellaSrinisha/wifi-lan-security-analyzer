import { useState, useEffect, useCallback } from 'react';
import { getHealth, getInterfaces } from '../services/networkService';
import { getDevices, getScanHistory, runDiscovery } from '../services/scanService';
import Card from '../components/Card';
import Button from '../components/Button';
import ErrorMessage from '../components/ErrorMessage';
import LoadingSpinner from '../components/LoadingSpinner';
import Table from '../components/Table';
import Badge from '../components/Badge';
import PageHeader from '../components/PageHeader';

function StatCard({ label, value, sub }) {
  return (
    <Card className="flex-1">
      <p className="text-sm text-gray-500">{label}</p>
      <p className="text-3xl font-bold text-gray-900 mt-1">{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </Card>
  );
}

export default function Dashboard() {
  const [health, setHealth] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [devices, setDevices] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [subnet, setSubnet] = useState('');
  const [showSubnetForm, setShowSubnetForm] = useState(false);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, ifaces, devs, sc] = await Promise.allSettled([
        getHealth(), getInterfaces(), getDevices(), getScanHistory()
      ]);
      if (h.status === 'fulfilled') setHealth(h.value);
      if (ifaces.status === 'fulfilled') setInterfaces(ifaces.value.interfaces || []);
      if (devs.status === 'fulfilled') setDevices(Array.isArray(devs.value) ? devs.value : []);
      if (sc.status === 'fulfilled') setScans(Array.isArray(sc.value) ? sc.value : []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  async function handleDiscovery(e) {
    e.preventDefault();
    if (!subnet.trim()) return;
    setScanning(true);
    setScanError(null);
    try {
      await runDiscovery(subnet.trim());
      setShowSubnetForm(false);
      setSubnet('');
      await fetchAll();
    } catch (err) {
      setScanError(err.message);
    } finally {
      setScanning(false);
    }
  }

  const recentScans = scans.slice(-5).reverse();
  const lastScan = scans.length > 0 ? scans[scans.length - 1] : null;

  const scanColumns = [
    { key: 'scan_type', label: 'Type' },
    { key: 'target', label: 'Target' },
    { key: 'status', label: 'Status', render: (v) => <Badge variant={v === 'completed' ? 'green' : v === 'error' ? 'red' : 'gray'}>{v}</Badge> },
    { key: 'started_at', label: 'Started', render: (v) => v ? new Date(v).toLocaleString() : '—' },
  ];

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Wi-Fi/LAN Security Analyzer overview" />
      <ErrorMessage message={error} onDismiss={() => setError(null)} />
      {loading ? <LoadingSpinner text="Loading dashboard..." /> : (
        <>
          <div className="flex gap-4 mb-6 flex-wrap">
            <StatCard label="Devices Found" value={devices.length} sub="from last scan" />
            <StatCard label="Last Scan" value={lastScan ? new Date(lastScan.started_at).toLocaleDateString() : 'Never'} sub={lastScan?.scan_type || ''} />
            <StatCard label="Active Interfaces" value={interfaces.filter(i => i.is_up).length} sub={`of ${interfaces.length} total`} />
            <StatCard
              label="Scanner Status"
              value={health?.nmap_available ? '✓ Ready' : '✗ Unavailable'}
              sub={health?.nmap_available ? 'Nmap detected' : 'Nmap not found'}
            />
          </div>

          <div className="mb-6">
            {!showSubnetForm ? (
              <Button onClick={() => setShowSubnetForm(true)}>Start Discovery Scan</Button>
            ) : (
              <Card title="Start Host Discovery">
                <form onSubmit={handleDiscovery} className="flex gap-3 flex-wrap items-end">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Private Subnet (e.g. 192.168.1.0/24)</label>
                    <input
                      type="text"
                      value={subnet}
                      onChange={e => setSubnet(e.target.value)}
                      placeholder="192.168.1.0/24"
                      className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-64"
                    />
                  </div>
                  <Button type="submit" loading={scanning}>Scan</Button>
                  <Button variant="secondary" onClick={() => { setShowSubnetForm(false); setScanError(null); }}>Cancel</Button>
                </form>
                {scanError && <ErrorMessage message={scanError} onDismiss={() => setScanError(null)} />}
                <p className="text-xs text-yellow-600 mt-2">⚠ Only scan networks you own or have explicit permission to test.</p>
              </Card>
            )}
          </div>

          {interfaces.length > 0 && (
            <Card title="Network Interfaces" className="mb-6">
              <div className="flex flex-wrap gap-3">
                {interfaces.map((iface, i) => (
                  <div key={i} className="flex items-center gap-2 px-3 py-2 bg-gray-50 rounded border border-gray-200 text-sm">
                    <span className={`h-2 w-2 rounded-full ${iface.is_up ? 'bg-green-500' : 'bg-gray-300'}`} />
                    <span className="font-medium">{iface.name}</span>
                    <span className="text-gray-500">{iface.ip_address || 'no IP'}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <Card title="Recent Scans">
            {recentScans.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                <p className="text-lg mb-2">No scans yet</p>
                <p className="text-sm">Use &ldquo;Start Discovery Scan&rdquo; above to discover devices on your network.</p>
              </div>
            ) : (
              <Table columns={scanColumns} data={recentScans} emptyMessage="No recent scans." />
            )}
          </Card>
        </>
      )}
    </div>
  );
}
