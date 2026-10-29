import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { runPortScan } from '../services/scanService';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import ErrorMessage from '../components/ErrorMessage';
import Table from '../components/Table';
import Badge from '../components/Badge';

const PRESET_PORTS = [
  { port: 22, label: 'SSH' },
  { port: 53, label: 'DNS' },
  { port: 80, label: 'HTTP' },
  { port: 443, label: 'HTTPS' },
  { port: 445, label: 'SMB' },
  { port: 3306, label: 'MySQL' },
  { port: 5432, label: 'PostgreSQL' },
  { port: 8080, label: 'HTTP-Alt' },
];

function stateVariant(state) {
  if (state === 'open') return 'green';
  if (state === 'filtered') return 'yellow';
  if (state === 'closed') return 'gray';
  return 'blue';
}

export default function PortScanner() {
  const [searchParams] = useSearchParams();
  const [targetIp, setTargetIp] = useState(searchParams.get('ip') || '');
  const [selectedPorts, setSelectedPorts] = useState(PRESET_PORTS.map(p => p.port));
  const [customPorts, setCustomPorts] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [inputError, setInputError] = useState(null);

  function togglePort(port) {
    setSelectedPorts(prev =>
      prev.includes(port) ? prev.filter(p => p !== port) : [...prev, port]
    );
  }

  function parseCustomPorts() {
    if (!customPorts.trim()) return [];
    const parts = customPorts.split(',').map(s => s.trim()).filter(Boolean);
    const parsed = [];
    for (const part of parts) {
      const n = parseInt(part, 10);
      if (isNaN(n) || n < 1 || n > 65535) {
        throw new Error(`Invalid port: "${part}". Ports must be integers between 1 and 65535.`);
      }
      parsed.push(n);
    }
    return parsed;
  }

  async function handleScan(e) {
    e.preventDefault();
    setInputError(null);
    setError(null);

    if (!targetIp.trim()) {
      setInputError('Please enter a target IP address.');
      return;
    }

    let extraPorts = [];
    try {
      extraPorts = parseCustomPorts();
    } catch (err) {
      setInputError(err.message);
      return;
    }

    const allPorts = [...new Set([...selectedPorts, ...extraPorts])];
    if (allPorts.length === 0) {
      setInputError('Select at least one port to scan.');
      return;
    }
    if (allPorts.length > 50) {
      setInputError('Too many ports selected (max 50).');
      return;
    }

    setLoading(true);
    try {
      const data = await runPortScan(targetIp.trim(), allPorts);
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const columns = [
    { key: 'port', label: 'Port' },
    { key: 'state', label: 'State', render: (v) => <Badge variant={stateVariant(v)}>{v}</Badge> },
    { key: 'service', label: 'Service', render: (v) => v || '--' },
    {
      key: 'product',
      label: 'Product',
      render: (v, row) => {
        if (v) return v;
        if (row.state === 'filtered') return <span className="text-xs text-gray-400 italic">filtered — no access</span>;
        if (row.state === 'closed') return <span className="text-xs text-gray-400 italic">closed — no service</span>;
        return <span className="text-xs text-gray-400 italic">not detected</span>;
      },
    },
    {
      key: 'version',
      label: 'Version',
      render: (v, row) => {
        if (v) return v;
        if (row.state === 'filtered') return <span className="text-xs text-gray-400">--</span>;
        if (row.state === 'closed') return <span className="text-xs text-gray-400">--</span>;
        return <span className="text-xs text-gray-400 italic">not detected</span>;
      },
    },
  ];

  return (
    <div>
      <PageHeader title="Port Scanner" subtitle="Scan TCP ports on a specific device" />
      <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 mb-4 text-sm text-yellow-800">
        ⚠ Only scan devices you own or have explicit permission to test. Unauthorized port scanning may be illegal.
      </div>
      <Card className="mb-6">
        <form onSubmit={handleScan}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1">Target IP Address</label>
            <input
              type="text"
              value={targetIp}
              onChange={e => setTargetIp(e.target.value)}
              placeholder="192.168.1.1"
              className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-64"
            />
          </div>
          <div className="mb-4">
            <p className="text-sm font-medium text-gray-700 mb-2">Preset Ports</p>
            <div className="flex flex-wrap gap-2">
              {PRESET_PORTS.map(({ port, label }) => (
                <label key={port} className="inline-flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedPorts.includes(port)}
                    onChange={() => togglePort(port)}
                    className="rounded border-gray-300 text-blue-600"
                  />
                  <span className="text-sm text-gray-700">{port} ({label})</span>
                </label>
              ))}
            </div>
          </div>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1">Custom Ports (comma-separated)</label>
            <input
              type="text"
              value={customPorts}
              onChange={e => setCustomPorts(e.target.value)}
              placeholder="8443, 9000, 27017"
              className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-64"
            />
          </div>
          {inputError && <ErrorMessage message={inputError} onDismiss={() => setInputError(null)} />}
          <div className="mt-4">
            <Button type="submit" loading={loading}>Scan Selected Ports</Button>
          </div>
        </form>
      </Card>
      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}
      {loading && <div className="text-sm text-gray-500 mt-2">Scanning ports... this may take up to 60 seconds.</div>}
      {results && (
        <Card title={`Results for ${results.target_ip}`}>
          <div className="mb-3 flex gap-2">
            <Badge variant={results.status === 'completed' ? 'green' : 'red'}>{results.status}</Badge>
          </div>
          {results.warnings?.map((w, i) => (
            <p key={i} className="text-xs text-yellow-700 bg-yellow-50 rounded px-2 py-1 mb-2">{w}</p>
          ))}
          <Table
            columns={columns}
            data={results.ports}
            emptyMessage="No port results returned."
          />
        </Card>
      )}
    </div>
  );
}
