import { useState, useEffect } from 'react';
import { getScanHistory, getFindings } from '../services/scanService';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Table from '../components/Table';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';

function severityVariant(severity) {
  if (severity === 'high') return 'red';
  if (severity === 'medium') return 'yellow';
  if (severity === 'low') return 'blue';
  return 'gray';
}

export default function SecurityFindings() {
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Load scan list and all findings on mount
  useEffect(() => {
    async function loadInitial() {
      setLoading(true);
      setError(null);
      try {
        const [scanList, allFindings] = await Promise.all([
          getScanHistory(),
          getFindings(),
        ]);
        setScans(Array.isArray(scanList) ? scanList : []);
        setFindings(Array.isArray(allFindings) ? allFindings : []);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    loadInitial();
  }, []);

  // Reload findings when scan filter changes
  async function handleScanFilterChange(e) {
    const value = e.target.value;
    setSelectedScanId(value);
    setLoading(true);
    setError(null);
    try {
      const data = await getFindings(value || null);
      setFindings(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Severity summary counts
  const counts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0, info: 0 }
  );

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      render: (v) => <Badge variant={severityVariant(v)}>{v}</Badge>,
    },
    { key: 'rule_id', label: 'Rule ID' },
    { key: 'title', label: 'Title' },
    {
      key: 'device_id',
      label: 'Device',
      render: (v) => v ? v.slice(0, 8) : '—',
    },
    { key: 'recommendation', label: 'Recommendation' },
  ];

  return (
    <div>
      <PageHeader
        title="Security Findings"
        subtitle="Automated security analysis of discovered devices"
      />

      {/* Severity summary */}
      <div className="flex gap-4 mb-6 flex-wrap">
        <div className="flex-1 min-w-[100px] bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-center">
          <p className="text-2xl font-bold text-red-700">{counts.high || 0}</p>
          <p className="text-xs text-red-600 mt-1">High</p>
        </div>
        <div className="flex-1 min-w-[100px] bg-yellow-50 border border-yellow-200 rounded-lg px-4 py-3 text-center">
          <p className="text-2xl font-bold text-yellow-700">{counts.medium || 0}</p>
          <p className="text-xs text-yellow-600 mt-1">Medium</p>
        </div>
        <div className="flex-1 min-w-[100px] bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 text-center">
          <p className="text-2xl font-bold text-blue-700">{counts.low || 0}</p>
          <p className="text-xs text-blue-600 mt-1">Low</p>
        </div>
        <div className="flex-1 min-w-[100px] bg-gray-50 border border-gray-200 rounded-lg px-4 py-3 text-center">
          <p className="text-2xl font-bold text-gray-700">{counts.info || 0}</p>
          <p className="text-xs text-gray-500 mt-1">Info</p>
        </div>
      </div>

      {/* Scan filter dropdown */}
      <div className="mb-4 flex items-center gap-3">
        <label className="text-sm font-medium text-gray-700">Filter by scan:</label>
        <select
          value={selectedScanId}
          onChange={handleScanFilterChange}
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All scans</option>
          {scans.map((s) => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.scan_type} — {s.target} — {s.started_at ? new Date(s.started_at).toLocaleString() : s.scan_id?.slice(0, 8)}
            </option>
          ))}
        </select>
      </div>

      <ErrorMessage message={error} onDismiss={() => setError(null)} />

      {loading ? (
        <LoadingSpinner text="Loading findings..." />
      ) : (
        <Card>
          <Table
            columns={columns}
            data={findings}
            emptyMessage="No findings yet. Run a scan to generate security findings."
          />
        </Card>
      )}
    </div>
  );
}
