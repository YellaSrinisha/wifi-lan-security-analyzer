import { useState, useEffect } from 'react';
import { getScanHistory, getReport, getReportCsvUrl } from '../services/scanService';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Table from '../components/Table';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';

function scoreBadgeVariant(score) {
  if (score >= 80) return 'green';
  if (score >= 50) return 'yellow';
  return 'red';
}

function approvalVariant(status) {
  if (status === 'approved') return 'green';
  if (status === 'revoked') return 'red';
  return 'yellow';
}

function severityVariant(severity) {
  if (severity === 'high') return 'red';
  if (severity === 'medium') return 'yellow';
  if (severity === 'low') return 'blue';
  return 'gray';
}

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [report, setReport] = useState(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingReport, setLoadingReport] = useState(false);
  const [error, setError] = useState(null);

  // Load scan list on mount
  useEffect(() => {
    async function loadScans() {
      try {
        const data = await getScanHistory();
        const list = Array.isArray(data) ? data : [];
        setScans(list);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoadingScans(false);
      }
    }
    loadScans();
  }, []);

  async function handleScanSelect(e) {
    const scanId = e.target.value;
    setSelectedScanId(scanId);
    setReport(null);
    if (!scanId) return;
    setLoadingReport(true);
    setError(null);
    try {
      const data = await getReport(scanId);
      setReport(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingReport(false);
    }
  }

  const deviceColumns = [
    { key: 'last_known_ip', label: 'IP Address' },
    { key: 'mac_address', label: 'MAC', render: (v) => v || '—' },
    { key: 'hostname', label: 'Hostname', render: (v) => v || '—' },
    {
      key: 'approval_status',
      label: 'Status',
      render: (v) => (
        <Badge variant={approvalVariant(v)}>{v || 'unknown'}</Badge>
      ),
    },
  ];

  const findingColumns = [
    {
      key: 'severity',
      label: 'Severity',
      render: (v) => <Badge variant={severityVariant(v)}>{v}</Badge>,
    },
    { key: 'rule_id', label: 'Rule' },
    { key: 'title', label: 'Title' },
    { key: 'recommendation', label: 'Recommendation' },
  ];

  return (
    <div>
      <PageHeader title="Reports" subtitle="Per-scan security report with score, devices, findings, and CSV export" />

      <div className="flex justify-end mb-4">
        <Button variant="secondary" onClick={() => window.print()}>
          🖨 Print Report
        </Button>
      </div>

      {/* Scan selector */}
      <Card className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Select a scan to report on:
        </label>
        {loadingScans ? (
          <LoadingSpinner text="Loading scans..." />
        ) : (
          <select
            value={selectedScanId}
            onChange={handleScanSelect}
            className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full max-w-xl"
          >
            <option value="">— Choose a scan —</option>
            {[...scans].reverse().map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.scan_type} — {s.target} —{' '}
                {s.started_at ? new Date(s.started_at).toLocaleString() : s.scan_id?.slice(0, 8)}
              </option>
            ))}
          </select>
        )}
      </Card>

      <ErrorMessage message={error} onDismiss={() => setError(null)} />

      {loadingReport && <LoadingSpinner text="Loading report..." />}

      {report && (
        <>
          {/* Scan summary */}
          <Card title="Scan Summary" className="mb-6">
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-gray-500">Scan ID</dt>
              <dd className="font-mono text-gray-900">{report.scan?.scan_id}</dd>
              <dt className="text-gray-500">Type</dt>
              <dd>{report.scan?.scan_type}</dd>
              <dt className="text-gray-500">Target</dt>
              <dd>{report.scan?.target_scope || report.scan?.target}</dd>
              <dt className="text-gray-500">Status</dt>
              <dd>
                <Badge variant={report.scan?.status === 'completed' ? 'green' : 'red'}>
                  {report.scan?.status}
                </Badge>
              </dd>
              <dt className="text-gray-500">Started</dt>
              <dd>
                {report.scan?.started_at
                  ? new Date(report.scan.started_at).toLocaleString()
                  : '—'}
              </dd>
              <dt className="text-gray-500">Completed</dt>
              <dd>
                {report.scan?.completed_at
                  ? new Date(report.scan.completed_at).toLocaleString()
                  : '—'}
              </dd>
            </dl>
          </Card>

          {/* Score card */}
          {report.score && (
            <Card title="Security Score" className="mb-6">
              <div className="flex items-center gap-4">
                <div className="text-5xl font-bold text-gray-900">
                  {report.score.score}
                  <span className="text-lg text-gray-400">/100</span>
                </div>
                <div>
                  <Badge variant={scoreBadgeVariant(report.score.score)}>
                    {report.score.score >= 80
                      ? 'Good'
                      : report.score.score >= 50
                      ? 'Fair'
                      : 'Poor'}
                  </Badge>
                  {report.score.provisional && (
                    <p className="text-xs text-yellow-600 mt-1">
                      ⚠ Provisional — scan did not complete fully
                    </p>
                  )}
                  {report.score.explanation && (
                    <p className="text-sm text-gray-500 mt-1">{report.score.explanation}</p>
                  )}
                </div>
              </div>
            </Card>
          )}

          {/* Devices */}
          <Card title="Devices" className="mb-6">
            <Table
              columns={deviceColumns}
              data={report.devices || []}
              emptyMessage="No devices recorded for this scan."
            />
          </Card>

          {/* Findings */}
          <Card title="Security Findings" className="mb-6">
            <Table
              columns={findingColumns}
              data={report.findings || []}
              emptyMessage="No findings for this scan."
            />
          </Card>

          {/* Download CSV */}
          <div className="flex gap-3">
            <Button
              variant="secondary"
              onClick={() => {
                window.location.href = getReportCsvUrl(selectedScanId);
              }}
            >
              ⬇ Download CSV
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
