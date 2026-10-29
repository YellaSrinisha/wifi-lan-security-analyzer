import { useState, useEffect } from 'react';
import { getScanHistory, getReport, getReportCsvUrl } from '../services/scanService';
import { get } from '../services/api';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Table from '../components/Table';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';

function scoreBadgeVariant(score) {
  if (score == null) return 'gray';
  if (score >= 80) return 'green';
  if (score >= 50) return 'yellow';
  return 'red';
}

function scoreLabel(score) {
  if (score == null) return '--';
  if (score >= 80) return 'Good';
  if (score >= 50) return 'Fair';
  return 'Poor';
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
  const [networkScore, setNetworkScore] = useState(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingReport, setLoadingReport] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadInitial() {
      try {
        const [scanData, scoreData] = await Promise.allSettled([
          getScanHistory(),
          get('/api/health/score'),
        ]);
        if (scanData.status === 'fulfilled') setScans(Array.isArray(scanData.value) ? scanData.value : []);
        if (scoreData.status === 'fulfilled') setNetworkScore(scoreData.value);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoadingScans(false);
      }
    }
    loadInitial();
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
    {
      key: 'ip_address',
      label: 'IP Address',
      render: (v, row) => v || row.last_known_ip || '--',
    },
    { key: 'mac_address', label: 'MAC', render: (v) => v || '--' },
    { key: 'hostname', label: 'Hostname', render: (v) => v || '--' },
    {
      key: 'approval_status',
      label: 'Status',
      render: (v) => <Badge variant={approvalVariant(v || 'pending_review')}>{v || 'pending_review'}</Badge>,
    },
  ];

  const portColumns = [
    { key: 'port_number', label: 'Port' },
    {
      key: 'state',
      label: 'State',
      render: (v) => (
        <Badge variant={v === 'open' ? 'green' : v === 'filtered' ? 'yellow' : 'gray'}>{v}</Badge>
      ),
    },
    { key: 'service_name', label: 'Service', render: (v) => v || '--' },
    { key: 'product', label: 'Product', render: (v) => v || '--' },
    { key: 'version_info', label: 'Version', render: (v) => v || '--' },
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

  const scanScore = report?.score?.score;
  const netScore = networkScore?.score;

  return (
    <div>
      <PageHeader title="Reports" subtitle="Per-scan security report with score, devices, findings, and CSV export" />

      <div className="flex justify-end mb-4">
        <Button variant="secondary" onClick={() => window.print()}>🖨 Print Report</Button>
      </div>

      {/* Overall network score banner */}
      {netScore != null && (
        <div className={`mb-6 p-4 rounded-lg border flex items-center gap-4 ${
          netScore >= 80 ? 'bg-green-50 border-green-200' :
          netScore >= 50 ? 'bg-yellow-50 border-yellow-200' :
          'bg-red-50 border-red-200'
        }`}>
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Current Network Score</p>
            <p className={`text-3xl font-bold ${
              netScore >= 80 ? 'text-green-700' : netScore >= 50 ? 'text-yellow-700' : 'text-red-700'
            }`}>{netScore}<span className="text-base text-gray-400">/100</span></p>
          </div>
          <div className="flex-1">
            <Badge variant={scoreBadgeVariant(netScore)}>{scoreLabel(netScore)}</Badge>
            <p className="text-xs text-gray-500 mt-1">
              Based on all unique findings from your current network only.
              {networkScore?.breakdown?.length > 0 && ` Deductions: ${networkScore.breakdown.join(', ')}`}
            </p>
            <p className="text-xs text-gray-400 mt-0.5">
              ℹ This is different from the per-scan score below — each scan only scores its own findings.
            </p>
          </div>
        </div>
      )}

      {/* Scan selector */}
      <Card className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Select a scan to view its report:
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
                {s.scan_type} — {s.target} — {s.started_at ? new Date(s.started_at).toLocaleString() : s.scan_id?.slice(0, 8)}
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
              <dd className="font-mono text-gray-800 text-xs">{report.scan?.scan_id}</dd>
              <dt className="text-gray-500">Type</dt>
              <dd><Badge variant={report.scan?.scan_type === 'discovery' ? 'blue' : 'gray'}>{report.scan?.scan_type}</Badge></dd>
              <dt className="text-gray-500">Target</dt>
              <dd>{report.scan?.target_scope || report.scan?.target}</dd>
              <dt className="text-gray-500">Status</dt>
              <dd><Badge variant={report.scan?.status === 'completed' ? 'green' : 'red'}>{report.scan?.status}</Badge></dd>
              <dt className="text-gray-500">Started</dt>
              <dd>{report.scan?.started_at ? new Date(report.scan.started_at).toLocaleString() : '--'}</dd>
              <dt className="text-gray-500">Completed</dt>
              <dd>{report.scan?.completed_at ? new Date(report.scan.completed_at).toLocaleString() : '--'}</dd>
            </dl>
          </Card>

          {/* Per-scan score */}
          <Card title="This Scan's Score" className="mb-6">
            {report.score ? (
              <div className="flex items-start gap-6">
                <div>
                  <p className="text-5xl font-bold text-gray-900">
                    {report.score.score}
                    <span className="text-lg text-gray-400">/100</span>
                  </p>
                  <Badge variant={scoreBadgeVariant(report.score.score)} className="mt-2">
                    {scoreLabel(report.score.score)}
                  </Badge>
                </div>
                <div className="flex-1">
                  <p className="text-sm text-gray-700">{report.score.explanation}</p>
                  {report.score.provisional === 1 && (
                    <p className="text-xs text-yellow-600 mt-1">⚠ Provisional — scan did not complete fully</p>
                  )}
                  {/* Explain discrepancy if per-scan differs from network score */}
                  {netScore != null && scanScore != null && scanScore !== netScore && (
                    <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded text-xs text-blue-700">
                      <strong>Why is this different from the Overall Network Score ({netScore}/100)?</strong>
                      <p className="mt-1">
                        This scan scored <strong>{scanScore}/100</strong> based on findings from this scan only.
                        The overall network score of <strong>{netScore}/100</strong> counts unique findings across
                        <strong> all scans</strong> — including port scans on other devices.
                        Check the Security Findings page to see all findings.
                      </p>
                    </div>
                  )}
                  {netScore != null && scanScore != null && scanScore === 100 && netScore < 100 && (
                    <div className="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-700">
                      <strong>This scan has no findings</strong> — score is 100 for this scan alone.
                      The overall network score is <strong>{netScore}/100</strong> because other scans
                      found issues on different devices. Check Security Findings for the full picture.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-sm text-gray-400">No score available for this scan.</p>
            )}
          </Card>

          {/* Devices */}
          <Card title={`Devices (${report.devices?.length || 0})`} className="mb-6">
            <Table
              columns={deviceColumns}
              data={report.devices || []}
              emptyMessage="No devices recorded for this scan."
            />
          </Card>

          {/* Ports */}
          {report.ports?.length > 0 && (
            <Card title={`Port Observations (${report.ports.length})`} className="mb-6">
              <Table
                columns={portColumns}
                data={report.ports}
                emptyMessage="No port observations for this scan."
              />
            </Card>
          )}

          {/* Findings */}
          <Card title={`Security Findings (${report.findings?.length || 0})`} className="mb-6">
            <Table
              columns={findingColumns}
              data={report.findings || []}
              emptyMessage="No findings for this scan. This scan found no security issues."
            />
          </Card>

          {/* Actions */}
          <div className="flex gap-3 mb-8">
            <Button
              variant="secondary"
              onClick={() => { window.location.href = getReportCsvUrl(selectedScanId); }}
            >
              ⬇ Download CSV
            </Button>
            <Button variant="secondary" onClick={() => window.print()}>
              🖨 Print Report
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
