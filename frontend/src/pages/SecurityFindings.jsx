import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScanHistory, getFindings } from '../services/scanService';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';

function severityVariant(severity) {
  if (severity === 'high') return 'red';
  if (severity === 'medium') return 'yellow';
  if (severity === 'low') return 'blue';
  return 'gray';
}

function severityHeaderClass(severity) {
  if (severity === 'high') return 'bg-red-100 border-b border-red-200';
  if (severity === 'medium') return 'bg-yellow-100 border-b border-yellow-200';
  if (severity === 'low') return 'bg-blue-100 border-b border-blue-200';
  return 'bg-gray-100 border-b border-gray-200';
}

function extractIp(evidence) {
  if (!evidence) return null;
  const matches = evidence.match(/(\d{1,3}\.){3}\d{1,3}/g);
  return matches ? matches[matches.length - 1] : null;
}

export default function SecurityFindings() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

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

  async function handleScanFilterChange(e) {
    const value = e.target.value;
    setSelectedScanId(value);
    setExpandedId(null);
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

  function toggleExpand(findingId) {
    setExpandedId(prev => prev === findingId ? null : findingId);
  }

  function handleRescan(finding) {
    if (finding.rule_id === 'NEW_DEVICE_001') {
      navigate('/devices');
      return;
    }
    const ip = extractIp(finding.evidence);
    if (ip) {
      navigate('/port-scanner?ip=' + encodeURIComponent(ip));
    }
  }

  const counts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0, info: 0 }
  );

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

      {/* Scan filter */}
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
          {findings.length === 0 ? (
            <p className="text-sm text-gray-500 py-4 text-center">
              No findings yet. Run a scan to generate security findings.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider">Rule ID</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider">Title</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider">Affected IP</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider">Recommendation</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider">Details</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-100">
                  {findings.map((f) => (
                    <>
                      <tr key={f.finding_id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 whitespace-nowrap">
                          <Badge variant={severityVariant(f.severity)}>{f.severity}</Badge>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-xs text-gray-600">{f.rule_id}</td>
                        <td className="px-4 py-3">{f.title}</td>
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-xs">{extractIp(f.evidence) || '—'}</td>
                        <td className="px-4 py-3 text-gray-600">{f.recommendation}</td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <button
                            onClick={() => toggleExpand(f.finding_id)}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-medium bg-gray-100 hover:bg-gray-200 text-gray-700 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
                            aria-expanded={expandedId === f.finding_id}
                            aria-controls={`fix-panel-${f.finding_id}`}
                          >
                            <span style={{display: 'inline-block', transform: expandedId === f.finding_id ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s'}}>▶</span>
                            How to Fix
                          </button>
                        </td>
                      </tr>
                      {expandedId === f.finding_id && (
                        <tr key={`${f.finding_id}-panel`} id={`fix-panel-${f.finding_id}`}>
                          <td colSpan={6} className="px-0 py-0">
                            <div className="mx-4 mb-3 mt-1 rounded-lg border overflow-hidden">
                              {/* Header */}
                              <div className={`px-4 py-2 flex items-center gap-2 ${severityHeaderClass(f.severity)}`}>
                                <span role="img" aria-label="wrench">🔧</span>
                                <span className="font-semibold text-sm">How to Fix — {f.title}</span>
                              </div>
                              {/* Body */}
                              <div className="px-4 py-3 bg-white">
                                {f.how_to_fix ? (
                                  <div className="mb-3">
                                    <pre className="whitespace-pre-wrap text-sm text-gray-800 font-sans leading-relaxed">{f.how_to_fix}</pre>
                                  </div>
                                ) : (
                                  <p className="text-sm text-gray-500 mb-3">No fix instructions available for this finding.</p>
                                )}
                                {f.verification_steps && (
                                  <div className="mb-3 p-3 bg-green-50 border border-green-200 rounded-md">
                                    <p className="text-xs font-semibold text-green-800 mb-1">✅ How to verify the fix:</p>
                                    <p className="text-sm text-green-900 whitespace-pre-wrap">{f.verification_steps}</p>
                                  </div>
                                )}
                                <div className="flex gap-2 mt-2">
                                  <Button
                                    variant="secondary"
                                    onClick={() => handleRescan(f)}
                                  >
                                    🔍 Rescan this device
                                  </Button>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
