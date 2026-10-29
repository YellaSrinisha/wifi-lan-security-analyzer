import { useState } from 'react';
import { useScans } from '../hooks/useScans';
import { compareScans } from '../services/scanService';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Table from '../components/Table';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';

export default function ScanHistory() {
  const { scans, loading, error, refetch } = useScans();
  const [scanAId, setScanAId] = useState('');
  const [scanBId, setScanBId] = useState('');
  const [comparing, setComparing] = useState(false);
  const [compareError, setCompareError] = useState(null);
  const [compareResult, setCompareResult] = useState(null);

  const reversedScans = [...scans].reverse();

  const columns = [
    {
      key: 'select_a',
      label: 'Scan A',
      render: (_v, row) => (
        <input
          type="radio"
          name="scanA"
          value={row.scan_id}
          checked={scanAId === row.scan_id}
          onChange={() => setScanAId(row.scan_id)}
          className="cursor-pointer accent-blue-600"
        />
      ),
    },
    {
      key: 'select_b',
      label: 'Scan B',
      render: (_v, row) => (
        <input
          type="radio"
          name="scanB"
          value={row.scan_id}
          checked={scanBId === row.scan_id}
          onChange={() => setScanBId(row.scan_id)}
          className="cursor-pointer accent-green-600"
        />
      ),
    },
    { key: 'scan_id', label: 'Scan ID', render: (v) => <span className="font-mono text-xs">{v?.slice(0, 8)}...</span> },
    {
      key: 'scan_type',
      label: 'Type',
      render: (v) => <Badge variant={v === 'discovery' ? 'blue' : 'gray'}>{v}</Badge>,
    },
    { key: 'target', label: 'Target' },
    {
      key: 'status',
      label: 'Status',
      render: (v) => (
        <Badge variant={v === 'completed' ? 'green' : v === 'error' || v === 'failed' ? 'red' : v === 'timed_out' ? 'yellow' : 'gray'}>
          {v}
        </Badge>
      ),
    },
    { key: 'host_count', label: 'Hosts', render: (v) => v ?? '--' },
    {
      key: 'started_at',
      label: 'Started',
      render: (v) => v ? new Date(v).toLocaleString() : '--',
    },
    {
      key: 'completed_at',
      label: 'Completed',
      render: (v) => v ? new Date(v).toLocaleString() : '--',
    },
  ];

  async function handleCompare() {
    if (!scanAId || !scanBId) return;
    if (scanAId === scanBId) {
      setCompareError('Please select two different scans.');
      return;
    }
    setComparing(true);
    setCompareError(null);
    setCompareResult(null);
    try {
      const result = await compareScans(scanAId, scanBId);
      setCompareResult(result);
    } catch (err) {
      setCompareError(err.message);
    } finally {
      setComparing(false);
    }
  }

  // Format port entry — backend returns {ip, port} objects
  function formatPort(p) {
    if (typeof p === 'object' && p !== null) {
      return `${p.ip}:${p.port}`;
    }
    return String(p);
  }

  return (
    <div>
      <PageHeader title="Scan History" subtitle="All scans stored in the database" />
      <ErrorMessage message={error} onDismiss={() => {}} />

      {loading ? (
        <LoadingSpinner text="Loading scan history..." />
      ) : (
        <>
          {/* Scan list */}
          <Card className="mb-6">
            <div className="flex justify-between items-center mb-4">
              <p className="text-sm text-gray-500">
                {scans.length} scan{scans.length !== 1 ? 's' : ''} total
              </p>
              <Button variant="secondary" onClick={refetch}>Refresh</Button>
            </div>
            <Table
              columns={columns}
              data={reversedScans}
              emptyMessage="No scans yet. Run a discovery scan from the Dashboard first."
            />
          </Card>

          {/* Compare panel */}
          <Card title="Compare Two Scans" className="mb-6">
            <p className="text-sm text-gray-500 mb-4">
              Select <strong>Scan A</strong> (blue radio) and <strong>Scan B</strong> (green radio) from the table above, then click Compare.
            </p>

            {/* Selected scan display */}
            <div className="flex items-center gap-6 flex-wrap mb-4 p-3 bg-gray-50 rounded-lg border border-gray-200">
              <div className="text-sm">
                <span className="font-medium text-blue-700">Scan A: </span>
                {scanAId ? (
                  <span className="font-mono text-gray-800 bg-blue-50 px-2 py-0.5 rounded">
                    {scanAId.slice(0, 8)}...
                  </span>
                ) : (
                  <span className="text-gray-400 italic">not selected</span>
                )}
              </div>
              <div className="text-sm">
                <span className="font-medium text-green-700">Scan B: </span>
                {scanBId ? (
                  <span className="font-mono text-gray-800 bg-green-50 px-2 py-0.5 rounded">
                    {scanBId.slice(0, 8)}...
                  </span>
                ) : (
                  <span className="text-gray-400 italic">not selected</span>
                )}
              </div>
              <Button
                onClick={handleCompare}
                loading={comparing}
                disabled={!scanAId || !scanBId || scanAId === scanBId}
              >
                Compare Scans
              </Button>
              {scanAId && scanBId && scanAId === scanBId && (
                <span className="text-xs text-red-500">Select two different scans</span>
              )}
            </div>

            <ErrorMessage message={compareError} onDismiss={() => setCompareError(null)} />
            {comparing && <LoadingSpinner text="Comparing scans..." />}

            {/* Results */}
            {compareResult && (
              <div className="mt-4 space-y-4">

                {/* Summary bar */}
                <div className="flex gap-3 flex-wrap p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm">
                  <span className="text-blue-800 font-medium">Comparison Result:</span>
                  <span className="text-green-700">{compareResult.devices_added?.length ?? 0} new devices</span>
                  <span className="text-red-700">{compareResult.devices_removed?.length ?? 0} removed devices</span>
                  <span className="text-gray-700">{compareResult.devices_common?.length ?? 0} common devices</span>
                  <span className="text-orange-700">{compareResult.ports_opened?.length ?? 0} ports opened</span>
                  <span className="text-purple-700">{compareResult.ports_closed?.length ?? 0} ports closed</span>
                </div>

                {/* New devices */}
                <div className="border border-green-200 rounded-lg overflow-hidden">
                  <div className="bg-green-50 px-4 py-2 border-b border-green-200">
                    <h4 className="text-sm font-semibold text-green-800">
                      New Devices in Scan B ({compareResult.devices_added?.length ?? 0})
                    </h4>
                    <p className="text-xs text-green-600 mt-0.5">Devices present in Scan B but not in Scan A</p>
                  </div>
                  <div className="p-4">
                    {compareResult.devices_added?.length > 0 ? (
                      <ul className="space-y-1">
                        {compareResult.devices_added.map((ip, i) => (
                          <li key={i} className="flex items-center gap-2 text-sm">
                            <span className="w-2 h-2 rounded-full bg-green-500 inline-block"></span>
                            <span className="font-mono text-gray-800">{ip}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-gray-400">No new devices found</p>
                    )}
                  </div>
                </div>

                {/* Removed devices */}
                <div className="border border-red-200 rounded-lg overflow-hidden">
                  <div className="bg-red-50 px-4 py-2 border-b border-red-200">
                    <h4 className="text-sm font-semibold text-red-800">
                      Devices No Longer Seen ({compareResult.devices_removed?.length ?? 0})
                    </h4>
                    <p className="text-xs text-red-600 mt-0.5">In Scan A but not in Scan B — may be offline, not confirmed gone</p>
                  </div>
                  <div className="p-4">
                    {compareResult.devices_removed?.length > 0 ? (
                      <ul className="space-y-1">
                        {compareResult.devices_removed.map((ip, i) => (
                          <li key={i} className="flex items-center gap-2 text-sm">
                            <span className="w-2 h-2 rounded-full bg-red-500 inline-block"></span>
                            <span className="font-mono text-gray-800">{ip}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-gray-400">No devices disappeared</p>
                    )}
                  </div>
                </div>

                {/* Common devices */}
                {compareResult.devices_common?.length > 0 && (
                  <div className="border border-gray-200 rounded-lg overflow-hidden">
                    <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
                      <h4 className="text-sm font-semibold text-gray-700">
                        Devices in Both Scans ({compareResult.devices_common.length})
                      </h4>
                    </div>
                    <div className="p-4">
                      <ul className="space-y-1">
                        {compareResult.devices_common.map((ip, i) => (
                          <li key={i} className="flex items-center gap-2 text-sm">
                            <span className="w-2 h-2 rounded-full bg-gray-400 inline-block"></span>
                            <span className="font-mono text-gray-700">{ip}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}

                {/* Port changes */}
                <div className="border border-orange-200 rounded-lg overflow-hidden">
                  <div className="bg-orange-50 px-4 py-2 border-b border-orange-200">
                    <h4 className="text-sm font-semibold text-orange-800">Port Changes</h4>
                    <p className="text-xs text-orange-600 mt-0.5">Open port differences between the two scans</p>
                  </div>
                  <div className="p-4 space-y-3">
                    {compareResult.ports_opened?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-green-700 mb-1">Ports Opened in Scan B:</p>
                        <ul className="space-y-1">
                          {compareResult.ports_opened.map((p, i) => (
                            <li key={i} className="flex items-center gap-2 text-sm">
                              <span className="w-2 h-2 rounded-full bg-green-500 inline-block"></span>
                              <span className="font-mono text-gray-800">{formatPort(p)}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {compareResult.ports_closed?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-red-700 mb-1">Ports Closed in Scan B:</p>
                        <ul className="space-y-1">
                          {compareResult.ports_closed.map((p, i) => (
                            <li key={i} className="flex items-center gap-2 text-sm">
                              <span className="w-2 h-2 rounded-full bg-red-500 inline-block"></span>
                              <span className="font-mono text-gray-800">{formatPort(p)}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {!compareResult.ports_opened?.length && !compareResult.ports_closed?.length && (
                      <p className="text-sm text-gray-400">No port changes detected between these two scans</p>
                    )}
                  </div>
                </div>

              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
