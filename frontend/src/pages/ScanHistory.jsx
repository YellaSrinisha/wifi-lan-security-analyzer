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
          className="cursor-pointer"
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
          className="cursor-pointer"
        />
      ),
    },
    { key: 'scan_id', label: 'Scan ID', render: (v) => v?.slice(0, 8) + '...' },
    { key: 'scan_type', label: 'Type' },
    { key: 'target', label: 'Target' },
    {
      key: 'status',
      label: 'Status',
      render: (v) => (
        <Badge variant={v === 'completed' ? 'green' : v === 'error' ? 'red' : 'gray'}>
          {v}
        </Badge>
      ),
    },
    { key: 'host_count', label: 'Hosts' },
    {
      key: 'started_at',
      label: 'Started',
      render: (v) => (v ? new Date(v).toLocaleString() : '—'),
    },
    {
      key: 'completed_at',
      label: 'Completed',
      render: (v) => (v ? new Date(v).toLocaleString() : '—'),
    },
  ];

  async function handleCompare() {
    if (!scanAId || !scanBId) return;
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

  return (
    <div>
      <PageHeader title="Scan History" subtitle="All scans stored in the database" />
      <ErrorMessage message={error} onDismiss={() => {}} />
      {loading ? (
        <LoadingSpinner text="Loading scan history..." />
      ) : (
        <>
          <Card className="mb-6">
            <div className="flex justify-between items-center mb-4">
              <p className="text-sm text-gray-500">
                {scans.length} scan{scans.length !== 1 ? 's' : ''} total
              </p>
              <Button variant="secondary" onClick={refetch}>
                Refresh
              </Button>
            </div>
            <Table
              columns={columns}
              data={reversedScans}
              emptyMessage="No scans yet. Run a discovery scan from the Dashboard first."
            />
          </Card>

          {/* Scan comparison */}
          <Card title="Compare Scans" className="mb-6">
            <p className="text-sm text-gray-500 mb-4">
              Select Scan A and Scan B using the radio buttons in the table above, then click Compare.
            </p>
            <div className="flex items-center gap-4 flex-wrap mb-4">
              <div className="text-sm">
                <span className="font-medium text-gray-700">Scan A: </span>
                <span className="font-mono text-gray-600">
                  {scanAId ? scanAId.slice(0, 8) + '...' : '—'}
                </span>
              </div>
              <div className="text-sm">
                <span className="font-medium text-gray-700">Scan B: </span>
                <span className="font-mono text-gray-600">
                  {scanBId ? scanBId.slice(0, 8) + '...' : '—'}
                </span>
              </div>
              <Button
                onClick={handleCompare}
                loading={comparing}
                disabled={!scanAId || !scanBId || scanAId === scanBId}
              >
                Compare
              </Button>
            </div>

            <ErrorMessage message={compareError} onDismiss={() => setCompareError(null)} />

            {comparing && <LoadingSpinner text="Comparing scans..." />}

            {compareResult && (
              <div className="mt-4 space-y-4">
                <div>
                  <h4 className="text-sm font-semibold text-green-700 mb-2">
                    New Devices ({compareResult.devices_added?.length ?? 0})
                  </h4>
                  {compareResult.devices_added?.length > 0 ? (
                    <ul className="text-sm text-gray-700 space-y-1 pl-4 list-disc">
                      {compareResult.devices_added.map((ip, i) => (
                        <li key={i} className="font-mono">{ip}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-gray-400">No new devices</p>
                  )}
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-red-700 mb-2">
                    Removed Devices ({compareResult.devices_removed?.length ?? 0})
                  </h4>
                  {compareResult.devices_removed?.length > 0 ? (
                    <ul className="text-sm text-gray-700 space-y-1 pl-4 list-disc">
                      {compareResult.devices_removed.map((ip, i) => (
                        <li key={i} className="font-mono">{ip}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-gray-400">No removed devices</p>
                  )}
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-blue-700 mb-2">Port Changes</h4>
                  {compareResult.ports_opened?.length > 0 && (
                    <div className="mb-2">
                      <p className="text-xs font-medium text-gray-500 mb-1">Ports opened:</p>
                      <ul className="text-sm text-gray-700 space-y-1 pl-4 list-disc">
                        {compareResult.ports_opened.map((p, i) => (
                          <li key={i} className="font-mono">{p}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {compareResult.ports_closed?.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-gray-500 mb-1">Ports closed:</p>
                      <ul className="text-sm text-gray-700 space-y-1 pl-4 list-disc">
                        {compareResult.ports_closed.map((p, i) => (
                          <li key={i} className="font-mono">{p}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {!compareResult.ports_opened?.length && !compareResult.ports_closed?.length && (
                    <p className="text-sm text-gray-400">No port changes</p>
                  )}
                </div>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
