import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDevices } from '../hooks/useDevices';
import { updateApproval } from '../services/scanService';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Table from '../components/Table';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import Badge from '../components/Badge';

function approvalVariant(status) {
  if (status === 'approved') return 'green';
  if (status === 'revoked') return 'red';
  return 'yellow';
}

export default function NetworkDevices() {
  const navigate = useNavigate();
  const [viewMode, setViewMode] = useState('latest'); // 'latest' or 'all'
  const { devices, loading, error, refetch } = useDevices(viewMode);
  const [actionError, setActionError] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);

  async function handleApproval(deviceId, newStatus) {
    if (!deviceId) {
      setActionError('This device has no database record. Run a new discovery scan first.');
      return;
    }
    setActionError(null);
    setActionSuccess(null);
    setUpdatingId(deviceId);
    try {
      await updateApproval(deviceId, newStatus);
      setActionSuccess(`Device ${newStatus === 'approved' ? 'approved ✓' : 'revoked ✗'} successfully.`);
      await refetch();
    } catch (err) {
      setActionError(`Update failed: ${err.message}`);
    } finally {
      setUpdatingId(null);
    }
  }

  const columns = [
    {
      key: 'last_known_ip',
      label: 'IP Address',
      render: (v, row) => v || row.ip_address || '--',
    },
    {
      key: 'mac_address',
      label: 'MAC Address',
      render: (v) => v || '--',
    },
    {
      key: 'hostname',
      label: 'Hostname',
      render: (v) => v || '--',
    },
    {
      key: 'approval_status',
      label: 'Status',
      render: (v) => {
        const status = v || 'pending_review';
        return <Badge variant={approvalVariant(status)}>{status}</Badge>;
      },
    },
    {
      key: 'first_seen',
      label: 'First Seen',
      render: (v) => v ? new Date(v).toLocaleString() : '--',
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (v) => v ? new Date(v).toLocaleString() : '--',
    },
    {
      key: 'device_id',
      label: 'Actions',
      render: (deviceId, row) => {
        const ip = row.last_known_ip || row.ip_address || '';
        const isUpdating = updatingId === deviceId;
        const status = row.approval_status || 'pending_review';
        const hasDbRecord = Boolean(deviceId);

        return (
          <div className="flex gap-2 flex-wrap items-center">
            <Button
              variant="secondary"
              onClick={() => navigate(`/port-scanner?ip=${ip}`)}
              className="py-1 px-2 text-xs"
            >
              Scan Ports
            </Button>

            {hasDbRecord && status !== 'approved' && (
              <Button
                variant="primary"
                loading={isUpdating}
                disabled={isUpdating}
                onClick={() => handleApproval(deviceId, 'approved')}
                className="py-1 px-2 text-xs"
              >
                Approve
              </Button>
            )}

            {hasDbRecord && status === 'approved' && (
              <Button
                variant="danger"
                loading={isUpdating}
                disabled={isUpdating}
                onClick={() => handleApproval(deviceId, 'revoked')}
                className="py-1 px-2 text-xs"
              >
                Revoke
              </Button>
            )}

            {hasDbRecord && status === 'revoked' && (
              <Button
                variant="primary"
                loading={isUpdating}
                disabled={isUpdating}
                onClick={() => handleApproval(deviceId, 'approved')}
                className="py-1 px-2 text-xs"
              >
                Re-approve
              </Button>
            )}

            {!hasDbRecord && (
              <span className="text-xs text-gray-400 italic">Run new scan</span>
            )}
          </div>
        );
      },
    },
  ];

  return (
    <div>
      <PageHeader
        title="Network Devices"
        subtitle={viewMode === 'latest' ? 'Devices from the latest discovery scan' : 'All devices ever discovered'}
      />

      {/* Success banner */}
      {actionSuccess && (
        <div className="mb-4 px-4 py-3 bg-green-50 border border-green-200 text-green-800 rounded-md text-sm flex justify-between items-center">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="ml-4 text-green-600 hover:text-green-800 font-bold">✕</button>
        </div>
      )}

      <ErrorMessage message={actionError} onDismiss={() => setActionError(null)} />
      <ErrorMessage message={error} onDismiss={() => {}} />

      {loading ? (
        <LoadingSpinner text="Loading devices..." />
      ) : (
        <Card>
          <div className="flex justify-between items-center mb-4 flex-wrap gap-3">
            <div className="flex items-center gap-2">
              <p className="text-sm text-gray-500">
                {devices.length} device{devices.length !== 1 ? 's' : ''}
                {viewMode === 'latest' ? ' from latest scan' : ' in total history'}
              </p>
            </div>

            {/* View mode toggle */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500">Show:</span>
              <div className="flex rounded-lg border border-gray-200 overflow-hidden text-xs">
                <button
                  onClick={() => setViewMode('latest')}
                  className={`px-3 py-1.5 font-medium transition-colors ${
                    viewMode === 'latest'
                      ? 'bg-blue-600 text-white'
                      : 'bg-white text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  Current Network
                </button>
                <button
                  onClick={() => setViewMode('all')}
                  className={`px-3 py-1.5 font-medium transition-colors border-l border-gray-200 ${
                    viewMode === 'all'
                      ? 'bg-blue-600 text-white'
                      : 'bg-white text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  All History
                </button>
              </div>
              <Button variant="secondary" onClick={refetch} className="text-xs py-1 px-2">
                Refresh
              </Button>
            </div>
          </div>

          {/* Info banner for latest mode */}
          {viewMode === 'latest' && (
            <div className="mb-4 px-3 py-2 bg-blue-50 border border-blue-200 rounded text-xs text-blue-700">
              Showing devices from your <strong>most recent discovery scan</strong>.
              Switch to <strong>All History</strong> to see devices from all networks and previous scans.
            </div>
          )}

          {/* Info banner for all history mode */}
          {viewMode === 'all' && (
            <div className="mb-4 px-3 py-2 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-700">
              Showing <strong>all devices ever discovered</strong> including previous networks.
              Switch to <strong>Current Network</strong> to see only the latest scan.
            </div>
          )}

          <Table
            columns={columns}
            data={devices}
            emptyMessage={
              viewMode === 'latest'
                ? 'No devices from the latest scan. Run a discovery scan from the Dashboard first.'
                : 'No devices found in history.'
            }
          />
        </Card>
      )}
    </div>
  );
}
