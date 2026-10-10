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
  return 'yellow'; // pending_review
}

export default function NetworkDevices() {
  const navigate = useNavigate();
  const { devices, loading, error, refetch } = useDevices();

  async function handleApproval(deviceId, status) {
    try {
      await updateApproval(deviceId, status);
      await refetch();
    } catch (err) {
      // Surface error via console; the table row will stay unchanged
      console.error('Approval update failed:', err.message);
    }
  }

  const columns = [
    {
      key: 'last_known_ip',
      label: 'IP Address',
      // fall back to ip_address for in-memory rows that don't have last_known_ip
      render: (v, row) => v || row.ip_address || '—',
    },
    { key: 'mac_address', label: 'MAC Address', render: (v) => v || '—' },
    { key: 'hostname', label: 'Hostname', render: (v) => v || '—' },
    {
      key: 'approval_status',
      label: 'Status',
      render: (v, row) => {
        // in-memory rows from nmap_service won't have approval_status
        if (!row.device_id) return <Badge variant="gray">unknown</Badge>;
        return <Badge variant={approvalVariant(v)}>{v || 'pending_review'}</Badge>;
      },
    },
    {
      key: 'first_seen',
      label: 'First Seen',
      render: (v) => (v ? new Date(v).toLocaleString() : '—'),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      render: (v, row) => {
        const ts = v || row.last_seen;
        return ts ? new Date(ts).toLocaleString() : '—';
      },
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (_v, row) => {
        // IP to navigate to port scanner — prefer last_known_ip, fall back to ip_address
        const ip = row.last_known_ip || row.ip_address || '';
        return (
          <div className="flex gap-2 flex-wrap">
            <Button
              variant="secondary"
              onClick={() => navigate(`/port-scanner?ip=${ip}`)}
              className="py-1 px-2 text-xs"
            >
              Scan Ports
            </Button>
            {/* Only show approve/revoke when the device has a DB record */}
            {row.device_id && row.approval_status !== 'approved' && (
              <Button
                variant="primary"
                onClick={() => handleApproval(row.device_id, 'approved')}
                className="py-1 px-2 text-xs"
              >
                Approve
              </Button>
            )}
            {row.device_id && row.approval_status === 'approved' && (
              <Button
                variant="danger"
                onClick={() => handleApproval(row.device_id, 'revoked')}
                className="py-1 px-2 text-xs"
              >
                Revoke
              </Button>
            )}
          </div>
        );
      },
    },
  ];

  return (
    <div>
      <PageHeader title="Network Devices" subtitle="Devices discovered on your local network" />
      <ErrorMessage message={error} onDismiss={() => {}} />
      {loading ? (
        <LoadingSpinner text="Loading devices..." />
      ) : (
        <Card>
          <div className="flex justify-between items-center mb-4">
            <p className="text-sm text-gray-500">
              {devices.length} device{devices.length !== 1 ? 's' : ''} found
            </p>
            <Button variant="secondary" onClick={refetch}>
              Refresh
            </Button>
          </div>
          <Table
            columns={columns}
            data={devices}
            emptyMessage="No devices found. Run a discovery scan from the Dashboard first."
          />
        </Card>
      )}
    </div>
  );
}
