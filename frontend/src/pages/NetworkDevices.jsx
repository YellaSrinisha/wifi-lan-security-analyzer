import { useNavigate } from 'react-router-dom';
import { useDevices } from '../hooks/useDevices';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Table from '../components/Table';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';
import Badge from '../components/Badge';

export default function NetworkDevices() {
  const navigate = useNavigate();
  const { devices, loading, error, refetch } = useDevices();

  const columns = [
    { key: 'ip_address', label: 'IP Address' },
    { key: 'mac_address', label: 'MAC Address' },
    { key: 'hostname', label: 'Hostname' },
    { key: 'state', label: 'State', render: (v) => <Badge variant={v === 'up' ? 'green' : 'gray'}>{v || 'unknown'}</Badge> },
    { key: 'last_seen', label: 'Last Seen', render: (v) => v ? new Date(v).toLocaleString() : '—' },
    {
      key: 'ip_address',
      label: 'Actions',
      render: (ip) => (
        <Button variant="secondary" onClick={() => navigate(`/port-scanner?ip=${ip}`)}
          className="py-1 px-2 text-xs">
          Scan Ports
        </Button>
      )
    },
  ];

  return (
    <div>
      <PageHeader title="Network Devices" subtitle="Devices discovered on your local network" />
      <ErrorMessage message={error} onDismiss={() => {}} />
      {loading ? <LoadingSpinner text="Loading devices..." /> : (
        <Card>
          <div className="flex justify-between items-center mb-4">
            <p className="text-sm text-gray-500">{devices.length} device{devices.length !== 1 ? 's' : ''} found</p>
            <Button variant="secondary" onClick={refetch}>Refresh</Button>
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
