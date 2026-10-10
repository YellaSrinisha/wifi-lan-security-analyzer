import { useScans } from '../hooks/useScans';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Table from '../components/Table';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorMessage from '../components/ErrorMessage';

export default function ScanHistory() {
  const { scans, loading, error, refetch } = useScans();

  const columns = [
    { key: 'scan_id', label: 'Scan ID', render: (v) => v?.slice(0, 8) + '...' },
    { key: 'scan_type', label: 'Type' },
    { key: 'target', label: 'Target' },
    { key: 'status', label: 'Status', render: (v) => <Badge variant={v === 'completed' ? 'green' : v === 'error' ? 'red' : 'gray'}>{v}</Badge> },
    { key: 'host_count', label: 'Hosts' },
    { key: 'started_at', label: 'Started', render: (v) => v ? new Date(v).toLocaleString() : '—' },
  ];

  return (
    <div>
      <PageHeader title="Scan History" subtitle="All scans performed this session" />
      <div className="text-sm text-blue-700 bg-blue-50 border border-blue-200 rounded-md px-3 py-2 mb-4">
        ℹ History is session-only. Persistent history and export will be available in Module 2.
      </div>
      <ErrorMessage message={error} onDismiss={() => {}} />
      {loading ? <LoadingSpinner text="Loading scan history..." /> : (
        <Card>
          <div className="flex justify-between items-center mb-4">
            <p className="text-sm text-gray-500">{scans.length} scan{scans.length !== 1 ? 's' : ''} this session</p>
            <Button variant="secondary" onClick={refetch}>Refresh</Button>
          </div>
          <Table columns={columns} data={[...scans].reverse()} emptyMessage="No scans yet this session." />
        </Card>
      )}
    </div>
  );
}
