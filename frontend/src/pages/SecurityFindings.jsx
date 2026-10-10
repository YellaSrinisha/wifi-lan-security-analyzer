import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Table from '../components/Table';

const placeholderColumns = [
  { key: 'severity', label: 'Severity' },
  { key: 'finding', label: 'Finding' },
  { key: 'device', label: 'Device' },
  { key: 'recommendation', label: 'Recommendation' },
];

export default function SecurityFindings() {
  return (
    <div>
      <PageHeader title="Security Findings" subtitle="Automated security analysis of discovered devices" />
      <Card className="mb-4">
        <div className="text-center py-6">
          <svg className="mx-auto h-12 w-12 text-gray-300 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <h3 className="text-base font-medium text-gray-700 mb-1">Security Analysis Engine</h3>
          <p className="text-sm text-gray-500 max-w-sm mx-auto">
            The automated security analysis engine will be implemented in <strong>Module 2</strong>.
            It will analyze open ports, identify known vulnerabilities, and provide remediation recommendations.
          </p>
        </div>
      </Card>
      <Card title="Findings Table (Module 2 Preview)">
        <Table
          columns={placeholderColumns}
          data={[]}
          emptyMessage="No findings yet. Security analysis will be available in Module 2."
        />
      </Card>
    </div>
  );
}
