import { BrowserRouter, Routes, Route } from 'react-router-dom';
import MainLayout from './layouts/MainLayout';
import Dashboard from './pages/Dashboard';
import NetworkDevices from './pages/NetworkDevices';
import PortScanner from './pages/PortScanner';
import SecurityFindings from './pages/SecurityFindings';
import ScanHistory from './pages/ScanHistory';
import Reports from './pages/Reports';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="devices" element={<NetworkDevices />} />
          <Route path="port-scanner" element={<PortScanner />} />
          <Route path="findings" element={<SecurityFindings />} />
          <Route path="history" element={<ScanHistory />} />
          <Route path="reports" element={<Reports />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
