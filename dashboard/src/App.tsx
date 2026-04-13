import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';
import Overview from './pages/Overview';
import Sessions from './pages/Sessions';
import SessionDetail from './pages/SessionDetail';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Policies from './pages/Policies';
import PolicyEditor from './pages/PolicyEditor';
import Replay from './pages/Replay';
import Analytics from './pages/Analytics';
import Organizations from './pages/Organizations';
import ApiKeys from './pages/ApiKeys';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-950 text-gray-100 overflow-hidden">
        <Sidebar />
        <div className="flex flex-col flex-1 overflow-hidden">
          <Header />
          <main className="flex-1 overflow-y-auto p-6">
            <Routes>
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<Overview />} />
              <Route path="/sessions" element={<Sessions />} />
              <Route path="/sessions/:id" element={<SessionDetail />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/policies" element={<Policies />} />
              <Route path="/policies/new" element={<PolicyEditor />} />
              <Route path="/policies/:id/edit" element={<PolicyEditor />} />
              <Route path="/replay/:sessionId" element={<Replay />} />
              <Route path="/analytics" element={<Analytics />} />
              <Route path="/organizations" element={<Organizations />} />
              <Route path="/apikeys" element={<ApiKeys />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}
