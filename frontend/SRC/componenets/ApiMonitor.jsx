import { useEffect, useState } from "react";
import axios from "axios";
import { getBackendUrl } from "../utils/api";

export default function ApiMonitor() {
  const [endpoints, setEndpoints] = useState([]);
  const [status, setStatus] = useState("Checking...");

  useEffect(() => {
    const fetchEndpoints = async () => {
      const base = getBackendUrl();
      try {
        const res = await axios.get(`${base}/openapi.json`);
        const paths = Object.keys(res.data.paths);
        setEndpoints(paths);
        setStatus("Online ✅");
      } catch (e) {
        setStatus("Offline ❌");
      }
    };
    fetchEndpoints();
  }, []);

  return (
    <div className="bg-white p-4 rounded-2xl shadow-md">
      <h2 className="text-xl font-semibold mb-2">API Monitor</h2>
      <p className="text-sm mb-3 text-gray-600">Status: {status}</p>
      <ul className="list-disc ml-4 text-sm">
        {endpoints.map((ep) => (
          <li key={ep} className="text-gray-700">{ep}</li>
        ))}
      </ul>
    </div>
  );
}