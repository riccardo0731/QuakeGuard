import React, {
    createContext,
    ReactNode,
    useContext,
    useEffect,
    useRef,
    useState,
} from "react";
import { Vibration } from "react-native";
import { API_BASE_URL } from "../constants/config";

// Definizione Tipi
interface AlertMessage {
  type: string;
  zone_id: number;
  magnitude: number;
  message: string;
  timestamp: string;
}

interface WebSocketContextType {
  isConnected: boolean;
  lastAlert: AlertMessage | null;
}

const WebSocketContext = createContext<WebSocketContextType | null>(null);

export const WebSocketProvider = ({ children }: { children: ReactNode }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastAlert, setLastAlert] = useState<AlertMessage | null>(null);
  const ws = useRef<WebSocket | null>(null);

  const connect = () => {
    // Sostituisci http con ws nell'URL
    const wsUrl = API_BASE_URL.replace("http", "ws") + "/ws/alerts";
    console.log("🔌 Tentativo connessione WS:", wsUrl);

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log("✅ WS Connesso");
      setIsConnected(true);
    };

    ws.current.onmessage = (e) => {
      try {
        const message: AlertMessage = JSON.parse(e.data);
        console.log("⚡ ALERT RICEVUTO:", message);

        setLastAlert(message);

        // Feedback immediato se critico
        if (message.type === "CRITICAL") {
          // Vibrazione pattern SOS (3 brevi, 3 lunghi, 3 brevi)
          Vibration.vibrate([
            0, 200, 100, 200, 100, 200, 300, 500, 300, 500, 300, 500, 300, 200,
            100, 200, 100, 200,
          ]);
        }
      } catch (err) {
        console.error("Errore parsing messaggio WS", err);
      }
    };

    ws.current.onclose = () => {
      console.log("❌ WS Disconnesso");
      setIsConnected(false);
      // Riprova a connetterti tra 5 secondi (Reconnection Logic)
      setTimeout(connect, 5000);
    };

    ws.current.onerror = (e) => {
      console.log("⚠️ WS Errore:", e);
    };
  };

  useEffect(() => {
    connect();
    return () => {
      ws.current?.close();
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{ isConnected, lastAlert }}>
      {children}
    </WebSocketContext.Provider>
  );
};

// Hook custom per usare il context facilmente
export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error(
      "useWebSocket deve essere usato dentro un WebSocketProvider",
    );
  }
  return context;
};
