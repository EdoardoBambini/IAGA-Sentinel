import { NeuralScene } from "./components/core/NeuralScene";
import { useIagaSentinelDemo } from "./hooks/useIagaSentinelDemo";

export function App() {
  useIagaSentinelDemo();

  return <NeuralScene />;
}
