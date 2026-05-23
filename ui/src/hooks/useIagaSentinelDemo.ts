import { useEffect, useState } from "react";
import { type AIState, type NeuronPulseKind, useVisualStore } from "../store/useVisualStore";

type DemoStage = "observe" | "correlate" | "govern" | "report";

export interface DemoStep {
  state: AIState;
  stage: DemoStage;
  badge: string;
  stateLabel: string;
  focusCluster: string;
  headline: string;
  description: string;
  traces: string[];
  pulseTargets: string[];
}

export const DEMO_STEPS: DemoStep[] = [
  {
    state: "listening",
    stage: "observe",
    badge: "mcp ingress",
    stateLabel: "Observing live tool intent",
    focusCluster: "session_graph",
    headline: "Every action enters through an inspected protocol surface.",
    description:
      "IAGA Sentinel reads the envelope first: tool name, payload shape, workspace context, and session metadata are all collected before the runtime decides how far execution can go.",
    traces: [
      "Parsing MCP and agent metadata before tool execution.",
      "Attaching session lineage to the incoming action envelope.",
      "Routing evidence into the layered governance graph.",
    ],
    pulseTargets: ["session_graph", "taint_tracking", "nhi_identity", "adaptive_risk"],
  },
  {
    state: "thinking",
    stage: "correlate",
    badge: "risk fusion",
    stateLabel: "Correlating layered evidence",
    focusCluster: "adaptive_risk",
    headline: "Risk is computed from multiple signals, not a single rule match.",
    description:
      "Sequence memory, identity posture, threat indicators, and workspace policy all converge into a runtime score that can explain why an action should pass, pause, or stop.",
    traces: [
      "Linking session graph anomalies to recent behavior.",
      "Combining identity posture with threat-intel confidence.",
      "Preparing evidence for policy and sandbox evaluation.",
    ],
    pulseTargets: ["adaptive_risk", "session_graph", "nhi_identity", "policy_engine"],
  },
  {
    state: "executing",
    stage: "govern",
    badge: "policy gate",
    stateLabel: "Enforcing governance in real time",
    focusCluster: "policy_engine",
    headline: "The runtime decides allow, review, or block before impact fans out.",
    description:
      "Policies, dry-run sandbox analysis, and the injection firewall operate as a coordinated gate. What matters is not only the command itself, but the context and the likely blast radius.",
    traces: [
      "Checking workspace rules and policy templates.",
      "Estimating destructive impact through sandbox planning.",
      "Passing suspicious prompts through the firewall stages.",
    ],
    pulseTargets: ["policy_engine", "sandbox", "injection_firewall", "taint_tracking"],
  },
  {
    state: "speaking",
    stage: "report",
    badge: "operator view",
    stateLabel: "Reporting evidence back to humans",
    focusCluster: "telemetry",
    headline: "Governance is only useful if operators can understand what happened.",
    description:
      "Telemetry, audit, and response scanning turn each decision into a readable trail. That makes the runtime practical for dashboards, review queues, exports, and SDK integrations.",
    traces: [
      "Persisting audit evidence and trace identifiers.",
      "Surfacing operator-facing review and export paths.",
      "Summarizing the decision for dashboards and SDK clients.",
    ],
    pulseTargets: ["telemetry", "policy_engine", "nhi_identity", "session_graph"],
  },
];

const STEP_DURATION_MS = 5200;
const AUDIO_TICK_MS = 120;
const PULSE_TICK_MS = 320;

const PULSE_KIND_BY_STAGE: Record<DemoStage, NeuronPulseKind> = {
  observe: "observe",
  correlate: "analyze",
  govern: "govern",
  report: "report",
};

export function useIagaSentinelDemo() {
  const [stepIndex, setStepIndex] = useState(0);
  const setAIState = useVisualStore((state) => state.setAIState);
  const setFocusedCluster = useVisualStore((state) => state.setFocusedCluster);
  const setAudioLevel = useVisualStore((state) => state.setAudioLevel);
  const firePulse = useVisualStore((state) => state.firePulse);
  const prunePulses = useVisualStore((state) => state.prunePulses);
  const step = DEMO_STEPS[stepIndex];

  useEffect(() => {
    const interval = window.setInterval(() => {
      setStepIndex((current) => (current + 1) % DEMO_STEPS.length);
    }, STEP_DURATION_MS);

    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    setAIState(step.state);
    setFocusedCluster(step.focusCluster);
  }, [setAIState, setFocusedCluster, step.focusCluster, step.state]);

  useEffect(() => {
    let tick = 0;
    const interval = window.setInterval(() => {
      tick += 1;
      const level =
        step.state === "listening"
          ? 0.32 + Math.abs(Math.sin(tick * 0.42)) * 0.46
          : 0.03 + Math.abs(Math.sin(tick * 0.14)) * 0.08;
      setAudioLevel(level);
    }, AUDIO_TICK_MS);

    return () => window.clearInterval(interval);
  }, [setAudioLevel, step.state]);

  useEffect(() => {
    let targetIndex = 0;
    firePulse(PULSE_KIND_BY_STAGE[step.stage], 0.95, step.focusCluster);

    const pulseInterval = window.setInterval(() => {
      const cluster = step.pulseTargets[targetIndex % step.pulseTargets.length];
      const intensity = 0.55 + (targetIndex % 3) * 0.14;
      firePulse(PULSE_KIND_BY_STAGE[step.stage], intensity, cluster);
      prunePulses();
      targetIndex += 1;
    }, PULSE_TICK_MS);

    return () => window.clearInterval(pulseInterval);
  }, [firePulse, prunePulses, step.focusCluster, step.pulseTargets, step.stage]);

  return step;
}
