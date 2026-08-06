export type ToastTone = "info" | "success" | "warning" | "error";

export interface Toast {
  id: string;
  message: string;
  tone: ToastTone;
}

export interface ToneStyle {
  color: string;
  border: string;
  background: string;
  shadow: string;
  edge: string;
  sheen: string;
}

const TONES: Record<ToastTone, ToneStyle> = {
  info: {
    color: "rgba(63, 82, 214, 1)",
    border: "rgba(98, 118, 252, 0.44)",
    background: "linear-gradient(180deg, rgba(149, 176, 255, 0.18) 0%, rgba(149, 176, 255, 0.09) 100%)",
    shadow: "0 12px 24px rgba(86, 109, 241, 0.18), inset 0 1px 0 rgba(255,255,255,0.36)",
    edge: "linear-gradient(90deg, rgba(86, 109, 241, 0.00) 0%, rgba(86, 109, 241, 0.30) 45%, rgba(86, 109, 241, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 22%, rgba(255,255,255,0.34) 48%, rgba(255,255,255,0.00) 72%)",
  },
  success: {
    color: "rgba(18, 145, 90, 1)",
    border: "rgba(35, 181, 118, 0.46)",
    background: "linear-gradient(180deg, rgba(108, 231, 170, 0.18) 0%, rgba(108, 231, 170, 0.09) 100%)",
    shadow: "0 12px 24px rgba(34, 166, 111, 0.17), inset 0 1px 0 rgba(255,255,255,0.36)",
    edge: "linear-gradient(90deg, rgba(34, 166, 111, 0.00) 0%, rgba(34, 166, 111, 0.28) 45%, rgba(34, 166, 111, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 22%, rgba(255,255,255,0.30) 48%, rgba(255,255,255,0.00) 72%)",
  },
  warning: {
    color: "rgba(205, 42, 78, 1)",
    border: "rgba(233, 78, 115, 0.50)",
    background: "linear-gradient(180deg, rgba(255, 133, 160, 0.20) 0%, rgba(255, 133, 160, 0.10) 100%)",
    shadow: "0 12px 24px rgba(225, 51, 92, 0.20), inset 0 1px 0 rgba(255,255,255,0.32)",
    edge: "linear-gradient(90deg, rgba(225, 51, 92, 0.00) 0%, rgba(225, 51, 92, 0.30) 45%, rgba(225, 51, 92, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 20%, rgba(255,255,255,0.32) 46%, rgba(255,255,255,0.00) 72%)",
  },
  error: {
    color: "rgba(205, 42, 78, 1)",
    border: "rgba(233, 78, 115, 0.50)",
    background: "linear-gradient(180deg, rgba(255, 133, 160, 0.20) 0%, rgba(255, 133, 160, 0.10) 100%)",
    shadow: "0 12px 24px rgba(225, 51, 92, 0.20), inset 0 1px 0 rgba(255,255,255,0.32)",
    edge: "linear-gradient(90deg, rgba(225, 51, 92, 0.00) 0%, rgba(225, 51, 92, 0.30) 45%, rgba(225, 51, 92, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 20%, rgba(255,255,255,0.32) 46%, rgba(255,255,255,0.00) 72%)",
  },
};

let toasts = $state<Toast[]>([]);
let anchor = $state<{ x: number; y: number } | null>(null);
const toastTimers = new Map<string, ReturnType<typeof setTimeout>>();

export function getToasts(): Toast[] {
  return toasts;
}

export function getAnchor(): { x: number; y: number } | null {
  return anchor;
}

export function setAnchor(pos: { x: number; y: number } | null): void {
  anchor = pos;
}

export function addToast(message: string, tone: ToastTone = "info", durationMs = 2800): void {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  toasts = [...toasts, { id, message, tone }];
  const timer = setTimeout(() => {
    toastTimers.delete(id);
    removeToast(id);
  }, durationMs);
  toastTimers.set(id, timer);
}

export function removeToast(id: string): void {
  const timer = toastTimers.get(id);
  if (timer !== undefined) {
    clearTimeout(timer);
    toastTimers.delete(id);
  }
  toasts = toasts.filter((t) => t.id !== id);
}

export function getToneStyle(tone: ToastTone): ToneStyle {
  return TONES[tone];
}

export function notify(message: string): void {
  addToast(message, "info");
}

export function notifySuccess(message: string): void {
  addToast(message, "success");
}

export function notifyWarning(message: string): void {
  addToast(message, "warning");
}

export function notifyError(message: string): void {
  addToast(message, "error");
}
