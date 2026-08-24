export const ENGLISH_MESSAGES = {
  "desktop.nav.tunnels": "Tunnels",
  "desktop.nav.settings": "Configuration",
  "desktop.nav.logs": "Logs",
  "desktop.nav.about": "About",
  "desktop.nav.primary": "Primary",
  "desktop.brand.logo": "QuicFuscate logo",
  "desktop.fatal.title": "Something went wrong",
  "desktop.fatal.body": "An unexpected desktop UI error occurred. Retry the view or restart the app.",
  "admin.nav.dashboard": "Dashboard",
  "admin.nav.configuration": "Configuration",
  "admin.nav.logs": "Logs",
  "admin.nav.about": "About",
  "admin.nav.logout": "Logout",
  "admin.nav.primary": "Primary",
  "admin.brand.logo": "QuicFuscate logo",
  "admin.fatal.title": "Something went wrong",
  "admin.login.title": "Admin Login",
} as const;

export type MessageKey = keyof typeof ENGLISH_MESSAGES;
export type Locale = "en";

const catalogs: Record<Locale, Record<MessageKey, string>> = {
  en: ENGLISH_MESSAGES,
};

let activeLocale: Locale = "en";

export function setLocale(locale: Locale): void {
  activeLocale = locale;
}

export function getLocale(): Locale {
  return activeLocale;
}

export function t(key: MessageKey): string {
  const value = catalogs[activeLocale][key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Missing i18n message for ${key}`);
  }
  return value;
}

export function availableLocales(): Locale[] {
  return ["en"];
}
