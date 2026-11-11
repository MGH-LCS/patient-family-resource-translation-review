// Settings for the translation review page.
// The key below is Supabase's public key: it is safe to ship in a web page.
// What reviewers may read or write is decided by the table's row rules, and
// only someone who knows the review password can sign in.

export const SUPABASE_URL = 'https://qaqqpnjerjjyuygjqwpf.supabase.co';
export const SUPABASE_KEY = 'sb_publishable_vv6cd3z8vRDlmNQPHkBtrA_NfAdmCzo';

// The shared reviewer account. Empty until the review is set up; while it is
// empty the unlock screen says so instead of asking for the password.
export const REVIEWER_EMAIL = '';

export const TABLE = 'translation_suggestions';

// Shown under the page title.
export const APP_SUBTITLE = 'MGB for Children · Family Resource app';
