import type { ScanResult } from '../types';

export interface LocalIntelligenceResult {
  scanResult: ScanResult;
  phishingProbability: number;
  indicatorScore: number;
}

type Indicator = {
  label: string;
  description: string;
  weight: number;
};

const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'];
const SUSPICIOUS_TLDS = ['top', 'xyz', 'click', 'work', 'support', 'zip', 'country', 'gq', 'tk', 'ml', 'cf', 'rest'];
const BRAND_TERMS = ['paypal', 'microsoft', 'apple', 'google', 'bank', 'chase', 'amazon', 'office365', 'netflix', 'whatsapp'];
const URL_LURE_TERMS = ['login', 'verify', 'secure', 'account', 'update', 'signin', 'reset', 'billing', 'confirm'];

const EMAIL_URGENCY_TERMS = ['urgent', 'immediately', 'asap', 'now', 'final warning', 'act now', 'limited time'];
const EMAIL_CREDENTIAL_TERMS = ['password', 'verify account', 'confirm account', 'security check', 'credential', 'login now'];
const EMAIL_THREAT_TERMS = ['suspended', 'disabled', 'locked', 'terminated', 'blocked', 'breach', 'unauthorized'];
const EMAIL_FINANCE_TERMS = ['bank', 'transfer', 'invoice', 'payment', 'gift card', 'crypto', 'bitcoin', 'wallet'];
const EMAIL_IMPERSONATION_TERMS = ['dear customer', 'support team', 'it admin', 'security team', 'compliance desk'];

const clamp01 = (value: number) => Math.max(0, Math.min(1, value));
const clampPercent = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

const wordBoundaryCount = (content: string, value: string) => {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`\\b${escaped}\\b`, 'gi');
  return content.match(regex)?.length ?? 0;
};

const countTermMatches = (content: string, terms: string[]) =>
  terms.reduce((total, term) => total + wordBoundaryCount(content, term), 0);

const sigmoidProbability = (score: number, center: number, spread: number) => 1 / (1 + Math.exp(-(score - center) / spread));

const riskFromProbability = (probability: number): ScanResult['risk'] => {
  if (probability >= 0.85) {
    return 'Critical';
  }
  if (probability >= 0.65) {
    return 'High';
  }
  if (probability >= 0.4) {
    return 'Medium';
  }
  return 'Low';
};

const defaultMitre = (category: ScanResult['category']) => {
  if (category === 'Malware') {
    return { technique: 'T1204.002', tactic: 'Execution' };
  }
  if (category === 'Spoofing') {
    return { technique: 'T1566.001', tactic: 'Initial Access' };
  }
  if (category === 'Social') {
    return { technique: 'T1598.003', tactic: 'Reconnaissance' };
  }
  if (category === 'Phishing') {
    return { technique: 'T1566.001', tactic: 'Initial Access' };
  }
  return { technique: 'T1589.001', tactic: 'Reconnaissance' };
};

const toTechnicalDetails = (indicators: Indicator[]) =>
  indicators
    .sort((first, second) => second.weight - first.weight)
    .slice(0, 6)
    .map((item) => ({ label: item.label, description: item.description }));

const analyzeUrlLocally = (content: string): LocalIntelligenceResult => {
  const trimmed = content.trim();
  const normalized = trimmed.toLowerCase();
  const indicators: Indicator[] = [];
  let score = 0;

  const addIndicator = (label: string, description: string, weight: number) => {
    indicators.push({ label, description, weight });
    score += weight;
  };

  const parseCandidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  let host = '';
  let path = '';
  let protocol = '';
  let port = '';

  try {
    const parsed = new URL(parseCandidate);
    host = parsed.hostname.toLowerCase();
    path = `${parsed.pathname}${parsed.search}`.toLowerCase();
    protocol = parsed.protocol.toLowerCase();
    port = parsed.port;
  } catch {
    addIndicator('Malformed URL', 'The URL format is invalid or intentionally obfuscated.', 26);
  }

  if (protocol && protocol !== 'https:') {
    addIndicator('Insecure transport', 'URL does not use HTTPS encryption.', 8);
  }

  if (normalized.includes('@')) {
    addIndicator('Credential masking token', 'Contains "@" in URL, often used to hide the real destination.', 16);
  }

  if (host) {
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      addIndicator('Raw IP destination', 'Destination host is a direct IP address.', 24);
    }

    if (host.includes('xn--')) {
      addIndicator('Punycode host', 'Host uses punycode and may imitate a trusted brand.', 18);
    }

    if (URL_SHORTENERS.some((value) => host === value || host.endsWith(`.${value}`))) {
      addIndicator('Shortened URL', 'Uses a URL shortener that obscures the final destination.', 14);
    }

    const domainParts = host.split('.').filter(Boolean);
    const tld = domainParts.at(-1) || '';
    if (SUSPICIOUS_TLDS.includes(tld)) {
      addIndicator('High-risk domain zone', `Domain uses a frequently abused TLD (.${tld}).`, 12);
    }

    const subdomainDepth = Math.max(0, domainParts.length - 2);
    if (subdomainDepth >= 3) {
      addIndicator('Deep subdomain chain', 'Unusually deep subdomain structure detected.', 10);
    }

    const brandInHost = BRAND_TERMS.filter((brand) => host.includes(brand));
    if (brandInHost.length > 0 && domainParts.length > 2) {
      addIndicator('Possible brand spoofing', `Host references brand term(s): ${brandInHost.join(', ')}.`, 14);
    }

    const hostHyphenCount = host.match(/-/g)?.length ?? 0;
    if (hostHyphenCount >= 3) {
      addIndicator('Host obfuscation', 'Multiple hyphens in domain may indicate typo-squatting.', 6);
    }

    const hostDigitCount = host.match(/\d/g)?.length ?? 0;
    if (hostDigitCount >= 6) {
      addIndicator('Digit-heavy domain', 'Destination host contains an unusually high number of digits.', 5);
    }
  }

  const encodedSequences = normalized.match(/%[0-9a-f]{2}/g)?.length ?? 0;
  if (encodedSequences >= 4) {
    addIndicator('Encoded payload hints', 'URL contains many encoded sequences.', 8);
  }

  if (trimmed.length >= 120) {
    addIndicator('Excessive URL length', `URL length is ${trimmed.length} characters.`, 10);
  }

  const lureCount = countTermMatches(path || normalized, URL_LURE_TERMS);
  if (lureCount > 0) {
    addIndicator('Credential lure terms', `Detected ${lureCount} credential-targeting term(s) in path/query.`, Math.min(16, lureCount * 4));
  }

  if (/\.(exe|scr|js|vbs|msi|apk|cmd|bat|zip)(\?|$)/i.test(path || normalized)) {
    addIndicator('Executable delivery pattern', 'URL references a potentially executable or archive payload.', 18);
  }

  if (port && !['80', '443'].includes(port)) {
    addIndicator('Non-standard port', `URL uses uncommon destination port ${port}.`, 6);
  }

  const probability = clamp01(sigmoidProbability(score, 40, 10));
  const risk = riskFromProbability(probability);
  const category: ScanResult['category'] =
    indicators.some((item) => item.label === 'Executable delivery pattern')
      ? 'Malware'
      : indicators.some((item) => item.label === 'Possible brand spoofing' || item.label === 'Punycode host')
        ? 'Spoofing'
        : probability >= 0.45
          ? 'Phishing'
          : 'Other';
  const mitre = defaultMitre(category);
  const suspicious = category !== 'Other' || probability >= 0.45;

  const scanResult: ScanResult = {
    summary: suspicious
      ? 'The URL exhibits phishing or destination-masking behavior and should be treated as suspicious.'
      : 'The URL appears lower risk, but destination validation is still recommended.',
    detailedSummary: `Local intelligence scored this URL at ${Math.round(probability * 100)}% phishing likelihood using ${
      indicators.length
    } indicator(s).`,
    confidence: clampPercent((suspicious ? probability : 1 - probability) * 100),
    recommendation: suspicious
      ? 'Open this URL only in an isolated environment, verify the domain owner, and block distribution if untrusted.'
      : 'Proceed with caution and verify destination authenticity before sharing.',
    risk,
    category,
    impactScore: Number((Math.max(1.5, probability * 9.5)).toFixed(1)),
    mitreTechnique: mitre.technique,
    mitreTactic: mitre.tactic,
    technicalDetails:
      toTechnicalDetails(indicators).length > 0
        ? toTechnicalDetails(indicators)
        : [{ label: 'Low-signal URL', description: 'No major high-risk indicators were detected in this URL.' }],
    analysisSource: 'local-intelligence',
    analysisSourceLabel: 'On-device threat intelligence',
  };

  return {
    scanResult,
    phishingProbability: probability,
    indicatorScore: score,
  };
};

const analyzeEmailLocally = (content: string): LocalIntelligenceResult => {
  const trimmed = content.trim();
  const normalized = trimmed.toLowerCase();
  const indicators: Indicator[] = [];
  let score = 0;

  const addIndicator = (label: string, description: string, weight: number) => {
    indicators.push({ label, description, weight });
    score += weight;
  };

  const numLinks = normalized.match(/https?:\/\/[^\s]+|www\.[^\s]+/gi)?.length ?? 0;
  if (numLinks > 0) {
    addIndicator('Embedded links', `Email contains ${numLinks} URL link(s).`, Math.min(16, numLinks * 4));
  }

  if (/(https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$))/i.test(normalized)) {
    addIndicator('IP-based link', 'Email includes a link pointing to a raw IP address.', 20);
  }

  const urgencyCount = countTermMatches(normalized, EMAIL_URGENCY_TERMS);
  if (urgencyCount > 0) {
    addIndicator('Urgency pressure language', `Detected ${urgencyCount} urgency term(s).`, Math.min(12, urgencyCount * 3));
  }

  const credentialCount = countTermMatches(normalized, EMAIL_CREDENTIAL_TERMS);
  if (credentialCount > 0) {
    addIndicator('Credential request signals', `Detected ${credentialCount} credential-oriented phrase(s).`, Math.min(18, credentialCount * 5));
  }

  const threatCount = countTermMatches(normalized, EMAIL_THREAT_TERMS);
  if (threatCount > 0) {
    addIndicator('Account-threat framing', `Detected ${threatCount} suspension or compromise threat phrase(s).`, Math.min(12, threatCount * 4));
  }

  const financeCount = countTermMatches(normalized, EMAIL_FINANCE_TERMS);
  if (financeCount > 0) {
    addIndicator('Financial lure content', `Detected ${financeCount} finance/payment term(s).`, Math.min(16, financeCount * 4));
  }

  const impersonationCount = countTermMatches(normalized, EMAIL_IMPERSONATION_TERMS);
  if (impersonationCount > 0) {
    addIndicator('Impersonation cues', `Detected ${impersonationCount} generic authority cue(s).`, Math.min(9, impersonationCount * 3));
  }

  if (/(verify|confirm|reset).{0,32}(account|password|identity)/i.test(normalized)) {
    addIndicator('Account takeover phrase', 'Contains common account verification/reset attack wording.', 14);
  }

  if (/(click|tap).{0,18}(link|button|below)/i.test(normalized)) {
    addIndicator('Forced click instruction', 'Contains direct call-to-click instructions.', 10);
  }

  if (/\b(gift card|wire transfer|crypto|bitcoin)\b/i.test(normalized)) {
    addIndicator('Fraud payment vector', 'Contains terms frequently tied to social engineering fraud.', 18);
  }

  if (/<form|input[^>]+type=["']?(password|email)|action=/i.test(trimmed)) {
    addIndicator('Embedded form markup', 'Email includes HTML form-like structures.', 12);
  }

  if (/\b(attachment|attached|invoice)\b.{0,30}\.(html|htm|zip|exe|js|vbs|scr|docm|xlsm)\b/i.test(normalized)) {
    addIndicator('Suspicious attachment lure', 'Message references a potentially dangerous attachment format.', 12);
  }

  const alphaOnly = trimmed.replace(/[^A-Za-z]/g, '');
  if (alphaOnly.length > 0) {
    const upperOnly = alphaOnly.replace(/[^A-Z]/g, '');
    const upperRatio = upperOnly.length / alphaOnly.length;
    if (upperRatio >= 0.35) {
      addIndicator('Aggressive uppercase ratio', `Uppercase ratio ${(upperRatio * 100).toFixed(0)}% indicates pressure messaging.`, 8);
    }
  }

  const exclamationCount = (trimmed.match(/!/g) || []).length;
  if (exclamationCount >= 3) {
    addIndicator('Excessive punctuation', `Detected ${exclamationCount} exclamation marks.`, 6);
  }

  const digitCount = (trimmed.match(/\d/g) || []).length;
  if (digitCount >= 20) {
    addIndicator('Digit-heavy message', `Detected ${digitCount} numeric characters.`, 5);
  }

  const probability = clamp01(sigmoidProbability(score, 34, 9));
  const risk = riskFromProbability(probability);

  const category: ScanResult['category'] =
    indicators.some((item) => item.label === 'Fraud payment vector')
      ? 'Social'
      : indicators.some((item) => item.label === 'Impersonation cues') && indicators.some((item) => item.label === 'Credential request signals')
        ? 'Spoofing'
        : probability >= 0.45
          ? 'Phishing'
          : 'Other';
  const mitre = defaultMitre(category);
  const suspicious = category !== 'Other' || probability >= 0.45;

  const scanResult: ScanResult = {
    summary: suspicious
      ? 'The email contains behavioral phishing signals and should be treated as suspicious.'
      : 'The email appears lower risk but should still be validated before interaction.',
    detailedSummary: `Local intelligence scored this email at ${Math.round(probability * 100)}% phishing likelihood from ${
      indicators.length
    } indicator(s).`,
    confidence: clampPercent((suspicious ? probability : 1 - probability) * 100),
    recommendation: suspicious
      ? 'Quarantine this message, verify sender identity through a trusted channel, and avoid credential or payment actions.'
      : 'Continue with caution and verify sender plus any links before acting.',
    risk,
    category,
    impactScore: Number((Math.max(1.8, probability * 9.8)).toFixed(1)),
    mitreTechnique: mitre.technique,
    mitreTactic: mitre.tactic,
    technicalDetails:
      toTechnicalDetails(indicators).length > 0
        ? toTechnicalDetails(indicators)
        : [{ label: 'Low-signal content', description: 'No dominant phishing indicators were detected in this message.' }],
    analysisSource: 'local-intelligence',
    analysisSourceLabel: 'On-device threat intelligence',
  };

  return {
    scanResult,
    phishingProbability: probability,
    indicatorScore: score,
  };
};

export const analyzeContentWithLocalIntelligence = (content: string, type: 'url' | 'email'): LocalIntelligenceResult =>
  type === 'url' ? analyzeUrlLocally(content) : analyzeEmailLocally(content);
