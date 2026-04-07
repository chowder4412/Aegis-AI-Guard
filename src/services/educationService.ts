import type {
  AcademyLesson,
  AcademyTrack,
  EducationSnapshot,
  LinkedEmail,
  PracticeScenario,
  RecommendedLesson,
  ResearchBrief,
  ScanEvent,
  ScannerCoachingInsight,
  Threat,
} from '../types';

const academyTracks: AcademyTrack[] = [
  {
    id: 'beginner-defense',
    title: 'Defense Foundations',
    summary: 'Build pattern recognition for the lures most likely to trick everyday users.',
    focus: 'Homoglyphs, urgency abuse, and suspicious redirects',
    audience: 'beginner',
  },
  {
    id: 'pro-mailbox',
    title: 'Mailbox Resilience',
    summary: 'Train against the exact inbox-native tactics now showing up in linked mailbox scans.',
    focus: 'Mailbox alerts, link masking, and impersonation defense',
    audience: 'professional',
  },
  {
    id: 'analyst-intel',
    title: 'Threat Intelligence',
    summary: 'Study campaign behavior, operational signals, and attacker tradecraft in analyst mode.',
    focus: 'MITRE patterns, escalation signals, and triage decisions',
    audience: 'analyst',
  },
];

const academyLessons: AcademyLesson[] = [
  {
    id: 'homoglyphs',
    title: 'Spotting Homoglyphs',
    summary: 'Identify lookalike domains and deceptive URL characters before they land a credential theft.',
    body:
      'Attackers increasingly impersonate trusted brands by swapping in lookalike unicode characters, subtle spelling shifts, and domain padding. Aegis teaches you to slow down at the exact moment visual trust is doing the attacker’s work for them.',
    category: 'Spoofing',
    difficulty: 'Foundational',
    audience: 'beginner',
    estimatedMinutes: 6,
    practicePrompt: 'Inspect the sender, root domain, and every visually similar character before you trust a sign-in flow.',
    researchSource: 'Aegis Research Academy / Open threat monitoring',
  },
  {
    id: 'masking',
    title: 'Link Masking',
    summary: 'Reveal hidden redirect chains and shortened URLs before trusting a destination.',
    body:
      'Modern phishing often hides behind shortened links, compromised redirectors, and seemingly harmless CTA buttons. This lesson trains users to reason about the path behind a click, not just the first label they see.',
    category: 'Phishing',
    difficulty: 'Intermediate',
    audience: 'professional',
    estimatedMinutes: 7,
    practicePrompt: 'Trace where the link resolves, whether it changes domains, and whether the final destination matches the message’s claimed intent.',
    researchSource: 'Aegis Research Academy / Redirect abuse brief',
  },
  {
    id: 'harvesting',
    title: 'Credential Harvesting',
    summary: 'Understand how fake sign-in portals capture passwords in seconds.',
    body:
      'Credential harvesting is still the fastest path from curiosity to compromise. This lesson explains cloned sign-in pages, fake MFA prompts, session bait, and the subtle UI behaviors that reveal a trap before credentials leave the user.',
    category: 'Phishing',
    difficulty: 'Advanced',
    audience: 'professional',
    estimatedMinutes: 9,
    practicePrompt: 'Look for login prompts after redirects, mismatched brand identity, and forms that advance without trustworthy authentication context.',
    researchSource: 'Aegis Research Academy / Credential capture brief',
  },
  {
    id: 'urgency',
    title: 'Urgency Tactics',
    summary: 'Disarm the psychological pressure that attackers use to bypass judgment.',
    body:
      'Attackers rarely win with technical perfection alone. They win by manufacturing time pressure, authority, and fear. This lesson focuses on the emotional cues that push users into fast, unsafe choices.',
    category: 'Social',
    difficulty: 'Foundational',
    audience: 'beginner',
    estimatedMinutes: 5,
    practicePrompt: 'When a message demands immediate action, pause and verify the sender, the business context, and the consequence being implied.',
    researchSource: 'Aegis Research Academy / Social engineering brief',
  },
  {
    id: 'mailbox-defense',
    title: 'Mailbox Defense',
    summary: 'Use Aegis mailbox telemetry to spot campaign patterns before they become incidents.',
    body:
      'Aegis does more than score a single message. It watches mailbox health, recurring signals, suspicious links, and alert cadence over time. This lesson teaches how to read mailbox protection signals like an analyst rather than a passive recipient.',
    category: 'Other',
    difficulty: 'Intermediate',
    audience: 'analyst',
    estimatedMinutes: 8,
    practicePrompt: 'Watch for repeated alert themes, degraded mailbox health, and suspicious links that recur across different messages.',
    researchSource: 'Aegis Research Academy / Mailbox telemetry brief',
  },
  {
    id: 'bec',
    title: 'Business Email Compromise',
    summary: 'Recognize impersonation, payment pressure, and executive trust abuse before money moves.',
    body:
      'BEC succeeds by sounding plausible and urgent at the same time. This lesson helps users catch authority impersonation, vendor fraud, invoice pressure, and tiny context mismatches that reveal a high-impact social attack.',
    category: 'Social',
    difficulty: 'Advanced',
    audience: 'professional',
    estimatedMinutes: 10,
    practicePrompt: 'Validate unusual payment, password-reset, or vendor-change requests through a second channel before acting.',
    researchSource: 'Aegis Research Academy / Executive impersonation brief',
  },
];

const lessonById = new Map(academyLessons.map((lesson) => [lesson.id, lesson]));

const normalize = (value: string) => value.trim().toLowerCase();

const includesAny = (value: string, patterns: string[]) => patterns.some((pattern) => value.includes(pattern));

const recentHighRiskFindings = (scanEvents: ScanEvent[], threats: Threat[]) =>
  scanEvents.filter((item) => item.risk === 'High' || item.risk === 'Critical').length +
  threats.filter((item) => item.risk === 'High' || item.risk === 'Critical').length;

const buildResearchBriefs = (scanEvents: ScanEvent[], threats: Threat[], linkedEmails: LinkedEmail[]): ResearchBrief[] => {
  const highRiskCount = recentHighRiskFindings(scanEvents, threats);
  const mailboxWatchCount = linkedEmails.filter((item) => item.provider === 'gmail-oauth' && item.health !== 'healthy').length;
  const spoofingHits = threats.filter((item) => item.category === 'Spoofing').length;
  const socialHits = threats.filter((item) => item.category === 'Social').length;

  return [
    {
      id: 'brief-credential-capture',
      title: highRiskCount > 3 ? 'Credential-harvest pressure is rising in active scans' : 'Credential-harvest pages remain the fastest path to compromise',
      summary:
        highRiskCount > 0
          ? `Aegis has seen ${highRiskCount} high-risk finding${highRiskCount === 1 ? '' : 's'} in recent activity. Attackers are still relying on cloned sign-in pages and redirect-led credential traps.`
          : 'Brand-cloned sign-in pages and fake account verification prompts remain a dominant phishing pattern in active campaigns.',
      threatFamily: 'Credential Harvesting',
      urgency: highRiskCount > 3 ? 'Critical' : 'Elevated',
      source: 'Aegis Research Academy / Open anti-phishing intelligence',
      action: 'Prioritize credential harvesting lessons and drill the scanner on login-themed lures.',
    },
    {
      id: 'brief-mailbox-campaigns',
      title: mailboxWatchCount > 0 ? 'Linked mailbox telemetry shows active pressure signals' : 'Mailbox-native phishing is shifting toward delayed redirect chains',
      summary:
        mailboxWatchCount > 0
          ? `Aegis currently marks ${mailboxWatchCount} linked mailbox${mailboxWatchCount === 1 ? '' : 'es'} on heightened watch or degraded health. Repeated signals matter more than any one message.`
          : 'Campaigns are increasingly spreading trust across multiple low-drama messages before pushing the high-risk click.',
      threatFamily: 'Mailbox Threat Shield',
      urgency: mailboxWatchCount > 0 ? 'Critical' : 'Watch',
      source: 'Aegis Research Academy / Mailbox defense observatory',
      action: 'Review mailbox defense guidance and monitor repeated top signals, not just single alerts.',
    },
    {
      id: 'brief-impersonation',
      title: spoofingHits + socialHits > 0 ? 'Impersonation remains a top human-targeting attack surface' : 'Executive trust abuse and spoofing still outperform flashy malware lures',
      summary:
        spoofingHits + socialHits > 0
          ? `Recent activity includes ${spoofingHits} spoofing and ${socialHits} social-engineering finding${spoofingHits + socialHits === 1 ? '' : 's'}, reinforcing that human trust remains a primary attack vector.`
          : 'Attackers continue to weaponize authority, familiarity, and urgency more often than obviously malicious payloads.',
      threatFamily: 'Spoofing & Social Engineering',
      urgency: spoofingHits + socialHits > 1 ? 'Elevated' : 'Watch',
      source: 'Aegis Research Academy / Impersonation monitoring',
      action: 'Train on homoglyphs, BEC, and urgency cues before the next high-trust request reaches a user.',
    },
  ];
};

const buildRecommendations = (scanEvents: ScanEvent[], threats: Threat[], linkedEmails: LinkedEmail[]): RecommendedLesson[] => {
  const recommendations: RecommendedLesson[] = [];
  const summaries = `${scanEvents.map((item) => item.summary).join(' ')} ${threats.map((item) => item.aiAnalysis.summary).join(' ')}`.toLowerCase();
  const mailboxSignals = linkedEmails.flatMap((item) => item.topSignals || []).map(normalize);

  if (threats.some((item) => item.category === 'Phishing' || item.risk === 'High' || item.risk === 'Critical')) {
    recommendations.push({
      lessonId: 'harvesting',
      priority: 'High',
      reason: 'Recent activity shows phishing or high-risk signals that point toward credential capture.',
      signal: 'High-risk phishing findings',
    });
  }

  if (
    includesAny(summaries, ['redirect', 'shortened', 'masked', 'link', 'destination']) ||
    scanEvents.some((item) => item.inputType === 'url')
  ) {
    recommendations.push({
      lessonId: 'masking',
      priority: 'High',
      reason: 'Recent scanner activity suggests your users would benefit from deeper redirect and destination analysis.',
      signal: 'Link-heavy scan activity',
    });
  }

  if (
    threats.some((item) => item.category === 'Spoofing') ||
    includesAny(summaries, ['brand', 'lookalike', 'impersonat', 'sender mismatch', 'spoof'])
  ) {
    recommendations.push({
      lessonId: 'homoglyphs',
      priority: 'Medium',
      reason: 'Impersonation and trust abuse patterns are showing up in the current threat mix.',
      signal: 'Spoofing-adjacent indicators',
    });
  }

  if (
    threats.some((item) => item.category === 'Social') ||
    includesAny(summaries, ['urgent', 'authority', 'invoice', 'payment', 'executive'])
  ) {
    recommendations.push({
      lessonId: 'bec',
      priority: 'Medium',
      reason: 'Social engineering patterns suggest BEC-style trust abuse is worth drilling now.',
      signal: 'Authority and urgency cues',
    });
  }

  if (linkedEmails.some((item) => item.provider === 'gmail-oauth')) {
    recommendations.push({
      lessonId: 'mailbox-defense',
      priority: linkedEmails.some((item) => item.health !== 'healthy') ? 'High' : 'Medium',
      reason: 'You already have live mailbox telemetry available, so analyst-grade mailbox defense training can be personalized.',
      signal: mailboxSignals[0] || 'Live mailbox protection enabled',
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      lessonId: 'urgency',
      priority: 'Medium',
      reason: 'No strong historical pattern is available yet, so start with the psychology most phishing campaigns depend on.',
      signal: 'Foundational resilience',
    });
  }

  return recommendations.filter(
    (item, index, items) => items.findIndex((candidate) => candidate.lessonId === item.lessonId) === index,
  );
};

const buildPracticeScenarios = (scanEvents: ScanEvent[], threats: Threat[], recommendations: RecommendedLesson[]): PracticeScenario[] => {
  const scenarios: PracticeScenario[] = [];

  for (const event of scanEvents.slice(0, 3)) {
    const recommendation = recommendations.find((item) =>
      item.lessonId === 'masking' && event.inputType === 'url'
        ? true
        : item.lessonId === 'harvesting' && event.category === 'Phishing'
          ? true
          : item.lessonId === 'bec' && event.category === 'Social'
            ? true
            : item.lessonId === 'homoglyphs' && event.category === 'Spoofing',
    );

    scenarios.push({
      id: `event-${event.id}`,
      title: event.inputType === 'url' ? 'Replay a suspicious link analysis' : 'Replay a suspicious email drill',
      summary: `${event.summary} Practice the pattern recognition path before your next live scan.`,
      inputType: event.inputType,
      draftInput: event.inputPreview,
      lessonId: recommendation?.lessonId || recommendations[0]?.lessonId || 'urgency',
      sourceLabel: event.analysisSourceLabel,
      riskLevel: event.risk,
    });
  }

  for (const threat of threats.slice(0, 2)) {
    if (scenarios.length >= 4) {
      break;
    }
    scenarios.push({
      id: `threat-${threat.id}`,
      title: `Drill the ${threat.category.toLowerCase()} pattern`,
      summary: threat.aiAnalysis.summary,
      inputType: 'email',
      draftInput: threat.source,
      lessonId:
        threat.category === 'Spoofing'
          ? 'homoglyphs'
          : threat.category === 'Social'
            ? 'bec'
            : threat.category === 'Phishing'
              ? 'harvesting'
              : 'mailbox-defense',
      sourceLabel: threat.type,
      riskLevel: threat.risk,
    });
  }

  if (scenarios.length === 0) {
    scenarios.push({
      id: 'starter-url',
      title: 'Starter drill: inspect a suspicious login lure',
      summary: 'Use the scanner to practice your first Aegis Research Academy scenario.',
      inputType: 'url',
      draftInput: 'https://secure-verification-check.example/account',
      lessonId: 'masking',
      sourceLabel: 'Aegis Academy drill',
      riskLevel: 'Medium',
    });
  }

  return scenarios;
};

export const getAcademyLesson = (lessonId: string) => lessonById.get(lessonId);

export const getScannerCoachingInsight = ({
  activeScenario,
  latestEvent,
  linkedMailboxCount,
}: {
  activeScenario: PracticeScenario | null;
  latestEvent?: ScanEvent;
  linkedMailboxCount: number;
}): ScannerCoachingInsight => {
  if (activeScenario) {
    return {
      eyebrow: 'Academy Drill Loaded',
      title: activeScenario.title,
      body: `${activeScenario.summary} Practice the exact signal path before you trust the next live message or destination.`,
      actionLabel: 'Run the drill and compare the verdict with the lesson cues.',
    };
  }

  if (latestEvent && (latestEvent.risk === 'High' || latestEvent.risk === 'Critical')) {
    return {
      eyebrow: 'Adaptive Coaching',
      title: 'Train from your last high-risk finding',
      body: `${latestEvent.summary} Aegis is using your recent threat history to steer the next scan toward the behavior that needs reinforcement.`,
      actionLabel: 'Replay a similar example or open Education for the matching lesson.',
    };
  }

  if (linkedMailboxCount > 0) {
    return {
      eyebrow: 'Mailbox-Aware Coaching',
      title: 'Scanner drills now reinforce live mailbox protection',
      body: 'Your linked mailbox signals can now feed both recommended lessons and future training candidates, so drills are tied to what Aegis is actually seeing.',
      actionLabel: 'Use the scanner on suspicious URLs and email text to strengthen the learning loop.',
    };
  }

  return {
    eyebrow: 'Research Academy',
    title: 'Start with a live drill, not a static lesson',
    body: 'Open a practice scenario from Education and Aegis will preload the scanner with a guided example built from current research themes.',
    actionLabel: 'Move from research to practice by launching an academy drill.',
  };
};

export const getEducationSnapshot = ({
  scanEvents,
  threats,
  linkedEmails,
}: {
  scanEvents: ScanEvent[];
  threats: Threat[];
  linkedEmails: LinkedEmail[];
}): EducationSnapshot => {
  const researchBriefs = buildResearchBriefs(scanEvents, threats, linkedEmails);
  const recommendedLessons = buildRecommendations(scanEvents, threats, linkedEmails);
  const practiceScenarios = buildPracticeScenarios(scanEvents, threats, recommendedLessons);

  return {
    tracks: academyTracks,
    lessons: academyLessons,
    researchBriefs,
    recommendedLessons,
    practiceScenarios,
    stats: {
      researchBriefCount: researchBriefs.length,
      linkedMailboxCount: linkedEmails.filter((item) => item.provider === 'gmail-oauth').length,
      highRiskFindings: recentHighRiskFindings(scanEvents, threats),
      recommendedLessonCount: recommendedLessons.length,
    },
  };
};
