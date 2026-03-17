'use strict';

// ─── Common passwords list (top 50 for demo) ──────────────────────────────
const COMMON_PASSWORDS = new Set([
  'password','123456','123456789','12345678','12345','1234567','password1',
  'iloveyou','admin','welcome','monkey','dragon','master','abc123','letmein',
  'shadow','sunshine','princess','football','charlie','donald','password123',
  'qwerty','qwerty123','1q2w3e4r','superman','batman','trustno1','passw0rd',
  'hello','login','solo','starwars','whatever','nicole','jessica','joshua',
  'michael','daniel','george','jordan','harley','ranger','dakota','test',
  'pass','1234','0000','0987654321','987654321','123123','111111','000000',
]);

// ─── Entropy Calculation ──────────────────────────────────────────────────
function calcEntropy(password) {
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;
  if (poolSize === 0) return 0;
  return Math.floor(password.length * Math.log2(poolSize));
}

// ─── Crack Time Estimate ──────────────────────────────────────────────────
// Assumes ~10 billion guesses/sec (modern GPU offline attack)
function estimateCrackTime(entropyBits) {
  const guessesPerSec = 1e10;
  const totalGuesses = Math.pow(2, entropyBits);
  const seconds = totalGuesses / (2 * guessesPerSec); // average is half keyspace

  if (seconds < 1)        return '< 1 second';
  if (seconds < 60)       return `${Math.round(seconds)} seconds`;
  if (seconds < 3600)     return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400)    return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 2592000)  return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
  const years = seconds / 31536000;
  if (years < 1e6)        return `${Math.round(years).toLocaleString()} years`;
  if (years < 1e9)        return `${(years / 1e6).toFixed(1)} million years`;
  if (years < 1e12)       return `${(years / 1e9).toFixed(1)} billion years`;
  return 'heat death of universe+';
}

// ─── Pattern Detection ────────────────────────────────────────────────────
function detectPatterns(password) {
  const warnings = [];

  // Repeated characters (aaa, 111)
  if (/(.)\1{2,}/.test(password)) {
    warnings.push('Contains repeated characters (e.g. "aaa" or "111")');
  }

  // Sequential letters
  const lower = password.toLowerCase();
  const seqLetters = 'abcdefghijklmnopqrstuvwxyz';
  const seqNumbers = '0123456789';
  for (let i = 0; i < lower.length - 2; i++) {
    const slice = lower.slice(i, i + 3);
    if (seqLetters.includes(slice) || seqLetters.split('').reverse().join('').includes(slice)) {
      warnings.push('Contains sequential letters (e.g. "abc" or "xyz")');
      break;
    }
  }
  for (let i = 0; i < password.length - 2; i++) {
    const slice = password.slice(i, i + 3);
    if (seqNumbers.includes(slice) || seqNumbers.split('').reverse().join('').includes(slice)) {
      warnings.push('Contains sequential numbers (e.g. "123" or "987")');
      break;
    }
  }

  // Keyboard patterns
  const keyboardRows = ['qwertyuiop','asdfghjkl','zxcvbnm','1234567890'];
  for (const row of keyboardRows) {
    for (let i = 0; i < lower.length - 2; i++) {
      const slice = lower.slice(i, i + 4);
      if (row.includes(slice)) {
        warnings.push(`Contains keyboard pattern ("${slice}")`);
        break;
      }
    }
  }

  // Leet speak common substitutions that still form common words
  const leetMap = { '@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '$': 's', '7': 't' };
  let deleet = password.toLowerCase();
  for (const [k, v] of Object.entries(leetMap)) {
    deleet = deleet.replaceAll(k, v);
  }
  if (COMMON_PASSWORDS.has(deleet)) {
    warnings.push('Leet-speak substitution of a common password detected');
  }

  // Year pattern
  if (/19\d{2}|20[0-2]\d/.test(password)) {
    warnings.push('Contains a year (easy to guess)');
  }

  // Only digits
  if (/^\d+$/.test(password)) {
    warnings.push('Password is all numbers — very weak');
  }

  // Only letters
  if (/^[a-zA-Z]+$/.test(password)) {
    warnings.push('Password is all letters — add numbers or symbols');
  }

  return [...new Set(warnings)]; // deduplicate
}

// ─── Scoring ──────────────────────────────────────────────────────────────
function scorePassword(password) {
  if (!password) return { score: 0, entropy: 0, criteria: {}, warnings: [] };

  const len = password.length;
  const entropy = calcEntropy(password);
  const warnings = detectPatterns(password);

  const criteria = {
    length:     len >= 12,
    upper:      /[A-Z]/.test(password),
    lower:      /[a-z]/.test(password),
    number:     /[0-9]/.test(password),
    special:    /[^a-zA-Z0-9]/.test(password),
    noRepeat:   !(/(.)\1{2,}/.test(password)),
    noSequence: !warnings.some(w => w.includes('sequential') || w.includes('keyboard')),
    noCommon:   !COMMON_PASSWORDS.has(password.toLowerCase()),
  };

  // Base score from entropy
  let score = Math.min(entropy, 100);

  // Deductions
  if (!criteria.length)     score -= 15;
  if (!criteria.noCommon)   score -= 40;
  if (!criteria.noRepeat)   score -= 10;
  if (!criteria.noSequence) score -= 10;
  if (warnings.length > 2)  score -= 5;

  // Bonuses for variety
  const varietyCount = [criteria.upper, criteria.lower, criteria.number, criteria.special].filter(Boolean).length;
  score += (varietyCount - 1) * 5;

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, entropy, criteria, warnings };
}

// ─── Strength Label ───────────────────────────────────────────────────────
function getStrength(score) {
  if (score < 20) return { label: 'Very Weak',  cls: 'strength-weak',    pct: 12 };
  if (score < 40) return { label: 'Weak',        cls: 'strength-weak',    pct: 25 };
  if (score < 55) return { label: 'Fair',        cls: 'strength-fair',    pct: 45 };
  if (score < 70) return { label: 'Good',        cls: 'strength-good',    pct: 65 };
  if (score < 85) return { label: 'Strong',      cls: 'strength-strong',  pct: 82 };
  return             { label: 'Very Strong', cls: 'strength-vstrong', pct: 100 };
}

// ─── DOM Helpers ──────────────────────────────────────────────────────────
function show(el) { el.style.display = ''; }
function hide(el) { el.style.display = 'none'; }

function setCriterion(id, pass) {
  const el = document.getElementById(id);
  el.classList.toggle('pass', pass);
  el.classList.toggle('fail', !pass);
}

// ─── HaveIBeenPwned k-Anonymity API ───────────────────────────────────────
async function sha1(str) {
  const buf = new TextEncoder().encode(str);
  const hashBuf = await crypto.subtle.digest('SHA-1', buf);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

async function checkBreach(password) {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' }
  });

  if (!res.ok) throw new Error(`HIBP API error: ${res.status}`);

  const text = await res.text();
  const lines = text.split('\r\n');

  for (const line of lines) {
    const [hashSuffix, countStr] = line.split(':');
    if (hashSuffix === suffix) {
      return parseInt(countStr, 10);
    }
  }
  return 0; // not found
}

// ─── Main UI Logic ────────────────────────────────────────────────────────
const passwordInput   = document.getElementById('password');
const toggleBtn       = document.getElementById('toggle-visibility');
const eyeIcon         = document.getElementById('eye-icon');
const eyeOffIcon      = document.getElementById('eye-off-icon');
const strengthMeter   = document.getElementById('strength-meter');
const meterFill       = document.getElementById('meter-fill');
const strengthLabel   = document.getElementById('strength-label');
const scoreCard       = document.getElementById('score-card');
const entropyValue    = document.getElementById('entropy-value');
const crackTime       = document.getElementById('crack-time');
const scoreValue      = document.getElementById('score-value');
const criteriaSection = document.getElementById('criteria-section');
const warningsSection = document.getElementById('warnings-section');
const warningsList    = document.getElementById('warnings-list');
const breachSection   = document.getElementById('breach-section');
const checkBreachBtn  = document.getElementById('check-breach-btn');
const breachResult    = document.getElementById('breach-result');

// Toggle visibility
toggleBtn.addEventListener('click', () => {
  const isPassword = passwordInput.type === 'password';
  passwordInput.type = isPassword ? 'text' : 'password';
  eyeIcon.style.display    = isPassword ? 'none' : '';
  eyeOffIcon.style.display = isPassword ? '' : 'none';
});

// Live analysis
passwordInput.addEventListener('input', () => {
  const password = passwordInput.value;

  // Reset breach result when password changes
  breachResult.textContent = '';
  breachResult.className = 'breach-result';

  if (!password) {
    hide(strengthMeter);
    hide(scoreCard);
    hide(criteriaSection);
    hide(warningsSection);
    hide(breachSection);
    return;
  }

  const { score, entropy, criteria, warnings } = scorePassword(password);
  const strength = getStrength(score);

  // Strength meter
  show(strengthMeter);
  meterFill.style.width = `${strength.pct}%`;
  meterFill.className = `meter-fill ${strength.cls}`;
  strengthLabel.textContent = strength.label;
  strengthLabel.className = `strength-label ${strength.cls}`;

  // Score card
  show(scoreCard);
  entropyValue.textContent = `${entropy} bits`;
  crackTime.textContent    = estimateCrackTime(entropy);
  scoreValue.textContent   = `${score} / 100`;

  // Criteria
  show(criteriaSection);
  setCriterion('c-length',      criteria.length);
  setCriterion('c-upper',       criteria.upper);
  setCriterion('c-lower',       criteria.lower);
  setCriterion('c-number',      criteria.number);
  setCriterion('c-special',     criteria.special);
  setCriterion('c-no-repeat',   criteria.noRepeat);
  setCriterion('c-no-sequence', criteria.noSequence);
  setCriterion('c-no-common',   criteria.noCommon);

  // Warnings
  warningsList.innerHTML = '';
  if (warnings.length > 0) {
    show(warningsSection);
    warnings.forEach(w => {
      const li = document.createElement('li');
      li.textContent = w;
      warningsList.appendChild(li);
    });
  } else {
    hide(warningsSection);
  }

  // Breach section
  show(breachSection);
});

// Breach check
checkBreachBtn.addEventListener('click', async () => {
  const password = passwordInput.value;
  if (!password) return;

  checkBreachBtn.disabled = true;
  breachResult.className = 'breach-result loading';
  breachResult.textContent = 'Checking breach database...';

  try {
    const count = await checkBreach(password);
    if (count === 0) {
      breachResult.className = 'breach-result safe';
      breachResult.textContent = 'Not found in any known data breaches.';
    } else {
      breachResult.className = 'breach-result pwned';
      breachResult.textContent = `Found in ${count.toLocaleString()} data breaches! Avoid this password.`;
    }
  } catch (err) {
    breachResult.className = 'breach-result error';
    breachResult.textContent = `Check failed: ${err.message}`;
  } finally {
    checkBreachBtn.disabled = false;
  }
});
