#!/usr/bin/env node

/**
 * Weekly cannabis strain report generator.
 *
 * This script analyses the data.json state file and creates a Markdown
 * report containing all products (cannabis strains) that were created
 * within the past seven days. The report is stored in the reports
 * directory and can be executed manually or scheduled via cron.
 */
const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '..', 'data.json');
const REPORT_DIR = path.join(__dirname, '..', 'reports');

function readData() {
  if (!fs.existsSync(DATA_FILE)) {
    throw new Error(`Daten-Datei nicht gefunden: ${DATA_FILE}`);
  }
  const raw = fs.readFileSync(DATA_FILE, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`data.json konnte nicht geparst werden: ${error.message}`);
  }
}

function ensureDirectory(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function formatDate(date) {
  return new Intl.DateTimeFormat('de-DE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(date);
}

function formatDateTime(date) {
  return new Intl.DateTimeFormat('de-DE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

function toNumber(value, fallback = null) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function normaliseTiers(tiersValue) {
  if (!tiersValue) return [];
  if (Array.isArray(tiersValue)) {
    return tiersValue
      .map(tier => ({
        minAmount: toNumber(tier.minAmount, 0),
        unitPrice: toNumber(tier.unitPrice, null)
      }))
      .filter(tier => tier.unitPrice !== null);
  }
  const numeric = toNumber(tiersValue, null);
  if (numeric !== null) {
    return [{ minAmount: 0, unitPrice: numeric }];
  }
  return [];
}

function extractProductSummary(product, users) {
  const createdAt = product.createdAt ? new Date(product.createdAt) : null;
  const seller = users.find(u => u.id === product.sellerId) || null;
  const prices = product.prices || {};
  const buyerSummaries = [];
  let minPrice = Infinity;
  let maxPrice = -Infinity;

  Object.entries(prices).forEach(([buyerId, tiersValue]) => {
    const tiers = normaliseTiers(tiersValue);
    if (!tiers.length) return;
    const buyer = users.find(u => u.id === Number(buyerId));
    const buyerName = buyer ? buyer.name : `Käufer ${buyerId}`;
    const tierLines = tiers
      .sort((a, b) => a.minAmount - b.minAmount)
      .map(tier => {
        minPrice = Math.min(minPrice, tier.unitPrice);
        maxPrice = Math.max(maxPrice, tier.unitPrice);
        return `    - Ab ${tier.minAmount.toFixed(0)} €: ${tier.unitPrice.toFixed(2)} € pro Einheit`;
      });
    buyerSummaries.push({
      buyerName,
      tierLines
    });
  });

  if (minPrice === Infinity) minPrice = null;
  if (maxPrice === -Infinity) maxPrice = null;

  return {
    name: product.name,
    seller,
    createdAt,
    minPrice,
    maxPrice,
    buyerSummaries
  };
}

function buildReportContent(products, users, now) {
  const nowDate = formatDateTime(now);
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const weekAgoDate = formatDate(weekAgo);
  const todayDate = formatDate(now);

  const header = [
    '# Wochenbericht: Neue Cannabissorten',
    '',
    `Zeitraum: ${weekAgoDate} – ${todayDate}`,
    `Erstellt am: ${nowDate}`,
    ''
  ];

  if (!products.length) {
    return header
      .concat([
        'In den vergangenen sieben Tagen wurden keine neuen Sorten registriert.'
      ])
      .join('\n');
  }

  const sellerCount = new Set(products.map(product => product.seller && product.seller.id).filter(Boolean)).size;
  const summary = [
    `Insgesamt wurden ${products.length} neue Sorte${products.length === 1 ? '' : 'n'} von ${sellerCount} Verkäufer${sellerCount === 1 ? '' : 'n'} registriert.`,
    '',
    '## Details',
    ''
  ];

  const detailSections = products.map(product => {
    const lines = [];
    lines.push(`### ${product.name}`);
    const sellerName = product.seller ? `${product.seller.name}${product.seller.sellerNumber ? ` (Verkäufer-Nr. ${product.seller.sellerNumber})` : ''}` : 'Unbekannter Verkäufer';
    lines.push(`- Anbieter: ${sellerName}`);
    lines.push(`- Hinzugefügt am: ${product.createdAt ? formatDateTime(product.createdAt) : 'unbekannt'}`);
    if (product.minPrice !== null && product.maxPrice !== null) {
      if (product.minPrice === product.maxPrice) {
        lines.push(`- Preisniveau: ${product.minPrice.toFixed(2)} € pro Einheit`);
      } else {
        lines.push(`- Preisspanne: ${product.minPrice.toFixed(2)} € – ${product.maxPrice.toFixed(2)} € pro Einheit`);
      }
    } else {
      lines.push('- Preisinformationen: Keine Preisstaffeln hinterlegt');
    }

    if (product.buyerSummaries.length) {
      lines.push('- Käufer-spezifische Staffelungen:');
      product.buyerSummaries.forEach(buyer => {
        lines.push(`  - ${buyer.buyerName}:`);
        lines.push(...buyer.tierLines);
      });
    }
    lines.push('');
    return lines.join('\n');
  });

  return header.concat(summary).concat(detailSections).join('\n');
}

function main() {
  const now = new Date();
  const weekAgoMs = now.getTime() - 7 * 24 * 60 * 60 * 1000;
  const data = readData();
  const users = data.users || [];
  const products = (data.products || [])
    .filter(product => typeof product.createdAt === 'number' && product.createdAt >= weekAgoMs)
    .map(product => extractProductSummary(product, users))
    .sort((a, b) => (b.createdAt ? b.createdAt.getTime() : 0) - (a.createdAt ? a.createdAt.getTime() : 0));

  const content = buildReportContent(products, users, now);

  ensureDirectory(REPORT_DIR);
  const fileName = `wochenbericht_${now.toISOString().slice(0, 10)}.md`;
  const filePath = path.join(REPORT_DIR, fileName);
  fs.writeFileSync(filePath, content, 'utf8');
  console.log(`Bericht erstellt: ${filePath}`);
}

main();
