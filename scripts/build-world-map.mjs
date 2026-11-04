#!/usr/bin/env node

import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const source = 'https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, 'manager', 'public', 'world-map.svg');
const response = await fetch(source);
if (!response.ok) throw new Error(`Natural Earth download failed: HTTP ${response.status}`);
const data = await response.json();

const point = ([longitude, latitude]) => {
  const x = ((longitude + 180) / 360) * 1000;
  const y = ((90 - latitude) / 180) * 500;
  return `${x.toFixed(1)} ${y.toFixed(1)}`;
};

const ring = (coordinates) => {
  if (!coordinates.length) return '';
  let result = `M${point(coordinates[0])}`;
  for (let index = 1; index < coordinates.length; index += 1) {
    const previous = coordinates[index - 1];
    const current = coordinates[index];
    result += Math.abs(current[0] - previous[0]) > 180
      ? `M${point(current)}`
      : `L${point(current)}`;
  }
  return `${result}Z`;
};

const geometryPath = (geometry) => {
  if (!geometry) return '';
  const polygons = geometry.type === 'Polygon' ? [geometry.coordinates] : geometry.coordinates;
  return polygons.flatMap((polygon) => polygon.map(ring)).join('');
};

const countries = data.features.map((feature) => {
  const code = feature.properties?.ISO_A2_EH || feature.properties?.ISO_A2 || feature.properties?.ADM0_A3 || '';
  return `  <path data-country="${String(code).replace(/[^A-Za-z0-9_-]/g, '')}" d="${geometryPath(feature.geometry)}"/>`;
}).join('\n');

const svg = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Natural Earth 1:110m Admin-0 Countries; public-domain map data. -->
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 500" role="img" aria-label="World map">
 <g fill="#304765" fill-rule="evenodd" stroke="#587493" stroke-width="0.75" stroke-linejoin="round" vector-effect="non-scaling-stroke">
${countries}
 </g>
</svg>
`;

await writeFile(output, svg, 'utf8');
console.log(`Generated ${path.relative(root, output)} from Natural Earth (${data.features.length} countries)`);
