#pragma once

// Minimal radar UI — polls /api/players (PenisFinger / dma_webserver style, no cheat controls).
inline const char* PZ_WEB_UI_HTML = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>PZ Live Viewer</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, sans-serif; background: #0f1419; color: #e7ecf1; }
  header { padding: 12px 16px; border-bottom: 1px solid #2a3540; display: flex; gap: 16px; align-items: center; }
  h1 { font-size: 1rem; margin: 0; font-weight: 600; }
  #meta { font-size: 0.85rem; opacity: 0.8; }
  main { padding: 16px; display: grid; grid-template-columns: 1fr 220px; gap: 16px; }
  canvas { width: 100%; max-width: 900px; height: 520px; background: #1a2330; border: 1px solid #2a3540; border-radius: 8px; }
  ul { list-style: none; padding: 0; margin: 0; font-size: 0.9rem; }
  li { padding: 6px 0; border-bottom: 1px solid #2a3540; }
  .note { font-size: 0.75rem; opacity: 0.65; margin-top: 12px; line-height: 1.4; }
</style>
</head>
<body>
<header>
  <h1>Project Zomboid — Live Viewer</h1>
  <span id="meta">loading…</span>
</header>
<main>
  <canvas id="map" width="900" height="520"></canvas>
  <div>
    <strong>Players</strong>
    <ul id="list"></ul>
    <p class="note">Server-side telemetry only. Admin/co-op on servers you control.</p>
  </div>
</main>
<script>
const canvas = document.getElementById('map');
const ctx = canvas.getContext('2d');
const listEl = document.getElementById('list');
const metaEl = document.getElementById('meta');

function bounds(players) {
  if (!players.length) return { minX:0, maxX:1, minY:0, maxY:1 };
  let minX=players[0].x, maxX=players[0].x, minY=players[0].y, maxY=players[0].y;
  for (const p of players) {
    minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
    minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
  }
  const pad = Math.max(80, (maxX-minX+maxY-minY)*0.08);
  return { minX: minX-pad, maxX: maxX+pad, minY: minY-pad, maxY: maxY+pad };
}

function draw(players, updatedMs) {
  const b = bounds(players);
  const w = canvas.width, h = canvas.height;
  ctx.fillStyle = '#1a2330';
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = '#2a3540';
  for (let i = 0; i <= 10; i++) {
    const x = (w/10)*i, y = (h/10)*i;
    ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,h); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke();
  }
  const sx = w / (b.maxX - b.minX);
  const sy = h / (b.maxY - b.minY);
  listEl.innerHTML = '';
  for (const p of players) {
    const px = (p.x - b.minX) * sx;
    const py = h - (p.y - b.minY) * sy;
    ctx.fillStyle = '#3d9eff';
    ctx.beginPath(); ctx.arc(px, py, 7, 0, Math.PI*2); ctx.fill();
    ctx.fillStyle = '#e7ecf1';
    ctx.font = '12px system-ui';
    ctx.fillText(p.username || '?', px + 10, py - 8);
    const li = document.createElement('li');
    li.textContent = `${p.username}: (${p.x.toFixed(0)}, ${p.y.toFixed(0)}) z=${p.z.toFixed(1)}`;
    listEl.appendChild(li);
  }
  metaEl.textContent = `${players.length} online · updated ${updatedMs ? new Date(updatedMs).toLocaleTimeString() : '—'}`;
}

async function tick() {
  try {
    const r = await fetch('/api/players');
    const data = await r.json();
    draw(data.players || [], data.updatedMs || 0);
  } catch (e) {
    metaEl.textContent = 'waiting for telemetry…';
  }
}
setInterval(tick, 1000);
tick();
</script>
</body>
</html>)HTML";