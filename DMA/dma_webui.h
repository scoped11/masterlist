#pragma once

inline const char* WEB_UI_HTML = R"RAWHTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>UnturnedDMA</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
--bg:rgba(5,5,10,0.92);--card:rgba(10,15,10,0.85);--card-border:rgba(0,255,65,0.12);
--accent:#00ff41;--accent-dim:#00cc33;--accent-glow:rgba(0,255,65,0.15);
--danger:#ff4757;--text:#c8e6c9;--text-dim:#5a7a5c;--text-bright:#e0ffe0;
--toggle-off:#1a2a1a;--slider-track:#1a2a1a;--slider-fill:#00ff41;
}
html,body{height:100%;overflow-x:hidden}
body{
color:var(--text);font-family:'Consolas','Courier New',monospace;
background:#000;position:relative;
}
canvas#matrix{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0}
.app{position:relative;z-index:1;min-height:100vh;background:var(--bg)}
.container{max-width:880px;margin:0 auto;padding:20px 16px}
header{
display:flex;align-items:center;justify-content:space-between;
padding:14px 20px;margin-bottom:20px;
background:rgba(0,20,0,0.7);border:1px solid var(--card-border);border-radius:8px;
backdrop-filter:blur(10px);
}
header h1{
font-size:18px;font-weight:700;letter-spacing:3px;
color:var(--accent);text-shadow:0 0 20px rgba(0,255,65,0.5);
}
.status{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text-dim)}
.dot{width:8px;height:8px;border-radius:50%;background:#ff4757;transition:background .3s}
.dot.on{background:var(--accent);box-shadow:0 0 10px var(--accent)}
.section{
background:var(--card);border:1px solid var(--card-border);border-radius:8px;
padding:16px 18px;margin-bottom:14px;backdrop-filter:blur(8px);
}
.section h2{
font-size:11px;font-weight:600;letter-spacing:3px;text-transform:uppercase;
color:var(--accent);margin-bottom:14px;opacity:0.8;
}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px}
.item{
display:flex;align-items:center;justify-content:space-between;
padding:10px 12px;border-radius:6px;
background:rgba(0,10,0,0.5);border:1px solid transparent;
cursor:pointer;transition:all .15s;user-select:none;
}
.item:hover{border-color:rgba(0,255,65,0.2);background:rgba(0,20,0,0.6)}
.item.on{border-color:rgba(0,255,65,0.3);background:rgba(0,40,0,0.5)}
.item-name{font-size:12px;color:var(--text)}
.item.on .item-name{color:var(--accent)}
.sw{
width:34px;height:18px;border-radius:9px;
background:var(--toggle-off);position:relative;
transition:background .2s;flex-shrink:0;margin-left:8px;
border:1px solid rgba(0,255,65,0.1);
}
.item.on .sw{background:var(--accent);border-color:var(--accent)}
.sw::after{
content:'';position:absolute;top:2px;left:2px;
width:12px;height:12px;border-radius:50%;
background:#0a0a0a;transition:transform .2s;
}
.item.on .sw::after{transform:translateX(16px);background:#001a00}
.sliders{margin-top:12px;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.srow{
display:flex;align-items:center;gap:10px;padding:8px 12px;
background:rgba(0,10,0,0.5);border-radius:6px;border:1px solid rgba(0,255,65,0.06);
}
.srow:hover{border-color:rgba(0,255,65,0.15)}
.slbl{font-size:11px;color:var(--text-dim);min-width:70px;letter-spacing:1px}
.sval{
font-size:13px;color:var(--accent);min-width:44px;text-align:right;
font-weight:700;text-shadow:0 0 8px rgba(0,255,65,0.3);
}
input[type=range]{
flex:1;height:3px;-webkit-appearance:none;appearance:none;
background:var(--slider-track);border-radius:2px;outline:none;
}
input[type=range]::-webkit-slider-thumb{
-webkit-appearance:none;width:14px;height:14px;border-radius:50%;
background:var(--accent);cursor:pointer;border:2px solid #001a00;
box-shadow:0 0 6px rgba(0,255,65,0.4);
}
input[type=range]::-moz-range-thumb{
width:14px;height:14px;border-radius:50%;
background:var(--accent);cursor:pointer;border:2px solid #001a00;
}
.footer{
text-align:center;padding:14px;color:var(--text-dim);font-size:10px;
letter-spacing:2px;
}
.toast{
position:fixed;bottom:20px;right:20px;padding:8px 18px;
background:var(--accent);color:#001a00;border-radius:6px;
font-size:12px;font-weight:700;letter-spacing:1px;opacity:0;
transform:translateY(8px);transition:all .25s;z-index:99;
box-shadow:0 0 20px rgba(0,255,65,0.4);
}
.toast.show{opacity:1;transform:translateY(0)}
.section.combat{border-color:rgba(255,70,70,0.15)}
.section.combat h2{color:#ff6b6b}
.section.movement{border-color:rgba(255,200,50,0.15)}
.section.movement h2{color:#ffd93d}
.section.visuals{border-color:rgba(100,200,255,0.15)}
.section.visuals h2{color:#64c8ff}
.section.esp{border-color:rgba(180,130,255,0.15)}
.section.esp h2{color:#b482ff}
.section.player{border-color:rgba(0,255,65,0.15)}
.section.loot{border-color:rgba(255,170,0,0.25)}
.section.loot h2{color:#ffaa00}
.loot-info{font-size:11px;color:var(--text-dim);line-height:1.6;margin-top:10px;padding:8px 10px;background:rgba(255,170,0,0.04);border-radius:4px;border:1px solid rgba(255,170,0,0.08)}
.section.live{border-color:rgba(0,255,65,0.25)}
.section.live h2{color:#00ff41}
.radar-wrap{display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap}
#radar{border:1px solid rgba(0,255,65,0.15);border-radius:6px;background:#050a05;flex-shrink:0}
.radar-legend{display:flex;flex-direction:column;gap:6px;padding:4px 0}
.legend-item{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-dim)}
.ldot{width:8px;height:8px;border-radius:50%;display:inline-block}
.ldot.green{background:#00ff41}.ldot.red{background:#ff3232}.ldot.yellow{background:#ffff00}
.ldot.purple{background:#b400b4}.ldot.cyan{background:#00c8ff}.ldot.orange{background:#ffaa00}
.player-list{max-height:260px;overflow-y:auto}
.pl-row{display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:4px;
background:rgba(0,10,0,0.4);margin-bottom:3px;border:1px solid transparent;font-size:12px}
.pl-row:hover{background:rgba(0,20,0,0.6)}
.pl-target{border-color:rgba(255,255,0,0.3);background:rgba(40,40,0,0.3)}
.pl-name{flex:1;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pl-target .pl-name{color:#ffff00}
.pl-dist{color:var(--text-dim);min-width:40px;text-align:right;font-size:11px}
.pl-hp-bar{width:60px;height:6px;background:#1a1a1a;border-radius:3px;overflow:hidden;flex-shrink:0}
.pl-hp-fill{height:100%;border-radius:3px;transition:width .2s}
.pl-hp-text{min-width:24px;text-align:right;font-size:11px;font-weight:700}
.pl-empty{color:var(--text-dim);font-size:11px;padding:12px;text-align:center}
.entity-counts{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px}
.ecount{font-size:11px;padding:4px 10px;border-radius:4px;background:rgba(0,10,0,0.5);border:1px solid rgba(0,255,65,0.08)}
</style>
</head>
)RAWHTML"
R"RAWHTML(
<body>

<canvas id="matrix"></canvas>

<div class="app">
<div class="container">

<header>
<h1>UNTURNED DMA</h1>
<div class="status">
<span class="dot" id="dot"></span>
<span id="stxt">OFFLINE</span>
</div>
</header>

<div class="section combat">
<h2>// Combat</h2>
<div class="grid">
<div class="item" data-k="aimbot"><span class="item-name">Aimbot</span><div class="sw"></div></div>
<div class="item" data-k="silentAim"><span class="item-name">Silent Aim</span><div class="sw"></div></div>
<div class="item" data-k="triggerbot"><span class="item-name">Triggerbot</span><div class="sw"></div></div>
<div class="item" data-k="noRecoil"><span class="item-name">No Recoil</span><div class="sw"></div></div>
<div class="item" data-k="noSpread"><span class="item-name">No Spread</span><div class="sw"></div></div>
<div class="item" data-k="rapidFire"><span class="item-name">Rapid Fire</span><div class="sw"></div></div>
<div class="item" data-k="infiniteRange"><span class="item-name">Inf Range</span><div class="sw"></div></div>
<div class="item" data-k="extendedMelee"><span class="item-name">Ext Melee</span><div class="sw"></div></div>
<div class="item" data-k="spinBot"><span class="item-name">Spin Bot</span><div class="sw"></div></div>
<div class="item" data-k="instantReload"><span class="item-name">Instant Reload</span><div class="sw"></div></div>
</div>
<div class="sliders">
<div class="srow"><span class="slbl">AIM FOV</span><input type="range" min="2" max="90" step="1" data-k="aimbotFOV"><span class="sval" id="v_aimbotFOV">15</span></div>
<div class="srow"><span class="slbl">SMOOTH</span><input type="range" min="1" max="20" step="0.5" data-k="aimbotSmooth"><span class="sval" id="v_aimbotSmooth">5.0</span></div>
<div class="srow"><span class="slbl">MELEE RNG</span><input type="range" min="1" max="50" step="1" data-k="meleeRange"><span class="sval" id="v_meleeRange">20</span></div>
</div>
</div>

<div class="section movement">
<h2>// Movement</h2>
<div class="grid">
<div class="item" data-k="speedHack"><span class="item-name">Speed Hack</span><div class="sw"></div></div>
<div class="item" data-k="flyHack"><span class="item-name">Fly Hack</span><div class="sw"></div></div>
<div class="item" data-k="superJump"><span class="item-name">Super Jump</span><div class="sw"></div></div>
<div class="item" data-k="vehicleFly"><span class="item-name">Vehicle Fly</span><div class="sw"></div></div>
<div class="item" data-k="noFallDamage"><span class="item-name">No Fall Dmg</span><div class="sw"></div></div>
<div class="item" data-k="noclip"><span class="item-name">Noclip</span><div class="sw"></div></div>
</div>
<div class="sliders">
<div class="srow"><span class="slbl">SPEED</span><input type="range" min="1" max="1.5" step="0.1" data-k="speedMultiplier"><span class="sval" id="v_speedMultiplier">1.3</span></div>
<div class="srow"><span class="slbl">JUMP</span><input type="range" min="1" max="2" step="0.1" data-k="jumpMultiplier"><span class="sval" id="v_jumpMultiplier">1.5</span></div>
<div class="srow"><span class="slbl">FLY SPD</span><input type="range" min="2" max="15" step="1" data-k="flySpeed"><span class="sval" id="v_flySpeed">8</span></div>
<div class="srow"><span class="slbl">NOCLIP SPD</span><input type="range" min="1" max="15" step="0.5" data-k="noclipSpeed"><span class="sval" id="v_noclipSpeed">5</span></div>
<div class="srow"><span class="slbl">VEH FLY</span><input type="range" min="1" max="10" step="0.5" data-k="vehicleFlySpeed"><span class="sval" id="v_vehicleFlySpeed">3</span></div>
</div>
</div>

<div class="section visuals">
<h2>// Visuals</h2>
<div class="grid">
<div class="item" data-k="esp"><span class="item-name">ESP</span><div class="sw"></div></div>
<div class="item" data-k="chams"><span class="item-name">Chams</span><div class="sw"></div></div>
<div class="item" data-k="fullbright"><span class="item-name">Fullbright</span><div class="sw"></div></div>
<div class="item" data-k="fovChanger"><span class="item-name">FOV Changer</span><div class="sw"></div></div>
<div class="item" data-k="noScopeSway"><span class="item-name">No Scope Sway</span><div class="sw"></div></div>
<div class="item" data-k="noFlinch"><span class="item-name">No Flinch</span><div class="sw"></div></div>
<div class="item" data-k="streamProof"><span class="item-name">Stream Proof</span><div class="sw"></div></div>
</div>
<div class="sliders">
<div class="srow"><span class="slbl">FOV</span><input type="range" min="60" max="160" step="1" data-k="customFOV"><span class="sval" id="v_customFOV">120</span></div>
</div>
</div>

<div class="section esp">
<h2>// ESP Options</h2>
<div class="grid">
<div class="item" data-k="espBoxes"><span class="item-name">Boxes</span><div class="sw"></div></div>
<div class="item" data-k="espNames"><span class="item-name">Names</span><div class="sw"></div></div>
<div class="item" data-k="espDistance"><span class="item-name">Distance</span><div class="sw"></div></div>
<div class="item" data-k="espHealth"><span class="item-name">Health Bars</span><div class="sw"></div></div>
<div class="item" data-k="espSnaplines"><span class="item-name">Snaplines</span><div class="sw"></div></div>
<div class="item" data-k="radar"><span class="item-name">Radar</span><div class="sw"></div></div>
<div class="item" data-k="vehicleESP"><span class="item-name">Vehicle ESP</span><div class="sw"></div></div>
<div class="item" data-k="zombieESP"><span class="item-name">Zombie ESP</span><div class="sw"></div></div>
<div class="item" data-k="itemESP"><span class="item-name">Item ESP</span><div class="sw"></div></div>
</div>
</div>

<div class="section live">
<h2>// Live Radar</h2>
<div class="radar-wrap">
<canvas id="radar" width="280" height="280"></canvas>
<div>
<div class="radar-legend">
<span class="legend-item"><span class="ldot green"></span>You</span>
<span class="legend-item"><span class="ldot red"></span>Players</span>
<span class="legend-item"><span class="ldot yellow"></span>Target</span>
<span class="legend-item"><span class="ldot purple"></span>Zombies</span>
<span class="legend-item"><span class="ldot cyan"></span>Vehicles</span>
<span class="legend-item"><span class="ldot orange"></span>Items</span>
</div>
<div class="entity-counts" id="ecounts"></div>
</div>
</div>
</div>

<div class="section live">
<h2>// Nearby Players</h2>
<div id="playerList" class="player-list"><div class="pl-empty">Waiting for data...</div></div>
</div>

<div class="section loot">
<h2>// Loot Teleport</h2>
<div class="grid">
<div class="item" data-k="lootTeleport"><span class="item-name">Loot Teleport</span><div class="sw"></div></div>
<div class="item" data-k="lootSilent"><span class="item-name">Silent Mode</span><div class="sw"></div></div>
<div class="item" data-k="lootStaggered"><span class="item-name">Staggered</span><div class="sw"></div></div>
<div class="item" data-k="lootFilterGuns"><span class="item-name">Guns Only</span><div class="sw"></div></div>
<div class="item" data-k="lootFilterMeds"><span class="item-name">Meds Only</span><div class="sw"></div></div>
<div class="item" data-k="lootFilterGear"><span class="item-name">Gear Only</span><div class="sw"></div></div>
</div>
<div class="sliders">
<div class="srow"><span class="slbl">RADIUS</span><input type="range" min="5" max="200" step="5" data-k="lootRadius"><span class="sval" id="v_lootRadius">50</span></div>
<div class="srow"><span class="slbl">STAGGER</span><input type="range" min="1" max="30" step="1" data-k="lootDelay"><span class="sval" id="v_lootDelay">10</span></div>
</div>
<div class="loot-info">
<b style="color:#ffaa00">How to use:</b> Hold TAB to pull items. <b>Silent</b> drops items at your feet (less visible). <b>Staggered</b> moves one item per interval. Enable filter toggles to only grab <b>Guns</b>, <b>Meds</b>, or <b>Gear</b> (attachments/ammo). Multiple filters can be combined. With no filters, grabs everything.
</div>
</div>

<div class="section player">
<h2>// Player</h2>
<div class="grid">
<div class="item" data-k="godMode"><span class="item-name">God Mode</span><div class="sw"></div></div>
<div class="item" data-k="adminMode"><span class="item-name">Admin Mode</span><div class="sw"></div></div>
<div class="item" data-k="infiniteStats"><span class="item-name">Infinite Stats</span><div class="sw"></div></div>
<div class="item" data-k="noDebuffs"><span class="item-name">No Debuffs</span><div class="sw"></div></div>
<div class="item" data-k="alwaysGPS"><span class="item-name">Always GPS</span><div class="sw"></div></div>
<div class="item" data-k="alwaysCompass"><span class="item-name">Always Compass</span><div class="sw"></div></div>
</div>
</div>

<div class="footer">STREAMPROOF &mdash; DMA RADAR OVERLAY</div>

</div>
</div>

<div class="toast" id="toast"></div>
)RAWHTML"
R"RAWHTML(
<script>
(function(){
const c=document.getElementById('matrix'),x=c.getContext('2d');
let W,H,cols,drops;
const chars='01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
function initMatrix(){
W=c.width=window.innerWidth;H=c.height=window.innerHeight;
const sz=14;cols=Math.floor(W/sz);
drops=Array.from({length:cols},()=>Math.random()*-100);
}
function draw(){
x.fillStyle='rgba(0,0,0,0.06)';x.fillRect(0,0,W,H);
x.fillStyle='#00ff41';x.font='14px monospace';
for(let i=0;i<cols;i++){
const ch=chars[Math.floor(Math.random()*chars.length)];
const bright=Math.random();
x.fillStyle=bright>0.95?'#aaffaa':bright>0.8?'#00ff41':'#005a10';
x.fillText(ch,i*14,drops[i]*14);
if(drops[i]*14>H&&Math.random()>0.975)drops[i]=0;
drops[i]++;
}
}
initMatrix();window.addEventListener('resize',initMatrix);
setInterval(draw,45);
})();

const O=window.location.origin;
let live=false;
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1200)}
function sync(cfg){
document.querySelectorAll('.item').forEach(e=>{const k=e.dataset.k;if(k in cfg)e.classList.toggle('on',!!cfg[k])});
document.querySelectorAll('input[type=range]').forEach(e=>{const k=e.dataset.k;if(k in cfg){e.value=cfg[k];const s=document.getElementById('v_'+k);if(s){let v=parseFloat(cfg[k]);s.textContent=v%1===0?v.toString():v.toFixed(1)}}});
}
async function poll(){
try{const r=await fetch(O+'/api/config',{signal:AbortSignal.timeout(2000)});if(!r.ok)throw 0;const d=await r.json();sync(d);
if(!live){live=true;document.getElementById('dot').classList.add('on');document.getElementById('stxt').textContent='ONLINE'}}
catch(e){if(live){live=false;document.getElementById('dot').classList.remove('on');document.getElementById('stxt').textContent='OFFLINE'}}
}
document.querySelectorAll('.item').forEach(e=>e.addEventListener('click',async()=>{
try{const r=await fetch(O+'/api/toggle/'+e.dataset.k,{method:'POST'});if(r.ok){const d=await r.json();toast(e.dataset.k+': '+(d.value?'ON':'OFF'));poll()}}catch(e){}}));
document.querySelectorAll('input[type=range]').forEach(e=>{let t;e.addEventListener('input',()=>{
const k=e.dataset.k,v=e.value,s=document.getElementById('v_'+k);
if(s){let n=parseFloat(v);s.textContent=n%1===0?n.toString():n.toFixed(1)}
clearTimeout(t);t=setTimeout(()=>fetch(O+'/api/set/'+k+'/'+v,{method:'POST'}).catch(()=>{}),80)})});
poll();setInterval(poll,500);

let gd=null;
async function pollGD(){try{const r=await fetch(O+'/api/gamedata',{signal:AbortSignal.timeout(1500)});if(r.ok)gd=await r.json()}catch(e){}}
setInterval(pollGD,120);

const rc=document.getElementById('radar'),rx=rc.getContext('2d'),RS=280,RR=200;
function w2r(wx,wz){
if(!gd)return null;
const yr=-gd.yaw*Math.PI/180,dx=wx-gd.lx,dz=wz-gd.lz;
const px=dx*Math.cos(yr)-dz*Math.sin(yr),pz=dx*Math.sin(yr)+dz*Math.cos(yr);
const sx=RS/2+(px/RR)*(RS/2),sy=RS/2-(pz/RR)*(RS/2);
if(sx<2||sx>RS-2||sy<2||sy>RS-2)return null;
return{x:sx,y:sy};
}
function drawRadar(){
if(!gd)return;
rx.fillStyle='rgba(5,10,5,0.97)';rx.fillRect(0,0,RS,RS);
rx.strokeStyle='rgba(0,255,65,0.07)';rx.lineWidth=1;
for(let i=1;i<=3;i++){rx.beginPath();rx.arc(RS/2,RS/2,(RS/2)*(i/3),0,Math.PI*2);rx.stroke()}
rx.beginPath();rx.moveTo(RS/2,0);rx.lineTo(RS/2,RS);rx.stroke();
rx.beginPath();rx.moveTo(0,RS/2);rx.lineTo(RS,RS/2);rx.stroke();
if(gd.i){gd.i.forEach(it=>{const p=w2r(it.x,it.z);if(!p)return;rx.fillStyle='#ffaa00';rx.fillRect(p.x-1.5,p.y-1.5,3,3)})}
if(gd.v){gd.v.forEach(v=>{const p=w2r(v.x,v.z);if(!p)return;rx.fillStyle='#00c8ff';rx.fillRect(p.x-3,p.y-3,6,6)})}
if(gd.z){gd.z.forEach(z=>{const p=w2r(z.x,z.z);if(!p)return;rx.fillStyle='#b400b4';rx.beginPath();rx.arc(p.x,p.y,2.5,0,Math.PI*2);rx.fill()})}
if(gd.p){gd.p.forEach(pl=>{const p=w2r(pl.x,pl.z);if(!p)return;rx.fillStyle=pl.t?'#ffff00':'#ff3232';rx.beginPath();rx.arc(p.x,p.y,4,0,Math.PI*2);rx.fill()})}
rx.fillStyle='#00ff41';rx.beginPath();rx.arc(RS/2,RS/2,4,0,Math.PI*2);rx.fill();
rx.strokeStyle='#00ff41';rx.lineWidth=2;rx.beginPath();rx.moveTo(RS/2,RS/2);rx.lineTo(RS/2,RS/2-14);rx.stroke();
}
setInterval(drawRadar,80);

function updPL(){
const el=document.getElementById('playerList');
const ec=document.getElementById('ecounts');
if(!gd||!gd.p||gd.p.length===0){el.innerHTML='<div class="pl-empty">No players detected</div>';
ec.innerHTML='';return}
let h='';
gd.p.slice().sort((a,b)=>a.d-b.d).forEach(p=>{
const hp=Math.min(100,Math.max(0,p.hp));
const r=Math.round(255*(1-hp/100)),g=Math.round(255*(hp/100));
const tc=p.t?' pl-target':'';
h+='<div class="pl-row'+tc+'"><span class="pl-name">'+p.n+'</span><span class="pl-dist">'+p.d.toFixed(0)+'m</span><div class="pl-hp-bar"><div class="pl-hp-fill" style="width:'+hp+'%;background:rgb('+r+','+g+',0)"></div></div><span class="pl-hp-text" style="color:rgb('+r+','+g+',0)">'+hp.toFixed(0)+'</span></div>';
});
el.innerHTML=h;
let counts='';
if(gd.p.length)counts+='<span class="ecount" style="color:#ff3232">Players: '+gd.p.length+'</span>';
if(gd.z&&gd.z.length)counts+='<span class="ecount" style="color:#b400b4">Zombies: '+gd.z.length+'</span>';
if(gd.v&&gd.v.length)counts+='<span class="ecount" style="color:#00c8ff">Vehicles: '+gd.v.length+'</span>';
if(gd.i&&gd.i.length)counts+='<span class="ecount" style="color:#ffaa00">Items: '+gd.i.length+'</span>';
ec.innerHTML=counts;
}
setInterval(updPL,200);
</script>
</body>
</html>
)RAWHTML";
