#pragma once
inline const char* PZ_RADAR_HTML = R"HTML(<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>PZ radar</title>
<style>
body{margin:0;background:#0f1419;color:#e8eef5;font-family:system-ui,sans-serif}
header{padding:10px 14px;border-bottom:1px solid #2a3540}
canvas{display:block;margin:12px auto;background:#1a2330;border:1px solid #2a3540;border-radius:8px}
#meta{font-size:.85rem;opacity:.85}
</style></head>
<body>
<header><strong>Project Zomboid live radar</strong> <span id="meta"></span></header>
<canvas id="c" width="900" height="520"></canvas>
<script>
const ctx=document.getElementById("c").getContext("2d");
async function tick(){
  try{
    const d=await (await fetch("/api/players")).json();
    const ps=d.players||[];
    document.getElementById("meta").textContent=`${ps.length} players · mock=${d.mock}`;
    let minX=1e9,maxX=-1e9,minY=1e9,maxY=-1e9;
    for(const p of ps){minX=Math.min(minX,p.x);maxX=Math.max(maxX,p.x);minY=Math.min(minY,p.y);maxY=Math.max(maxY,p.y);}
    const pad=60;minX-=pad;maxX+=pad;minY-=pad;maxY+=pad;
    const w=900,h=520;ctx.fillStyle="#1a2330";ctx.fillRect(0,0,w,h);
    const sx=w/(maxX-minX), sy=h/(maxY-minY);
    for(const p of ps){
      const x=(p.x-minX)*sx,y=h-(p.y-minY)*sy;
      ctx.fillStyle=p.local?"#6cf":"#3d9eff";
      ctx.beginPath();ctx.arc(x,y,6,0,7);ctx.fill();
      ctx.fillStyle="#fff";ctx.fillText(p.username||"?",x+8,y-6);
    }
  }catch(e){document.getElementById("meta").textContent="waiting";}
}
setInterval(tick,500);tick();
</script></body></html>)HTML";