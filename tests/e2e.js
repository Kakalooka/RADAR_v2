// RADAR regression + CSV import tests. Run: npm i -D playwright && npx playwright install chromium && node tests/e2e.js
// Optional arg: path to the HTML under test (default: index.html next to this folder).
let pw; try { pw=require('playwright'); } catch { pw=require('/opt/npm-tools/node_modules/playwright'); }
const { chromium } = pw;
const fs=require('fs'), path=require('path'), os=require('os');
const FILE='file://'+path.resolve(process.argv[2]||path.join(__dirname,'..','index.html'));
const TMP=fs.mkdtempSync(path.join(os.tmpdir(),'radar-'));
const GOLDEN=JSON.parse(fs.readFileSync(path.join(__dirname,'golden-demo.json'),'utf8'));
const H='id,nazwa_inicjatywy,dzial,grupa_tematyczna,wlasciciel,sponsor,status,postep_procent,data_ostatniej_aktualizacji,zalezy_od,notatka_statusu\n';
const row=(id,dep='',extra={})=>{const r={n:'Name '+id,d:'Dept',st:'on_track',p:'50',u:'2026-08-20',note:'n',...extra};return `${id},${r.n},${r.d},G,Owner,Sponsor,${r.st},${r.p},${r.u},"${dep}",${r.note}\n`;};
let pass=0, fail=0; const ok=(c,m)=>{ (c?pass++:fail++); console.log((c?'PASS ':'FAIL ')+m); };
(async()=>{
  const b=await chromium.launch(); const p=await b.newPage({viewport:{width:1400,height:900}});
  const errs=[], dialogs=[]; p.on('pageerror',e=>errs.push(e.message)); p.on('dialog',d=>{dialogs.push(d.message());d.dismiss().catch(()=>{})});
  await p.goto(FILE);
  const load=async(name,content)=>{ const f=path.join(TMP,name); fs.writeFileSync(f,content); await p.setInputFiles('#csv-file',f); await p.waitForTimeout(300);
    return p.evaluate(()=>({err:getComputedStyle(document.getElementById('csv-err')).display!=='none', title:document.getElementById('csv-err-title').textContent,
      items:[...document.querySelectorAll('#csv-err-list li')].map(l=>l.textContent), n:APP_DATA.inicjatywy.length, ids:APP_DATA.inicjatywy.map(r=>r.id), asof:APP_DATA.asof})); };
  const close=()=>p.evaluate(()=>closeCsvErrors());

  // 0. golden regression: startup output must equal the accepted v7.3 result
  const g=await p.evaluate(()=>{
    const pick=d=>({asof:d.asof,
      iv:d.interwencje.map(i=>[i.id,i.rola,i.priority,i.score,i.rekomendacja,i.rekomendacja_en,i.dlaczego,i.typ]),
      stale:d.inicjatywy.map(r=>[r.id,r.staleness,r.postep,r.dep.join('|'),r.downstream.join('|'),r.bad_downstream.join('|')]),
      alerty:d.alerty, brief:d.brief});
    const res={};
    for(const L of ['en','pl']){ LANG=L; delete APP_DATA.dqIssues; res['dq_'+L]=buildDQIssues(APP_DATA).map(i=>[i.severity,i.title,i.desc]); }
    LANG='en'; delete APP_DATA.dqIssues;
    res.boot=pick(APP_DATA); res.tlRows=document.querySelectorAll('.tl-row').length;
    res.tbody=document.querySelectorAll('#tbody tr').length; res.nodes=document.querySelectorAll('.gnode').length; return res; });
  for(const k of Object.keys(GOLDEN)) ok(JSON.stringify(g[k])===JSON.stringify(GOLDEN[k]), `golden demo: ${k} unchanged`);
  ok(g.boot.iv.length===13 && g.boot.iv.filter(i=>i[2]==='p1').length===3, 'golden demo: 13 interventions, 3 × P1');

  // 1. demo CSV + snapshot_date=2026-08-25 via the real import path = startup output (parity)
  const demo=await p.evaluate(()=>DEMO_CSV);
  const before=await p.evaluate(()=>JSON.stringify(APP_DATA.interwencje.map(i=>[i.id,i.rola,i.priority,i.score,i.rekomendacja])));
  const withSnap=demo.split('\n').map((l,i)=>l+(i===0?',snapshot_date':',2026-08-25')).join('\n');
  let r=await load('demo_snap.csv',withSnap);
  const after=await p.evaluate(()=>JSON.stringify(APP_DATA.interwencje.map(i=>[i.id,i.rola,i.priority,i.score,i.rekomendacja])));
  ok(!r.err && before===after && r.asof==='2026-08-25', `demo + snapshot_date re-import parity (asof ${r.asof})`);
  // 1b. without snapshot_date the analysis date is today, and it is disclosed
  r=await load('demo.csv',demo);
  const today=await p.evaluate(()=>{const n=new Date();return `${n.getFullYear()}-${String(n.getMonth()+1).padStart(2,'0')}-${String(n.getDate()).padStart(2,'0')}`;});
  const dqToday=await p.evaluate(()=>{gotoTab('dq'); renderDQ(APP_DATA); return document.getElementById('dq-body').textContent;});
  ok(!r.err && r.asof===today && /today's date/.test(dqToday), `no snapshot_date → analysis as of today (${r.asof}), labelled in DQ`);

  // 2. original InPost-shaped CSV without schedule columns
  const noSched=demo.split('\n').map(l=>{const f=[];let c='',q=false;for(const ch of l){if(ch==='"')q=!q;if(ch===','&&!q){f.push(c);c='';}else c+=ch;}f.push(c);f.splice(9,3);return f.join(',');}).join('\n');
  r=await load('nosched.csv',noSched);
  const tl=await p.evaluate(()=>!!document.querySelector('.tl-empty'));
  const iv2=await p.evaluate(()=>JSON.stringify(APP_DATA.interwencje.map(i=>[i.id,i.rola,i.priority,i.score,i.rekomendacja])));
  ok(!r.err && tl, 'CSV without schedule fields: accepted, timeline shows "unavailable"');

  // 3. XSS payloads — valid file, must render as text
  r=await load('xss.csv', H+row('A1','',{n:'"<img src=x onerror=alert(1)>"',note:'"<script>alert(2)</script>"'})+row('A2','A1',{st:'blocked',d:'"<b onmouseover=alert(3)>D</b>"'}));
  await p.evaluate(()=>{ openPanel('A1'); gotoTab('brief'); renderBrief(); gotoTab('dq'); renderDQ(APP_DATA); gotoTab('timeline'); closePanel(); });
  const inj=await p.evaluate(()=>document.querySelectorAll('body img, #sp-body script, #dept-list b, #brief-body b, #tbody img').length);
  const shown=await p.evaluate(()=>document.querySelector('#tbody .td-name').textContent);
  ok(!r.err && inj===0 && dialogs.length===0 && shown.includes('<img'), `XSS: payload shown as text, 0 injected elements, ${dialogs.length} dialogs`);

  // 4. multiline quoted note preserved, no silent drop
  r=await load('multi.csv', H+row('A1','',{note:'"line1, still\nline2 ""quoted"""'})+row('A2','A1'));
  const note=await p.evaluate(()=>APP_DATA.inicjatywy[0].notatka_statusu);
  ok(!r.err && note==='line1, still\nline2 "quoted"', 'multiline quoted field kept intact: '+JSON.stringify(note));

  // 5..n rejections — previous dataset (A1,A2) must stay loaded
  const cases=[
    ['cycle', H+row('A1','A3')+row('A2','A1')+row('A3','A2'), /cycle/i],
    ['self-dep', H+row('A1','A1')+row('A2'), /depends on itself/],
    ['duplicate id', H+row('A1')+row('A1')+row('A2'), /duplicate id A1/],
    ['unknown dep', H+row('A1','ZZ-9')+row('A2'), /ZZ-9/],
    ['wrong column count', H+row('A1')+row('A2')+'A3,bad,cols\n', /line 4: 3 columns/],
    ['bad status / progress / date', H+row('A1','',{st:'green',p:'150',u:'20.08.2026'})+row('A2'), /unknown status[\s\S]*integer 0–100[\s\S]*YYYY-MM-DD/],
    ['missing column', 'id,nazwa_inicjatywy\nA1,x\nA2,y\n', /Missing required columns/],
    ['unclosed quote', H+row('A1')+'A2,"oops,D,G,O,S,on_track,1,2026-08-20,,n\n', /Unclosed quote/],
    ['bad id (quote injection)', H+row("A1');alert(4);('")+row('A2'), /invalid id/],
  ];
  await load('base.csv', H+row('A1')+row('A2','A1',{st:'blocked'}));
  for(const [name,csv,re] of cases){
    r=await load(name.replace(/\W+/g,'_')+'.csv',csv);
    const txt=r.items.join(' | ');
    ok(r.err && re.test(txt) && r.ids.join()==='A1,A2', `rejects ${name}: ${txt.slice(0,110)}`);
    await close();
  }

  // snapshot handling
  const HS=H.replace('\n',',snapshot_date\n');
  r=await load('y2027.csv', HS+row('A1','',{u:'2027-03-01'}).replace('\n',',2027-03-03\n')+row('A2','A1',{u:'2027-03-02'}).replace('\n',',2027-03-03\n'));
  const st=await p.evaluate(()=>APP_DATA.inicjatywy.map(r=>r.staleness));
  ok(!r.err && st.join()==='2,1', `2027 data with snapshot_date: staleness ${st} (was -188/-189 on main)`);
  r=await load('future.csv', H+row('A1','',{u:'2099-01-01'})+row('A2','A1'));
  ok(r.err && /later than the snapshot/.test(r.items.join()), 'update date after today rejected when no snapshot_date'); await close();
  r=await load('snapempty.csv', HS+row('A1').replace('\n',',2027-01-10\n')+row('A2','A1').replace('\n',',\n'));
  ok(r.err && /snapshot_date/.test(r.items.join()), 'snapshot_date present but empty in some rows → rejected'); await close();
  r=await load('snap.csv', HS+row('A1').replace('\n',',2027-01-10\n')+row('A2','A1').replace('\n',',2027-01-10\n'));
  const dqa=await p.evaluate(()=>{gotoTab('dq'); renderDQ(APP_DATA); return document.getElementById('dq-body').textContent;});
  ok(!r.err && r.asof==='2027-01-10' && /snapshot_date column/.test(dqa), 'snapshot_date column honoured and disclosed in DQ assumptions');
  r=await load('snapfut.csv', HS+row('A1').replace('\n',',2026-08-01\n')+row('A2','A1').replace('\n',',2026-08-01\n'));
  ok(r.err && /later than the snapshot/.test(r.items.join()), 'update after snapshot_date rejected'); await close();

  // INIT-16 DQ gating
  const dq16=await p.evaluate(H=>{ const mk=n=>buildDataFromRecs(parseCSV(H+`INIT-03,x,Marketing,G,O,S,on_track,10,2026-08-20,"",n\nINIT-16,y,Marketing,G,O,S,on_track,10,2026-08-20,"INIT-03",${n}\n`)); return [buildDQIssues(mk('neutral')).some(i=>i.title.includes('INIT-16')), buildDQIssues(mk('potrzebujemy akceptacji Pricing')).some(i=>i.title.includes('INIT-16'))]; }, H);
  ok(dq16[0]===false && dq16[1]===true, 'INIT-16 DQ flag only when the note asks for Pricing sign-off');

  // listeners do not accumulate
  await p.goto(FILE);
  const lc=await p.evaluate(()=>{ let n=0; const o=EventTarget.prototype.addEventListener; const live=new Set();
    EventTarget.prototype.addEventListener=function(t,f,opt){ if(this===window){ n++; const s=opt&&opt.signal; live.add(f); if(s) s.addEventListener('abort',()=>live.delete(f)); } return o.call(this,t,f,opt); };
    for(let i=0;i<10;i++) setLayout(i%2?'cols':'lanes'); setLang('pl'); setLang('en'); return live.size; });
  ok(lc<=4, `window listeners alive after 10 layout + 2 language switches: ${lc} (was 28 and growing)`);

  // drag + pan still work
  await p.evaluate(()=>gotoTab('mapa'));
  const box=await p.locator('.gnode[data-id="INIT-05"] rect').boundingBox();
  const x0=await p.evaluate(()=>nodePositions['INIT-05'].x);
  await p.mouse.move(box.x+20,box.y+20); await p.mouse.down(); await p.mouse.move(box.x+120,box.y+60,{steps:5}); await p.mouse.up();
  const x1=await p.evaluate(()=>nodePositions['INIT-05'].x);
  ok(x1>x0+30, `node drag still works (x ${x0} → ${Math.round(x1)})`);
  await p.evaluate(()=>setLang('pl'));
  r=await load('cyc_pl.csv', H+row('A1','A2')+row('A2','A1'));
    ok(r.err && /odrzucony/.test(r.title), 'PL error dialog: '+r.title);
  ok(errs.length===0, 'no page errors '+JSON.stringify(errs));
  console.log(`\n${pass} passed, ${fail} failed`);
  await b.close(); fs.rmSync(TMP,{recursive:true,force:true}); process.exit(fail?1:0);
})();
