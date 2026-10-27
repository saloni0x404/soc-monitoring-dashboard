var ME={role:'VIEWER',username:''},TEAM=[],incOpenId=null,lt;
var NAV=['Overview',[1,'&#9638;','Dashboard'],[3,'&#9888;','Alerts','ob'],[6,'&#9873;','Incidents','ib'],[2,'&#9906;','Threat Analysis'],'Operations',[9,'&#9889;','Live Events'],[4,'&#9776;','Event Logs'],[5,'&#9707;','Assets'],'Administration',[7,'&#9881;','Account &amp; Team'],[8,'&#9783;','Audit Log','',1]];
function badges(){var a=$('ob'),b=$('ib');if(a){a.textContent=S.openCount;a.hidden=!S.openCount}if(b){b.textContent=S.incOpen||0;b.hidden=!S.incOpen}}
function nav(){$('side').innerHTML='<div class="brand"><i>&#128737;</i><b>SOC Console</b></div>'+NAV.map(function(n){if(typeof n=='string')return'<div class="grp">'+n+'</div>';if(n[4]&&ME.role!='ADMIN')return'';return'<button class="nav'+(n[0]==tab?' on':'')+'" data-v="'+n[0]+'" title="'+n[2]+'"><span>'+n[1]+'</span><span class="lbl">'+n[2]+'</span>'+(n[3]?'<span class="bd" id="'+n[3]+'" hidden></span>':'')+'</button>'}).join('');badges()}
$('side').onclick=function(e){var b=e.target.closest('[data-v]');if(b)show(+b.dataset.v)};
var _s=show;show=function(t){_s(t);nav();var v=$('v'+t);v.classList.remove('vin');void v.offsetWidth;v.classList.add('vin')};
var _r=refresh;refresh=function(){return _r().then(function(){fetched=Date.now();badges();tween($('threats'),S.total);tween($('events'),S.events);tween($('sc'),S.score);if(firstPaint){firstPaint=false;document.body.classList.remove('loading');if(!RM){['s1','s2'].forEach(function(i){$(i).classList.add('draw');setTimeout(function(){$(i).classList.remove('draw')},1300)})}}var a=document.activeElement.tagName;if((tab==5||tab==6)&&a!='INPUT'&&a!='SELECT')EXTRA[tab]()})};
function row(c){return'<tr>'+c.map(function(x){return'<td>'+x+'</td>'}).join('')+'</tr>'}
function empty(n,t){return'<tr><td colspan="'+n+'" class="mute">'+t+'</td></tr>'}
function sevTag(s){return'<span class="tag '+s+'">'+s+'</span>'}
function done(r,f){toast(r.error||'Saved');if(!r.error)f()}
// logs
function loadLogs(){api('/api/logs?q='+encodeURIComponent($('lq').value)).then(function(r){$('lg').innerHTML=r.map(function(l){return row([ago(l.ts),esc(l.source),esc(l.host),esc(l.src_ip),esc(l.type),'<span style="white-space:normal">'+esc(l.message)+'</span>'])}).join('')||empty(6,'No logs match this filter.')})}
$('lq').oninput=function(){clearTimeout(lt);lt=setTimeout(loadLogs,250)};
// assets
function loadAssets(){api('/api/assets').then(function(r){$('as').innerHTML=r.map(function(a){return row([esc(a.name),esc(a.ip),esc(a.type),sevTag(a.criticality),a.open?'<span class="tag Critical">'+a.open+' open alert'+(a.open>1?'s':'')+'</span>':(a.seen&&Date.now()-a.seen<600000?'<span class="tag Low">Healthy</span>':'<span class="tag Medium">No recent data</span>'),a.seen?ago(a.seen):'never',ME.role=='ADMIN'?'<button class="btn ghost sm" data-del="'+a.id+'">Remove</button>':''])}).join('')||empty(7,'No assets yet. Add your first one above.')})}
$('aadd').onclick=function(){api('/api/assets',{method:'POST',body:{name:$('an').value,ip:$('aip').value,type:$('at').value,criticality:$('ac').value}}).then(function(r){done(r,function(){$('an').value='';$('aip').value='';loadAssets()})})};
$('as').onclick=function(e){var b=e.target.closest('[data-del]');if(b&&confirm('Remove this asset?'))api('/api/assets/'+b.dataset.del,{method:'DELETE'}).then(loadAssets)};
// incidents
function incDetail(i){var sel=function(f,o,cur){return'<select data-f="'+f+'" data-id="'+i.id+'">'+o.map(function(x){return'<option value="'+esc(x[0])+'"'+(x[0]==cur?' selected':'')+'>'+esc(x[1])+'</option>'}).join('')+'</select>'};
 return'<tr class="dt"><td colspan="6"><div class="frm">Status '+sel('status',[['Open','Open'],['Investigating','Investigating'],['Resolved','Resolved']],i.status)+' Assignee '+sel('assignee',[['','Unassigned']].concat(TEAM.map(function(u){return[u,u]})),i.assignee)+'</div>'+i.notes.map(function(n){return'<div style="margin-bottom:4px"><b style="color:var(--text)">'+esc(n.by)+'</b> '+ago(n.ts)+': <span style="color:var(--text)">'+esc(n.text)+'</span></div>'}).join('')+'<div class="frm" style="margin:10px 0 0"><input id="nt" placeholder="Add an investigation note" style="min-width:280px"><button class="btn sm" data-note="'+i.id+'">Add note</button></div></td></tr>'}
function loadInc(){Promise.all([api('/api/incidents'),api('/api/team')]).then(function(r){TEAM=r[1];$('ic').innerHTML=r[0].map(function(i){return'<tr data-i="'+i.id+'" style="cursor:pointer"><td>'+esc(i.ref)+'</td><td>'+esc(i.title)+' <span class="mute">on '+esc(i.host)+'</span></td><td>'+sevTag(i.sev)+'</td><td>'+i.status+'</td><td>'+(esc(i.assignee)||'Unassigned')+'</td><td>'+ago(i.updated)+'</td></tr>'+(incOpenId==i.id?incDetail(i):'')}).join('')||empty(6,'No incidents yet. Open an alert and choose Escalate to incident.')})}
$('ic').onclick=function(e){var b=e.target.closest('[data-note]');if(b){var v=$('nt').value;if(v.trim())api('/api/incidents/'+b.dataset.note,{method:'POST',body:{note:v}}).then(loadInc);return}var t=e.target.closest('tr[data-i]');if(t){incOpenId=incOpenId==t.dataset.i?null:+t.dataset.i;loadInc()}};
$('ic').onchange=function(e){var s=e.target.closest('select[data-f]');if(s){var o={};o[s.dataset.f]=s.value;api('/api/incidents/'+s.dataset.id,{method:'POST',body:o}).then(function(){loadInc();refresh()})}};
// account and team
function loadUsers(){$('adm').hidden=ME.role!='ADMIN';if(ME.role!='ADMIN')return;api('/api/users').then(function(r){$('us').innerHTML=r.map(function(u){return row([esc(u.name),esc(u.username),'<span class="tag '+(u.role=='ADMIN'?'Critical':u.role=='ANALYST'?'Medium':'Low')+'">'+u.role+'</span>',u.username==ME.username?'<span class="mute">You</span>':'<button class="btn ghost sm" data-u="'+esc(u.username)+'">Remove</button>'])}).join('')})}
$('uadd').onclick=function(){api('/api/users',{method:'POST',body:{name:$('un').value,username:$('uu').value,password:$('up').value,role:$('ur').value}}).then(function(r){done(r,function(){$('un').value=$('uu').value=$('up').value='';loadUsers()})})};
$('us').onclick=function(e){var b=e.target.closest('[data-u]');if(b&&confirm('Remove user '+b.dataset.u+'?'))api('/api/users/'+encodeURIComponent(b.dataset.u),{method:'DELETE'}).then(function(r){done(r,loadUsers)})};
$('pbtn').onclick=function(){api('/api/password',{method:'POST',body:{current:$('pc').value,next:$('pn').value}}).then(function(r){done(r,function(){$('pc').value=$('pn').value='';toast('Password updated')})})};
// audit
function loadAudit(){api('/api/audit').then(function(r){$('au').innerHTML=r.map(function(a){return row([new Date(a.ts).toLocaleString(),esc(a.user),esc(a.action),'<span style="white-space:normal">'+esc(a.detail)+'</span>'])}).join('')||empty(4,'No activity recorded yet.')})}
var EXTRA={4:loadLogs,5:loadAssets,6:loadInc,7:loadUsers,8:loadAudit};
// ---- preferences, theme, layout ----
function getp(k,d){try{return localStorage.getItem('soc.'+k)||d}catch(e){return d}}
function pref(k,v){try{localStorage.setItem('soc.'+k,v)}catch(e){}}
var RNG=getp('rng','24h'),RM=matchMedia('(prefers-reduced-motion: reduce)').matches,fetched=Date.now(),firstPaint=true;
function theme(t){document.documentElement.dataset.theme=t;pref('theme',t)}theme(getp('theme','dark'));
$('theme').onclick=function(){theme(document.documentElement.dataset.theme=='light'?'dark':'light')};
if(getp('collapsed','')=='1')document.body.classList.add('collapsed');
$('burger').onclick=function(){pref('collapsed',document.body.classList.toggle('collapsed')?'1':'')};
$('rng').value=RNG;$('rng').onchange=function(){RNG=this.value;pref('rng',RNG);refresh()};
filter=getp('sev','All Threats');
function tween(el,to){var from=+el.dataset.v||0;el.dataset.v=to;if(RM||from==to){el.textContent=to.toLocaleString();return}var t0=performance.now();(function f(n){var p=Math.min(1,(n-t0)/500);el.textContent=Math.round(from+(to-from)*p).toLocaleString();if(p<1)requestAnimationFrame(f)})(t0)}
var RK=['brute','port scan','powershell','privilege','malware','web attack'];
$('s2').onclick=function(e){var t=e.target.closest('text[data-k]');if(t){kw=RK[+t.dataset.k];$('q').value=kw;$('st').value='All';list();table();show(3)}};
// ---- connection and freshness ----
var lastEv=Date.now();
function conn(s){var c=$('conn');c.className='pill'+(s=='live'?'':s=='wait'?' warn':' bad');c.querySelector('b').textContent={live:'Live',wait:'Reconnecting',off:'Offline'}[s]}
sock.on('connect',function(){conn('live');refresh()});sock.on('disconnect',function(){conn('off')});sock.on('connect_error',function(){conn('wait')});
if(sock.connected)conn('live');
setInterval(function(){var s=Math.round((Date.now()-lastEv)/1000),stale=s>30||!sock.connected;$('fresh').textContent=!sock.connected?'Connection lost. Data may be stale. Retrying...':s>30?'No events for '+s+'s. Data may be stale.':'Last event '+(s<2?'just now':s+'s ago');$('fresh').style.color=stale?'var(--yel)':'';var u=S.uptime?S.uptime+Math.round((Date.now()-fetched)/1000):0;$('upt').textContent=u?'Server up '+(u>3600?Math.floor(u/3600)+'h ':'')+Math.floor(u%3600/60)+'m':''},1000);
setInterval(function(){if(document.visibilityState=='visible')refresh()},10000);
// ---- critical alert banner ----
var cb=document.createElement('div'),ct;cb.className='crit';cb.setAttribute('role','alert');document.body.appendChild(cb);
sock.on('alert',function(a){if(a.sev!='Critical')return;cb.innerHTML='<span class="dot" style="background:#fff"></span><b>Critical alert</b> '+esc(a.title)+' on '+esc(a.host)+' <u>Review</u>';cb.classList.add('show');clearTimeout(ct);ct=setTimeout(function(){cb.classList.remove('show')},9000)});
cb.onclick=function(){cb.classList.remove('show');show(3)};
// ---- live event stream ----
var EV=[],paused=false,cleared=0,page=0,esort='ts',edir=-1,PS=15,pend=0,et,SR={Critical:4,High:3,Medium:2,Low:1,Info:0};
function evVis(){var q=$('eq').value.toLowerCase(),sv=$('es').value;return EV.filter(function(l){return l.ts>cleared&&(sv=='All'||(l.sev||'Info')==sv)&&(l.message+' '+l.host+' '+l.src_ip+' '+(l.dst||'')+' '+l.type).toLowerCase().indexOf(q)>-1}).sort(function(a,b){var x=esort=='sev'?SR[a.sev||'Info']:a.ts,y=esort=='sev'?SR[b.sev||'Info']:b.ts;return(x-y)*edir})}
function evRender(){var r=evVis(),pg=Math.max(1,Math.ceil(r.length/PS));if(page>=pg)page=pg-1;$('eb').innerHTML=r.slice(page*PS,page*PS+PS).map(function(l){var s=l.sev||'Info';return row([new Date(l.ts).toLocaleTimeString(),s=='Info'?'<span class="tag" style="background:var(--panel2);color:var(--mute)">Info</span>':sevTag(s),esc(l.src_ip),esc(l.dst||'-'),esc(l.type),esc(l.host),'<span style="white-space:normal">'+esc(l.message)+'</span>'])}).join('')||empty(7,EV.length?'No events match these filters.':'Waiting for events...');$('ep').textContent='Page '+(page+1)+' of '+pg+' ('+r.length+' events)';$('ebuf').textContent=paused&&pend?pend+' new events waiting':''}
function loadEvents(){if(EV.length)evRender();else api('/api/logs').then(function(r){EV=r;evRender()})}
EXTRA[9]=loadEvents;
sock.on('event',function(l){lastEv=Date.now();EV.unshift(l);if(EV.length>1000)EV.pop();if(tab!=9)return;if(paused){pend++;$('ebuf').textContent=pend+' new events waiting';return}clearTimeout(et);et=setTimeout(evRender,300)});
['eq','es'].forEach(function(i){$(i).oninput=$(i).onchange=function(){page=0;evRender()}});
$('epause').onclick=function(){paused=!paused;this.textContent=paused?'Resume':'Pause';if(!paused){pend=0;evRender()}else $('ebuf').textContent='Paused. Events keep arriving in the background.'};
$('eclear').onclick=function(){cleared=Date.now();page=0;evRender();toast('View cleared. Events keep arriving in the background.')};
$('eprev').onclick=function(){if(page>0){page--;evRender()}};$('enext').onclick=function(){page++;evRender()};
function srt(e){var t=e.target.closest('th[data-k]');if(t){edir=esort==t.dataset.k?-edir:-1;esort=t.dataset.k;evRender()}}
$('eh').onclick=srt;$('eh').onkeydown=function(e){if(e.key=='Enter')srt(e)};

api('/api/me').then(function(u){ME=u;nav();refresh()});
