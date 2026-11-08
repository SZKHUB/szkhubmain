'use strict';
// SZKHUB backend: zero dependencies, runs on any Node 18+ host (VPS, Railway, Render, Docker).
const http=require('http'),crypto=require('crypto'),fs=require('fs'),dns=require('dns').promises,path=require('path');
const E=process.env,PORT=+E.PORT||3000,DIR=E.DATA_DIR||'./data',RATE=+E.RATE_LIMIT||60,CH=6000;
const KEY=Buffer.from(E.MASTER_KEY||'','hex');
if(KEY.length!==32||!E.ADMIN_USER||!E.ADMIN_PASSWORD){console.error('Set MASTER_KEY (64 hex chars), ADMIN_USER and ADMIN_PASSWORD');process.exit(1)}
fs.mkdirSync(DIR,{recursive:true});const DBF=path.join(DIR,'db.json');
let db={scripts:{},logs:[],domains:[],ver:1,at:Date.now(),maint:false,off:{}};
try{Object.assign(db,JSON.parse(fs.readFileSync(DBF,'utf8')))}catch{}
let st;const save=()=>{clearTimeout(st);st=setTimeout(()=>{fs.writeFileSync(DBF+'.tmp',JSON.stringify(db));fs.renameSync(DBF+'.tmp',DBF)},200)};
const log=(type,msg,ip)=>{db.logs.unshift({t:Date.now(),type,msg,ip});db.logs.length>2000&&(db.logs.length=2000);save()};
const salt=crypto.randomBytes(16),H=s=>crypto.scryptSync(String(s),salt,64),AU=H(E.ADMIN_USER),AP=H(E.ADMIN_PASSWORD);
const eq=(a,b)=>crypto.timingSafeEqual(a,b);
const enc=t=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',KEY,iv),d=Buffer.concat([c.update(t,'utf8'),c.final()]);return[iv,c.getAuthTag(),d].map(b=>b.toString('base64'))};
const dec=([i,t,d])=>{const c=crypto.createDecipheriv('aes-256-gcm',KEY,Buffer.from(i,'base64'));c.setAuthTag(Buffer.from(t,'base64'));return Buffer.concat([c.update(Buffer.from(d,'base64')),c.final()]).toString('utf8')};
const sessions=new Map(),tickets=new Map(),admins=new Map(),rl=new Map();
const rid=n=>crypto.randomBytes(n).toString('hex');
setInterval(()=>{const n=Date.now();for(const m of[sessions,tickets,admins])for(const[k,v]of m)if((v.exp||v)<n)m.delete(k);rl.clear()},60000).unref();
const limited=(k,max)=>{const n=(rl.get(k)||0)+1;rl.set(k,n);return n>max};
const active=()=>Object.values(db.scripts).filter(s=>s.status==='published').sort((a,b)=>b.at-a.at)[0];
const body=req=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>2e6){no(new Error('too large'));req.destroy()}});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{no(new Error('bad json'))}})});
const pub=req=>E.PUBLIC_URL||`https://${req.headers.host}`;
const loaderLine=req=>`loadstring(game:HttpGet("${pub(req)}/api/loader"))()`;
const bootstrap=base=>`-- SZKHUB protected loader
local H=game:GetService("HttpService")
local B="${base}/api"
local s=H:JSONDecode(game:HttpGet(B.."/session"))
local t=H:JSONDecode(game:HttpGet(B.."/ticket?s="..s.token))
local p={}
for i=1,t.chunks do p[i]=game:HttpGet(B.."/chunks?t="..t.ticket.."&i="..i) end
loadstring(table.concat(p))()
`;
http.createServer(async(req,res)=>{
 const ip=(E.TRUST_PROXY?String(req.headers['x-forwarded-for']||'').split(',')[0].trim():'')||req.socket.remoteAddress;
 const J=(c,o)=>{res.writeHead(c,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(o))};
 const T=(c,s)=>{res.writeHead(c,{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'});res.end(s)};
 try{
  const u=new URL(req.url,'http://x'),p=u.pathname,m=req.method,q=u.searchParams;
  if(p==='/'||p==='/index.html'){const f=path.join(__dirname,'public','index.html');return fs.existsSync(f)?(res.writeHead(200,{'content-type':'text/html; charset=utf-8'}),res.end(fs.readFileSync(f))):T(404,'No dashboard installed')}
  if(!p.startsWith('/api/'))return T(404,'Not found');
  if(limited('g'+ip,RATE)){log('blocked','Rate limit exceeded',ip);return J(429,{error:'rate_limited'})}
  const down=()=>db.maint||db.off['/api/'+p.split('/')[2]];
  if(p==='/api/loader'){if(down())return T(503,'-- SZKHUB unavailable');log('loader','Loader fetched',ip);return T(200,bootstrap(pub(req)))}
  if(p==='/api/session'){if(down())return J(503,{error:'unavailable'});const token=rid(24);sessions.set(token,{ip,exp:Date.now()+120000});log('api','Session issued',ip);return J(200,{token,expires_in:120})}
  if(p==='/api/ticket'){const s=sessions.get(q.get('s'));sessions.delete(q.get('s'));
   if(!s||s.exp<Date.now()||s.ip!==ip){log('blocked','Invalid or expired session',ip);return J(403,{error:'invalid_session'})}
   const sc=active();if(!sc||down())return J(503,{error:'no_active_script'});
   const src=dec(sc.enc),parts=[];for(let i=0;i<src.length;i+=CH)parts.push(src.slice(i,i+CH));
   const ticket=rid(24);tickets.set(ticket,{ip,exp:Date.now()+60000,parts,got:new Set(),sid:sc.id,v:sc.v});
   log('api','Ticket issued for '+sc.name+' v'+sc.v,ip);return J(200,{ticket,chunks:parts.length})}
  if(p==='/api/chunks'){const t=tickets.get(q.get('t')),i=+q.get('i');
   if(!t||t.exp<Date.now()||t.ip!==ip||!(i>=1&&i<=t.parts.length)){log('blocked','Invalid ticket',ip);return J(403,{error:'invalid_ticket'})}
   if(t.got.has(i)){tickets.delete(q.get('t'));log('blocked','Replay detected, ticket revoked',ip);return J(403,{error:'replay'})}
   t.got.add(i);if(t.got.size===t.parts.length){tickets.delete(q.get('t'));log('script','Script delivered (v'+t.v+')',ip)}
   return T(200,t.parts[i-1])}
  if(p==='/api/discord/get'){const a=String(req.headers.authorization||''),ok=E.DISCORD_BOT_SECRET&&a.length===('Bot '+E.DISCORD_BOT_SECRET).length&&eq(Buffer.from(a),Buffer.from('Bot '+E.DISCORD_BOT_SECRET));
   const gs=(E.DISCORD_GUILDS||'').split(',').filter(Boolean),g=req.headers['x-guild-id'];
   if(!ok||(gs.length&&!gs.includes(g))){log('blocked','Discord auth failed',ip);return J(403,{error:'forbidden'})}
   return J(200,{loader:loaderLine(req)})}
  const ad=()=>{const t=String(req.headers.authorization||'').slice(7),a=admins.get(t);return a&&a.exp>Date.now()};
  if(p==='/api/admin/login'&&m==='POST'){if(limited('l'+ip,8)){log('blocked','Login rate limit',ip);return J(429,{error:'rate_limited'})}
   const b=await body(req);if(eq(H(b.user),AU)&eq(H(b.password),AP)){const t=rid(32);admins.set(t,{exp:Date.now()+12*3600e3});log('security','Admin login',ip);return J(200,{token:t})}
   log('blocked','Admin login failed',ip);return J(401,{error:'invalid_credentials'})}
  if(!ad())return J(401,{error:'unauthorized'});
  if(p==='/api/analytics'||p==='/api/admin/stats'){const c=t=>db.logs.filter(l=>l.type===t).length;
   return J(200,{scripts:Object.keys(db.scripts).length,active_loaders:active()&&!db.maint?1:0,api_requests:c('api'),protected_endpoints:8-Object.values(db.off).filter(Boolean).length,blocked:c('blocked'),active_sessions:sessions.size,tickets:tickets.size,maintenance:db.maint,loader_version:db.ver,updated:db.at,loader:loaderLine(req)})}
  if(p==='/api/admin/logs')return J(200,db.logs.slice(0,+q.get('n')||200));
  if(p==='/api/admin'&&m==='POST'){const b=await body(req);
   if(b.action==='revoke_sessions'){sessions.clear();admins.forEach((v,k)=>k!==String(req.headers.authorization).slice(7)&&admins.delete(k))}
   else if(b.action==='revoke_tickets')tickets.clear();
   else if(b.action==='rotate'||b.action==='regenerate'){db.ver++;db.at=Date.now();sessions.clear();tickets.clear()}
   else if(b.action==='maintenance')db.maint=!!b.on;
   else if(b.action==='endpoint'&&/^[a-z]+$/.test(b.name||''))db.off['/api/'+b.name]=!!b.disabled;
   else return J(400,{error:'unknown_action'});
   log('security','Admin action: '+b.action,ip);save();return J(200,{ok:true})}
  if(p==='/api/scripts'&&m==='GET')return J(200,Object.values(db.scripts).map(({enc,...s})=>s));
  if(p==='/api/scripts'&&m==='POST'){const b=await body(req);if(!b.name||!b.source)return J(400,{error:'name_and_source_required'});
   const id=rid(8);db.scripts[id]={id,name:String(b.name).slice(0,80),v:1,status:'draft',at:Date.now(),enc:enc(String(b.source))};log('script','Created '+b.name,ip);save();return J(201,{id})}
  const sm=p.match(/^\/api\/scripts\/(\w+)$/);
  if(sm){const s=db.scripts[sm[1]];if(!s)return J(404,{error:'not_found'});
   if(m==='DELETE'){delete db.scripts[s.id];log('script','Deleted '+s.name,ip);save();return J(200,{ok:true})}
   if(m==='PUT'){const b=await body(req);if(b.source){s.enc=enc(String(b.source));s.v++}if(b.name)s.name=String(b.name).slice(0,80);
    if(['draft','published','disabled'].includes(b.status))s.status=b.status;s.at=Date.now();log('script','Updated '+s.name+' v'+s.v+' ('+s.status+')',ip);save();return J(200,{ok:true,v:s.v})}
   if(m==='GET'&&q.get('source')==='1')return J(200,{source:dec(s.enc)})}
  if(p==='/api/domains'&&m==='GET')return J(200,db.domains);
  if(p==='/api/domains'&&m==='POST'){const b=await body(req),n=String(b.name||'').toLowerCase();
   if(!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(n))return J(400,{error:'invalid_domain'});
   if(!db.domains.some(d=>d.name===n))db.domains.push({name:n,dns:'pending',primary:!db.domains.length});save();return J(201,{ok:true})}
  const dm=p.match(/^\/api\/domains\/([a-z0-9.-]+)(\/verify|\/primary)?$/);
  if(dm){const d=db.domains.find(x=>x.name===dm[1]);if(!d)return J(404,{error:'not_found'});
   if(m==='DELETE'){db.domains=db.domains.filter(x=>x!==d);if(d.primary&&db.domains[0])db.domains[0].primary=true;save();return J(200,{ok:true})}
   if(dm[2]==='/primary'){db.domains.forEach(x=>x.primary=x===d);save();return J(200,{ok:true})}
   if(dm[2]==='/verify'){try{await dns.resolveCname(d.name);d.dns='verified'}catch{try{await dns.resolve4(d.name);d.dns='verified'}catch{d.dns='pending'}}save();return J(200,{dns:d.dns})}}
  return J(404,{error:'not_found'});
 }catch(e){return J(400,{error:String(e.message||'bad_request')})}
}).listen(PORT,()=>console.log('SZKHUB listening on :'+PORT));
