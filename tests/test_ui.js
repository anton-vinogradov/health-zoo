/* Browser-independent contract tests; the actual layout is checked in a browser. */
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

class Element {
  constructor(tag='div') { this.tagName=tag; this.children=[]; this.attrs={}; this.style={}; this.textContent=''; this.className=''; this._html=''; this.dataset={}; this.events={}; this.classList={add:(name)=>this.classList.toggle(name,true),remove:(name)=>this.classList.toggle(name,false),toggle:(name,on)=>{const names=new Set(this.className.split(' ').filter(Boolean));if(on===undefined)on=!names.has(name);if(on)names.add(name);else names.delete(name);this.className=[...names].join(' ');},contains:(name)=>this.className.split(' ').includes(name)}; }
  focus(){}
  scrollIntoView(){}
  appendChild(child){this.children.push(child);return child;}
  setAttribute(key,value){this.attrs[key]=value;if(key==='value')this.value=String(value);if(key==='disabled')this.disabled=true;}
  addEventListener(name,callback){this.events[name]=callback;}
  set innerHTML(value){this._html=value;this.children=[];}
  get innerHTML(){return this._html;}
  get text(){return this.textContent+this.children.map(x=>x.text || x.textContent || '').join('');}
}
function context() {
  const elements=new Map();
  const ctx={console,AbortSignal,Promise,Date,Intl,Array,JSON,Math,String,Number,
    localStorage:{getItem(){return null;},setItem(){},removeItem(){}},
    sessionStorage:{getItem(){return null;},setItem(){},removeItem(){}},
    document:{createElement:tag=>new Element(tag),createTextNode:text=>({textContent:text}),
      createDocumentFragment:()=>new Element(),
      getElementById:id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},
      querySelectorAll:()=>[],addEventListener(){},},
    setInterval:()=>1,clearInterval(){},setTimeout:()=>1,alert(){},confirm:()=>false,
    fetch:()=>Promise.reject(new Error('offline'))};
  ctx.window={location:{hash:''},scrollY:0,scrollTo(x,y){this.scrollY=y;},history:{pushState(a,b,hash){ctx.window.location.hash=hash;},replaceState(a,b,hash){ctx.window.location.hash=hash;}},addEventListener(){}};
  vm.createContext(ctx);
  for(const file of ['core.js','cards.js','details.js','actions.js','workspace.js','wiring.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui',file),'utf8'),ctx);
  ctx.elements=elements;
  return ctx;
}

test('network failure immediately marks old dashboard as disconnected',async()=>{
  const ctx=context();ctx.state={generated:Date.now()/1000,hosts:[]};
  let renders=0;ctx.renderAlert=()=>renders++;
  await ctx.load();
  assert.equal(ctx.connectionLost,true);assert.equal(renders,1);
  assert.match(ctx.elements.get('connection-label').textContent,/Нет связи/);
});

test('freshness degrades without another successful request',()=>{
  const ctx=context();ctx.state={generated:Date.now()/1000-1000,poll_interval:180};
  assert.equal(ctx.snapshotAge().level,'bad');
  let renders=0;ctx.renderAlert=()=>renders++;ctx.updateFreshness();
  assert.equal(renders,1);assert.match(ctx.elements.get('connection-label').textContent,/устарели/);
});

test('service search and offline filter operate on host facts',()=>{
  const ctx=context();ctx.searchText='nginx';
  assert.equal(ctx.hostMatches({name:'web',services:[{name:'nginx.service'}]}),true);
  ctx.searchText='';ctx.fleetFilter='offline';
  assert.equal(ctx.hostMatches({reachable:true}),false);
  assert.equal(ctx.hostMatches({reachable:false}),true);
});

test('a failed completed job renders a failed host and 1/1 completion',async()=>{
  const ctx=context();ctx.currentJobId='job42';ctx.load=()=>Promise.resolve();
  let requested='';ctx.fetch=url=>{requested=url;return Promise.resolve({json:()=>Promise.resolve({id:'job42',kind:'restart',state:'done',targets:['srv'],hosts:{srv:{name:'Web',state:'failed',reason:'exit 1',log:['failure']}}})});};
  ctx.pollJob();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(requested,'/api/job/job42');
  assert.match(ctx.elements.get('job-status').text,/завершено 1\/1/);
  assert.match(ctx.elements.get('job-status').text,/Web: exit 1/);
});

test('incident queue retains every finding and offers expansion',()=>{
  const ctx=context();ctx.state={generated:Date.now()/1000,hosts:[]};
  ctx.renderAlert([{id:'host',name:'Host',issues:Array.from({length:45},(_,i)=>({key:'test'+i,level:'bad',text:'Problem '+i}))}]);
  const box=ctx.elements.get('alert');
  assert.equal(box.children.find(x=>x.className.startsWith('alert-list')).children.length,45);
  assert.match(box.text,/Ещё 41/);
});

test('first poll never claims healthy before any observation',()=>{
  const ctx=context();ctx.state={generated:0,hosts:[]};ctx.renderAlert([]);
  assert.doesNotMatch(ctx.elements.get('alert').text,/в порядке/);
  assert.match(ctx.elements.get('alert').text,/первый/);
});

test('lost job after restart stops polling with an explicit unknown outcome',async()=>{
  const ctx=context();ctx.currentJobId='job1';ctx.jobTimer=1;ctx.load=()=>Promise.resolve();
  ctx.fetch=()=>Promise.resolve({json:()=>Promise.resolve({error:'no such job'})});
  ctx.pollJob();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ctx.jobTimer,null);
  assert.match(ctx.elements.get('job-status').text,/недоступен после перезапуска/);
});

test('attention count and filter respect accepted outages',()=>{
  const ctx=context();
  const accepted={reachable:false,level:'off',issues:[{level:'info',suppressed:true}]};
  const outage={reachable:false,level:'off',issues:[{level:'bad',text:'offline'}]};
  const warning={reachable:true,level:'warn',issues:[{level:'warn',text:'hot'}]};
  ctx.state={hosts:[accepted,outage,warning]};ctx.renderOverview();
  const attention=ctx.elements.get('overview').children[2];
  assert.equal(attention.children[1].textContent,'2');
  ctx.onlyProblems=true;
  assert.equal(ctx.hostMatches(accepted),false);
  assert.equal(ctx.hostMatches(outage),true);
  assert.equal(ctx.hostMatches(warning),true);
  ctx.onlyProblems=false;ctx.fleetFilter='offline';
  assert.equal(ctx.hostMatches(accepted),true);
});

function descendants(el){return [el,...el.children.flatMap(x=>x.children?descendants(x):[x])];}
function settingsResponse(){return {fields:[{key:'disk_warn',group:'Диски',label:'Диск',unit:'%',min:50,max:99}],values:{disk_warn:91},defaults:{disk_warn:90},overridden:['disk_warn'],auto_reboot:{from_hour:8,to_hour:9},hosts:[]};}

test('management views activate in the workspace and preserve edited settings',async()=>{
  const ctx=context();ctx.state={generated:1,hosts:[],suppressions:[]};
  let requests=0;ctx.fetch=()=>{requests++;return Promise.resolve({ok:true,json:()=>Promise.resolve(settingsResponse())});};
  const modal=ctx.document.getElementById('modal');modal.className='modal hidden';
  ctx.showView('settings');await new Promise(resolve=>setImmediate(resolve));
  const root=ctx.elements.get('settings');const field=descendants(root).find(x=>x.attrs?.['aria-label']==='Диск');
  field.value='95';root.oninput();
  ctx.showView('sites');ctx.showView('suppressions');ctx.showView('settings');ctx.refreshManagementView();
  assert.equal(field.value,'95');assert.equal(requests,1);assert.equal(ctx.settingsDirty,true);
  assert.equal(ctx.window.location.hash,'#settings');assert.equal(root.classList.contains('hidden'),false);
  assert.equal(ctx.elements.get('fleet').classList.contains('hidden'),true);
  assert.equal(ctx.elements.get('fleet-alert').classList.contains('hidden'),true);
  assert.equal(modal.className,'modal hidden');
  ctx.showView('suppressions',true);
  assert.match(ctx.elements.get('suppressions').text,/Исключений нет/);
  assert.equal(ctx.document.title,'health-zoo · Исключения');
  ctx.showView('unknown',true);assert.equal(ctx.currentView,'fleet');
});

test('settings retry works and late load never steals navigation',async()=>{
  const ctx=context();ctx.state={generated:1,hosts:[]};
  ctx.currentView='settings';await ctx.renderSettings();
  assert.match(ctx.elements.get('settings').text,/Повторить загрузку/);
  let finish;ctx.fetch=()=>new Promise(resolve=>finish=resolve);
  const request=ctx.renderSettings();ctx.showView('sites');
  finish({ok:true,json:()=>Promise.resolve(settingsResponse())});await request;
  assert.equal(ctx.currentView,'sites');assert.equal(ctx.settingsLoaded,true);
  assert.equal(ctx.elements.get('settings').classList.contains('hidden'),true);
});

test('reset is an edit and later edits remain dirty after an earlier save',async()=>{
  const ctx=context();ctx.state={generated:1,hosts:[],actions_enabled:true};ctx.load=()=>Promise.resolve();
  ctx.fetch=()=>Promise.resolve({ok:true,json:()=>Promise.resolve(settingsResponse())});await ctx.renderSettings();
  const root=ctx.elements.get('settings');const nodes=descendants(root);
  nodes.find(x=>x.textContent==='↺').events.click();assert.equal(ctx.settingsDirty,true);
  let finish;ctx.fetch=()=>new Promise(resolve=>finish=resolve);
  const save=nodes.find(x=>x.textContent==='Сохранить');save.events.click({currentTarget:save});
  root.oninput();finish({json:()=>Promise.resolve({ok:true})});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ctx.settingsDirty,true);assert.match(root.text,/новые правки ещё не сохранены/);
  assert.equal(save.disabled,false);
});

test('history navigation closes host overlays and first snapshot refreshes untouched settings',async()=>{
  const ctx=context();ctx.state={generated:0,hosts:[]};
  const modal=ctx.document.getElementById('modal');modal.className='modal';
  ctx.document.querySelectorAll=selector=>selector==='.modal'?[modal]:[];
  let requests=0;ctx.fetch=()=>{requests++;return Promise.resolve({ok:true,json:()=>Promise.resolve(settingsResponse())});};
  ctx.showView('settings',true);await new Promise(resolve=>setImmediate(resolve));
  assert.equal(modal.classList.contains('hidden'),true);
  ctx.state.generated=123;ctx.refreshManagementView();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(requests,2);
  ctx.refreshManagementView();assert.equal(requests,2);
});

test('HTTP status is independent of host uptime and expires without another snapshot',()=>{
  const ctx=context();ctx.state={generated:1,hosts:[{id:'one',name:'alive',reachable:true,web:[{port:80,scheme:'http'}]}]};
  assert.match(ctx.serviceRows()[0].health.text,/ещё не проверен/);
  const checked=Math.floor(Date.now()/1000);
  assert.equal(ctx.serviceHealth({http:{checked_at:checked,status:503}}).level,'bad');
  assert.equal(ctx.serviceHealth({http:{checked_at:checked,status:403}}).level,'info');
  assert.equal(ctx.serviceHealth({http:{checked_at:checked,status:200}}).level,'ok');
  assert.match(ctx.serviceHealth({http:{checked_at:checked-601,status:200}}).text,/устарела/);
  ctx.currentView='sites';ctx.serviceBadges=[{link:{http:{checked_at:checked-601,status:200}},text:'HTTP 200 · отвечает'}];
  let painted=0;ctx.renderServices=()=>painted++;ctx.refreshServiceFreshness();assert.equal(painted,1);
});

test('selecting an update preserves checkbox and package disclosure nodes across selection',()=>{
  const ctx=context();ctx.state={generated:1,actions_enabled:true,hosts:[
    {id:'one',name:'First',reachable:true,updatable:true,update_count:3,security_count:1,updates:[{pkg:'openssl',new:'3.0',security:'1'}]},
    {id:'off',name:'Offline',reachable:false,updatable:true,update_count:4}]};
  ctx.renderUpdates();
  const body=ctx.updateControls.body;const box=descendants(body).find(x=>x.attrs?.['aria-label']==='Выбрать First');
  box.checked=true;box.events.change();assert.ok(ctx.selectedUpdates.has('one'));
  assert.equal(descendants(body).find(x=>x.attrs?.['aria-label']==='Выбрать First'),box);
  assert.match(body.text,/openssl · 3.0 · security/);assert.match(ctx.updateControls.summary.text,/Выбрано 1 · 3 пакетов/);
  assert.equal(ctx.updateEligible(ctx.state.hosts[1]),false);
  let targets;ctx.startUpdate=ids=>targets=ids;ctx.updateControls.start.events.click();assert.deepEqual(Array.from(targets),['one']);
  ctx.state.hosts[0].update_count=0;ctx.renderUpdates();assert.equal(ctx.selectedUpdates.size,0);assert.equal(ctx.updateControls.start.disabled,true);
});

test('network filters keep source-device selection across both representations',()=>{
  const ctx=context();ctx.state={hosts:[{id:'a',subnet:'one'},{id:'b',subnet:'two'}]};
  ctx.networkHost='b';ctx.networkSubnet='two';assert.deepEqual(Array.from(ctx.networkHosts(),h=>h.id),['b']);
  ctx.networkTab='egress';assert.deepEqual(Array.from(ctx.networkHosts(),h=>h.id),['b']);
  ctx.networkSubnet='one';assert.equal(ctx.networkHosts().length,0);
  ctx.renderNetwork=()=>{};ctx.showView('egress');assert.equal(ctx.currentView,'network');assert.equal(ctx.networkTab,'egress');assert.equal(ctx.window.location.hash,'#network');
});

test('journal ignores out-of-order responses and old rows do not masquerade under new filters',async()=>{
  const ctx=context();ctx.state={generated:1,hosts:[]};const requests=[];
  ctx.fetch=url=>new Promise(resolve=>requests.push({url,resolve}));ctx.renderJournal();
  ctx.journalKind='actions';const latest=ctx.fetchJournal(false);
  assert.equal(ctx.journalControls.body.text,'');
  requests[1].resolve({ok:true,json:()=>Promise.resolve({entries:[{id:2,ts:1,kind:'actions',title:'Saved'}],next_before:null,started_at:1})});await latest;
  requests[0].resolve({ok:true,json:()=>Promise.resolve({entries:[{id:1,ts:1,kind:'events',title:'Old'}]})});await new Promise(r=>setImmediate(r));
  assert.equal(ctx.journalEntries[0].title,'Saved');assert.doesNotMatch(ctx.journalControls.body.text,/Old/);
  assert.match(requests[1].url,/kind=actions/);
});

test('an exclusion being saved cannot be replaced by another editor',async()=>{
  const ctx=context();const one={id:'a/disk',host:'a',host_name:'A',reason:'Known',days_left:null,age_days:20};
  ctx.state={generated:1,actions_enabled:true,hosts:[],suppressions:[one]};ctx.load=()=>Promise.resolve();
  ctx.renderSuppressionReview();ctx.editSuppression(one);
  const editor=ctx.suppressionControls.editor;const save=descendants(editor).find(x=>x.textContent==='Сохранить исключение');
  let finish;ctx.fetch=()=>new Promise(resolve=>finish=resolve);save.events.click();
  ctx.editSuppression({...one,id:'b/disk',host_name:'B'});assert.equal(ctx.suppressionDraft.id,'a/disk');
  assert.equal(ctx.suppressionSaving,true);finish({json:()=>Promise.resolve({ok:true})});await new Promise(r=>setImmediate(r));
  assert.equal(ctx.suppressionSaving,false);assert.equal(ctx.suppressionDraft,null);
});

test('interrupted jobs explicitly show unknown outcome and stop polling',async()=>{
  const ctx=context();ctx.jobTimer=1;ctx.load=()=>{};
  ctx.fetch=()=>Promise.resolve({json:()=>Promise.resolve({state:'done',kind:'reboot',outcome:'interrupted',targets:['x'],hosts:{x:{name:'Box',state:'interrupted',reason:'Результат неизвестен',log:[]}}})});
  await ctx.pollJob();assert.equal(ctx.jobTimer,null);assert.match(ctx.elements.get('job-status').text,/Результат неизвестен/);assert.match(ctx.elements.get('job-status').text,/1\/1/);
  assert.match(ctx.elements.get('job-tabs').text,/\? Box/);
});
