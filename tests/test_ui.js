/* Browser-independent contract tests; the actual layout is checked in a browser. */
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

class Element {
  constructor(tag='div') { this.tagName=tag; this.children=[]; this.attrs={}; this.style={}; this.textContent=''; this.className=''; this._html=''; this.classList={add(){},remove(){},toggle(){},contains(){return false;}}; }
  appendChild(child){this.children.push(child);return child;}
  setAttribute(key,value){this.attrs[key]=value;}
  addEventListener(){}
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
  vm.createContext(ctx);
  for(const file of ['core.js','cards.js','actions.js','wiring.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../ui',file),'utf8'),ctx);
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
