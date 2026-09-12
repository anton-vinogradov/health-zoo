/* Settings navigation must preserve the draft and the saved values. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.attrs = {};
    this.events = {};
    this.className = '';
    this.textContent = '';
    this.value = '';
    this.classList = {
      contains: name => this.className.split(' ').includes(name),
      toggle: (name, enabled) => {
        const classes = new Set(this.className.split(' ').filter(Boolean));
        if (enabled) classes.add(name); else classes.delete(name);
        this.className = [...classes].join(' ');
      }
    };
  }
  appendChild(child) { this.children.push(child); return child; }
  addEventListener(name, handler) { this.events[name] = handler; }
  setAttribute(name, value) {
    this.attrs[name] = String(value);
    if (name === 'value') this.value = String(value);
    if (name === 'disabled') this.disabled = true;
  }
  set innerHTML(value) { this.children = []; }
}

const config = {
  fields: [{key:'disk_warn', group:'Диски', label:'Диск', min:50, max:99}],
  values: {disk_warn:91, camera_quiet_warn_hours:6, camera_quiet_bad_hours:12},
  defaults: {disk_warn:90}, overridden:['disk_warn'], by_role:{nas:{disk_warn:96}},
  models:['Camera One'],
  firmware:{'Camera One':{version:'V1', built:'260902', url:'https://example.org/fw'}},
  cameras:[{key:'srv/1', name:'Вход', host:'Рекордер', limits:{warn:5,bad:10}}],
  auto_security:{enabled:false}, auto_cleanup:{enabled:true},
  auto_reboot:{enabled:true,from_hour:8,to_hour:9,timezone:'Europe/Moscow',exclude:['srv']},
  hosts:[{id:'srv',name:'Рекордер'}]
};
const expectedPayload = {
  thresholds:{disk_warn:91}, firmware:config.firmware, cameras:{'srv/1':{warn:5,bad:10}},
  auto_security:{enabled:false}, auto_cleanup:{enabled:true},
  auto_reboot:config.auto_reboot
};

function context() {
  const root = new Element('main');
  const calls = [];
  const ctx = {
    AbortSignal, Promise, Intl,
    state:{generated:1,actions_enabled:true},
    document:{getElementById:()=>root,createElement:tag=>new Element(tag),createTextNode:text=>({textContent:text})},
    actionHeaders:()=>({'Content-Type':'application/json'}), actionFailed:()=>false,
    load:()=>Promise.resolve(), alert:message=>assert.fail(message),
    fetch:(url,options)=>{
      calls.push({url,options});
      return Promise.resolve({ok:true,json:()=>Promise.resolve(options?.method === 'POST' ? {ok:true} : config)});
    }
  };
  vm.createContext(ctx);
  const ui = path.join(__dirname,'../ui');
  vm.runInContext(fs.readFileSync(path.join(ui,'core.js'),'utf8'),ctx);
  ctx.section = (title,node)=>ctx.h('div',{},[ctx.h('h3',{text:title}),node]);
  ctx.table = (headers,rows)=>ctx.h('div',{},rows);
  const source = fs.readFileSync(path.join(ui,'actions.js'),'utf8');
  vm.runInContext(source.slice(source.indexOf('/* ---------- settings ---------- */')),ctx);
  ctx.state = {generated:1,actions_enabled:true};
  return {ctx,root,calls};
}
function descendants(node) { return [node,...(node.children || []).flatMap(descendants)]; }
function button(root,text) { return descendants(root).find(node=>node.tagName === 'button' && node.textContent === text); }
function field(root,label) { return descendants(root).find(node=>node.attrs?.['aria-label'] === label); }
function click(node) { node.events.click({currentTarget:node}); }
const settle = ()=>new Promise(resolve=>setImmediate(resolve));

test('internal navigation changes neither mounted fields nor saved values',async()=>{
  const {ctx,root,calls} = context();
  await ctx.renderSettings();
  const checks = descendants(root).find(node=>node.attrs?.id === 'settings-checks-panel');
  const automatic = descendants(root).find(node=>node.attrs?.id === 'settings-automatic-panel');
  const initialInputs = descendants(root).filter(node=>node.tagName === 'input');
  const checksButton = button(root,'Проверки');
  const automaticButton = button(root,'Автоматические действия');
  assert.equal(checksButton.attrs.type,'button');
  assert.equal(automaticButton.attrs.type,'button');
  assert.equal(checksButton.attrs['aria-pressed'],'true');
  click(automaticButton);
  assert.equal(checks.classList.contains('hidden'),true);
  assert.equal(automatic.classList.contains('hidden'),false);
  assert.equal(automaticButton.attrs['aria-pressed'],'true');
  click(checksButton);
  assert.equal(ctx.settingsDirty,false);
  assert.equal(calls.length,1);
  assert.deepEqual(descendants(root).filter(node=>node.tagName === 'input'),initialInputs);
  assert.ok(initialInputs.every(node=>node.attrs['aria-label']?.trim()),'every input has an accessible name');
  const save = button(root,'Сохранить');
  assert.equal(descendants(checks).includes(save),false);
  assert.equal(descendants(automatic).includes(save),false);
  click(save);
  await settle();
  assert.deepEqual(JSON.parse(calls[1].options.body),expectedPayload);
  assert.equal(ctx.settingsDirty,false);
});

test('edits in both panels are saved together and switching during save stays clean',async()=>{
  const {ctx,root} = context();
  await ctx.renderSettings();
  const disk = field(root,'Диск');
  disk.value = '95'; root.oninput();
  click(button(root,'Автоматические действия'));
  field(root,'Автоматические обновления безопасности').checked = true; root.onchange();
  click(button(root,'Проверки'));
  assert.equal(field(root,'Диск'),disk);
  assert.equal(disk.value,'95');
  let finish, sent;
  ctx.fetch = (url,options)=>{
    sent = JSON.parse(options.body);
    return new Promise(resolve=>{finish=resolve;});
  };
  click(button(root,'Сохранить'));
  click(button(root,'Автоматические действия'));
  finish({json:()=>Promise.resolve({ok:true})});
  await settle();
  assert.equal(sent.thresholds.disk_warn,95);
  assert.equal(sent.auto_security.enabled,true);
  assert.deepEqual(sent.cameras,expectedPayload.cameras);
  assert.equal(ctx.settingsDirty,false);
});

test('discard resets both panels while keeping the selected settings section',async()=>{
  const {ctx,root,calls} = context();
  await ctx.renderSettings();
  field(root,'Диск').value = '95'; root.oninput();
  click(button(root,'Автоматические действия'));
  field(root,'Автоматическая перезагрузка').checked = false; root.onchange();
  click(button(root,'Отменить изменения'));
  await settle();
  assert.equal(calls.length,2);
  assert.equal(field(root,'Диск').value,'91');
  assert.equal(field(root,'Автоматическая перезагрузка').checked,true);
  assert.equal(button(root,'Автоматические действия').attrs['aria-pressed'],'true');
  assert.equal(ctx.settingsDirty,false);
});
