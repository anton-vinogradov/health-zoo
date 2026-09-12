/* Workspace views: retain controls and drafts while the snapshot refreshes. */
function panelIntro(title, text) {
  return h('div', {class:'page-intro'}, [h('h2', {text:title}), h('p', {text:text})]);
}
function selectControl(label, options, value, change) {
  var input = h('select', {class:'filter-select', 'aria-label':label, onchange:function () { change(input.value); }},
    options.map(function (o) { return h('option', {value:o[0], text:o[1]}); }));
  input.value = value;
  return input;
}
function searchControl(label, change) {
  var input = h('input', {class:'search panel-search',type:'search','aria-label':label,placeholder:label,
    oninput:function () { change(input.value.trim().toLowerCase()); }});
  return input;
}
function hostButton(host) {
  return h('button', {class:'text-button',text:host.name || host.id,onclick:function () { showHost(host); }});
}
function emptyPanel(text) { return h('p', {class:'empty-state',role:'status',text:text}); }
function stateReady(root) {
  if (state && state.generated) return true;
  root.innerHTML = '';
  root.appendChild(emptyPanel('Ожидаем первый снимок устройств…'));
  return false;
}
function hostOptions() { return [['','Все устройства']].concat(((state && state.hosts) || []).map(function (host) {return [host.id,host.name || host.id];})); }
function updateOptions(control, options) {
  var value = control.value;
  control.innerHTML = '';
  options.forEach(function (o) { control.appendChild(h('option', {value:o[0],text:o[1]})); });
  control.value = options.some(function (o) {return o[0] === value;}) ? value : '';
}

/* One network workspace, two ways of looking at the same source devices. */
var networkTab = 'topology', networkHost = '', networkSubnet = '', networkControls = null;
function networkHosts() {
  return ((state && state.hosts) || []).filter(function (host) {
    return (!networkHost || host.id === networkHost) && (!networkSubnet || host.subnet === networkSubnet);
  });
}
function renderNetwork() {
  var root = document.getElementById('network-controls');
  if (!networkControls) {
    root.innerHTML = '';
    root.appendChild(panelIntro('Два взгляда на сеть', 'Связи показывают подключения к коммутаторам и Wi-Fi. Выход в интернет — маршруты сервисов и туннели. Фильтры выбирают устройства, от которых получены данные.'));
    var tabs = h('div', {class:'subnav','aria-label':'Представление сети'});
    var buttons = ['topology','egress'].map(function (key, i) {
      var button = h('button', {class:'subtab',text:i ? 'Выход в интернет' : 'Связи устройств',onclick:function () {networkTab=key;renderNetwork();}});
      tabs.appendChild(button); return button;
    });
    var host = selectControl('Устройство — источник данных',hostOptions(),networkHost,function (v) {networkHost=v;renderNetwork();});
    var subnet = selectControl('Сегмент сети',[['','Все сегменты']],networkSubnet,function (v) {networkSubnet=v;renderNetwork();});
    root.appendChild(tabs); root.appendChild(h('div',{class:'filter-bar'},[host,subnet]));
    networkControls = {buttons:buttons,host:host,subnet:subnet};
  }
  updateOptions(networkControls.host,hostOptions()); networkHost=networkControls.host.value;
  updateOptions(networkControls.subnet,[['','Все сегменты']].concat(((state && state.subnets) || []).map(function(s){return [s.cidr,s.name || s.cidr];})));
  networkSubnet=networkControls.subnet.value;
  ['topology','egress'].forEach(function(key,i){
    document.getElementById(key).classList.toggle('hidden',key!==networkTab);
    networkControls.buttons[i].classList.toggle('active',key===networkTab);
    networkControls.buttons[i].setAttribute('aria-pressed',String(key===networkTab));
  });
  renderTopology(); renderEgress();
}

/* Service status comes from HTTP observations, never from host reachability. */
var serviceBadges = [];
function refreshServiceFreshness() {
  if (currentView === 'sites' && serviceBadges.some(function(badge){return badge.text !== serviceHealth(badge.link).text;})) renderServices();
}
var serviceControls = null, serviceSearch = '', serviceFilter = 'all', serviceGroup = 'purpose';
function servicePurpose(link, host) {
  var name = [link.title,link.label,link.path].join(' ').toLowerCase();
  if (/zoneminder|surveillance|camera|\bzm\b/.test(name)) return 'Камеры и видео';
  if (/pihole|pi-hole|unifi|router|openwrt|proxy|vpn|caddy/.test(name)) return 'Сеть и доступ';
  if (/synology|diskstation|nas|photo|backup/.test(name)) return 'Файлы и резервные копии';
  if (/zoo|grafana|prometheus|status|monitor/.test(name)) return 'Мониторинг';
  if (host && host.role==='nas') return 'Файлы и резервные копии';
  if (host && host.role==='camera') return 'Камеры и видео';
  if (host && ['router','ap','mesh'].indexOf(host.role)>=0) return 'Сеть и доступ';
  if (/sonos|plex|jellyfin/.test(name) || (host && host.role==='media')) return 'Медиа';
  return 'Другие сервисы';
}
function serviceHealth(link) {
  if (link.local) return {level:'info',text:'Только на устройстве'};
  var http = link.http || {};
  if (!http.checked_at) return {level:'info',text:'HTTP ещё не проверен'};
  if (Date.now()/1000-http.checked_at > 600) return {level:'info',text:'HTTP: проверка устарела'};
  if (http.status === 401 || http.status === 403) return {level:'info',text:'HTTP '+http.status+' · нужен вход'};
  if (http.status >= 200 && http.status < 400) return {level:'ok',text:'HTTP '+http.status+' · отвечает'};
  return {level:'bad',text:http.status ? 'HTTP '+http.status+' · ошибка' : 'HTTP не отвечает'};
}
function serviceRows() {
  var result=[];
  ((state && state.hosts) || []).forEach(function(host){ (host.web || []).forEach(function(link){
    var url=webUrl(host,link), health=serviceHealth(link);
    var purpose=servicePurpose(link,host);
    var text=[host.name,host.addr,url,link.title,link.label,purpose].join(' ').toLowerCase();
    if (serviceSearch && text.indexOf(serviceSearch)<0) return;
    if (serviceFilter==='problems' && health.level!=='bad') return;
    if (serviceFilter==='https' && link.scheme!=='https') return;
    if (serviceFilter==='local' && !link.local) return;
    result.push({host:host,link:link,url:url,health:health,purpose:purpose});
  }); });
  return result;
}
function renderServices() {
  var root=document.getElementById('sites');
  if (!stateReady(root)) {serviceControls=null;return;}
  if (!serviceControls) {
    root.innerHTML='';
    root.appendChild(panelIntro('Сервисы под рукой','Каталог собирается автоматически. Доступность HTTP проверяется отдельно от устройства; HTTPS и срок сертификата не означают, что его подлинность проверена.'));
    var counter=h('span',{class:'result-count',role:'status'}), results=h('div',{class:'service-groups'});
    root.appendChild(h('div',{class:'filter-bar'},[
      searchControl('Найти сервис, адрес или устройство',function(v){serviceSearch=v;renderServices();}),
      selectControl('Состояние сервисов',[['all','Все сервисы'],['problems','Ошибки HTTP'],['https','С HTTPS'],['local','Только локальные']],serviceFilter,function(v){serviceFilter=v;renderServices();}),
      selectControl('Группировка сервисов',[['purpose','По назначению'],['host','По устройству']],serviceGroup,function(v){serviceGroup=v;renderServices();}),counter]));
    root.appendChild(results);serviceControls={results:results,counter:counter};
  }
  var rows=serviceRows(), groups=Object.create(null);
  serviceBadges=[];
  rows.forEach(function(row){var key=serviceGroup==='host' ? row.host.name || row.host.id : row.purpose; if(!groups[key]) groups[key]=[];groups[key].push(row);});
  serviceControls.counter.textContent='Найдено: '+rows.length;
  var body=serviceControls.results;body.innerHTML='';
  if (!rows.length) body.appendChild(emptyPanel('Под эти фильтры ничего не подошло. Попробуйте другой запрос или состояние.'));
  Object.keys(groups).sort(function(a,b){return (a==='Другие сервисы')-(b==='Другие сервисы') || a.localeCompare(b);}).forEach(function(group){
    body.appendChild(section(group,h('div',{class:'service-grid'},groups[group].map(function(row){
      serviceBadges.push({link:row.link,text:row.health.text});
      var link=row.link, cert=link.cert || {}, certText=link.scheme==='https' ? 'HTTPS · срок сертификата неизвестен' : 'HTTP · без шифрования';
      if (typeof cert.days_left==='number') certText='HTTPS · сертификат '+(cert.days_left<0 ? 'истёк' : 'ещё '+Math.floor(cert.days_left)+' дн.');
      return h('article',{class:'service-card'},[
        h('div',{class:'service-card-head'},[h('h3',{text:link.title || link.label || 'Веб-интерфейс'}),h('span',{class:'status-pill '+row.health.level,text:row.health.text})]),
        h('p',{class:'service-address',text:link.local ? 'localhost:'+link.port : row.url}),
        h('p',{class:'muted '+(cert.days_left<7?'warn':''),text:certText}),
        h('div',{class:'service-card-foot'},[hostButton(row.host),link.local ? h('span',{class:'muted',text:link.served_by ? 'Через '+link.served_by : 'Открывается на хосте'}) : h('a',{class:'btn btn-sm',href:row.url,target:'_blank',rel:'noopener',text:'Открыть ↗'})])
      ]);
    }))));
  });
}

/* A queue of work: nothing is selected implicitly. */
var updateControls=null, updateFilter='pending', updateSearch='', selectedUpdates=new Set();
function updateEligible(host) {return !!(host.updatable && host.reachable && host.update_count>0);}
function updateMatches(host) {
  if (updateSearch && [host.name,host.addr,host.os].join(' ').toLowerCase().indexOf(updateSearch)<0) return false;
  if (updateFilter==='security') return host.security_count>0;
  if (updateFilter==='reboot') return !!host.reboot_required;
  if (updateFilter==='manual') return !host.updatable && (host.update_count>0 || (host.issues || []).some(function(i){return /firmware|version|update/.test(i.key);}));
  return host.update_count>0 || host.reboot_required || (host.updatable && updateFilter==='all');
}
function updateSelectionSummary() {
  if (!updateControls) return;
  updateControls.summary.textContent='Выбрано '+selectedUpdates.size+' · '+((state && state.hosts) || []).filter(function(host){return selectedUpdates.has(host.id);}).reduce(function(n,host){return n+host.update_count;},0)+' пакетов';
  updateControls.start.disabled=!selectedUpdates.size || state.actions_enabled===false;
}
function renderUpdates() {
  var root=document.getElementById('updates');
  if (!stateReady(root)) {updateControls=null;return;}
  if (!updateControls) {
    root.innerHTML='';
    root.appendChild(panelIntro('Обслуживание устройств','Выберите устройства для установки пакетов. Security входит в обычное обновление; перезагрузка выполняется отдельно. Прошивки NAS, камер и роутеров обновляются вручную.'));
    var body=h('div'), summary=h('span',{class:'selection-summary',role:'status'});
    var start=h('button',{class:'btn btn-primary',text:'Обновить выбранные',onclick:function(){
      var ids=(state.hosts || []).filter(function(host){return selectedUpdates.has(host.id) && updateEligible(host);}).map(function(host){return host.id;});
      if (ids.length) startUpdate(ids);
    }});
    root.appendChild(h('div',{class:'filter-bar'},[
      searchControl('Найти устройство для обновления',function(v){updateSearch=v;renderUpdates();}),
      selectControl('Тип обслуживания',[['pending','Ожидают действий'],['security','Есть security'],['reboot','Нужна перезагрузка'],['manual','Обновляются вручную'],['all','Все управляемые']],updateFilter,function(v){updateFilter=v;renderUpdates();})]));
    root.appendChild(h('div',{class:'selection-bar'},[
      h('button',{class:'btn',text:'Выбрать доступные в списке',onclick:function(){(state.hosts || []).filter(updateMatches).filter(updateEligible).forEach(function(host){selectedUpdates.add(host.id);});renderUpdates();}}),
      h('button',{class:'btn',text:'Снять выбор',onclick:function(){selectedUpdates.clear();renderUpdates();}}),summary,start]));
    root.appendChild(body);
    root.appendChild(h('button',{class:'text-button journal-shortcut',text:'История обновлений и действий →',onclick:function(){journalKind='actions';showView('journal');if(journalControls){journalControls.kind.value='actions';fetchJournal(false);}}}));
    updateControls={body:body,start:start,summary:summary};
  }
  var all=state.hosts || [], eligible=all.filter(updateEligible);
  selectedUpdates.forEach(function(id){if(!eligible.some(function(host){return host.id===id;})) selectedUpdates.delete(id);});
  var hosts=all.filter(updateMatches).sort(function(a,b){return (b.security_count||0)-(a.security_count||0) || (a.name||'').localeCompare(b.name||'');});
  updateSelectionSummary();
  var body=updateControls.body;body.innerHTML='';
  if (!hosts.length) {body.appendChild(emptyPanel('В этом списке нет устройств, требующих действий.'));return;}
  body.appendChild(table(['Выбор','Устройство','Пакеты','Следующий шаг'],hosts.map(function(host){
    var box=h('input',{type:'checkbox','aria-label':'Выбрать '+host.name,disabled:!updateEligible(host) || state.actions_enabled===false ? true:null,onchange:function(){if(box.checked) selectedUpdates.add(host.id);else selectedUpdates.delete(host.id);updateSelectionSummary();}});box.checked=selectedUpdates.has(host.id);
    var next=!host.reachable ? 'Устройство не отвечает' : !host.updatable ? 'Вручную через интерфейс устройства' : host.reboot_required ? 'Требуется перезагрузка' : host.update_count ? 'Готово к обновлению' : host.updates_checked ? 'Обновления проверены' : 'Нет данных о проверке';
    var packages=h('div',null,[h('strong',{text:(host.update_count || 0)+' доступно'}),h('div',{class:host.security_count?'warn':'muted',text:(host.security_count || 0)+' security'})]);
    if ((host.updates || []).length) packages.appendChild(h('details',null,[h('summary',{text:'Список пакетов'}),h('ul',{class:'package-list'},host.updates.map(function(p){return h('li',{text:typeof p==='string'?p:[p.pkg || p.name,p.new || p.version || p.new_version,(p.security === '1' || p.security === true)?'security':''].filter(Boolean).join(' · ')});} ))]));
    return h('tr',null,[h('td',null,[box]),h('td',null,[hostButton(host),h('div',{class:'muted',text:host.addr})]),h('td',null,[packages]),h('td',null,[h('div',{text:next}),host.reboot_required && host.reachable && host.updatable ? h('button',{class:'btn btn-sm',text:'Перезагрузить',disabled:state.actions_enabled===false?true:null,onclick:function(){rebootHost(host);}}):null])]);
  })));
}

/* Persistent timeline; request sequence prevents an old response changing filters. */
var journalControls=null, journalKind='all', journalHost='', journalDays='7', journalBefore=null;
var journalEntries=[], journalRequest=0, journalFetched=0, journalStarted=0, journalLoading=false, journalPaintedGeneration=0;
function renderJournal() {
  var root=document.getElementById('journal');
  if (!journalControls) {
    root.innerHTML='';
    root.appendChild(panelIntro('Что изменилось','События сети и результаты действий в одной ленте. Откройте устройство или сохранённый журнал задания прямо из записи.'));
    var kind=selectControl('Тип записей',[['all','Вся лента'],['events','События'],['actions','Действия']],journalKind,function(v){journalKind=v;fetchJournal(false);});
    var host=selectControl('Устройство в журнале',hostOptions(),journalHost,function(v){journalHost=v;fetchJournal(false);});
    var status=h('p',{class:'muted',role:'status'}), body=h('div',{class:'timeline'});
    var more=h('button',{class:'btn',text:'Показать более ранние',onclick:function(){fetchJournal(true);}});
    root.appendChild(h('div',{class:'filter-bar'},[kind,host,
      selectControl('Период журнала',[['1','За сутки'],['7','За неделю'],['30','За месяц'],['0','Вся история']],journalDays,function(v){journalDays=v;fetchJournal(false);}),
      h('button',{class:'btn',text:'Обновить ленту',onclick:function(){fetchJournal(false);}})]));
    root.appendChild(status);root.appendChild(body);root.appendChild(more);
    journalControls={kind:kind,host:host,status:status,body:body,more:more};
    fetchJournal(false);
  } else {
    updateOptions(journalControls.host,hostOptions());
    if (state && state.generated!==journalPaintedGeneration && journalFetched) paintJournal();
    if (!journalLoading && journalEntries.length<=50 && Date.now()-journalFetched>60000) fetchJournal(false);
  }
}
function fetchJournal(append) {
  if (!journalControls || (append && (journalLoading || !journalBefore))) return Promise.resolve();
  var request=++journalRequest;
  journalLoading=true;
  if (!append) { journalEntries=[];journalBefore=null;journalControls.body.innerHTML='';journalControls.more.classList.add('hidden'); }
  journalControls.status.textContent='Загружаем записи…';journalControls.more.disabled=true;
  var query='?kind='+encodeURIComponent(journalKind)+'&host='+encodeURIComponent(journalHost)+'&limit=50';
  if (Number(journalDays)>0) query+='&since='+Math.floor(Date.now()/1000-Number(journalDays)*86400);
  if (append) query+='&before='+journalBefore;
  return fetch('/api/journal'+query,{signal:AbortSignal.timeout(15000)}).then(function(r){if(!r.ok) throw new Error('HTTP '+r.status);return r.json();}).then(function(data){
    if(request!==journalRequest)return;
    if(data.error) throw new Error(data.error);
    journalEntries=append ? journalEntries.concat(data.entries || []) : data.entries || [];
    journalBefore=data.next_before; journalStarted=data.started_at;journalFetched=Date.now();
    paintJournal();
  }).catch(function(err){if(request===journalRequest)journalControls.status.textContent='Не удалось загрузить журнал: '+err.message+'. Нажмите «Обновить ленту».';})
    .finally(function(){if(request===journalRequest){journalLoading=false;journalControls.more.disabled=false;}});
}
function paintJournal() {
  journalPaintedGeneration=(state && state.generated) || 0;
  var body=journalControls.body;body.innerHTML='';
  journalControls.status.textContent='Записей: '+journalEntries.length+(journalStarted ? ' · история ведётся с '+new Date(journalStarted*1000).toLocaleString('ru-RU') : '');
  journalControls.more.classList.toggle('hidden',!journalBefore);
  if(!journalEntries.length)body.appendChild(emptyPanel('За выбранный период записей нет. Новые события появятся после следующего изменения состояния.'));
  var day='';
  journalEntries.forEach(function(entry){
    var date=new Date(entry.ts*1000), dayLabel=date.toLocaleDateString('ru-RU',{day:'numeric',month:'long',year:'numeric'});
    if(day!==dayLabel){day=dayLabel;body.appendChild(h('h3',{class:'timeline-day',text:day}));}
    var host=((state && state.hosts)||[]).find(function(x){return x.id===entry.host_id;});
    var actions=h('div',{class:'timeline-links'},[host?hostButton(host):entry.host_name?h('span',{text:entry.host_name}):null,
      entry.job_id?h('button',{class:'text-button',text:'Журнал задания →',onclick:function(){openJobLog(entry.job_id);}}):null]);
    body.appendChild(h('article',{class:'timeline-entry'},[
      h('time',{class:'timeline-time',datetime:date.toISOString(),text:date.toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})}),
      h('span',{class:'timeline-dot '+(['bad','warn','info','ok'].indexOf(entry.severity)>=0?entry.severity:'info'),'aria-hidden':'true'}),
      h('div',{class:'timeline-content'},[h('div',{class:'timeline-heading'},[h('h3',{text:entry.title}),h('span',{class:'entry-kind',text:entry.kind==='actions'?'Действие':'Событие'})]),entry.detail?h('p',{text:entry.detail}):null,actions])
    ]));
  });
}

/* Review exclusions in context, with an inline editor that survives polling. */
var suppressionSaving=false;
var suppressionControls=null, suppressionFilter='all', suppressionSearch='', suppressionDraft=null;
function suppressionMatches(s) {
  if(suppressionSearch && [s.host_name,s.key,s.reason].join(' ').toLowerCase().indexOf(suppressionSearch)<0)return false;
  if(suppressionFilter==='firing')return s.still_firing;
  if(suppressionFilter==='expiring')return s.days_left!==null && s.days_left<=7;
  if(suppressionFilter==='quiet')return !s.still_firing && (s.quiet_days===null ? s.age_days>=14 : s.quiet_days>=14);
  return true;
}
function renderSuppressionReview() {
  var root=document.getElementById('suppressions');
  if(!stateReady(root)){suppressionControls=null;return;}
  if(!suppressionControls){
    root.innerHTML='';
    root.appendChild(panelIntro('Исключения на пересмотр','Проверки продолжаются, а причина исключения остаётся видимой. Пересмотрите срок или снимите исключение, когда оно больше не нужно.'));
    var body=h('div'),editor=h('div'),count=h('span',{class:'result-count',role:'status'});
    root.appendChild(h('div',{class:'filter-bar'},[searchControl('Найти исключение',function(v){suppressionSearch=v;renderSuppressionReview();}),
      selectControl('Состояние исключений',[['all','Все исключения'],['expiring','Истекают за 7 дней'],['firing','Скрывают проблему'],['quiet','Не срабатывают 14 дней']],suppressionFilter,function(v){suppressionFilter=v;renderSuppressionReview();}),count]));
    root.appendChild(editor);root.appendChild(body);suppressionControls={body:body,editor:editor,count:count};
  }
  var list=(state.suppressions || []).filter(suppressionMatches);
  suppressionControls.count.textContent=list.length+' из '+(state.suppressions || []).length;
  var body=suppressionControls.body;body.innerHTML='';
  if(!list.length){body.appendChild(emptyPanel((state.suppressions || []).length ? 'Под выбранные фильтры исключений нет.' : 'Исключений нет — дашборд показывает всё, что находит.'));return;}
  body.appendChild(h('div',{class:'exclusion-list'},list.map(function(s){
    var host=(state.hosts || []).find(function(x){return x.id===s.host;});
    var status=s.still_firing?'Скрывает проблему':s.quiet_days===null?'Пока не срабатывало':'Не срабатывает '+Math.round(s.quiet_days)+' дн.';
    return h('article',{class:'exclusion-card'},[
      h('div',{class:'exclusion-heading'},[host?hostButton(host):h('strong',{text:s.host_name}),h('span',{class:'status-pill '+(s.still_firing?'warn':'info'),text:status})]),
      h('div',{class:'muted',text:s.note || s.key}),h('p',{text:s.reason}),
      h('div',{class:'exclusion-foot'},[h('span',{class:'muted',text:'Создано '+Math.round(s.age_days)+' дн. назад · '+(s.days_left===null?'бессрочно':'осталось '+Math.ceil(s.days_left)+' дн.')}),
        h('button',{class:'btn btn-sm',text:'Изменить',disabled:suppressionSaving || state.actions_enabled===false?true:null,onclick:function(){editSuppression(s);}}),
        h('button',{class:'text-button',text:'Снять исключение',disabled:suppressionSaving || state.actions_enabled===false?true:null,onclick:function(){unsuppress(s.id,renderSuppressionReview);}})])
    ]);
  })));
}
function editSuppression(s) {
  if(suppressionSaving)return;
  if(suppressionDraft && suppressionDraft.dirty && !confirm('Отменить несохранённые изменения другого исключения?'))return;
  suppressionDraft={id:s.id,dirty:false};
  var root=suppressionControls.editor;root.innerHTML='';
  var reason=h('textarea',{class:'editor-reason','aria-label':'Причина исключения',maxlength:2000});reason.value=s.reason;
  var days=h('input',{class:'set-input',type:'number',min:1,max:3650,'aria-label':'Новый срок в днях',placeholder:'Без срока'});days.value=s.days_left===null?'':String(Math.max(1,Math.ceil(s.days_left)));
  var status=h('p',{class:'muted',role:'status'});
  function dirty(){suppressionDraft.dirty=true;status.textContent='Есть несохранённые изменения';}
  reason.oninput=days.oninput=dirty;
  var cancel=h('button',{class:'btn',text:'Отмена',onclick:function(){suppressionDraft=null;root.innerHTML='';}});
  var save=h('button',{class:'btn btn-primary',text:'Сохранить исключение',onclick:function(){
    var amount=days.value===''?null:Number(days.value);
    if(reason.value.trim().length<3 || (amount!==null && (!Number.isInteger(amount) || amount<1 || amount>3650))){status.textContent='Укажите причину от 3 символов и срок от 1 до 3650 дней или оставьте его пустым.';return;}
    suppressionSaving=true;save.disabled=cancel.disabled=reason.disabled=days.disabled=true;status.textContent='Сохраняем…';renderSuppressionReview();
    fetch('/api/suppress/update',{method:'POST',headers:actionHeaders(),body:JSON.stringify({id:s.id,reason:reason.value.trim(),days:amount})}).then(function(r){return r.json();}).then(function(res){
      if(res.error){actionFailed(res);throw new Error(res.error);}
      suppressionDraft=null;root.innerHTML='';load();
    }).catch(function(err){status.textContent='Не сохранено: '+err.message;}).finally(function(){suppressionSaving=false;save.disabled=cancel.disabled=reason.disabled=days.disabled=false;renderSuppressionReview();});
  }});
  root.appendChild(h('section',{class:'inline-editor'},[h('h3',{text:'Изменить исключение · '+s.host_name}),h('label',{text:'Причина'},[reason]),
    h('label',{text:'Срок от сегодняшнего дня'},[days]),h('p',{class:'muted',text:'Пустой срок — бессрочно. Исходная дата создания и история срабатываний сохраняются.'}),h('div',{class:'filter-bar'},[save,cancel]),status]));
  reason.focus();root.scrollIntoView({block:'nearest',behavior:'smooth'});
}
