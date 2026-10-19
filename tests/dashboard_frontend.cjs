// Run with: node --test tests/dashboard_frontend.cjs
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');

test('recorded findings render, filter, and escape untrusted content',async()=>{
  const nodes=new Map();
  const node=key=>{
    if(!nodes.has(key)) nodes.set(key,{value:'',innerHTML:'',textContent:'',listeners:{},addEventListener(type,fn){this.listeners[type]=fn;},replaceChildren(){this.innerHTML='';},classList:{toggle(){}},showModal(){this.open=true;},close(){this.open=false;}});
    return nodes.get(key);
  };
  const record={run:{status:'completed',skill:'port_scan',model:{}},findings:[{id:'f1',title:'<script>alert(1)</script>',severity:'critical',status:'possible',claims:[]}],events:[],observations:[],gaps:[],report:'Report'};
  const context=vm.createContext({document:{querySelector:node,querySelectorAll:()=>[],addEventListener(){}},fetch:async url=>({ok:true,json:async()=>url==='/api/runs'?[{directory:'demo',skill:'port_scan'}]:record}),Date,Blob,URL,setTimeout});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/harness/web/app.js'),'utf8'),context);
  await new Promise(resolve=>setImmediate(resolve));
  assert.match(node('#content').innerHTML,/Total findings/);
  assert.match(node('#content').innerHTML,/&lt;script&gt;/);
  assert.doesNotMatch(node('#content').innerHTML,/<script>/);
  vm.runInContext("view='findings';render()",context);
  assert.match(node('#finding-results').innerHTML,/f1/);
  node('#search').value='no-match';node('#search').listeners.input();
  assert.match(node('#finding-results').innerHTML,/No findings match/);
  node('#search').value='';node('#severity').value='low';node('#severity').listeners.change();
  assert.match(node('#finding-results').innerHTML,/No findings match/);
  vm.runInContext("view='report';render()",context);
  assert.match(node('#content').innerHTML,/Download .md/);
});
