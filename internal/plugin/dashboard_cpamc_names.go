package plugin

// cpamcNamesScript reads only the current server's name registry. Authentication
// storage is never read. Names are matched by CPAMC's SHA-256 identity contract.
const cpamcNamesScript = `
function apiKeyLabelHeaders(ref,label){var value=JSON.stringify({ref:ref,label:label}).replace(/[^\x20-\x7e]/g,function(ch){return '\\u'+ch.charCodeAt(0).toString(16).padStart(4,'0');});return {'X-API-Key-Label':value};}
function cpamcSHA256(value){
 var bytes=new TextEncoder().encode(value),length=Math.ceil((bytes.length+9)/64)*64,buffer=new Uint8Array(length);buffer.set(bytes);buffer[bytes.length]=128;var view=new DataView(buffer.buffer);view.setUint32(length-4,bytes.length*8);var h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],k=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2],w=new Uint32Array(64);
 function r(x,n){return (x>>>n)|(x<<(32-n));}
 for(var offset=0;offset<length;offset+=64){for(var i=0;i<16;i++)w[i]=view.getUint32(offset+i*4);for(i=16;i<64;i++){var x=w[i-15],y=w[i-2];w[i]=(w[i-16]+(r(x,7)^r(x,18)^(x>>>3))+w[i-7]+(r(y,17)^r(y,19)^(y>>>10)))>>>0;}var a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];for(i=0;i<64;i++){var t1=(z+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+k[i]+w[i])>>>0,t2=((r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c)))>>>0;z=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}[a,b,c,d,e,f,g,z].forEach(function(v,i){h[i]=(h[i]+v)>>>0;});}
 return h.map(function(v){return v.toString(16).padStart(8,'0');}).join('');
}
function cpamcNameRegistries(){
 var registries=[];try{var prefix='api-key-names:v1:',expected=new URL(publicPathPrefix||'/',window.location.origin),storage=window.localStorage;
 for(var i=0;i<storage.length;i++){var storageKey=storage.key(i);if(!storageKey||!storageKey.startsWith(prefix))continue;var base=storageKey.slice(prefix.length),server;try{server=new URL(base);}catch(_error){continue;}if(server.origin!==expected.origin||server.pathname.replace(/\/+$/,'')!==expected.pathname.replace(/\/+$/,''))continue;
 var raw=storage.getItem(storageKey);if(raw&&/^enc::v[12]::/.test(raw)){var salt='cli-proxy-api-webui::secure-storage|'+window.location.host+(raw.startsWith('enc::v1::')?'|'+navigator.userAgent:''),key=new TextEncoder().encode(salt),binary=atob(raw.slice(9)),bytes=Uint8Array.from(binary,function(ch,index){return ch.charCodeAt(0)^key[index%key.length];});raw=new TextDecoder().decode(bytes);}try{var names=JSON.parse(raw);if(names&&typeof names==='object'&&!Array.isArray(names))registries.push({base:base,names:names});}catch(_error){}
 }}catch(_error){}return registries;
}
var cpamcNameSyncInFlight=false;
async function syncCPAMCNames(data){
 if(cpamcNameSyncInFlight||!apiKeyTrackingEnabled||!fullModeSession)return;var registries=cpamcNameRegistries();if(!registries.length)return;cpamcNameSyncInFlight=true;
 try{var keys=(data&&data.api_keys||[]).slice();for(var item of keys){if(!item.ref||!item.key||item.status!=='available')continue;var label='';for(var registry of registries){var hash=cpamcSHA256(JSON.stringify(['api-key-name',registry.base,item.key])),candidate=registry.names[hash];if(typeof candidate==='string'&&candidate.trim()){label=candidate.trim();break;}}if(!label||Array.from(label).length>120||apiKeyLabels[item.ref])continue;await api(resourceBase+'/full-mode/api-key-labels',{method:'GET',cache:'no-store',headers:apiKeyLabelHeaders(item.ref,label)});apiKeyLabels[item.ref]=label;}
 renderAPIKeyFilter();renderAPIKeyShare();if(currentData)renderGroups(visibleGroups());if(currentRequestPage)renderRequests(currentRequestPage);
 }finally{cpamcNameSyncInFlight=false;}
}
`
