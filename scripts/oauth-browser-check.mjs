import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { chromium } from 'playwright-core';
import { PGlite } from '@electric-sql/pglite';
import { createOAuthServer } from '../dist/oauth/server.js';
import { createHttpServer } from '../dist/http.js';
import { derivePassword, randomSecret, challengeFor } from '../dist/oauth/security.js';
// Local-only regression test: no Render/database accounts or external requests.
// Requires Chromium and OpenSSL; the self-signed certificate is ONLY for this test.
const tlsDir=await mkdtemp(join(tmpdir(),'hh-oauth-browser-'));
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(tlsDir,'key.pem'),'-out',join(tlsDir,'cert.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],{stdio:'ignore'});
const tls={key:await readFile(join(tlsDir,'key.pem')),cert:await readFile(join(tlsDir,'cert.pem'))};
const pg=new PGlite();
const db={query:(s,v)=>pg.query(s,v),transaction:fn=>pg.transaction(tx=>fn({query:(s,v)=>tx.query(s,v)})),close:async()=>{}};
let upstream;
const proxy=https.createServer(tls,(req,res)=>{
  const forward=http.request({hostname:'127.0.0.1',port:upstream.address().port,path:req.url,method:req.method,headers:req.headers},r=>{res.writeHead(r.statusCode,r.headers);r.pipe(res);});
  forward.on('error',()=>{res.writeHead(502);res.end();});req.pipe(forward);
});
proxy.listen(0,'127.0.0.1');await once(proxy,'listening');
const origin='https://localhost:'+proxy.address().port;
let received, callbackReferrer, attackBody='';
const callbackServer=https.createServer(tls,(req,res)=>{
 res.setHeader('Content-Type','text/html');
 if(req.url.startsWith('/cb')){ received=new URL(req.url,callbackOrigin);callbackReferrer=req.headers.referer;res.end('<p>Callback received locally</p>'); }
 else res.end(attackBody);
});
callbackServer.listen(0,'127.0.0.1');await once(callbackServer,'listening');
const callbackOrigin='https://127.0.0.1:'+callbackServer.address().port;
const password=randomSecret(),salt=randomSecret().slice(0,32);
const env={MCP_PUBLIC_URL:origin,MCP_OAUTH_CLIENT_ID:'browser-test-client',MCP_OAUTH_CLIENT_SECRET:randomSecret(),MCP_OAUTH_REDIRECT_URIS:callbackOrigin+'/cb',MCP_ADMIN_PASSWORD_HASH:`scrypt$${salt}$${(await derivePassword(password,salt)).toString('hex')}`};
upstream=createHttpServer(await createOAuthServer(env,db),{HH_ALLOWED_HOSTS:new URL(origin).host});
upstream.listen(0,'127.0.0.1');await once(upstream,'listening');
let browser;
const report={};
try{
 browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const context=await browser.newContext({ignoreHTTPSErrors:true});

 const page=await context.newPage();
 const verifier=randomSecret(),state=randomSecret();
 const url=origin+'/oauth/authorize?'+new URLSearchParams({client_id:env.MCP_OAUTH_CLIENT_ID,redirect_uri:env.MCP_OAUTH_REDIRECT_URIS,response_type:'code',resource:origin+'/mcp',scope:'mcp:tools offline_access',state,code_challenge_method:'S256',code_challenge:challengeFor(verifier)});
 await page.goto(url);
 const cookies=await context.cookies();assert(cookies.some(c=>c.name==='__Host-hh_oauth'&&c.secure&&c.httpOnly&&c.sameSite==='Lax'));
 report.secure_cookie=true;
 await page.locator('input[name=password]').fill(password);
 await Promise.all([page.waitForURL(callbackOrigin+'/cb**',{timeout:5000}),page.getByRole('button',{name:'Войти и разрешить доступ'}).click()]);
 assert.equal(received.searchParams.get('state'),state);assert.equal(received.searchParams.get('iss'),origin);assert(received.searchParams.get('code'));
 report.native_https_form_login=true;report.state_and_issuer=true;assert.equal(callbackReferrer,undefined);report.no_cross_site_referrer=true;
 // Start another flow in the same browser, then attempt a cross-site POST with
 // even the correct CSRF/password values. No request reaches an external site.
 await page.goto(url);const flow=await page.locator('input[name=flow]').inputValue();const csrf=await page.locator('input[name=csrf]').inputValue();
 attackBody=`<form method="post" action="${origin}/oauth/authorize"><input name="flow" value="${flow}"><input name="csrf" value="${csrf}"><input name="password" value="${password}"><button>Attack</button></form>`;
 await page.goto(callbackOrigin+'/attack');
 const responsePromise=page.waitForResponse(r=>r.url()===origin+'/oauth/authorize'&&r.request().method()==='POST');
 await page.getByRole('button',{name:'Attack'}).click();const rejected=await responsePromise;assert.equal(rejected.status(),400);
 report.cross_site_post_rejected=true;

 console.log(JSON.stringify(report));
}finally{
 await browser?.close();upstream.closeAllConnections();proxy.closeAllConnections();callbackServer.closeAllConnections();
 await new Promise(r=>upstream.close(r));await new Promise(r=>proxy.close(r));await new Promise(r=>callbackServer.close(r));await pg.close();await rm(tlsDir,{recursive:true,force:true});
}
