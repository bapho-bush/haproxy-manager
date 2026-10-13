// The actual account and Web UI forms under a DOM, with the API boundary stubbed.
const { parseHTML } = await import(process.env.LINKEDOM || "linkedom");
const { document, window } = parseHTML(`<!doctype html><html><body>
<div id="ovl"><div id="dlg"><div id="dlgtitle"></div><button id="dlgclose"></button>
<div id="dlgbody"></div><div id="dlgfoot"></div></div></div>
<aside id="nav"><div id="whofoot"></div></aside><div id="content"></div>
<div id="login"><form id="loginbox"><input id="lu"><input id="lp"><input id="lp2">
<div id="lp2wrap" hidden></div><div id="lcodewrap" hidden><input id="lcode"></div>
<div id="lerr"></div><button id="lbtn"></button><div id="logintitle"></div><div id="loginintro"></div></form></div>
</body></html>`);
Object.assign(globalThis, { document, window, location: { protocol: "https:", host: "proxy.test", hash: "#/" },
  MutationObserver: class { observe(){} }, localStorage: { getItem(){return null;}, setItem(){} } });
let sent, failSwitch = true;
globalThis.fetch = async (url, opts) => {
  const path = String(url).replace(/^\/api\//, "");
  if(opts?.body)sent=JSON.parse(opts.body);
  const body = path === "whoami" ? {authenticated:true,username:"alice",auth_mode:"pam",email:"alice@example.org",peers:2}
    : path === "webui" ? {enabled:false,port:8080}
    : path.startsWith("ui-auth") ? {mode:"pam",pam_service:"haproxy-manager",allowed_group:"ops",ready:true,members:["alice"],members_note:"Enumeration may be incomplete."}
    : {ok:true};
  const failed = path === "ui-auth" && opts?.method === "PUT" && failSwitch;
  return {ok:!failed,status:failed?403:200,json:async()=>failed?{error:"target denied"}:body,text:async()=>""};
};
const { refreshWho, openAccount, showLogin } = await import("../../static/js/auth.js");
const { renderWebui } = await import("../../static/js/pages/webui.js");
const assert = (condition, message) => {if(!condition)throw Error(message);console.log("PASS: "+message);};
const click = async button => {button.dispatchEvent(new window.Event("click"));await new Promise(r=>setTimeout(r,10));};
const field = key => document.querySelector("#f_"+key);

await refreshWho();openAccount();
assert(field("username").readOnly && field("username").value === "alice", "PAM username is read-only");
assert(!field("new") && !field("current") && !field("propagate"), "PAM account hides credential and propagation controls");
assert(!document.querySelector("#dlgbody").textContent.includes("Two-factor"), "PAM account hides local TOTP");
for(const option of field("theme").options)option.selected=option.value==="dark";
await click([...document.querySelectorAll("#dlgfoot button")].find(b=>b.textContent==="Save"));
assert(JSON.stringify(sent) === JSON.stringify({email:"alice@example.org",theme:"dark"}), "PAM profile sends only its own preferences");
showLogin(false);
assert(document.querySelector("#loginintro").textContent.includes("system username"), "PAM login explains system credentials");

await renderWebui();
assert(document.querySelector("#content").textContent.includes("Panel sign-in"), "authentication is on Web UI access");
assert(document.querySelector("#content").textContent.includes("alice"), "group overview lists enumerated users");
field("auth_current_password").value="current-test";
field("auth_target_password").value="target-test";
const save=[...document.querySelectorAll("#content button")].find(b=>b.textContent==="Verify and change sign-in");
await click(save);
assert(sent.mode==="pam" && sent.allowed_group==="ops" && sent.current.username==="alice" && sent.target.username==="alice",
       "switch submits current and target proof with the selected policy");
assert(!field("auth_current_password").value && !field("auth_target_password").value, "failed switching clears both password fields");
assert(document.querySelector("#content").textContent.includes("target denied") && !save.disabled, "failed switching reports the error and allows retry");
failSwitch=false;
field("auth_current_password").value="current-test";
field("auth_target_password").value="target-test";
await click(save);
assert(!field("auth_current_password").value && !field("auth_target_password").value, "successful switching refreshes the form without credentials");
console.log("PASS: PAM forms");
