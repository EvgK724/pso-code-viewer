// Synthetic, offline cross-runtime test. Never imports a doctor's private key.
import {createInterface} from 'node:readline';
const exchange = await import(process.env.PSO_EXCHANGE_MODULE);
const {makeDevice} = await import(new URL('./crypto.mjs',process.env.PSO_EXCHANGE_MODULE));
const a=await makeDevice(),b=await makeDevice();
console.log(JSON.stringify({cards:[await exchange.exportPublicCard(a,'Получатель А'),await exchange.exportPublicCard(b,'Получатель Б')]}));
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
  const input=JSON.parse(line),sender={...await exchange.importPublicCard(input.card),verified:true};
  const first=await exchange.openSurname(a,input.tokens[0],[sender],input.now);
  const second=await exchange.openSurname(b,input.tokens[1],[sender],input.now);
  let wrong=false,tampered=false;
  try{await exchange.openSurname(b,input.tokens[0],[sender],input.now);}catch{wrong=true;}
  const parts=input.tokens[0].split('.');parts[4]=(parts[4][0]==='A'?'B':'A')+parts[4].slice(1);
  try{await exchange.openSurname(a,parts.join('.'),[sender],input.now);}catch{tampered=true;}
  const {signature,...unsigned}=input.envelope;
  const verified=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},sender.signingPublicKey,Buffer.from(signature,'base64url'),new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned)));
  console.log(JSON.stringify({first,second,wrong,tampered,verified,senderID:sender.id}));
  break;
}
