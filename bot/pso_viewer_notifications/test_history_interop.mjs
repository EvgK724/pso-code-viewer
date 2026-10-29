// Synthetic OpenSSL -> WebCrypto interoperability, including organizer archive.
// No network or real device/private-key files are used.
import {createInterface} from 'node:readline';
const exchange = await import(process.env.PSO_EXCHANGE_MODULE);
const {makeDevice} = await import(new URL('./crypto.mjs',process.env.PSO_EXCHANGE_MODULE));
const {openBotArchivedMessage,HISTORY_TTL} = await import(new URL('./messages.mjs',process.env.PSO_EXCHANGE_MODULE));
const {makeRecipientGrant,verifyRecipientGrant} = await import(new URL('./recipient-trust.mjs',process.env.PSO_EXCHANGE_MODULE));
const [recipient,organizer,other] = await Promise.all([makeDevice(),makeDevice(),makeDevice()]);
console.log(JSON.stringify({cards:[await exchange.exportPublicCard(recipient,'Получатель'),
  await exchange.exportPublicCard(organizer,'Организатор'),await exchange.exportPublicCard(other,'Другое устройство')]}));
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
  const input=JSON.parse(line),card=await exchange.importPublicCard(input.botCard);
  const member={...card,name:'Тестовый бот',role:'bot'};
  member.approvalProof=await makeRecipientGrant(organizer,member,{now:input.meta.issued-1000});
  const own=await exchange.exportPublicCard(organizer,'Организатор');
  const sender=await verifyRecipientGrant(member,own,input.meta.issued);
  const first=await exchange.openSurname(recipient,input.recipientToken,[sender],input.meta.issued);
  const late=await exchange.openSurname(recipient,input.recipientToken,[sender],input.meta.issued+47*3600000);
  const archive=await openBotArchivedMessage(organizer,input.organizerToken,input.meta,sender,input.meta.issued+49*3600000);
  const last=await openBotArchivedMessage(organizer,input.organizerToken,input.meta,sender,input.meta.issued+HISTORY_TTL-1);
  async function denied(fn){try{await fn();return false;}catch{return true;}}
  const results={first,late,archive,last,
    expired:await denied(()=>exchange.openSurname(recipient,input.recipientToken,[sender],input.meta.expires)),
    archiveExpired:await denied(()=>openBotArchivedMessage(organizer,input.organizerToken,input.meta,sender,input.meta.issued+HISTORY_TTL)),
    wrongRecipient:await denied(()=>exchange.openSurname(other,input.recipientToken,[sender],input.meta.issued)),
    wrongOrganizer:await denied(()=>openBotArchivedMessage(other,input.organizerToken,input.meta,sender,input.meta.issued)),
    substitutedID:await denied(()=>openBotArchivedMessage(organizer,input.organizerOtherToken,input.meta,sender,input.meta.issued)),
    substitutedGroup:await denied(()=>openBotArchivedMessage(organizer,input.organizerToken,{...input.meta,group:'orit'},sender,input.meta.issued)),
    unboundRejected:await denied(()=>openBotArchivedMessage(organizer,input.unboundToken,input.meta,sender,input.meta.issued))
  };
  console.log(JSON.stringify(results));
  break;
}
