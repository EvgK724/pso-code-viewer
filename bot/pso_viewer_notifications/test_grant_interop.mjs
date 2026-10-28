// Offline synthetic public certificate fixture; no network and no real patients.
import {webcrypto} from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const base=process.env.PSO_VIEWER_BASE;
const {makeDevice}=await import(new URL('crypto.mjs',base));
const {exportPublicCard,importPublicCard}=await import(new URL('exchange.mjs',base));
const {makeRecipientGrant,shortTrustedInvitationURL}=await import(new URL('recipient-trust.mjs',base));
const [organizer,doctor]=await Promise.all([makeDevice(),makeDevice()]);
const organizerCard=await exportPublicCard(organizer,'Проверочный организатор');
const card=await exportPublicCard(doctor,'Устройство'),subject=await importPublicCard(card);
const now=1791961200000;
const member={id:subject.id,role:'cardiologist',name:'Тестовый врач',card};
member.approvalProof=await makeRecipientGrant(organizer,member,{now});
const invitationId=Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url');
const invitationURL=await shortTrustedInvitationURL('https://viewer.example/',invitationId,organizerCard);
process.stdout.write(JSON.stringify({organizerCard,member,now,invitationId,invitationURL}));
