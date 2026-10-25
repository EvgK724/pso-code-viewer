// Photos are processed locally. Only a freshly rendered JPEG may be encrypted.
// No filename, EXIF, GPS, source URL or creation date is put into the message.
import {MAX_PHOTO_BYTES, jpegDimensions, inspectJPEGStructure, messageBase64url, messageUnbase64url, validateMessagePhoto} from './messages.mjs';
export const MAX_PHOTO_INPUT_BYTES=20*1024*1024;
export const MAX_PHOTO_INPUT_PIXELS=25000000;
export const MAX_PHOTO_SIDE=2000;
const ascii=(bytes,start,end)=>String.fromCharCode(...bytes.subarray(start,end));
function size(width,height,type){
  if(!Number.isSafeInteger(width)||!Number.isSafeInteger(height)||width<1||height<1||width>12000||height>12000||width*height>MAX_PHOTO_INPUT_PIXELS)throw new Error('Фото слишком большое: выберите обычный снимок до 25 мегапикселей.');
  return {width,height,type};
}
export function inspectPhotoBytes(bytes){
  if(!(bytes instanceof Uint8Array)||bytes.length<12||bytes.length>MAX_PHOTO_INPUT_BYTES)throw new Error('Выберите фото размером до 20 МБ.');
  const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  if(bytes[0]===255&&bytes[1]===216){const d=jpegDimensions(bytes);return size(d.width,d.height,'image/jpeg');}
  if(bytes[0]===137&&ascii(bytes,1,4)==='PNG'&&bytes[4]===13&&bytes[5]===10&&bytes[6]===26&&bytes[7]===10){
    if(bytes.length<33||view.getUint32(8)!==13||ascii(bytes,12,16)!=='IHDR')throw new Error('Повреждённое PNG-фото.');
    let offset=8;
    while(offset+12<=bytes.length){
      const length=view.getUint32(offset),type=ascii(bytes,offset+4,offset+8);
      if(length>bytes.length-offset-12)throw new Error('Повреждённое PNG-фото.');
      if(type==='acTL')throw new Error('Нужно обычное фото, без анимации.');
      if(type==='IHDR'&&offset!==8)throw new Error('Повреждённое PNG-фото.');
      offset+=12+length;if(type==='IEND')break;
    }
    return size(view.getUint32(16),view.getUint32(20),'image/png');
  }
  if(ascii(bytes,0,4)==='RIFF'&&ascii(bytes,8,12)==='WEBP'){
    if(view.getUint32(4,true)+8!==bytes.length)throw new Error('Повреждённое WebP-фото.');
    let offset=12,dimensions;
    while(offset+8<=bytes.length){
      const kind=ascii(bytes,offset,offset+4),length=view.getUint32(offset+4,true),p=offset+8;
      if(length>bytes.length-p)throw new Error('Повреждённое WebP-фото.');
      if(kind==='ANIM'||kind==='ANMF')throw new Error('Нужно обычное фото, без анимации.');
      if(kind==='VP8X'){
        if(length!==10||(bytes[p]&2))throw new Error('Нужно обычное WebP-фото.');
        const d={width:1+bytes[p+4]+(bytes[p+5]<<8)+(bytes[p+6]<<16),height:1+bytes[p+7]+(bytes[p+8]<<8)+(bytes[p+9]<<16)};
        if(dimensions&&(dimensions.width!==d.width||dimensions.height!==d.height))throw new Error('Неверный размер WebP.');dimensions=d;
      }else if(kind==='VP8 '){
        if(length<10||bytes[p+3]!==0x9d||bytes[p+4]!==1||bytes[p+5]!==0x2a)throw new Error('Повреждённое WebP-фото.');
        const d={width:view.getUint16(p+6,true)&0x3fff,height:view.getUint16(p+8,true)&0x3fff};
        if(dimensions&&(dimensions.width!==d.width||dimensions.height!==d.height))throw new Error('Неверный размер WebP.');
        dimensions=d;
      }else if(kind==='VP8L'){
        if(length<5||bytes[p]!==0x2f)throw new Error('Повреждённое WebP-фото.');
        const bits=view.getUint32(p+1,true),d={width:(bits&0x3fff)+1,height:((bits>>>14)&0x3fff)+1};
        if(dimensions&&(dimensions.width!==d.width||dimensions.height!==d.height))throw new Error('Неверный размер WebP.');dimensions=d;
      }
      offset=p+length+(length%2);
    }
    if(!dimensions)throw new Error('Размер WebP-фото не найден.');return size(dimensions.width,dimensions.height,'image/webp');
  }
  throw new Error('Поддерживаются JPEG, PNG и WebP. Выберите обычное фото или сохраните снимок в JPEG.');
}
export function fitPhotoSize(width,height,maxSide=MAX_PHOTO_SIDE){
  size(width,height,'image/jpeg');
  if(!Number.isSafeInteger(maxSide)||maxSide<1||maxSide>MAX_PHOTO_SIDE)throw new Error('Неверный размер результата.');
  const ratio=Math.min(1,maxSide/Math.max(width,height));
  return {width:Math.max(1,Math.round(width*ratio)),height:Math.max(1,Math.round(height*ratio))};
}
// Remove ancillary APP/COM metadata even if a browser encoder adds it. Keep
// the JFIF APP0 and Adobe APP14 color-transform markers used by JPEG decoders.
export function stripJPEGMetadata(bytes){
  const {segments}=inspectJPEGStructure(bytes);
  const chunks=segments.filter(({marker})=>marker!==0xfe&&!(marker>=0xe1&&marker<=0xef&&marker!==0xee)).map(({start,end})=>bytes.subarray(start,end));
  const result=new Uint8Array(chunks.reduce((n,c)=>n+c.length,0));let position=0;
  for(const chunk of chunks){result.set(chunk,position);position+=chunk.length;}return result;
}
async function decodeImage(blob){
  if(typeof globalThis.createImageBitmap==='function')return createImageBitmap(blob,{imageOrientation:'from-image'});
  const url=URL.createObjectURL(blob);
  try{return await new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>resolve(image);image.onerror=()=>reject(new Error('Фото не удалось открыть. Выберите JPEG или PNG.'));image.src=url;});}
  finally{URL.revokeObjectURL(url);}
}
function canvasBlob(canvas,quality){return new Promise((resolve,reject)=>canvas.toBlob(blob=>blob?resolve(blob):reject(new Error('Не удалось подготовить фотографию.')),'image/jpeg',quality));}
export async function preparePhoto(file,{signal}={}){
  const check=()=>{if(signal?.aborted)throw new DOMException('Подготовка фото отменена.','AbortError');};
  check();
  if(!file||!Number.isSafeInteger(file.size)||file.size<12||file.size>MAX_PHOTO_INPUT_BYTES||typeof file.arrayBuffer!=='function')throw new Error('Выберите фото размером до 20 МБ.');
  const input=new Uint8Array(await file.arrayBuffer());check();
  const inspected=inspectPhotoBytes(input);
  const blob=new Blob([input],{type:inspected.type});input.fill(0);
  let image,canvas;
  try{
    image=await decodeImage(blob);check();
    const originalWidth=image.naturalWidth||image.width,originalHeight=image.naturalHeight||image.height;
    size(originalWidth,originalHeight,inspected.type);
    // EXIF orientation may exchange width and height; no other change allowed.
    if(!((originalWidth===inspected.width&&originalHeight===inspected.height)||(originalWidth===inspected.height&&originalHeight===inspected.width)))throw new Error('Не удалось подтвердить размер фото.');
    canvas=document.createElement('canvas');
    let side=MAX_PHOTO_SIDE;
    while(side>=800){
      const dimensions=fitPhotoSize(originalWidth,originalHeight,side);canvas.width=dimensions.width;canvas.height=dimensions.height;
      const ctx=canvas.getContext('2d',{alpha:false});if(!ctx)throw new Error('Обработка фото недоступна на этом устройстве.');
      ctx.fillStyle='#fff';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.drawImage(image,0,0,canvas.width,canvas.height);
      for(const quality of [0.88,0.76,0.62]){
        check();const output=await canvasBlob(canvas,quality);check();
        if(output.type!=='image/jpeg')throw new Error('Телефон не смог преобразовать фото в JPEG.');
        const bytes=stripJPEGMetadata(new Uint8Array(await output.arrayBuffer()));check();
        if(bytes.length<=MAX_PHOTO_BYTES){const result={mime:'image/jpeg',data:messageBase64url(bytes),width:dimensions.width,height:dimensions.height};bytes.fill(0);return validateMessagePhoto(result);}
        bytes.fill(0);
      }
      side=Math.floor(side*0.8);
    }
    throw new Error('Фото слишком сложное для отправки. Снимите страницу крупнее или выберите другое фото.');
  }finally{image?.close?.();if(canvas){canvas.width=1;canvas.height=1;}}
}
export function photoObjectURL(photo){
  const p=validateMessagePhoto(photo);if(!p)throw new Error('Фото отсутствует.');
  return URL.createObjectURL(new Blob([messageUnbase64url(p.data)],{type:'image/jpeg'}));
}
