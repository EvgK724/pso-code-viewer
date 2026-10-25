import test from 'node:test';
import assert from 'node:assert/strict';
import {validateMessagePhoto,messageBase64url} from '../docs/messages.mjs';
import {inspectPhotoBytes,fitPhotoSize,stripJPEGMetadata,preparePhoto,MAX_PHOTO_INPUT_BYTES} from '../docs/photos.mjs';
const jpeg=Uint8Array.from(Buffer.from('_9j_4AAQSkZJRgABAQAAAQABAAD_2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj_2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj_wAARCAACAAMDASIAAhEBAxEB_8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL_8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4-Tl5ufo6erx8vP09fb3-Pn6_8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL_8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3-Pn6_9oADAMBAAIRAxEAPwDzSiiivpjwD__Z','base64url'));
function png(width,height,animated=false){
  const data=new Uint8Array(animated?57:45),v=new DataView(data.buffer);data.set([137,80,78,71,13,10,26,10]);v.setUint32(8,13);data.set(Buffer.from('IHDR'),12);v.setUint32(16,width);v.setUint32(20,height);data[24]=8;data[25]=2;
  const end=animated?45:33;if(animated){v.setUint32(33,0);data.set(Buffer.from('acTL'),37);}v.setUint32(end,0);data.set(Buffer.from('IEND'),end+4);return data;
}
test('sniffs file bytes, accepts bounded ordinary JPEG/PNG, rejects unsupported/SVG',()=>{
  assert.deepEqual(inspectPhotoBytes(jpeg),{type:'image/jpeg',width:3,height:2});
  assert.deepEqual(inspectPhotoBytes(png(4032,3024)),{type:'image/png',width:4032,height:3024});
  for(const b of [new Uint8Array(1),new Uint8Array(MAX_PHOTO_INPUT_BYTES+1),Uint8Array.from(Buffer.from('<svg width="100"/>')),png(12000,12000),png(1,0),png(10,10,true)])assert.throws(()=>inspectPhotoBytes(b));
});
test('fit preserves aspect ratio without upscaling and caps output dimensions',()=>{
  assert.deepEqual(fitPhotoSize(4032,3024),{width:2000,height:1500});assert.deepEqual(fitPhotoSize(100,50),{width:100,height:50});assert.deepEqual(fitPhotoSize(3000,4000),{width:1500,height:2000});assert.throws(()=>fitPhotoSize(10,10,2500));
});
test('removes EXIF/GPS/comments without altering image codestream or dimensions',()=>{
  const privateBytes=Uint8Array.from(Buffer.from('Exif\0\0GPS-test-and-doctor-name'));
  const segment=new Uint8Array(privateBytes.length+4);segment.set([255,225,(privateBytes.length+2)>>8,(privateBytes.length+2)&255]);segment.set(privateBytes,4);
  const input=new Uint8Array(jpeg.length+segment.length);input.set(jpeg.subarray(0,2));input.set(segment,2);input.set(jpeg.subarray(2),segment.length+2);
  assert.ok(Buffer.from(input).includes(Buffer.from('GPS-test')));assert.throws(()=>validateMessagePhoto({mime:'image/jpeg',data:messageBase64url(input),width:3,height:2}),/служебные/);const stripped=stripJPEGMetadata(input);assert.ok(!Buffer.from(stripped).includes(Buffer.from('GPS-test')));assert.deepEqual(inspectPhotoBytes(stripped),inspectPhotoBytes(jpeg));
  assert.deepEqual(stripped,jpeg);assert.throws(()=>stripJPEGMetadata(Uint8Array.from([255,216,255,225,255,255])));
});
test('photo preparation checks type/size/abort before decoding or canvas allocation',async()=>{
  await assert.rejects(preparePhoto({size:MAX_PHOTO_INPUT_BYTES+1,arrayBuffer:()=>{assert.fail('must not load');}}));
  const controller=new AbortController();controller.abort();await assert.rejects(preparePhoto(new Blob([jpeg]),{signal:controller.signal}),{name:'AbortError'});
  await assert.rejects(preparePhoto(new Blob(['<svg onload="alert(1)"/>'])),/Поддерживаются/);
});

test('local prepare renders JPEG, removes metadata and clears canvas/bitmap',async()=>{
  const oldBitmap=globalThis.createImageBitmap,oldDocument=globalThis.document;let closed=false,painted=false,inputType='';
  const canvas={width:0,height:0,getContext(type){assert.equal(type,'2d');return {fillRect(){},drawImage(){painted=true;}};},toBlob(callback,type,quality){assert.equal(type,'image/jpeg');assert.ok(quality<=0.88);callback(new Blob([jpeg],{type}));}};
  globalThis.createImageBitmap=async blob=>{inputType=blob.type;return {width:3,height:2,close(){closed=true;}};};globalThis.document={createElement(tag){assert.equal(tag,'canvas');return canvas;}};
  try{const result=await preparePhoto(new Blob([jpeg],{type:'application/octet-stream'}));assert.equal(result.mime,'image/jpeg');assert.equal(result.width,3);assert.equal(result.height,2);assert.ok(painted);assert.equal(inputType,'image/jpeg');assert.ok(closed);assert.equal(canvas.width,1);assert.equal(canvas.height,1);assert.deepEqual(Object.keys(result).sort(),['data','height','mime','width']);}
  finally{if(oldBitmap===undefined)delete globalThis.createImageBitmap;else globalThis.createImageBitmap=oldBitmap;if(oldDocument===undefined)delete globalThis.document;else globalThis.document=oldDocument;}
});

test('checks every JPEG scan and strips metadata after scan data',()=>{
  const segment=Uint8Array.from([255,254,0,12,...Buffer.from('GPS-secret')]);
  const input=new Uint8Array(jpeg.length+segment.length);
  input.set(jpeg.subarray(0,-2));input.set(segment,jpeg.length-2);input.set(jpeg.subarray(-2),jpeg.length-2+segment.length);
  assert.deepEqual(inspectPhotoBytes(input),{type:'image/jpeg',width:3,height:2});
  assert.throws(()=>validateMessagePhoto({mime:'image/jpeg',data:messageBase64url(input),width:3,height:2}),/служебные/);
  assert.deepEqual(stripJPEGMetadata(input),jpeg);
  const trailing=new Uint8Array(jpeg.length+2);trailing.set(jpeg);trailing.set([255,217],jpeg.length);
  assert.throws(()=>inspectPhotoBytes(trailing),/JPEG/);
  assert.throws(()=>inspectPhotoBytes(jpeg.subarray(0,-2)),/JPEG/);
});

test('rejects contradictory image dimension headers before decode',()=>{
  const first=png(100,100), duplicate=new Uint8Array(first.length+25);
  duplicate.set(first.subarray(0,33));duplicate.set(first.subarray(8,33),33);duplicate.set(first.subarray(33),58);
  assert.throws(()=>inspectPhotoBytes(duplicate),/PNG/);
  const webp=new Uint8Array(48),v=new DataView(webp.buffer);
  webp.set(Buffer.from('RIFF'),0);v.setUint32(4,40,true);webp.set(Buffer.from('WEBP'),8);
  for(const [offset,width] of [[12,100],[30,12000]]){webp.set(Buffer.from('VP8X'),offset);v.setUint32(offset+4,10,true);const n=width-1;webp[offset+12]=n&255;webp[offset+13]=(n>>8)&255;webp[offset+15]=99;}
  assert.throws(()=>inspectPhotoBytes(webp),/размер WebP/);
});


test('accepts ordinary progressive JPEG with multiple entropy scans',()=>{
  const progressive=Uint8Array.from(Buffer.from('_9j_4AAQSkZJRgABAQAAAQABAAD_2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL_2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL_wgARCAAHAA0DASIAAhEBAxEB_8QAFQABAQAAAAAAAAAAAAAAAAAAAAb_xAAVAQEBAAAAAAAAAAAAAAAAAAABBP_aAAwDAQACEAMQAAABngUf_8QAFBABAAAAAAAAAAAAAAAAAAAAEP_aAAgBAQABBQI__8QAFBEBAAAAAAAAAAAAAAAAAAAAAP_aAAgBAwEBPwF__8QAFBEBAAAAAAAAAAAAAAAAAAAAAP_aAAgBAgEBPwF__8QAFBABAAAAAAAAAAAAAAAAAAAAEP_aAAgBAQAGPwI__8QAFBABAAAAAAAAAAAAAAAAAAAAEP_aAAgBAQABPyE__9oADAMBAAIAAwAAABD3_8QAFBEBAAAAAAAAAAAAAAAAAAAAAP_aAAgBAwEBPxB__8QAFBEBAAAAAAAAAAAAAAAAAAAAAP_aAAgBAgEBPxB__8QAFBABAAAAAAAAAAAAAAAAAAAAEP_aAAgBAQABPxA__9k','base64url'));
  assert.deepEqual(inspectPhotoBytes(progressive),{type:'image/jpeg',width:13,height:7});
  assert.deepEqual(stripJPEGMetadata(progressive),progressive);
  assert.equal(validateMessagePhoto({mime:'image/jpeg',data:messageBase64url(progressive),width:13,height:7}).width,13);
});
