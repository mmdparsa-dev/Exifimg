(() => {
  "use strict";

  const SUPPORTED_EXT = [
    "jpg","jpeg","jfif","jpe",
    "png","webp","gif","bmp",
    "tif","tiff","svg","ico",
    "avif","heic","heif","jxl",
    "psd","dng","cr2","cr3",
    "nef","arw","raf","orf",
    "rw2","pef","sr2"
  ];
  const SUPPORTED_EXT_26 = SUPPORTED_EXT.filter(x => x !== "sr2");

  function extOf(name){
    const m = /\.([a-z0-9]+)$/i.exec(name || "");
    return m ? m[1].toLowerCase() : "";
  }

  function isSupportedExt(ext){
    return SUPPORTED_EXT_26.includes(ext);
  }

  function fmtBytes(n){
    const u = ["B","KB","MB","GB"];
    let i=0, x=n;
    while(x>=1024 && i<u.length-1){x/=1024;i++;}
    return `${x.toFixed(x>=10||i===0?0:1)} ${u[i]}`;
  }

  async function sha256Hex(buffer){
    const hash = await crypto.subtle.digest("SHA-256", buffer);
    const bytes = new Uint8Array(hash);
    return [...bytes].map(b=>b.toString(16).padStart(2,"0")).join("");
  }

  const TAGS_IFD0 = {
    0x010F:"Make",
    0x0110:"Model",
    0x0112:"Orientation",
    0x0132:"DateTime",
    0x8769:"ExifIFDPointer",
    0x8825:"GPSInfoIFDPointer"
  };
  const TAGS_EXIF = {
    0x9003:"DateTimeOriginal",
    0x8827:"ISOSpeedRatings",
    0x829A:"ExposureTime",
    0x829D:"FNumber",
    0x920A:"FocalLength",
    0xA434:"LensModel"
  };
  const TAGS_GPS = {
    0x0001:"GPSLatitudeRef",
    0x0002:"GPSLatitude",
    0x0003:"GPSLongitudeRef",
    0x0004:"GPSLongitude"
  };

  function readUInt16(view, off, le){ return view.getUint16(off, le); }
  function readUInt32(view, off, le){ return view.getUint32(off, le); }

  function getAscii(view, off, len){
    let s="";
    for(let i=0;i<len;i++){
      const c = view.getUint8(off+i);
      if(c===0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  function getRational(view, off, le){
    const n = view.getUint32(off, le);
    const d = view.getUint32(off+4, le);
    if(d===0) return null;
    return n / d;
  }

  function parseIFD(view, tiffStart, ifdOffset, le, tagMap){
    const out = {};
    const base = tiffStart;
    let p = base + ifdOffset;
    if(p < 0 || p + 2 > view.byteLength) return { out, next: 0 };

    const entries = readUInt16(view, p, le); p += 2;

    for(let i=0;i<entries;i++){
      const e = p + i*12;
      if(e+12 > view.byteLength) break;

      const tag = readUInt16(view, e, le);
      const type = readUInt16(view, e+2, le);
      const count = readUInt32(view, e+4, le);
      const valueOrOffset = readUInt32(view, e+8, le);

      const name = tagMap[tag];
      if(!name) continue;

      const typeSize = ({1:1,2:1,3:2,4:4,5:8,7:1,10:8}[type]) || 0;
      const valueBytes = count * typeSize;
      let valuePtr = (valueBytes <= 4) ? (e+8) : (base + valueOrOffset);

      if(valuePtr < 0 || valuePtr > view.byteLength) continue;

      let val = null;

      try{
        if(type === 2){
          val = getAscii(view, valuePtr, count);
        } else if(type === 3){
          val = (count===1) ? readUInt16(view, valuePtr, le) : Array.from({length:count}, (_,k)=>readUInt16(view,valuePtr+k*2,le));
        } else if(type === 4){
          val = (count===1) ? readUInt32(view, valuePtr, le) : Array.from({length:count}, (_,k)=>readUInt32(view,valuePtr+k*4,le));
        } else if(type === 5){
          if(count===1){
            val = getRational(view, valuePtr, le);
          } else {
            val = Array.from({length:count}, (_,k)=>getRational(view, valuePtr+k*8, le));
          }
        } else if(type === 1 || type === 7){
          val = (count===1) ? view.getUint8(valuePtr) : Array.from(new Uint8Array(view.buffer, valuePtr, Math.min(count, 64)));
        } else {
          val = null;
        }
      } catch(_e){
        val = null;
      }

      out[name] = val;
    }

    const nextOffPos = p + entries*12;
    const next = (nextOffPos+4 <= view.byteLength) ? readUInt32(view, nextOffPos, le) : 0;
    return { out, next };
  }

  function dmsToDecimal(arr, ref){
    if(!arr || arr.length < 3) return null;
    const [d,m,s] = arr;
    const dec = (d || 0) + (m || 0)/60 + (s || 0)/3600;
    const neg = (ref === "S" || ref === "W");
    return neg ? -dec : dec;
  }

  function formatExifValue(exif){
    const out = {...exif};

    if(typeof out.ExposureTime === "number"){
      if(out.ExposureTime > 0 && out.ExposureTime < 1){
        const inv = Math.round(1/out.ExposureTime);
        out.ExposureTime = `1/${inv}`;
      } else {
        out.ExposureTime = String(out.ExposureTime);
      }
    }

    if(typeof out.FNumber === "number"){
      out.FNumber = `f/${out.FNumber.toFixed(1)}`;
    }
    if(typeof out.FocalLength === "number"){
      out.FocalLength = `${out.FocalLength.toFixed(1)}mm`;
    }

    if(out.GPSLatitude && out.GPSLongitude && Array.isArray(out.GPSLatitude) && Array.isArray(out.GPSLongitude)){
      const latRef = out.GPSLatitudeRef || "N";
      const lonRef = out.GPSLongitudeRef || "E";
      const lat = dmsToDecimal(out.GPSLatitude, latRef);
      const lon = dmsToDecimal(out.GPSLongitude, lonRef);
      if(lat !== null && lon !== null){
        out.GPS = `${lat.toFixed(6)}, ${lon.toFixed(6)}`;
      }
    }

    delete out.GPSLatitude; delete out.GPSLongitude; delete out.GPSLatitudeRef; delete out.GPSLongitudeRef;
    return out;
  }

  function parseExifFromTIFF(view, tiffStart){
    const endian = getAscii(view, tiffStart, 2);
    const le = endian === "II";
    const magic = readUInt16(view, tiffStart+2, le);
    if(magic !== 42) return null;
    const ifd0Offset = readUInt32(view, tiffStart+4, le);

    const ifd0 = parseIFD(view, tiffStart, ifd0Offset, le, TAGS_IFD0).out;

    let exif = {};
    let gps = {};
    if(ifd0.ExifIFDPointer){
      exif = parseIFD(view, tiffStart, ifd0.ExifIFDPointer, le, TAGS_EXIF).out;
    }
    if(ifd0.GPSInfoIFDPointer){
      gps = parseIFD(view, tiffStart, ifd0.GPSInfoIFDPointer, le, TAGS_GPS).out;
    }

    const merged = {...ifd0, ...exif, ...gps};
    delete merged.ExifIFDPointer;
    delete merged.GPSInfoIFDPointer;

    return formatExifValue(merged);
  }

  function parseExifFromJPEG(buffer){
    const view = new DataView(buffer);
    if(view.byteLength < 4) return null;
    if(view.getUint8(0) !== 0xFF || view.getUint8(1) !== 0xD8) return null;

    let offset = 2;
    while(offset + 4 < view.byteLength){
      if(view.getUint8(offset) !== 0xFF){ offset++; continue; }
      const marker = view.getUint8(offset+1);
      if(marker === 0xD9 || marker === 0xDA) break;

      const size = view.getUint16(offset+2, false);
      if(size < 2) break;

      if(marker === 0xE1){
        const start = offset + 4;
        const hdr = getAscii(view, start, 6);
        if(hdr === "Exif\u0000\u0000"){
          const tiffStart = start + 6;
          return parseExifFromTIFF(view, tiffStart);
        }
      }

      offset += 2 + size;
    }
    return null;
  }

  function parseExif(buffer, ext){
    if(["jpg","jpeg","jfif","jpe"].includes(ext)){
      return parseExifFromJPEG(buffer);
    }
    if(["tif","tiff"].includes(ext)){
      try{
        return parseExifFromTIFF(new DataView(buffer), 0);
      } catch(_e){
        return null;
      }
    }
    return null;
  }

  async function tryGetDimensions(file){
    try{
      const bmp = await createImageBitmap(file);
      const w = bmp.width, h = bmp.height;
      bmp.close?.();
      return { width:w, height:h, canPreview:true };
    } catch(_e){
      const ext = extOf(file.name);
      if(ext === "svg"){
        try{
          const txt = await file.text();
          const mW = /width\s*=\s*["']([^"']+)["']/i.exec(txt);
          const mH = /height\s*=\s*["']([^"']+)["']/i.exec(txt);
          const mVB = /viewBox\s*=\s*["']([^"']+)["']/i.exec(txt);
          let width = null, height = null;
          if(mW && mH){
            width = parseFloat(mW[1]);
            height = parseFloat(mH[1]);
          } else if(mVB){
            const parts = mVB[1].trim().split(/\s+/).map(Number);
            if(parts.length === 4){
              width = parts[2];
              height = parts[3];
            }
          }
          return { width, height, canPreview:true };
        } catch(_e2){
          return { width:null, height:null, canPreview:false };
        }
      }
      return { width:null, height:null, canPreview:false };
    }
  }

  function gcd(a,b){ a=Math.abs(a); b=Math.abs(b); while(b){ [a,b] = [b, a%b]; } return a || 1; }
  function aspect(w,h){
    if(!w || !h) return null;
    const g = gcd(w,h);
    return `${(w/g)|0}:${(h/g)|0}`;
  }

  async function buildReport(file){
    const ext = extOf(file.name);
    const ok = isSupportedExt(ext);
    if(!ok) return { ok:false, ext, report:null, canPreview:false, thumbUrl:null, readFail:false };

    let buffer;
    try{
      buffer = await file.arrayBuffer();
    } catch(_e){
      return { ok:true, ext, report:null, canPreview:false, thumbUrl:null, readFail:true };
    }

    const sha = await sha256Hex(buffer);
    const dims = await tryGetDimensions(file);
    const canPreview = !!dims.canPreview;

    let thumbUrl = null;
    if(canPreview){
      try{ thumbUrl = URL.createObjectURL(file); } catch(_e){}
    }

    let exif = null;
    try{
      exif = parseExif(buffer, ext);
    } catch(_e){
      exif = null;
    }

    const lastModified = file.lastModified ? new Date(file.lastModified).toISOString() : null;

    const report = {
      name: file.name,
      ext,
      mime: file.type || null,
      sizeBytes: file.size,
      sizeHuman: fmtBytes(file.size),
      lastModified,
      sha256: sha,
      width: dims.width,
      height: dims.height,
      aspect: aspect(dims.width, dims.height),
      exif: exif || {}
    };

    return { ok:true, ext, report, canPreview, thumbUrl, readFail:false };
  }

  async function processFiles(fileListLike){
    const arr = Array.from(fileListLike || []);
    const items = [];
    const unsupported = [];
    const readFails = [];

    for(const file of arr){
      const ext = extOf(file.name);
      if(!isSupportedExt(ext)){
        unsupported.push(file);
        continue;
      }
      const it = await buildReport(file);
      if(it.readFail) readFails.push(file);
      items.push({ file, ext: it.ext, ok: it.ok, report: it.report, thumbUrl: it.thumbUrl, canPreview: it.canPreview });
    }

    return { items, unsupported, readFails };
  }

  window.ExifImgCore = { processFiles };
})();