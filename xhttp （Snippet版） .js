// --- 常量配置 ---
const UUID_DEFAULT = '6ffa85ff-4c3e-449d-a603-a0cedd379a2b';
const PROXY_DEFAULT = 'ProxyIP.US.CMLiussss.net:443'; // 默认为空，直连优先，失败兜底走 proxy

// 地址类型
const ADDRESS_TYPE_IPV4 = 1;
const ADDRESS_TYPE_URL = 2;
const ADDRESS_TYPE_IPV6 = 3;

// --- 环形缓冲区 ---
class RingBuffer {
  constructor(size = 16 * 1024) {
    this.buffer = new Uint8Array(size);
    this.size = size;
    this.readOffset = 0;
    this.writeOffset = 0;
    this.length = 0;
  }
  write(data) {
    if (data.length > this.size - this.length) {
      const newSize = Math.max(this.size * 2, this.length + data.length);
      const newBuffer = new Uint8Array(newSize);
      if (this.length > 0) {
        if (this.readOffset < this.writeOffset) {
          newBuffer.set(this.buffer.slice(this.readOffset, this.writeOffset), 0);
        } else {
          const first = this.buffer.slice(this.readOffset);
          const second = this.buffer.slice(0, this.writeOffset);
          newBuffer.set(first, 0);
          newBuffer.set(second, first.length);
        }
      }
      this.buffer = newBuffer;
      this.size = newSize;
      this.readOffset = 0;
      this.writeOffset = this.length;
    }
    if (this.writeOffset + data.length <= this.size) {
      this.buffer.set(data, this.writeOffset);
      this.writeOffset += data.length;
    } else {
      const first = this.size - this.writeOffset;
      this.buffer.set(data.slice(0, first), this.writeOffset);
      this.buffer.set(data.slice(first), 0);
      this.writeOffset = data.length - first;
    }
    this.length += data.length;
  }
  read(n) {
    if (this.length === 0) return null;
    const readLen = Math.min(n, this.length);
    let result;
    if (this.readOffset + readLen <= this.size) {
      result = this.buffer.slice(this.readOffset, this.readOffset + readLen);
      this.readOffset += readLen;
    } else {
      const first = this.size - this.readOffset;
      result = new Uint8Array(readLen);
      result.set(this.buffer.slice(this.readOffset), 0);
      result.set(this.buffer.slice(0, readLen - first), first);
      this.readOffset = readLen - first;
    }
    this.length -= readLen;
    if (this.length === 0) this.readOffset = this.writeOffset = 0;
    return result;
  }
}

// --- UUID 工具 ---
function parseUUID(uuid) {
  return uuid.replaceAll('-', '').match(/.{2}/g).map(x => parseInt(x, 16));
}

// --- VLESS Header 解析 ---
async function readVlessHeader(reader, uuidBytes) {
  let buffer = new Uint8Array(1024);
  let offset = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      if (offset === 0) return null;
      break;
    }
    if (offset + value.length > buffer.length) {
      const newBuf = new Uint8Array(offset + value.length);
      newBuf.set(buffer.slice(0, offset));
      buffer = newBuf;
    }
    buffer.set(value, offset);
    offset += value.length;

    if (offset < 18) continue;
    if (!buffer.slice(1, 17).every((b, i) => b === uuidBytes[i])) return null;

    const addonLen = buffer[17];
    if (offset < 18 + addonLen + 1) continue;
    const cmd = buffer[18 + addonLen];
    if (cmd !== 1) return null;

    const portIndex = 18 + addonLen + 1;
    const port = (buffer[portIndex] << 8) | buffer[portIndex + 1];
    const atypeIndex = portIndex + 2;
    const atype = buffer[atypeIndex];
    let hostIndex = atypeIndex + 1, hostLen = 0, hostname = '';

    switch (atype) {
      case ADDRESS_TYPE_IPV4:
        hostLen = 4;
        if (offset < hostIndex + hostLen) continue;
        hostname = Array.from(buffer.slice(hostIndex, hostIndex + hostLen)).join('.');
        break;
      case ADDRESS_TYPE_URL:
        hostLen = buffer[hostIndex];
        if (offset < hostIndex + 1 + hostLen) continue;
        hostname = new TextDecoder().decode(buffer.slice(hostIndex + 1, hostIndex + 1 + hostLen));
        hostLen++;
        break;
      case ADDRESS_TYPE_IPV6:
        hostLen = 16;
        if (offset < hostIndex + hostLen) continue;
        const dv = new DataView(buffer.buffer, hostIndex, 16);
        const parts = [];
        for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
        hostname = parts.join(':');
        break;
      default: return null;
    }

    const headerLen = hostIndex + hostLen;
    const data = buffer.slice(headerLen, offset);
    return { hostname, port, data, resp: new Uint8Array([buffer[0], 0]), reader };
  }
  return null;
}

// --- 上传管道 ---
async function uploadToRemote(writer, vless) {
  const ring = new RingBuffer(16 * 1024);
  if (vless.data?.length) ring.write(vless.data);
  let readerClosed = false, chunkSize = 16 * 1024;
  const MIN_CHUNK = 4 * 1024, MAX_CHUNK = 64 * 1024;
  while (!readerClosed || ring.length > 0) {
    if (ring.length === 0 && !readerClosed) {
      const { value, done } = await vless.reader.read();
      if (value) ring.write(value);
      if (done) readerClosed = true;
      if (ring.length === 0) continue;
    }
    const chunk = ring.read(chunkSize);
    if (chunk?.length) {
      const start = performance.now();
      await writer.write(chunk);
      const elapsed = performance.now() - start;
      if (elapsed < 5) chunkSize = Math.min(chunkSize * 2, MAX_CHUNK);
      else if (elapsed > 20) chunkSize = Math.max(chunkSize / 2, MIN_CHUNK);
    }
  }
}
function createUploader(vless, writable) {
  const writer = writable.getWriter();
  const done = uploadToRemote(writer, vless).finally(() => writer.close());
  return { done };
}

// --- 下载管道 ---
function createDownloader(resp, remoteReadable) {
  let heartbeatTimer;
  const stream = new TransformStream({
    start(controller) {
      controller.enqueue(resp);
      heartbeatTimer = setInterval(() => {
        try {
          controller.enqueue(new Uint8Array(0));
        } catch {
          clearInterval(heartbeatTimer);
        }
      }, 10000);
    },
    transform(chunk, controller) { controller.enqueue(chunk); },
    flush() { clearInterval(heartbeatTimer); }
  });
  remoteReadable.pipeTo(stream.writable).catch(() => {});
  return { readable: stream.readable };
}

// --- 连接远程 ---
async function connectToRemote(hostname, port, proxy) {
  try {
    const socket = connect({ hostname, port });
    await socket.opened;
    return socket;
  } catch {}
  if (proxy) {
    const [proxyHost, proxyPortRaw] = proxy.split(':');
    const proxyPort = proxyPortRaw ? Number(proxyPortRaw) : port;
    try {
      const proxySocket = connect({ hostname: proxyHost, port: proxyPort });
      await proxySocket.opened;
      return proxySocket;
    } catch {}
  }
  return null;
}

// --- 主处理函数 ---
export default {
  async fetch(request) {
    if (request.method !== 'POST') {
      return new Response('Expected POST', { status: 405 });
    }

    const config = { UUID: UUID_DEFAULT, PROXY: PROXY_DEFAULT };
    const uuidBytes = parseUUID(config.UUID);
    const vlessHeader = await readVlessHeader(request.body.getReader(), uuidBytes);
    if (!vlessHeader) return new Response('Invalid VLESS header', { status: 400 });

    const remoteSocket = await connectToRemote(vlessHeader.hostname, vlessHeader.port, config.PROXY);
    if (!remoteSocket) return new Response('Connect remote failed', { status: 502 });

    const uploader = createUploader(vlessHeader, remoteSocket.writable);
    const downloader = createDownloader(vlessHeader.resp, remoteSocket.readable);

    return new Response(downloader.readable, {
      headers: {
        'X-Accel-Buffering': 'no',
        'Cache-Control': 'no-store',
        'Connection': 'keep-alive',
        'Content-Type': 'application/grpc'
      }
    });
  }
};

// --- 引入 cloudflare sockets ---
import { connect } from 'cloudflare:sockets';
