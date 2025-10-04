


//【订阅格式】 https://域名/sub
 

// ========== 依赖导入 ==========
import { connect } from 'cloudflare:sockets';

// ==================== 统一配置区 ====================
// 所有配置均在此处修改，简单、直观、可靠
const CONFIG = {
    UUID: 'bc9fd3f6-1f61-4520-81a9-5086fe7abccf',
    PROXY_IP: 'ProxyIP.SG.CMLiussss.net:443 ', //格式ip:端口
    
    // 节点路径
    VLESS_PATH: '/?ed=2560', 
    
    // 节点名称
    NODE_NAME: '双协议SN 订阅版'
};

// ==================== 预处理常量 ====================
// 在脚本加载时，基于上面唯一的 CONFIG 生成常量，确保全局一致
const UUID_BYTES = parseUUID(CONFIG.UUID);
const VLESS_RESPONSE_HEADER = new Uint8Array([0, 0]);

// ==================== Worker 主入口 (协议自动识别) ====================
export default {
  async fetch(request) {
    try {
      const upgradeHeader = request.headers.get('Upgrade');

      // 1. 识别 VLESS+WS 请求
      if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        return await handleStandardWsRequest(request);
      } 
      
      // 2. 识别 VLESS+HTTP (POST) 请求
      if (request.method === 'POST') {
        return await handleStandardPostRequest(request);
      }
      
      // 3. 处理 GET 请求，提供订阅链接或欢迎信息
      if (request.method === 'GET') {
        const url = new URL(request.url);
        if (url.pathname === '/sub') {
          return generateSubscription(url.hostname);
        }
        return new Response(`Welcome! Access "/sub" to get subscription links.`, { status: 200 });
      }

      return new Response('Method Not Allowed', { status: 405 });

    } catch (e) {
      console.error('Global handler error:', e.stack || e);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};


// =================================================================
// ==================== 协议处理器 ===================================
// =================================================================

/**
 * 处理标准 VLESS+WS 请求
 */
async function handleStandardWsRequest(request) {
  const wsPair = new WebSocketPair();
  const [clientWs, serverWs] = Object.values(wsPair);
  serverWs.accept();

  try {
    const protocol = request.headers.get('sec-websocket-protocol');
    if (!protocol) {
      throw new Error('Missing sec-websocket-protocol header');
    }

    const vlessHeaderData = decodeBase64(protocol);
    if (!compareArray(vlessHeaderData.slice(1, 17), UUID_BYTES)) {
      throw new Error('Invalid UUID');
    }

    const { remoteHost, remotePort, initialData } = parseVlessHeaderWs(vlessHeaderData);
    
    const remoteSocket = await connectToRemote(remoteHost, remotePort, CONFIG.PROXY_IP);
    if (!remoteSocket) {
      throw new Error('Failed to connect to remote');
    }

    proxyPipelineWs(serverWs, remoteSocket, initialData);

    return new Response(null, { status: 101, webSocket: clientWs });

  } catch (err) {
    console.error('WS Handler Error:', err.stack || err);
    serverWs.close(1011, err.message);
    return new Response(err.message, { status: 500 });
  }
}

/**
 * 处理标准 VLESS+HTTP (POST) 请求
 */
async function handleStandardPostRequest(request) {
  const vlessData = await readVlessHeaderHttp(request.body.getReader());
  if (!vlessData) {
    return new Response('Invalid VLESS header', { status: 400 });
  }

  const { remoteHost, remotePort, uploadStream } = vlessData;

  const remoteSocket = await connectToRemote(remoteHost, remotePort, CONFIG.PROXY_IP);
  if (!remoteSocket) {
    return new Response('Failed to connect to remote server', { status: 502 });
  }

  uploadStream.pipeTo(remoteSocket.writable).catch(() => {});
  
  const downloader = createDownloaderHttp(remoteSocket.readable);
  
  return new Response(downloader, {
    headers: { 
      'X-Accel-Buffering': 'no', 
      'Cache-Control': 'no-store', 
      'Connection': 'Keep-Alive', 
      'Content-Type': 'application/octet-stream' 
    }
  });
}


// =================================================================
// ==================== 共享核心辅助函数 ==============================
// =================================================================

/**
 * 连接远程服务器，支持代理回退和详细错误日志
 */
async function connectToRemote(hostname, port, proxy) {
  try {
    const socket = connect({ hostname, port });
    await socket.opened;
    return socket;
  } catch (err) {
    console.warn(`Direct connection to ${hostname}:${port} failed: ${err.name}`);
  }

  if (proxy && proxy.length > 0) {
    try {
      const [proxyHost, proxyPortRaw] = proxy.split(':');
      const proxyPort = proxyPortRaw ? Number(proxyPortRaw) : port;
      const proxySocket = connect({ hostname: proxyHost, port: proxyPort });
      await proxySocket.opened;
      return proxySocket;
    } catch (perr) {
       console.error(`Proxy connection to ${proxy} failed: ${perr.name}`);
    }
  }
  
  console.error(`All connection attempts failed for: ${hostname}:${port}`);
  return null;
}

/**
 * 将 UUID 字符串解析为 Uint8Array
 */
function parseUUID(uuidStr) {
  if (!uuidStr) {
    throw new Error('UUID is not configured');
  }
  return new Uint8Array(uuidStr.replaceAll('-', '').match(/.{2}/g).map(byte => parseInt(byte, 16)));
}

/**
 * 比较两个 Uint8Array 是否相等
 */
function compareArray(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Base64 URL Safe 解码
 */
function decodeBase64(str) {
  return Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

// =================================================================
// ==================== 协议专用与订阅生成函数 ========================
// =================================================================

// --- WebSocket 专用 ---

function parseVlessHeaderWs(data) {
  const view = new DataView(data.buffer);
  const addonLen = data[17];
  const portOffset = 18 + addonLen + 1;
  const remotePort = view.getUint16(portOffset);
  const addressType = data[portOffset + 2];
  let addressOffset = portOffset + 3;
  let remoteHost = '';

  switch (addressType) {
    case 1: // IPv4
      remoteHost = Array.from(data.slice(addressOffset, addressOffset + 4)).join('.');
      addressOffset += 4;
      break;
    case 2: // Domain
      const len = data[addressOffset];
      remoteHost = new TextDecoder().decode(data.slice(addressOffset + 1, addressOffset + 1 + len));
      addressOffset += 1 + len;
      break;
    case 3: // IPv6
      remoteHost = `[${Array.from({ length: 8 }, (_, i) => view.getUint16(addressOffset + i * 2).toString(16)).join(':')}]`;
      addressOffset += 16;
      break;
    default:
      throw new Error(`Invalid address type: ${addressType}`);
  }

  return { remoteHost, remotePort, initialData: data.slice(addressOffset) };
}

async function proxyPipelineWs(ws, tcp, initialData) {
  const writer = tcp.writable.getWriter();
  ws.send(VLESS_RESPONSE_HEADER);
  if (initialData && initialData.byteLength > 0) {
    await writer.write(initialData);
  }

  ws.addEventListener('message', e => {
    if (e.data instanceof ArrayBuffer) {
      writer.write(e.data).catch(() => {});
    }
  });

  try {
    for await (const chunk of tcp.readable) {
      ws.send(chunk);
    }
  } catch (err) {
    // console.error("TCP read error:", err);
  }
  
  ws.close();
  tcp.close().catch(() => {});
  writer.releaseLock();
}


// --- HTTP (POST) 专用 ---

async function readVlessHeaderHttp(reader) {
  let buffer = new Uint8Array(4096);
  let offset = 0;

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }

    if (offset + value.length > buffer.length) {
      const newBuffer = new Uint8Array(buffer.length * 2);
      newBuffer.set(buffer);
      buffer = newBuffer;
    }
    buffer.set(value, offset);
    offset += value.length;

    // 依赖全局的 UUID_BYTES
    if (offset < 24 || !compareArray(buffer.slice(1, 17), UUID_BYTES)) {
      continue;
    }
    
    const addonLen = buffer[17];
    const cmdIndex = 18 + addonLen;
    if (offset < cmdIndex + 4) {
      continue;
    }
    
    const port = (buffer[cmdIndex + 1] << 8) | buffer[cmdIndex + 2];
    const atype = buffer[cmdIndex + 3];
    let hostIndex = cmdIndex + 4;
    let hostLen = 0, remoteHost = '';
    
    switch (atype) {
      case 1:
        hostLen = 4;
        remoteHost = Array.from(buffer.slice(hostIndex, hostIndex + hostLen)).join('.');
        break;
      case 2:
        hostLen = buffer[hostIndex] + 1;
        remoteHost = new TextDecoder().decode(buffer.slice(hostIndex + 1, hostIndex + hostLen));
        break;
      case 3:
        hostLen = 16;
        remoteHost = `[${Array.from({ length: 8 }, (_, i) => new DataView(buffer.buffer, hostIndex).getUint16(i * 2).toString(16)).join(':')}]`;
        break;
      default:
        continue;
    }

    const headerLen = hostIndex + hostLen;
    if (offset < headerLen) {
      continue;
    }
    
    const initialPayload = buffer.slice(headerLen, offset);
    const uploadStream = new ReadableStream({
      start(controller) {
        if (initialPayload.length > 0) {
          controller.enqueue(initialPayload);
        }
        (async () => {
          while (true) {
            try {
              const { value, done } = await reader.read();
              if (done) {
                controller.close();
                break;
              }
              controller.enqueue(value);
            } catch (err) {
              controller.error(err);
              break;
            }
          }
        })();
      },
      cancel() {
        reader.cancel();
      }
    });

    return { remoteHost, remotePort: port, uploadStream };
  }
  return null;
}

function createDownloaderHttp(remoteReadable) {
  const stream = new TransformStream({
    start(controller) {
      controller.enqueue(VLESS_RESPONSE_HEADER);
    }
  });
  remoteReadable.pipeTo(stream.writable).catch(() => {});
  return stream.readable;
}

// --- 订阅与链接生成 ---

function generateSubscription(hostname) {
  const wsLink = generateWsLink(hostname);
  const xhttpLink = generateXhttpLink(hostname);
  
  const subscriptionContent = [wsLink, xhttpLink].join('\n');
  const base64Subscription = btoa(subscriptionContent);
  
  return new Response(base64Subscription, {
    headers: { 'Content-Type': 'text/plain;charset=utf-8' }
  });
}

function generateWsLink(host) {
  const params = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: host,
    type: 'ws',
    host: host,
    path: CONFIG.VLESS_PATH
  });
  
  const nodeName = encodeURIComponent(CONFIG.NODE_NAME + '-WS');
  
  return `vless://${CONFIG.UUID}@${host}:443?${params.toString()}#${nodeName}`;
}

function generateXhttpLink(host) {
  const params = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: host,
    type: 'xhttp',
    host: host,
    path: CONFIG.VLESS_PATH,
    mode: 'stream-one'
  });

  const nodeName = encodeURIComponent(CONFIG.NODE_NAME + '-XHTTP');

  return `vless://${CONFIG.UUID}@${host}:443?${params.toString()}#${nodeName}`;
}