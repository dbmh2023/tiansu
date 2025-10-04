// =================== 固定UUID ===================
const FIXED_UUID = '6ffa85ff-4c3e-449d-a603-a0cedd379a2b';


// =================== 主要入口 ===================
export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      let socks5Address = '';
      let parsedSocks5Address = {};
      let enableSocks = false;
      let enableGlobalSocks = false;
      let ProxyIP = '';
      let ProxyPort = 443;
      let Nat64 = '';
      const pathParams = parsePathParams(url.pathname);
      const ipParam = url.searchParams.get('ip') || pathParams.ip;
      if (ipParam) {
        const parsed = parseProxyAddress(ipParam);
        ProxyIP = parsed.address;
        ProxyPort = parsed.port;
      }
      Nat64 = url.searchParams.get('nat64') || pathParams.nat64;
      const s5Param = pathParams.s5 || url.searchParams.get('s5');
      const gs5Param = pathParams.gs5 || url.searchParams.get('gs5');

      if (s5Param) {
        try {
          parsedSocks5Address = socks5AddressParser(s5Param);
          enableSocks = true;
        } catch (err) {
          enableSocks = false;
        }
      }

      if (gs5Param) {
        try {
          parsedSocks5Address = socks5AddressParser(gs5Param);
          enableGlobalSocks = true;
        } catch (err) {
          enableGlobalSocks = false;
        }
      }
      // 检查是否为 WebSocket 升级请求
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader !== 'websocket') {
        // 非 WebSocket 请求，直接返回200空响应
        return new Response('', { status: 400 });
      }
      
      return await handleVLESSWebSocket(request, {
        parsedSocks5Address,
        enableSocks,
        enableGlobalSocks,
        ProxyIP,
        ProxyPort,
        Nat64
      });
    } catch (err) {
      return new Response(err && err.stack ? err.stack : String(err), { status: 500 });
    }
  },
};

async function handleVLESSWebSocket(request, config) {
  const {
    parsedSocks5Address,
    enableSocks,
    enableGlobalSocks,
    ProxyIP,
    ProxyPort,
    Nat64
  } = config;
  const wsPair = new WebSocketPair();
  const [clientWS, serverWS] = Object.values(wsPair);

  serverWS.accept();

  // WebSocket心跳机制，每10秒发送一次ping
  let heartbeatInterval = setInterval(() => {
    if (serverWS.readyState === WS_READY_STATE_OPEN) {
      try {
        serverWS.send('ping');
      } catch (e) {}
    }
  }, 10000);
  function clearHeartbeat() {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
    }
  }
  serverWS.addEventListener('close', clearHeartbeat);
  serverWS.addEventListener('error', clearHeartbeat);

  // 处理 WebSocket 数据流
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const wsReadable = createWebSocketReadableStream(serverWS, earlyDataHeader);
  let remoteSocket = null;
  let udpStreamWrite = null;
  let isDns = false;

  wsReadable.pipeTo(new WritableStream({
    async write(chunk) {
      if (isDns && udpStreamWrite) {
        return udpStreamWrite(chunk);
      }
      if (remoteSocket) {
        try {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
        } catch (err) {
          closeSocket(remoteSocket);
          throw err;
        }
        return;
      }
      const result = parseVLESSHeader(chunk);
      if (result.hasError) {
        throw new Error(result.message);
      }
      const vlessRespHeader = new Uint8Array([result.vlessVersion[0], 0]);
      const rawClientData = chunk.slice(result.rawDataIndex);
      if (result.isUDP) {
        if (result.portRemote === 53) {
          isDns = true;
          const { write } = await handleUDPOutBound(serverWS, vlessRespHeader);
          udpStreamWrite = write;
          udpStreamWrite(rawClientData);
          return;
        } else {
          throw new Error('UDP代理仅支持DNS(端口53)');
        }
      }
      async function connectAndWrite(address, port) {
        const tcpSocket = await connect({ hostname: address, port: port }, { allowHalfOpen: true });
        remoteSocket = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
      }
      async function connectAndWriteSocks(address, port) {
        const tcpSocket = await socks5Connect(result.addressType, address, port, parsedSocks5Address);
        remoteSocket = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
      }
      async function retry() {
        try {
          let tcpSocket;
          if (enableSocks) {
            tcpSocket = await socks5Connect(result.addressType, result.addressRemote, result.portRemote, parsedSocks5Address);
          } else {
            const proxyConfig = await getProxyConfiguration(request.cf && request.cf.colo, result.addressRemote, result.portRemote, ProxyIP, ProxyPort, Nat64);
            tcpSocket = await connect({ hostname: proxyConfig.ip, port: proxyConfig.port }, { allowHalfOpen: true });
          }
          remoteSocket = tcpSocket;
          const writer = tcpSocket.writable.getWriter();
          await writer.write(rawClientData);
          writer.releaseLock();
          tcpSocket.closed.catch(() => {}).finally(() => {
            if (serverWS.readyState === WS_READY_STATE_OPEN) {
              serverWS.close(1000, '连接已关闭');
            }
          });
          pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, null);
        } catch (err) {
          closeSocket(remoteSocket);
          serverWS.close(1011, '代理连接失败: ' + (err && err.message ? err.message : err));
        }
      }
      try {
        if (enableGlobalSocks) {
          const tcpSocket = await connectAndWriteSocks(result.addressRemote, result.portRemote);
          pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, retry);
        } else {
          const tcpSocket = await connectAndWrite(result.addressRemote, result.portRemote);
          pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, retry);
        }
      } catch (err) {
        closeSocket(remoteSocket);
        serverWS.close(1011, '连接失败: ' + (err && err.message ? err.message : err));
      }
    },
    close() {
      if (remoteSocket) {
        closeSocket(remoteSocket);
      }
    }
  })).catch(err => {
    closeSocket(remoteSocket);
    serverWS.close(1011, '内部错误: ' + (err && err.message ? err.message : err));
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWS,
  });
}

function createWebSocketReadableStream(ws, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener('message', event => {
        controller.enqueue(event.data);
      });

      ws.addEventListener('close', () => {
        controller.close();
      });

      ws.addEventListener('error', err => {
        controller.error(err);
      });

      if (earlyDataHeader) {
        try {
          const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
          const data = Uint8Array.from(decoded, c => c.charCodeAt(0));
          controller.enqueue(data.buffer);
        } catch (e) {
        }
      }
    }
  });
}

// 只允许固定UUID
function parseVLESSHeader(buffer) {
  if (buffer.byteLength < 24) {
    return { hasError: true, message: '无效的头部长度' };
  }
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));
  const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
  if (uuid !== FIXED_UUID) {
    return { hasError: true, message: '无效的用户' };
  }
  const optionsLength = view.getUint8(17);
  const command = view.getUint8(18 + optionsLength);
  let isUDP = false;
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: '不支持的命令，仅支持TCP(01)和UDP(02)' };
  }
  let offset = 19 + optionsLength;
  const port = view.getUint16(offset);
  offset += 2;
  const addressType = view.getUint8(offset++);
  let address = '';
  switch (addressType) {
    case 1:
      address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
      offset += 4;
      break;
    case 2:
      const domainLength = view.getUint8(offset++);
      address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
      offset += domainLength;
      break;
    case 3:
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(view.getUint16(offset).toString(16).padStart(4, '0'));
        offset += 2;
      }
      address = ipv6.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
      break;
    default:
      return { hasError: true, message: '不支持的地址类型' };
  }
  return {
    hasError: false,
    addressRemote: address,
    portRemote: port,
    rawDataIndex: offset,
    vlessVersion: version,
    isUDP,
    addressType
  };
}

function pipeRemoteToWebSocket(remoteSocket, ws, vlessHeader, retry = null) {
  let headerSent = false;
  let hasIncomingData = false;

  remoteSocket.readable.pipeTo(new WritableStream({
    write(chunk) {
      hasIncomingData = true;
      if (ws.readyState === WS_READY_STATE_OPEN) {
        if (!headerSent) {
          const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
          combined.set(new Uint8Array(vlessHeader), 0);
          combined.set(new Uint8Array(chunk), vlessHeader.byteLength);
          ws.send(combined.buffer);
          headerSent = true;
        } else {
          ws.send(chunk);
        }
      }
    },
    close() {
      if (!hasIncomingData && retry) {
        retry();
        return;
      }
      if (ws.readyState === WS_READY_STATE_OPEN) {
        ws.close(1000, '正常关闭');
      }
    },
    abort() {
      closeSocket(remoteSocket);
    }
  })).catch(err => {
    closeSocket(remoteSocket);
    if (ws.readyState === WS_READY_STATE_OPEN) {
      ws.close(1011, '数据传输错误');
    }
  });
}

function closeSocket(socket) {
  if (socket) {
    try {
      socket.close();
    } catch (e) {
    }
  }
}

function formatUUID(bytes) {
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function socks5AddressParser(address) {
  let [latter, former] = address.split("@").reverse();
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(":");
    if (formers.length !== 2) {
      throw new Error('Invalid SOCKS address format');
    }
    [username, password] = formers;
  }
  const latters = latter.split(":");
  port = Number(latters.pop());
  if (isNaN(port)) {
    throw new Error('Invalid SOCKS address format');
  }
  hostname = latters.join(":");
  const regex = /^\[.*\]$/;
  if (hostname.includes(":") && !regex.test(hostname)) {
    throw new Error('Invalid SOCKS address format');
  }
  return {
    username,
    password,
    hostname,
    port,
  }
}

// 修正socks5Connect函数，不再引用parsedSocks5Address
async function socks5Connect(addressType, addressRemote, portRemote, socks5Address) {
  const { username, password, hostname, port } = socks5Address;
  const socket = connect({
    hostname,
    port,
  });
  const socksGreeting = new Uint8Array([5, 2, 0, 2]);
  const writer = socket.writable.getWriter();
  await writer.write(socksGreeting);
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (res[0] !== 0x05) {
    throw new Error(`socks server version error: ${res[0]} expected: 5`);
  }
  if (res[1] === 0xff) {
    throw new Error("no acceptable methods");
  }
  if (res[1] === 0x02) {
    if (!username || !password) {
      throw new Error("please provide username/password");
    }
    const authRequest = new Uint8Array([
      1,
      username.length,
      ...encoder.encode(username),
      password.length,
      ...encoder.encode(password)
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 0x01 || res[1] !== 0x00) {
      throw new Error("fail to auth socks server");
    }
  }
  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array(
        [1, ...addressRemote.split('.').map(Number)]
      );
      break;
    case 2:
      DSTADDR = new Uint8Array(
        [3, addressRemote.length, ...encoder.encode(addressRemote)]
      );
      break;
    case 3:
      DSTADDR = new Uint8Array(
        [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
      );
      break;
    default:
      throw new Error(`invalid addressType is ${addressType}`);
  }
  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (res[1] === 0x00) {
  } else {
    throw new Error("fail to open socks connection");
  }
  writer.releaseLock();
  reader.releaseLock();
  return socket;
}


async function handleUDPOutBound(webSocket, vlessResponseHeader) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {
    },
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(
          chunk.slice(index + 2, index + 2 + udpPacketLength)
        );
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {
    }
  });

  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch('https://1.1.1.1/dns-query',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/dns-message',
          },
          body: chunk,
        })
      const dnsQueryResult = await resp.arrayBuffer();
      const udpSize = dnsQueryResult.byteLength;
      const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

      if (webSocket.readyState === WS_READY_STATE_OPEN) {
        if (isVlessHeaderSent) {
          webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
        } else {
          webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
          isVlessHeaderSent = true;
        }
      }
    }
  })).catch((error) => {
  });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    }
  };
}

// ========== 必要常量和依赖 ==========
const WS_READY_STATE_OPEN = 1;
import { connect } from 'cloudflare:sockets';
function parsePathParams(pathname) {
  const params = {};
  const decodedPathname = decodeURIComponent(pathname);
  const ipMatch = decodedPathname.match(/(?:\/[^\/]*)?\/?ip=([^\/]+)(?:\/|$)/);
  const nat64Match = decodedPathname.match(/(?:\/[^\/]*)?\/?nat64=([^\/]+)(?:\/|$)/);
  const pathMatch = decodedPathname.match(/(?:\/[^\/]*)?\/?path=([^\/]+)(?:\/|$)/);
  const s5Match = decodedPathname.match(/(?:\/[^\/]*)?\/?s5=([^\/]+)(?:\/|$)/);
  const gs5Match = decodedPathname.match(/(?:\/[^\/]*)?\/?gs5=([^\/]+)(?:\/|$)/);
  if (ipMatch) params.ip = decodeURIComponent(ipMatch[1]);
  if (nat64Match) params.nat64 = decodeURIComponent(nat64Match[1]);
  if (pathMatch) params.path = decodeURIComponent(pathMatch[1]);
  if (s5Match) params.s5 = decodeURIComponent(s5Match[1]);
  if (gs5Match) params.gs5 = decodeURIComponent(gs5Match[1]);
  return params;
}

function parseProxyAddress(address) {
  if (!address) return { address: address, port: 443 };
  if (address.startsWith('[')) {
    const closeBracketIndex = address.indexOf(']');
    if (closeBracketIndex !== -1) {
      const ipv6Part = address.substring(0, closeBracketIndex + 1);
      const remaining = address.substring(closeBracketIndex + 1);
      if (remaining.startsWith(':')) {
        const port = parseInt(remaining.substring(1));
        if (!isNaN(port) && port > 0 && port <= 65535) {
          return { address: ipv6Part, port: port };
        }
      }
      return { address: ipv6Part, port: 443 };
    }
  }
  const colonIndex = address.lastIndexOf(':');
  if (colonIndex > 0) {
    const addressPart = address.substring(0, colonIndex);
    const portPart = address.substring(colonIndex + 1);
    const port = parseInt(portPart);
    if (!isNaN(port) && port > 0 && port <= 65535) {
      return { address: addressPart, port: port };
    }
  }
  return { address: address, port: 443 };
}

async function getProxyConfiguration(colo, addressRemote, portRemote, ProxyIP, ProxyPort, Nat64) {
  return { ip: ProxyIP || addressRemote, port: ProxyPort || portRemote };
}