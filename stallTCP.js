import { connect } from 'cloudflare:sockets';
const AUTH_UUID = "2523c510-9ff0-415b-9582-93949bfae7e3";
export default {
  async fetch(req) {
    if (req.headers.get('Upgrade') !== 'websocket') {
      return new Response('Hello World!', { status: 200 });
    }
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    server.accept();
    server.send(new Uint8Array([0, 0]));
    handleConnection(server);
    return new Response(null, { status: 101, webSocket: client });
  }
};
function buildUUID(arr, start) {
  const hex = Array.from(arr.slice(start, start + 16)).map(n => n.toString(16).padStart(2, '0')).join('');
  return hex.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
}
function handleConnection(ws) {
  let socket, writer, reader;
  let isFirstMsg = true;
  let writeQueue = Promise.resolve();
  let readQueue = Promise.resolve();
  let lastActivity = Date.now();
  let lastDataReceived = Date.now();
  let keepaliveTimer = null;
  let healthCheckTimer = null;
  let connectionInfo = null;
  let isReconnecting = false;
  let bytesReceived = 0;
  let reconnectCount = 0;
  const KEEPALIVE_INTERVAL = 20000; // 20秒心跳，更频繁
  const STALL_TIMEOUT = 8000; // 8秒无数据认为stall
  const MAX_STALL_COUNT = 8; // 允许8次stall再重连
  let stallCount = 0;
  ws.addEventListener('message', async (evt) => {
    try {
      if (isFirstMsg) {
        isFirstMsg = false;
        const result = await processHandshake(evt.data);
        socket = result.socket;
        writer = result.writer;
        reader = result.reader;
        connectionInfo = result.info;
        startReading();
        startKeepalive();
        startHealthCheck();
      } else {
        lastActivity = Date.now();
        writeQueue = writeQueue.then(async () => {
          try {
            await writer.write(evt.data);
          } catch (err) {
            console.error('Write error:', err);
            throw err;
          }
        }).catch(() => {
          if (!isReconnecting) {
            setTimeout(() => attemptReconnect(), 100);
          }
        });
      }
    } catch (err) {
      console.error('Connection error:', err);
      cleanup();
      ws.close(1006, 'Connection abnormal');
    }
  });
  async function processHandshake(data) {
    const bytes = new Uint8Array(data);
    const authKey = buildUUID(bytes, 1);
    if (authKey !== AUTH_UUID) {
      throw new Error('Auth failed');
    }
    const addrInfo = extractAddress(bytes);
    const sock = connect({ hostname: addrInfo.host, port: addrInfo.port });
    await sock.opened;
    const w = sock.writable.getWriter();
    const r = sock.readable.getReader();
    if (addrInfo.payload.length > 0) {
      await w.write(addrInfo.payload);
    }
    return {
      socket: sock,
      writer: w,
      reader: r,
      info: { host: addrInfo.host, port: addrInfo.port }
    };
  }
  async function startReading() {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (value && value.length > 0) {
          bytesReceived += value.length;
          lastDataReceived = Date.now();
          lastActivity = Date.now();
          stallCount = 0;
          reconnectCount = 0;
          readQueue = readQueue.then(() => {
            if (ws.readyState === 1) {
              return ws.send(value);
            }
          }).catch(() => {});
        }
        if (done) {
          console.log('Stream ended gracefully');
          await attemptReconnect();
          break;
        }
      }
    } catch (err) {
      console.error('Read error:', err);
      if (!isReconnecting) {
        await attemptReconnect();
      }
    }
  }
  async function attemptReconnect() {
    if (isReconnecting || !connectionInfo || ws.readyState !== 1) {
      return;
    }
    isReconnecting = true;
    reconnectCount++;
    console.log(`Reconnecting (attempt ${reconnectCount})...`);
    try {
      try {
        writer?.releaseLock();
        reader?.releaseLock();
      } catch (e) {}
      try {
        socket?.close();
      } catch (e) {}
      await new Promise(resolve => setTimeout(resolve, 300));
      const sock = connect({
        hostname: connectionInfo.host,
        port: connectionInfo.port
      });
      await sock.opened;
      socket = sock;
      writer = sock.writable.getWriter();
      reader = sock.readable.getReader();
      lastActivity = Date.now();
      lastDataReceived = Date.now();
      stallCount = 0;
      console.log('Reconnected successfully');
      isReconnecting = false;
      startReading();
    } catch (err) {
      console.error('Reconnect failed:', err);
      isReconnecting = false;
      if (ws.readyState === 1 && reconnectCount < 5) {
        setTimeout(() => attemptReconnect(), 1000);
      } else {
        cleanup();
        ws.close(1011, 'Reconnection failed');
      }
    }
  }
  function startKeepalive() {
    keepaliveTimer = setInterval(async () => {
      const idle = Date.now() - lastActivity;
      if (idle > KEEPALIVE_INTERVAL && !isReconnecting) {
        try {
          await writer.write(new Uint8Array(0));
          lastActivity = Date.now();
        } catch (e) {
          console.error('Keepalive failed:', e);
        }
      }
    }, KEEPALIVE_INTERVAL / 2);
  }
  function startHealthCheck() {
    healthCheckTimer = setInterval(() => {
      const timeSinceData = Date.now() - lastDataReceived;
      if (bytesReceived > 0 && timeSinceData > STALL_TIMEOUT && !isReconnecting) {
        stallCount++;
        console.log(`Stall detected (${stallCount}/${MAX_STALL_COUNT}), ${timeSinceData}ms since last data`);
        if (stallCount >= MAX_STALL_COUNT) {
          console.log('Multiple stalls detected, reconnecting...');
          attemptReconnect();
        }
      }
    }, STALL_TIMEOUT / 2);
  }
  function cleanup() {
    if (keepaliveTimer) {
      clearInterval(keepaliveTimer);
      keepaliveTimer = null;
    }
    if (healthCheckTimer) {
      clearInterval(healthCheckTimer);
      healthCheckTimer = null;
    }
    try {
      writer?.releaseLock();
      reader?.releaseLock();
    } catch (e) {}
    try {
      socket?.close();
    } catch (e) {}
  }
  ws.addEventListener('close', cleanup);
  ws.addEventListener('error', cleanup);
}
function extractAddress(bytes) {
  const offset1 = 18 + bytes[17] + 1;
  const port = (bytes[offset1] << 8) | bytes[offset1 + 1];
  const addrType = bytes[offset1 + 2];
  let offset2 = offset1 + 3;
  let length, host;
  switch (addrType) {
    case 1:
      length = 4;
      host = bytes.slice(offset2, offset2 + length).join('.');
      break;
    case 2:
      length = bytes[offset2];
      offset2++;
      host = new TextDecoder().decode(bytes.slice(offset2, offset2 + length));
      break;
    case 3:
      length = 16;
      const segments = [];
      for (let i = 0; i < 8; i++) {
        const seg = (bytes[offset2 + i * 2] << 8) | bytes[offset2 + i * 2 + 1];
        segments.push(seg.toString(16));
      }
      host = `[${segments.join(':')}]`;
      break;
    default:
      throw new Error('Invalid address type.');
  }
  const payload = bytes.slice(offset2 + length);
  return { host, port, payload };
}