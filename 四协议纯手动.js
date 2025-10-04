/*
代码基本都抄的CM和天书大佬的项目，在此感谢各位大佬的无私奉献。
支持xhttp和trojan和vless和ss协议,ss协议无密码
路径可写可不写?, 同时写s5和proxyall相当于写gs5，http同理，只写proxyall为纯直连模式，支持的参数：ip，proxyip，pyip，socks5，s5，gs5，s5all，http，ghttp，httpall，proxyall，globalproxy
ipv6地址需要[ipv6]
有proxyall参数即为全局代理，如果只写proxyall为全走直连，同时写了socks5和http时socks5优先
*/
import {connect} from 'cloudflare:sockets';
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';//vless使用的uuid
const password = '666';//trojan使用的密码
const concurrentOnlyDomain = false;//只对域名并发开关
const concurrency = 4;//socket获取并发数
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohFetchOptions = {method: 'POST', headers: {'content-type': 'application/dns-message'}};
const proxyIpAddrs = {EU: 'ProxyIP.GB.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};//分区域proxyip
const finallyProxyHost = 'ProxyIP.CMLiussss.net';//兜底proxyip
const coloRegions = {
    JP: new Set(['FUK', 'ICN', 'KIX', 'NRT', 'OKA']),
    EU: new Set([
        'ACC', 'ADB', 'ALA', 'ALG', 'AMM', 'AMS', 'ARN', 'ATH', 'BAH', 'BCN', 'BEG', 'BGW', 'BOD', 'BRU', 'BTS', 'BUD', 'CAI',
        'CDG', 'CPH', 'CPT', 'DAR', 'DKR', 'DMM', 'DOH', 'DUB', 'DUR', 'DUS', 'DXB', 'EBB', 'EDI', 'EVN', 'FCO', 'FRA', 'GOT',
        'GVA', 'HAM', 'HEL', 'HRE', 'IST', 'JED', 'JIB', 'JNB', 'KBP', 'KEF', 'KWI', 'LAD', 'LED', 'LHR', 'LIS', 'LOS', 'LUX',
        'LYS', 'MAD', 'MAN', 'MCT', 'MPM', 'MRS', 'MUC', 'MXP', 'NBO', 'OSL', 'OTP', 'PMO', 'PRG', 'RIX', 'RUH', 'RUN', 'SKG',
        'SOF', 'STR', 'TBS', 'TLL', 'TLV', 'TUN', 'VIE', 'VNO', 'WAW', 'ZAG', 'ZRH']),
    AS: new Set([
        'ADL', 'AKL', 'AMD', 'BKK', 'BLR', 'BNE', 'BOM', 'CBR', 'CCU', 'CEB', 'CGK', 'CMB', 'COK', 'DAC', 'DEL', 'HAN', 'HKG',
        'HYD', 'ISB', 'JHB', 'JOG', 'KCH', 'KHH', 'KHI', 'KTM', 'KUL', 'LHE', 'MAA', 'MEL', 'MFM', 'MLE', 'MNL', 'NAG', 'NOU',
        'PAT', 'PBH', 'PER', 'PNH', 'SGN', 'SIN', 'SYD', 'TPE', 'ULN', 'VTE'])
};
const coloToProxyMap = new Map(Object.entries(coloRegions).flatMap(([region, colos]) => Array.from(colos, colo => [colo, proxyIpAddrs[region]])));
const uuidToBytes = new Uint8Array(uuid.replace(/-/g, '').match(/.{2}/g).map(byte => parseInt(byte, 16)));
const [uuidPart1, uuidPart2] = [new DataView(uuidToBytes.buffer).getBigUint64(0), new DataView(uuidToBytes.buffer).getBigUint64(8)];
const expectedHash = sha224Hash(password);
const expectedHashBytes = new TextEncoder().encode(expectedHash);
const [textEncoder, textDecoder, socks5Init, httpHeaderEnd] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2]), new Uint8Array([13, 10, 13, 10])];
const html = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
function sha224Hash(message) {
    const kConstants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
        0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
        0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
        0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const toUtf8 = (str) => {return unescape(encodeURIComponent(str))};
    const bytesToHex = (byteArray) => {
        let hexString = '';
        for (let i = 0; i < byteArray.length; i++) {
            hexString += ((byteArray[i] >>> 4) & 0x0F).toString(16);
            hexString += (byteArray[i] & 0x0F).toString(16);
        }
        return hexString;
    };
    const computeHash = (inputStr) => {
        let hState = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ];
        const messageBitLength = inputStr.length * 8;
        inputStr += String.fromCharCode(0x80);
        while ((inputStr.length * 8) % 512 !== 448) {inputStr += String.fromCharCode(0)}
        const highBits = Math.floor(messageBitLength / 0x100000000);
        const lowBits = messageBitLength & 0xFFFFFFFF;
        inputStr += String.fromCharCode(
            (highBits >>> 24) & 0xFF, (highBits >>> 16) & 0xFF, (highBits >>> 8) & 0xFF, highBits & 0xFF,
            (lowBits >>> 24) & 0xFF, (lowBits >>> 16) & 0xFF, (lowBits >>> 8) & 0xFF, lowBits & 0xFF
        );
        const words = [];
        for (let i = 0; i < inputStr.length; i += 4) {
            words.push((inputStr.charCodeAt(i) << 24) | (inputStr.charCodeAt(i + 1) << 16) | (inputStr.charCodeAt(i + 2) << 8) | inputStr.charCodeAt(i + 3));
        }
        for (let i = 0; i < words.length; i += 16) {
            const w = new Array(64);
            for (let j = 0; j < 16; j++) {
                w[j] = words[i + j];
            }
            for (let j = 16; j < 64; j++) {
                const s0 = rotateRight(w[j - 15], 7) ^ rotateRight(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                const s1 = rotateRight(w[j - 2], 17) ^ rotateRight(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
            }
            let [a, b, c, d, e, f, g, h] = hState;
            for (let j = 0; j < 64; j++) {
                const S1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (h + S1 + ch + kConstants[j] + w[j]) >>> 0;
                const S0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) >>> 0;
                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }
            hState[0] = (hState[0] + a) >>> 0;
            hState[1] = (hState[1] + b) >>> 0;
            hState[2] = (hState[2] + c) >>> 0;
            hState[3] = (hState[3] + d) >>> 0;
            hState[4] = (hState[4] + e) >>> 0;
            hState[5] = (hState[5] + f) >>> 0;
            hState[6] = (hState[6] + g) >>> 0;
            hState[7] = (hState[7] + h) >>> 0;
        }
        return hState.slice(0, 7);
    };
    const rotateRight = (value, shift) => {return ((value >>> shift) | (value << (32 - shift))) >>> 0};
    const utf8Message = toUtf8(message);
    const hashWords = computeHash(utf8Message);
    return bytesToHex(hashWords.flatMap(h => [(h >>> 24) & 0xFF, (h >>> 16) & 0xFF, (h >>> 8) & 0xFF, h & 0xFF]));
}
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) {
        return textDecoder.decode(addrBytes);
    } else if (addrType === 1) {
        return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    } else if (addrType === 4) {
        const view = new DataView(addrBytes.buffer, addrBytes.byteOffset, addrBytes.byteLength);
        let result = view.getUint16(0).toString(16);
        for (let i = 1; i < 8; i++) result += ':' + view.getUint16(i * 2).toString(16);
        return `[${result}]`;
    }
};
const parseHostPort = (addr, defaultPort) => {
    if (addr.startsWith('[')) {
        const sepIndex = addr.indexOf(']:');
        if (sepIndex !== -1) {
            const host = addr.substring(0, sepIndex + 1);
            const portStr = addr.substring(sepIndex + 2);
            const port = parseInt(portStr, 10);
            if (!isNaN(port)) return [host, port];
        }
        return [addr, defaultPort];
    }
    const tpIndex = addr.indexOf('.tp');
    const lastColon = addr.lastIndexOf(':');
    if (tpIndex !== -1 && lastColon === -1) {
        const portStartIndex = tpIndex + 3;
        let portEndIndex = portStartIndex;
        while (portEndIndex < addr.length && addr.charCodeAt(portEndIndex) >= 48 && addr.charCodeAt(portEndIndex) <= 57) portEndIndex++;
        if (portEndIndex > portStartIndex) return [addr, parseInt(addr.substring(portStartIndex, portEndIndex), 10)];
    }
    if (lastColon === -1) return [addr, defaultPort];
    const host = addr.substring(0, lastColon);
    const port = parseInt(addr.substring(lastColon + 1), 10);
    return !isNaN(port) ? [host, port] : [addr, defaultPort];
};
const parseAuthString = (authParam) => {
    let username = '', password = '', hostStr;
    const atIndex = authParam.lastIndexOf('@');
    if (atIndex === -1) {hostStr = authParam} else {
        const cred = authParam.substring(0, atIndex);
        hostStr = authParam.substring(atIndex + 1);
        const colonIndex = cred.indexOf(':');
        if (colonIndex === -1) {username = cred} else {
            username = cred.substring(0, colonIndex);
            password = cred.substring(colonIndex + 1);
        }
    }
    const [hostname, port] = parseHostPort(hostStr, 1080);
    return {username, password, hostname, port};
};
const isIPv4optimized = (str) => {
    if (str.length > 15 || str.length < 7) return false;
    let part = 0, dots = 0, partLen = 0;
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i);
        if (charCode === 46) {
            dots++;
            if (dots > 3 || partLen === 0 || (str.charCodeAt(i - 1) === 48 && partLen > 1)) return false;
            part = 0;
            partLen = 0;
        } else if (charCode >= 48 && charCode <= 57) {
            partLen++;
            part = part * 10 + (charCode - 48);
            if (part > 255 || partLen > 3) return false;
        } else {return false}
    }
    return !(dots !== 3 || partLen === 0 || (str.charCodeAt(str.length - partLen) === 48 && partLen > 1));
};
const isDomainName = (inputStr) => {
    if (!concurrentOnlyDomain) return true;
    if (!inputStr || inputStr[0] === '[') return false;
    if (inputStr[0].charCodeAt(0) < 48 || inputStr[0].charCodeAt(0) > 57) return true;
    return !isIPv4optimized(inputStr);
};
const concurrentConnect = async (hostname, port, addrType) => {
    if (concurrentOnlyDomain && addrType !== 3) {
        const socket = connect({hostname, port});
        return socket.opened.then(() => socket);
    }
    const socketPromises = Array(concurrency).fill(null).map(async () => {
        const socket = connect({hostname, port});
        return socket.opened.then(() => socket);
    });
    return await Promise.any(socketPromises);
};
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, targetAddrBytes) => {
    const addrType = isDomainName(socksAuth.hostname) ? 3 : 0;
    const socksSocket = await concurrentConnect(socksAuth.hostname, socksAuth.port, addrType);
    const writer = socksSocket.writable.getWriter();
    const reader = socksSocket.readable.getReader();
    try {
        await writer.write(socks5Init);
        const {value: authMethodResponse} = await reader.read();
        if (!authMethodResponse || authMethodResponse[0] !== 5 || authMethodResponse[1] === 0xFF) return null;
        if (authMethodResponse[1] === 2) {
            if (!socksAuth.username) return null;
            const userBytes = textEncoder.encode(socksAuth.username);
            const passBytes = textEncoder.encode(socksAuth.password || '');
            await writer.write(new Uint8Array([1, userBytes.length, ...userBytes, passBytes.length, ...passBytes]));
            const {value: authResult} = await reader.read();
            if (!authResult || authResult[0] !== 1 || authResult[1] !== 0) return null;
        } else if (authMethodResponse[1] !== 0) {return null}
        await writer.write(new Uint8Array([
            5, 1, 0, targetAddrType,
            ...(targetAddrType === 3 ? [targetAddrBytes.length] : []),
            ...targetAddrBytes,
            targetPortNum >> 8,
            targetPortNum & 0xff
        ]));
        const {value: finalResponse} = await reader.read();
        if (!finalResponse || finalResponse[1] !== 0) return null;
        return socksSocket;
    } finally {
        writer.releaseLock();
        reader.releaseLock();
    }
};
const findSequence = (chunks) => {
    const seqLen = httpHeaderEnd.length;
    if (seqLen === 0) return 0;
    let totalLen = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    if (totalLen < seqLen) return -1;
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
    }
    for (let i = 0; i <= combined.length - seqLen; i++) {
        let found = true;
        for (let j = 0; j < seqLen; j++) {
            if (combined[i + j] !== httpHeaderEnd[j]) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return -1;
};
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, targetAddrBytes) => {
    const {username, password, hostname, port} = httpAuth;
    const addrType = isDomainName(hostname) ? 3 : 0;
    const proxySocket = await concurrentConnect(hostname, port, addrType);
    const writer = proxySocket.writable.getWriter();
    const httpHost = binaryAddrToString(targetAddrType, targetAddrBytes);
    const requestHeaders = [`CONNECT ${httpHost}:${targetPortNum} HTTP/1.1`, `Host: ${httpHost}:${targetPortNum}`];
    if (username) requestHeaders.push(`Proxy-Authorization: Basic ${btoa(`${username}:${password || ''}`)}`);
    requestHeaders.push('Proxy-Connection: Keep-Alive', 'Connection: Keep-Alive', '\r\n');
    await writer.write(textEncoder.encode(requestHeaders.join('\r\n')));
    writer.releaseLock();
    const reader = proxySocket.readable.getReader();
    const chunks = [];
    let headerFound = false;
    try {
        while (!headerFound) {
            const {value, done} = await reader.read();
            if (done) break;
            chunks.push(value);
            if (findSequence(chunks) !== -1) headerFound = true;
        }
        if (!headerFound) {
            await proxySocket.close();
            return null;
        }
        let totalLen = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
        const combined = new Uint8Array(totalLen);
        let offset = 0;
        for (const chunk of chunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
        }
        const responseStr = textDecoder.decode(combined.subarray(0, 20));
        if (!responseStr.startsWith('HTTP/1.1 200') && !responseStr.startsWith('HTTP/1.0 200')) {
            await proxySocket.close();
            return null;
        }
        reader.releaseLock();
        return proxySocket;
    } catch {
        reader.releaseLock();
        await proxySocket.close();
        return null;
    }
};
const parseAddressAndPort = (buffer, offset, addrType) => {
    let addressLength;
    if (addrType === 3) {
        addressLength = buffer[offset++];
    } else if (addrType === 1) {
        addressLength = 4;
    } else if (addrType === 4) {
        addressLength = 16;
    } else {return null}
    const newOffset = offset + addressLength;
    if (newOffset > buffer.length) return null;
    const targetAddrBytes = buffer.subarray(offset, newOffset);
    return {targetAddrBytes, dataOffset: newOffset};
};
const parseRequestData = (firstChunk) => {
    const dataView = new DataView(firstChunk.buffer);
    if (dataView.getBigUint64(1) !== uuidPart1 || dataView.getBigUint64(9) !== uuidPart2) return null;
    let offset = 17 + firstChunk[17] + 1;
    const command = firstChunk[offset++];
    const port = dataView.getUint16(offset);
    if (command !== 1 && port !== 53) return null;
    offset += 2;
    let addrType = firstChunk[offset++];
    if (addrType === 2 || addrType === 3) addrType += 1;
    const addressInfo = parseAddressAndPort(firstChunk, offset, addrType);
    if (!addressInfo) return null;
    return {addrType, ...addressInfo, port, isDns: port === 53};
};
const parseTransparent = (firstChunk) => {
    const dataView = new DataView(firstChunk.buffer);
    for (let i = 0; i < 56; i++) {if (firstChunk[i] !== expectedHashBytes[i]) return null}
    let offset = 58;
    if (firstChunk[offset++] !== 1) return null;
    const addrType = firstChunk[offset++];
    const addressInfo = parseAddressAndPort(firstChunk, offset, addrType);
    if (!addressInfo) return null;
    const port = dataView.getUint16(addressInfo.dataOffset);
    return {addrType, ...addressInfo, port, dataOffset: addressInfo.dataOffset + 4, isDns: port === 53};
};
const parseShadow = (firstChunk) => {
    const dataView = new DataView(firstChunk.buffer);
    const addrType = dataView.getUint8(0);
    let offset = 1;
    const addressInfo = parseAddressAndPort(firstChunk, offset, addrType);
    if (!addressInfo) return null;
    const port = dataView.getUint16(addressInfo.dataOffset);
    return {addrType, ...addressInfo, port, dataOffset: addressInfo.dataOffset + 2, isDns: port === 53};
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, targetAddrBytes}) => {
        const hostname = binaryAddrToString(addrType, targetAddrBytes);
        return concurrentConnect(hostname, port, addrType);
    }],
    [1, async ({addrType, port, targetAddrBytes}, param) => {
        const socksAuth = parseAuthString(param);
        return connectViaSocksProxy(addrType, port, socksAuth, targetAddrBytes);
    }],
    [2, async ({addrType, port, targetAddrBytes}, param) => {
        const httpAuth = parseAuthString(param);
        return connectViaHttpProxy(addrType, port, httpAuth, targetAddrBytes);
    }],
    [3, async (_parsedRequest, _param, {proxyHost, proxyPort}) => {
        const addrType = isDomainName(proxyHost) ? 3 : 0;
        return concurrentConnect(proxyHost, proxyPort, addrType);
    }],
    [4, async (_parsedRequest, _param, _proxyHost) => {
        return concurrentConnect(finallyProxyHost, 443, 3);
    }]
]);
const parseQueryString = (query) => {
    const params = new Map();
    if (!query) return params;
    let startIndex = 0;
    query = query.replaceAll('%26', '&');
    while (startIndex < query.length) {
        let endIndex = query.indexOf('&', startIndex);
        if (endIndex === -1) endIndex = query.length;
        const pair = query.substring(startIndex, endIndex);
        if (pair) {
            const decodedPair = decodeURIComponent(pair);
            const eqIndex = decodedPair.indexOf('=');
            if (eqIndex === -1) {
                params.set(decodedPair, "");
            } else {
                params.set(
                    decodedPair.substring(0, eqIndex),
                    decodedPair.substring(eqIndex + 1)
                );
            }
        }
        startIndex = endIndex + 1;
    }
    return params;
};
const prepareProxyConfig = (request) => {
    let urlString = request.url;
    if (urlString.endsWith('/')) urlString = urlString.slice(0, -1);
    const params = parseQueryString(urlString.match(/^(?:.*?(?:\?|%3F))(.*)$/)?.[1] ?? urlString.split('/').pop());
    const socksParam = params.get('socks5') ?? params.get('s5') ?? params.get('gs5') ?? params.get('s5all');
    const httpParam = params.get('http') ?? params.get('ghttp') ?? params.get('httpall');
    const proxyAll = params.has('proxyall') || params.has('gs5') || params.has('s5all') || params.has('ghttp') || params.has('httpall') || params.has('globalproxy');
    const connectionStrategies = [];
    const mapToStrategies = (param, type) => {
        if (!param) return [];
        return param.split(',').filter(Boolean).map(p => ({type, param: p.trim()}));
    };
    if (proxyAll) {
        connectionStrategies.push(...mapToStrategies(socksParam, 1));
        connectionStrategies.push(...mapToStrategies(httpParam, 2));
        if (connectionStrategies.length === 0) connectionStrategies.push({type: 0});
    } else {
        connectionStrategies.push({type: 0});
        connectionStrategies.push(...mapToStrategies(socksParam, 1));
        connectionStrategies.push(...mapToStrategies(httpParam, 2));
        connectionStrategies.push({type: 3});
        connectionStrategies.push({type: 4});
    }
    const proxyString = params.get('proxyip') ?? params.get('pyip') ?? params.get('ip') ?? coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US;
    const [proxyHost, proxyPort] = parseHostPort(proxyString, 443);
    return {connectionStrategies, proxyHost, proxyPort};
};
const dohDnsHandler = async (webSocket, haveEarlyData, payload) => {
    if (payload.byteLength < 2) throw new Error();
    const dnsQueryData = payload.subarray(2);
    const resp = await Promise.any(dohEndpoints.map(endpoint =>
        fetch(endpoint, {...dohFetchOptions, body: dnsQueryData})
            .then(response => {
                if (!response.ok) throw new Error();
                return response;
            })
    ));
    const dnsQueryResult = await resp.arrayBuffer();
    if (webSocket.readyState !== WebSocket.OPEN) throw new Error();
    const udpSize = dnsQueryResult.byteLength;
    const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
    const packet = new Uint8Array(udpSizeBuffer.length + udpSize);
    packet.set(udpSizeBuffer, 0);
    packet.set(new Uint8Array(dnsQueryResult), udpSizeBuffer.length);
    webSocket.send(packet);
    if (!haveEarlyData) webSocket.close();
};
const tcpToWebSocket = async (tcpSocket, webSocket) => {
    for await (const chunk of tcpSocket.readable) {
        if (webSocket.readyState !== WebSocket.OPEN) break;
        if (chunk.byteLength) webSocket.send(chunk);
    }
};
const handleWebSocketConn = async (request) => {
    const {0: clientSocket, 1: webSocket} = new WebSocketPair();
    webSocket.accept();
    const protocolHeader = request.headers.get('sec-websocket-protocol');
    const earlyData = protocolHeader ? Uint8Array.fromBase64(protocolHeader, {alphabet: 'base64url'}) : null;
    const tcpSocketHolder = {value: null};
    let messageHandler = null;
    if (earlyData) {
        await processChunk(earlyData).catch(async () => {
            await tcpSocketHolder.value?.close();
            webSocket?.close();
        });
    }
    webSocket.addEventListener("message", async (event) => {
        await processChunk(event.data).catch(async () => {
            await tcpSocketHolder.value?.close();
            webSocket?.close();
        });
    });
    async function processChunk(chunk) {
        if (messageHandler) return messageHandler(chunk);
        chunk = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        let parsedRequest;
        if (chunk.length > 58 && chunk[56] === 0x0d && chunk[57] === 0x0a) {
            parsedRequest = parseTransparent(chunk);
        } else if ((parsedRequest = parseRequestData(chunk))) {
            webSocket.send(new Uint8Array([chunk[0], 0]));
        } else {parsedRequest = parseShadow(chunk)}
        if (!parsedRequest) throw new Error();
        const payload = chunk.subarray(parsedRequest.dataOffset);
        if (parsedRequest.isDns) {
            await dohDnsHandler(webSocket, !!earlyData, payload);
        } else {
            const {connectionStrategies, proxyHost, proxyPort} = prepareProxyConfig(request);
            let tcpSocket = null;
            for (const strategy of connectionStrategies) {
                const executor = strategyExecutorMap.get(strategy.type);
                if (!executor) continue;
                try {
                    tcpSocket = await executor(parsedRequest, strategy.param, {proxyHost, proxyPort});
                    if (tcpSocket) break;
                } catch {}
            }
            tcpSocketHolder.value = tcpSocket;
            const tcpWriter = tcpSocket.writable.getWriter();
            if (payload.byteLength) await tcpWriter.write(payload);
            tcpToWebSocket(tcpSocket, webSocket);
            messageHandler = (chunk) => tcpWriter.write(chunk);
        }
    }
    return new Response(null, {status: 101, webSocket: clientSocket});
};
const parseXhttpRequestData = async (reader) => {
    let capacity = 4096;
    let buffer = new Uint8Array(capacity);
    let used = 0;
    while (true) {
        const {value, done} = await reader.read();
        if (done) return null;
        if (used + value.length > capacity) {
            capacity = Math.max(capacity * 2, used + value.length);
            const newBuffer = new Uint8Array(capacity);
            newBuffer.set(buffer.subarray(0, used), 0);
            buffer = newBuffer;
        }
        buffer.set(value, used);
        used += value.length;
        if (used < 48) continue;
        const currentBuffer = buffer.subarray(0, used);
        const dataView = new DataView(buffer.buffer, 0, used);
        if (dataView.getBigUint64(1) !== uuidPart1 || dataView.getBigUint64(9) !== uuidPart2) return null;
        let offset = 18 + currentBuffer[17];
        const command = currentBuffer[offset++];
        const port = dataView.getUint16(offset);
        if (command !== 1) return null;
        offset += 2;
        let addrType = currentBuffer[offset++];
        let requiredLength;
        if (addrType === 2) {
            const domainLen = currentBuffer[offset++];
            requiredLength = offset + domainLen;
            if (used < requiredLength) continue;
            addrType += 1;
        } else if (addrType === 1) {
            requiredLength = offset + 4;
        } else if (addrType === 3) {
            requiredLength = offset + 16;
            addrType += 1;
        } else {return null}
        return {
            addrType,
            port,
            targetAddrBytes: currentBuffer.subarray(offset, requiredLength),
            payload: currentBuffer.subarray(requiredLength),
            reader,
            xhttpResponse: new Uint8Array([currentBuffer[0], 0])
        };
    }
};
const handleXhttp = async (request) => {
    const reader = request.body.getReader();
    const xhttpHeader = await parseXhttpRequestData(reader);
    if (!xhttpHeader) return new Response(null, {status: 500});
    const parsedRequest = {
        addrType: xhttpHeader.addrType,
        port: xhttpHeader.port,
        targetAddrBytes: xhttpHeader.targetAddrBytes
    };
    const {connectionStrategies, proxyHost, proxyPort} = prepareProxyConfig(request);
    let tcpSocket = null;
    for (const strategy of connectionStrategies) {
        const executor = strategyExecutorMap.get(strategy.type);
        if (!executor) continue;
        try {
            tcpSocket = await executor(parsedRequest, strategy.param, {proxyHost, proxyPort});
            if (tcpSocket) break;
        } catch {}
    }
    if (!tcpSocket) return new Response(null, {status: 500});
    const {readable, writable} = new TransformStream();
    const requestToTcp = async () => {
        const writer = tcpSocket.writable.getWriter();
        try {
            if (xhttpHeader.payload.byteLength) await writer.write(xhttpHeader.payload);
            while (true) {
                const {value, done} = await xhttpHeader.reader.read();
                if (done) break;
                await writer.write(value);
            }
        } finally {writer.close()}
    };
    const tcpToResponse = async () => {
        const reader = tcpSocket.readable.getReader();
        const writer = writable.getWriter();
        try {
            await writer.write(xhttpHeader.xhttpResponse);
            while (true) {
                const {value, done} = await reader.read();
                if (done) break;
                await writer.write(value);
            }
        } finally {writer.close()}
    };
    requestToTcp();
    tcpToResponse();
    return new Response(readable, {
        headers: {
            'Content-Type': 'application/octet-stream',
            'X-Accel-Buffering': 'no',
            'Cache-Control': 'no-store'
        }
    });
};
export default {
    async fetch(request) {
        if (request.method === 'POST') {
            return handleXhttp(request);
        } else if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
            return handleWebSocketConn(request);
        } else {
            return new Response(html, {status: 404, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
        }
    }
};