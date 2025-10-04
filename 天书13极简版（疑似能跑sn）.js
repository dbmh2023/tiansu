import { connect } from 'cloudflare:sockets';
let 我的VL密钥 = '6ffa85ff-4c3e-449d-a603-a0cedd379a2b';
let 反代IP = 'sjc.o00o.ooo:443';
export default {
  async fetch(访问请求) {
    if (访问请求.headers.get('Upgrade') === 'websocket') {
      const 读取路径 = 访问请求.url.replace(/^https?:\/\/[^/]+/, '');
      反代IP = 读取路径.match(/ip=([^&]+)/)?.[1] || 反代IP;
      const [客户端, WS接口] = Object.values(new WebSocketPair());
      WS接口.accept();
      WS接口.send(new Uint8Array([0, 0]));
      启动传输管道(WS接口);
      return new Response(null, { status: 101, webSocket: 客户端 });
    } else {
      return new Response('Hello World!', { status: 200 });
    }
  }
};
async function 启动传输管道(WS接口, TCP接口) {
  let 识别地址类型, 访问地址, 地址长度, 首包数据 = false, 首包处理完成 = null, 传输数据, 读取数据, 传输队列 = Promise.resolve();
  try {
    WS接口.addEventListener('message', async event => {
      if (!首包数据) {
        首包数据 = true;
        首包处理完成 = 解析首包数据(event.data);
        传输队列 = 传输队列.then(() => 首包处理完成);
      } else {
        await 首包处理完成;
        传输队列 = 传输队列.then(() => 传输数据.write(event.data));
      }
    });
    async function 解析首包数据(首包数据) {
      const 二进制数据 = new Uint8Array(首包数据);
      const 验证VL的密钥 = (a, i = 0) => [...a.slice(i, i + 16)].map(b => b.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
      if (验证VL的密钥(二进制数据.slice(1, 17)) !== 我的VL密钥) throw new Error('UUID验证失败');
      const 提取端口索引 = 18 + 二进制数据[17] + 1;
      const 访问端口 = new DataView(二进制数据.buffer, 提取端口索引, 2).getUint16(0);
      const 提取地址索引 = 提取端口索引 + 2;
      识别地址类型 = 二进制数据[提取地址索引];
      let 地址信息索引 = 提取地址索引 + 1;
      switch (识别地址类型) {
        case 1:
          地址长度 = 4;
          访问地址 = 二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度).join('.');
          break;
        case 2:
          地址长度 = 二进制数据[地址信息索引];
          地址信息索引 += 1;
          访问地址 = new TextDecoder().decode(二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度));
          break;
        case 3:
          地址长度 = 16;
          const ipv6 = [];
          const 读取IPV6地址 = new DataView(二进制数据.buffer, 地址信息索引, 16);
          for (let i = 0; i < 8; i++) ipv6.push(读取IPV6地址.getUint16(i * 2).toString(16));
          访问地址 = ipv6.join(':');
          break;
        default:
          throw new Error('无效的访问地址');
      }
      try {
        TCP接口 = connect({ hostname: 访问地址, port: 访问端口 });
        await TCP接口.opened;
      } catch {
        if (!反代IP) throw new Error('直连失败且未配置反代IP');
        const [反代IP地址, 反代IP端口 = 443] = 反代IP.split(':');
        TCP接口 = connect({ hostname: 反代IP地址, port: 反代IP端口 });
        await TCP接口.opened;
      }
      传输数据 = TCP接口.writable.getWriter();
      读取数据 = TCP接口.readable.getReader();
      const 写入初始数据 = 二进制数据.slice(地址信息索引 + 地址长度);
      if(写入初始数据) await 传输数据.write(写入初始数据);
      启动回传管道();
    }
    async function 启动回传管道() {
      while (true) {
        await 传输队列;
        const { done: 流结束, value: 返回数据 } = await 读取数据.read();
        if (返回数据 && 返回数据.length > 0) {
          传输队列 = 传输队列.then(() => WS接口.send(返回数据));
        }
        if (流结束) break;
      }
      throw new Error('传输完成');
    }
  } catch (e) {
    try { await TCP接口.close?.() } catch {};
    WS接口.close?.();
  }
}
