import { connect } from 'cloudflare:sockets';

// ==================== 确定性动态 UUID 机制 ====================

const BASE_KEY = 'e78639c5-88bf-45bf-81a6-53693830a574'; // 原默认值，可被 env 覆盖

let sharedUUID = {
  value: '',
  period: 0
};

// 获取当前小时整点的秒级时间戳（UTC 或本地均可，这里用本地时间，更符合用户体验）
function getCurrentHourPeriod() {
  const now = new Date();
  now.setMinutes(0, 0, 0);
  return Math.floor(now.getTime() / 1000);
}

// 双重 SHA-256 哈希
async function doubleHash(input) {
  const utf8 = new TextEncoder().encode(input);
  const first = await crypto.subtle.digest('SHA-256', utf8);
  const firstHex = Array.from(new Uint8Array(first))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  const second = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(firstHex));
  return Array.from(new Uint8Array(second))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// 生成确定性 UUID（每小时固定）
async function generateDeterministicUUID(base, period) {
  const hash = await doubleHash(`${base}${period}`);
  const uuid = [
    hash.slice(0, 8),
    hash.slice(8, 12),
    hash.slice(12, 16),
    hash.slice(16, 20),
    hash.slice(20, 32)
  ].join('-');
  return uuid;
}

// 获取当前有效的 UUID
async function getCurrentUUID(env) {
  // 优先级1：环境变量固定 UUID（最高优先级）
  if (env.UUID || env.KEY || env.TOKEN) {
    return (env.UUID || env.KEY || env.TOKEN).trim();
  }

  // 优先级2：每小时确定性生成
  const currentPeriod = getCurrentHourPeriod();
  if (currentPeriod !== sharedUUID.period || !sharedUUID.value) {
    const base = BASE_KEY;
    sharedUUID.value = await generateDeterministicUUID(base, currentPeriod);
    sharedUUID.period = currentPeriod;
    console.log(`新小时 UUID 生成: ${sharedUUID.value}`);
  }
  return sharedUUID.value;
}

// ============================================================

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // /sfu 返回当前 UUID（纯文本）
    if (url.pathname === '/sfu') {
      const currentUUID = await getCurrentUUID(env);
      return new Response(currentUUID, {
        status: 200,
        headers: { 'Content-Type': 'text/plain;charset=utf-8' }
      });
    }

    if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const [client, ws] = Object.values(new WebSocketPair());
      ws.accept();

      // 修复URL编码的查询参数
      if (url.pathname.includes('%3F')) {
        const decoded = decodeURIComponent(url.pathname);
        const queryIndex = decoded.indexOf('?');
        if (queryIndex !== -1) {
          url.search = decoded.substring(queryIndex);
          url.pathname = decoded.substring(0, queryIndex);
        }
      }

      const mode = url.searchParams.get('mode') || 'auto';
      const s5Param = url.searchParams.get('s5');
      const proxyParam = url.searchParams.get('proxyip');
      const path = s5Param ? s5Param : url.pathname.slice(1);

      // 解析 SOCKS5 和 ProxyIP
      const socks5 = path.includes('@') ? (() => {
        const [cred, server] = path.split('@');
        const [user, pass] = cred.split(':');
        const [host, port = 443] = server.split(':');
        return { user, pass, host, port: +port };
      })() : null;
      const PROXY_IP = proxyParam ? String(proxyParam) : null;

      const getOrder = () => {
        if (mode === 'proxy') return ['direct', 'proxy'];
        if (mode !== 'auto') return [mode];
        const order = [];
        const searchStr = url.search.slice(1);
        for (const pair of searchStr.split('&')) {
          const key = pair.split('=')[0];
          if (key === 'direct') order.push('direct');
          else if (key === 's5') order.push('s5');
          else if (key === 'proxyip') order.push('proxy');
        }
        return order.length ? order : ['direct'];
      };

      let remote = null, udpWriter = null, isDNS = false;

      const socks5Connect = async (targetHost, targetPort) => {
        const sock = connect({ hostname: socks5.host, port: socks5.port });
        await sock.opened;
        const w = sock.writable.getWriter();
        const r = sock.readable.getReader();
        await w.write(new Uint8Array([5, 2, 0, 2]));
        const auth = (await r.read()).value;
        if (auth[1] === 2 && socks5.user) {
          const user = new TextEncoder().encode(socks5.user);
          const pass = new TextEncoder().encode(socks5.pass);
          await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
          await r.read();
        }
        const domain = new TextEncoder().encode(targetHost);
        await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]));
        await r.read();
        w.releaseLock(); r.releaseLock();
        return sock;
      };

      new ReadableStream({
        start(ctrl) {
          ws.addEventListener('message', e => ctrl.enqueue(e.data));
          ws.addEventListener('close', () => { remote?.close(); ctrl.close(); });
          ws.addEventListener('error', () => { remote?.close(); ctrl.error(); });

          const early = req.headers.get('sec-websocket-protocol');
          if (early) {
            try {
              ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
                c => c.charCodeAt(0)).buffer);
            } catch {}
          }
        }
      }).pipeTo(new WritableStream({
        async write(data) {
          if (isDNS) return udpWriter?.write(data);
          if (remote) {
            const w = remote.writable.getWriter();
            await w.write(data);
            w.releaseLock();
            return;
          }

          if (data.byteLength < 24) return;

          // ======================== 修改后的 UUID 校验部分 ========================
          const received = new Uint8Array(data.slice(1, 17));

          const currentUUID = (await getCurrentUUID(env)).replace(/-/g, '');
          const emergencyUUID = BASE_KEY.replace(/-/g, '').toLowerCase();

          const matchCurrent = received.every((b, i) =>
            b === parseInt(currentUUID.substr(i * 2, 2), 16)
          );

          const matchEmergency = received.every((b, i) =>
            b === parseInt(emergencyUUID.substr(i * 2, 2), 16)
          );

          if (!matchCurrent && !matchEmergency) {
            return;
          }
          // =====================================================================

          const view = new DataView(data);
          const optLen = view.getUint8(17);
          const cmd = view.getUint8(18 + optLen);
          if (cmd !== 1 && cmd !== 2) return;

          let pos = 19 + optLen;
          const port = view.getUint16(pos);
          const type = view.getUint8(pos + 2);
          pos += 3;

          let addr = '';
          if (type === 1) {
            addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
            pos += 4;
          } else if (type === 2) {
            const len = view.getUint8(pos++);
            addr = new TextDecoder().decode(data.slice(pos, pos + len));
            pos += len;
          } else if (type === 3) {
            const ipv6 = [];
            for (let i = 0; i < 8; i++, pos += 2)
              ipv6.push(view.getUint16(pos).toString(16));
            addr = ipv6.join(':');
          } else return;

          const header = new Uint8Array([data[0], 0]);
          const payload = data.slice(pos);

          // UDP DNS
          if (cmd === 2) {
            if (port !== 53) return;
            isDNS = true;
            let sent = false;
            const { readable, writable } = new TransformStream({
              transform(chunk, ctrl) {
                for (let i = 0; i < chunk.byteLength;) {
                  const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                  ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
                  i += 2 + len;
                }
              }
            });

            readable.pipeTo(new WritableStream({
              async write(query) {
                try {
                  const resp = await fetch('https://1.1.1.1/dns-query', {
                    method: 'POST',
                    headers: { 'content-type': 'application/dns-message' },
                    body: query
                  });
                  if (ws.readyState === 1) {
                    const result = new Uint8Array(await resp.arrayBuffer());
                    ws.send(new Uint8Array([...(sent ? [] : header),
                      result.length >> 8, result.length & 0xff, ...result
                    ]));
                    sent = true;
                  }
                } catch {}
              }
            }));
            udpWriter = writable.getWriter();
            return udpWriter.write(payload);
          }

          // TCP 连接
          let sock = null;
          for (const method of getOrder()) {
            try {
              if (method === 'direct') {
                sock = connect({ hostname: addr, port });
                await sock.opened;
                break;
              } else if (method === 's5' && socks5) {
                sock = await socks5Connect(addr, port);
                break;
              } else if (method === 'proxy' && PROXY_IP) {
                const [ph, pp = port] = PROXY_IP.split(':');
                sock = connect({ hostname: ph, port: +pp || port });
                await sock.opened;
                break;
              }
            } catch {}
          }

          if (!sock) return;

          remote = sock;
          const w = sock.writable.getWriter();
          await w.write(payload);
          w.releaseLock();

          let sent = false;
          sock.readable.pipeTo(new WritableStream({
            write(chunk) {
              if (ws.readyState === 1) {
                ws.send(sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]));
                sent = true;
              }
            },
            close: () => ws.readyState === 1 && ws.close(),
            abort: () => ws.readyState === 1 && ws.close()
          })).catch(() => {});
        }
      })).catch(() => {});

      return new Response(null, { status: 101, webSocket: client });
    }

    // 其他请求伪装
    url.hostname = 'example.com';
    return fetch(new Request(url, req));
  }
};
