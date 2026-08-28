#!/usr/bin/env node

import { createReadStream, readFileSync, statSync } from 'node:fs';
import { request as requestHttp } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { extname, join, normalize, relative, resolve } from 'node:path';
import { URL } from 'node:url';

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key?.startsWith('--') || !argv[index + 1]) throw new Error(`missing value for ${key ?? 'argument'}`);
    values.set(key.slice(2), argv[index + 1]);
    index += 1;
  }
  for (const key of ['listen', 'api', 'web-root', 'cert', 'key']) {
    if (!values.has(key)) throw new Error(`--${key} is required`);
  }
  return values;
}

function splitListen(value) {
  const match = /^(127\.0\.0\.1|localhost):(\d+)$/.exec(value);
  if (!match || Number(match[2]) < 1024 || Number(match[2]) > 65535) throw new Error('--listen must be loopback:high-port');
  return { host: match[1], port: Number(match[2]) };
}

function contentType(path) {
  return {
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
  }[extname(path)] ?? 'application/octet-stream';
}

function serveStatic(request, response, webRoot) {
  const requestPath = new URL(request.url ?? '/', 'https://loopback.invalid').pathname;
  const candidate = resolve(webRoot, `.${requestPath}`);
  const root = resolve(webRoot);
  const withinRoot = candidate === root || relative(root, candidate) && !relative(root, candidate).startsWith('..');
  let filePath = withinRoot ? candidate : join(root, 'index.html');
  try {
    if (!statSync(filePath).isFile()) filePath = join(root, 'index.html');
  } catch {
    filePath = join(root, 'index.html');
  }
  try {
    response.writeHead(200, { 'Content-Type': contentType(filePath), 'Cache-Control': 'no-store' });
    createReadStream(filePath).pipe(response);
  } catch {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('not found');
  }
}

function proxyApi(request, response, apiOrigin) {
  const target = new URL(request.url ?? '/', apiOrigin);
  const headers = { ...request.headers, host: target.host, connection: 'close' };
  const upstream = requestHttp(target, { method: request.method, headers }, (upstreamResponse) => {
    const responseHeaders = { ...upstreamResponse.headers };
    delete responseHeaders.connection;
    response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
    upstreamResponse.pipe(response);
  });
  upstream.on('error', () => {
    if (!response.headersSent) response.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ code: 'proxy_unavailable', message: 'local API proxy unavailable' }));
  });
  request.pipe(upstream);
}

const args = parseArgs(process.argv.slice(2));
const listen = splitListen(args.get('listen'));
const apiOrigin = new URL(args.get('api'));
const apiPort = Number(apiOrigin.port);
if (apiOrigin.protocol !== 'http:' || apiOrigin.hostname !== '127.0.0.1' || !Number.isInteger(apiPort) || apiPort < 1024 || apiPort > 65535 || apiOrigin.username || apiOrigin.password || apiOrigin.pathname !== '/' || apiOrigin.search || apiOrigin.hash) throw new Error('--api must be a loopback HTTP origin on an explicit high port');
const webRoot = resolve(args.get('web-root'));
if (!statSync(webRoot).isDirectory()) throw new Error('--web-root must be a directory');
const server = createHttpsServer({ key: readFileSync(resolve(args.get('key'))), cert: readFileSync(resolve(args.get('cert'))) }, (request, response) => {
  if ((request.url ?? '').startsWith('/api/')) proxyApi(request, response, apiOrigin);
  else serveStatic(request, response, webRoot);
});
server.listen(listen.port, listen.host, () => {
  process.stdout.write(`live_web_proxy listening on https://${listen.host}:${listen.port}\n`);
});
