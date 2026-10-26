#!/usr/bin/env node
// minimal victim for local DoS lab
import http from 'node:http';
const PORT = process.env.VICTIM_PORT || 8080;
const server = http.createServer((req,res)=>{ res.writeHead(200); res.end('ok'); });
server.listen(PORT, ()=>console.log(`node-victim:${PORT}`));
