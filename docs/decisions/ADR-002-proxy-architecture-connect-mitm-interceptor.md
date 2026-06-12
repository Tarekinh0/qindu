# ADR-002: Architecture du proxy - CONNECT MITM + Interceptor

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Qindu doit intercepter le trafic HTTPS entre le navigateur et les services IA web. Le proxy doit:
1. Accepter les requêtes CONNECT du navigateur (HTTP/1.1)
2. Établir un tunnel TLS MITM pour les domaines IA supportés
3. Laisser passer les autres domaines sans décryptage (tunnel aveugle)
4. Servir des endpoints HTTP locaux (PAC, health) sur le même port

## Decision

- **Serveur HTTP unique** sur `127.0.0.1:8787` gérant à la fois:
  - `CONNECT` → Handler MITM (Hijacker) pour les tunnels proxy
  - `GET`/`HEAD` → Handler HTTP pour `/proxy.pac` et `/health`
- **DomainRouter**: décide par domaine si la connexion est MITM ou Tunnel
- **Tunnel**: `io.Copy` aveugle sans décryptage pour les domaines non-IA
- **MITM**: établit deux connexions TLS (navigateur + upstream), forward via le pipeline Interceptor

## Consequences

**Devient plus facile**:
- Single-port, single-process - pas de coordination multi-ports
- Ajout de nouveaux providers IA sans modifier le cœur du proxy
- Développement progressif (NoOp → PII → Tokenization)

**Devient plus difficile**:
- HTTP/2 multiplexing vs Hijacker - le CONNECT reste en HTTP/1.1 (standard)
- Debugging des deux côtés TLS simultanément
