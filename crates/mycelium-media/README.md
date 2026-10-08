# 🎬 `mycelium-media` — Streaming de Mídia P2P e HLS Soberano

Biblioteca de segmentação, transcodificação e distribuição P2P de streaming de áudio e vídeo para o ecossistema Mycelium (backbone do Mycelium Video).

---

## 🎯 Arquitetura

- **Segmentação HLS (HTTP Live Streaming)**:
  - Fatiamento de fluxos de vídeo em pedaços `.m4s` / `.ts` indexados por playlists `.m3u8`.
- **Distribuição por Esporos P2P**:
  - Cada segmento de vídeo torna-se um esporo indexado por `ContentId` no `mycelium-sporebank`.
  - Assistir a um vídeo faz com que o cliente baixe e replique simultaneamente os blocos para os nós vizinhos, reduzindo custos de banda a zero para o criador.
