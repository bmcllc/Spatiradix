# Mycelium Habitat — Fase H0 (registro soberano de serviços)

Status: implementação local em \`crates/mycelium-node/src/habitat.rs\`.
Este documento descreve o que o código **faz hoje**, não uma promessa de nuvem pública.

## Objetivo

Uma identidade \`Gland\` ed25519 registra manifestos de serviços sob um ID
\`ContentId\` estável derivado do proprietário e do nome. Cada manifesto
declara o tipo, privacidade, transporte, réplicas desejadas e nós autorizados.
O conteúdo assinado é separado do estado operacional de outros subsistemas.

## CLI (daemon iniciado)

\`\`\`bash
# Ao lado de um daemon "mycelium ... daemon" já em execução:
mycelium --home ~/.local/share/mycelium habitat register --name arquivos --kind data --visibility local
mycelium --home ~/.local/share/mycelium habitat list
mycelium --home ~/.local/share/mycelium habitat inspect arquivos

# Descriptor para réplica privada em outro NodeId autorizado:
mycelium --home ~/.local/share/mycelium habitat register \
  --name meu-vault --kind data --visibility private --replicas 2 \
  --peer <NODEID_HEX_DO_SEGUNDO_NO>

# Cria APENAS a declaração de um site público; não faz deploy:
mycelium --home ~/.local/share/mycelium habitat register \
  --name portfolio --kind site --visibility public
\`\`\`

## Contratos

- \`local\`: uma réplica desejada, transporte \`local_only\`, sem pares autorizados.
- \`private\`: transporte \`authenticated_mesh\`, criptografia **obrigatória antes**
  de o conteúdo sair do host, réplicas desejadas limitadas a \`1 + pares\` autorizados.
- \`public\`: transporte \`public_mesh\`, sem allowlist; a publicação depende
  de uma ação explícita **ainda não implementada**.
- Execução é sempre \`owner_only\` nesta versão (evita dar execução remota
  por um campo não aplicado pelo runtime).
- Nomes de serviços aceitam apenas \`[a-z0-9-]\`, com 1..64 caracteres.
- O daemon recusa manifestos adulterados e assinaturas sem a chave do dono.
- O índice \`{home}/habitat/services.json\` é escrito atomicamente e,
  em Unix, protegido por permissões 0600; diretório com 0700.

## Limites de segurança

**Nenhum manifesto desta fase é anunciado pela DHT, pelo Gossipsub, pelo
Pkarr, pelo Nostr ou servido pelo Event Horizon.** As permissões de
\`may_view_manifest\` são uma decisão verificável para metadados, não
controle de acesso implementado à rede ou aos arquivos.

\`storage.encryption_required = true\` é uma **exigência de política**, não
um criptossistema executado automaticamente. O registro não armazena arquivos
da aplicação. O cofre privado cifrado deve integrar \`mycelium-root\`
(ou um envelope AEAD equivalente) antes de habilitar replicação.

O controle do daemon é local-first, mas depende das proteções existentes do
socket e da configuração \`MYCELIUM_CONTROL_TOKEN\`; o registro não introduz
um novo mecanismo de autenticação para clientes locais.

## Próximos gates

1. H1: Envelopes cifrados, teste de leitura negativa por nós não autorizados,
   e ligação Root → SporeBank sem bytes privados em claro no transporte.
2. H2: Transporte e descoberta verificados em **dois hosts diferentes**,
   fallback Nostr/relay, persistência offline e reconciliação.
3. H3: \`ServiceManifest\` aplicado como gate pelo \`singularity\` e \`vacuum\`.
   Uma declaração \`public\` só vira exposta após publicação explícita.
4. H4: Interface de painel local e diagnóstico de serviço.

Nenhuma funcionalidade financeira ou monetária foi alterada nesta fase.
