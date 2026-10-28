# Plano de migração do NBA LIVE 18

## Decisão de base

Este projeto parte do código do Court 16 V1.00-C e do nightly oficial do shadPS4 `3eecea94ddaca360b19f4b800523b609a8b2ffcc` (26/10/2026). O código-base Live 18 anterior usava um snapshot shadPS4 mais antigo (`b4e7ae7`, 02/10/2026). O repositório do Court 16 de onde partimos estava fixado em `2cdefaa1298c6e4ece6c74bd84e90f3906282d51` (25/10/2026).

Os patches de integração e customização do Court 16 foram verificados com `git apply --check` contra o nightly escolhido e aplicam sem conflito. Isso confirma compatibilidade estrutural dos patches, não o funcionamento do Live 18.

## Evidência que trazemos do projeto anterior

- Dump alvo: CUSA06321, versão de conteúdo 01.11.
- A análise estática encontrou 679 imports e um fechamento de 71 módulos. Isso só confirma o resultado do linker estático.
- Há 116 identidades de import exclusivas do Live 18; 61 pertencem a GNM, 22 a JSON2 e oito a SaveData.
- O último checkpoint registra a janela presa em Loading/0 FPS. `FGGameSim` e `FGGameRender` ficam em espera e não aparecem submissões GNM nem apresentação de primeiro quadro.
- Portanto, a primeira meta técnica é descobrir o que impede a inicialização de chegar à primeira submissão GNM/flip, sem presumir que o problema seja o driver da GPU.

## Evidência da build portátil do Live 16

Em 27/10/2026, a build portátil já existente do Live 16 abriu o dump CUSA06321 e chegou a uma partida em andamento. A janela registrou 60 FPS com FSR ativo; o log marcou pelo menos oito minutos de execução e apresentou avisos de flip fora de ordem, chamadas repetidas a `sceNpPartyCheckCallback` ainda stubbed e solicitações de alguns arquivos de interface/áudio ausentes. A captura mostra a partida renderizada, com artefatos verdes em cabelo/rosto; a causa ainda não está identificada.

Esse resultado confirma que o runtime empacotado antigo consegue executar o Live 18 até a partida, mas não comprova que a nova base compilada neste projeto tenha o mesmo comportamento. Usaremos a build antiga como referência observável e manteremos seus executáveis, dados de usuário, módulos, chaves e saves fora do projeto-fonte.

## O que podemos reaproveitar

1. Resultados e relatórios estáticos do CUSA06321: imports, módulos requeridos, identidade dos provedores e comparação canônica com Live 16.
2. Hipóteses e medições dos logs antigos, usadas como evidência para escolher instrumentação — não como substituto de um teste na nova base.
3. Integração genérica do runtime: carregamento ELF/SELF, ABI, VFS, chamadas POSIX e camada gráfica, depois de revisar cada alteração contra o nightly novo.
4. Fluxo de diagnóstico: captura de pilhas, eventos de threads, rastreamento GNM, logs e encerramento controlado.

## O que exige adaptação própria para CUSA06321

- Identidade do título, validação do dump, caminhos de recursos e perfis.
- Seleção de módulos, provedores de imports, ordem de inicialização e ABI de chamadas próprias do Live 18.
- GNM e serviços exclusivos usados por este jogo; offsets, slots de módulos e bootstraps descobertos para CUSA01933 ficam excluídos.
- Configuração, saves, controles e interface com rótulos e caminhos próprios do Live 18.
- A resposta fixa `3` do stub `libSceAppContentUtil` no port antigo foi observada no CUSA01933 e não tem confirmação para o CUSA06321; manter como hipótese pendente e validar pela chamada real antes de confiar nela.
- A arte do launcher herdada do Court 16 ainda contém referências visuais ao número 16; não deve entrar em uma build identificada como Live 18 até ser substituída por arte adequada.

## Marcos

1. Fixar e documentar a revisão exata do nightly e validar a aplicação das integrações genéricas.
2. Primeira passada concluída: caminhos do dump, identificador usado pelo inspetor, nomes de janela e executável foram trocados para CUSA06321/NBA LIVE 18.
3. Auditar stubs de serviços e patches do Court 16; separar o que é genérico do que depende do título antes de adaptar a preparação/linker com o dump e os módulos do usuário.
4. Capturar inicialização até a primeira submissão GNM; corrigir a primeira diferença observável com evidência reproduzível.
5. Confirmar primeiro quadro, entrada, áudio, saves e partidas antes de preparar qualquer pacote.

## Dados e licença

O dump, módulos, chaves, saves, logs e arquivos de crash do usuário ficam fora deste repositório. A base do shadPS4 está sob GPL-2.0-or-later; patches derivados devem manter os avisos aplicáveis e acompanhar o código-fonte correspondente.
