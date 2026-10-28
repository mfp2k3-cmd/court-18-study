# COURT 18 — V: 1.00-A (Beta)

Primeira build beta do projeto COURT 18 para avaliar o NBA LIVE 18 (PS4) no runtime Windows.

## Jogos aceitos

O launcher e o runtime leem o `TITLE_ID` em `sce_sys/param.sfo` e permitem somente CUSA06321, CUSA06316 e CUSA08562. A configuração gráfica é salva no arquivo específico de cada Title ID.

## O que está incluído

- Launcher COURT 18 com seleção do dump e perfis/saves.
- Ajustes de resolução, FSR 1, sincronização, volume e contador de FPS.
- Runtime baseado no snapshot shadPS4 `3eecea94ddaca360b19f4b800523b609a8b2ffcc` com alterações locais.
- Readbacks no modo Precise e leitura de imagens lineares ativada para o jogo.

## Estado conhecido

CUSA06321 chegou à partida e a captura recente não mostrou os clarões gráficos extremos anteriores. O teste de save de carreira ainda está pendente. CUSA06316 e CUSA08562 estão na lista permitida, mas ainda não foram testados. Podem ocorrer artefatos, crashes ou incompatibilidades.

## Como começar

1. Extraia o pacote numa pasta gravável.
2. Abra `COURT 18 Launcher.exe`.
3. Selecione uma pasta de dump própria com um dos Title IDs aceitos e inicie.
4. Forneça seus próprios módulos de firmware pelo ambiente shadPS4; eles não são distribuídos aqui.

Não inclua nem compartilhe dump, firmware, módulos, chaves, saves ou logs pessoais ao enviar relatórios.

## Distribuição

Este é um pacote beta de teste. Preserve `LICENSE`, `LICENSES/` e `THIRD-PARTY-NOTICES.txt`. A publicação pública deve acompanhar o código-fonte correspondente a esta build, incluindo patches e scripts locais, conforme GPL-2.0-or-later.
## Código-fonte

O código correspondente ao runtime e os patches locais estão no repositório público. Para obter também a revisão exata do shadPS4 usada nesta build, clone com submódulos: git clone --recurse-submodules https://github.com/mfp2k3-cmd/court-18-study.git. Preserve as licenças e avisos incluídos no repositório.
