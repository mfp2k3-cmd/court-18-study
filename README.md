# COURT 18 — V: 1.00-A (Beta)

Projeto experimental para Windows destinado aos dumps próprios do NBA LIVE 18 para PS4, com suporte restrito aos Title IDs CUSA06321, CUSA06316 e CUSA08562. O launcher e o runtime verificam o `TITLE_ID` de `sce_sys/param.sfo` antes de iniciar; outros jogos são recusados.

## Estado da beta

- O jogo CUSA06321 iniciou e chegou à partida em uma NVIDIA GeForce RTX 3060.
- O perfil registrou `readbacks_mode: 2` (Precise) e `readback_linear_images_enabled: true`. A captura mais recente mostrou a partida sem os grandes clarões observados anteriormente.
- O teste com um save do modo carreira ainda está pendente; não trate a correção gráfica como definitiva.
- CUSA06316 e CUSA08562 são aceitos pela verificação de ID, mas ainda não foram testados em execução.
- Compatibilidade com outras GPUs e versões de driver ainda não foi verificada.

## Requisitos do usuário

- Um dump próprio do NBA LIVE 18 com um dos três Title IDs aceitos, selecionado no launcher.
- Módulos de firmware PS4 obtidos pelo próprio usuário, colocados em `user/sys_modules` ao lado do runtime. Eles não fazem parte deste pacote.
- Windows x64 e GPU/driver compatíveis com Vulkan.

O pacote não inclui dump do jogo, firmware, módulos, chaves, saves ou logs pessoais.

## Controles do menu durante o jogo

O menu do jogo pode ser aberto pelo botão PS, pelo botão Xbox Guide ou mantendo Start + Select pressionados por cerca de dois segundos. Nele é possível alternar o contador de FPS, mudar para tela cheia, reiniciar ou fechar o jogo.

## Licenças e código-fonte

O runtime shadPS4 está sob GPL-2.0-or-later. Os avisos e licenças distribuídos estão em `THIRD-PARTY-NOTICES.txt` e `LICENSES/`. Antes de qualquer distribuição pública, disponibilize o código-fonte exato correspondente a esta build, incluindo as alterações locais e os scripts de compilação, conforme a GPL.

Este é um projeto experimental da comunidade, sem vínculo oficial com Electronic Arts, NBA ou Sony.