# COURT 18 — V: 1.01-B

Projeto comunitário para Windows que executa dumps próprios do NBA LIVE 18 para PS4. O launcher e o runtime aceitam somente os Title IDs CUSA06321, CUSA06316 e CUSA08562; o `TITLE_ID` é conferido em `sce_sys/param.sfo` antes de iniciar.

## Mudanças desta versão

- O menu Opções permite selecionar o modo de readbacks da GPU: Disabled (0), Relaxed (1) ou Precise (2).
- A seleção de readbacks fica salva nas preferências e é aplicada ao iniciar o jogo.
- Correções de bugs gráficos observados durante as partidas.
- Correção de crash durante o gameplay e ao retornar ao menu, validada nos testes relatados para CUSA06321.
- Atualização da identificação do launcher e do menu para V: 1.01-B.

## Compatibilidade e testes

- CUSA06321: nos testes recentes relatados pelo usuário, o jogo iniciou e não houve crash ao retornar ao menu.
- CUSA06316 e CUSA08562: aceitos pela verificação de Title ID, mas ainda sem validação de execução nesta versão.
- Quedas de FPS em cenas carregadas ainda podem ocorrer; esta atualização não afirma corrigir esse comportamento.

## Requisitos

- Windows x64 e GPU/driver com suporte a Vulkan.
- Dump próprio do NBA LIVE 18 com um dos Title IDs aceitos.
- Módulos de firmware PS4 fornecidos pelo próprio usuário em `user/sys_modules`; eles não são distribuídos aqui.

O pacote não inclui dumps, firmware, módulos, chaves, saves ou logs pessoais.

## Controles do menu durante o jogo

Abra pelo botão PS, pelo botão Xbox Guide ou mantendo Start + Select pressionados por cerca de dois segundos. O menu permite alternar o contador de FPS, mudar para tela cheia, reiniciar ou fechar o jogo.

## Licenças e código-fonte

O runtime shadPS4 está sob GPL-2.0-or-later. Preserve `LICENSE`, `LICENSES/` e `THIRD-PARTY-NOTICES.txt`. A distribuição deve acompanhar o código-fonte correspondente à build, incluindo alterações locais e scripts de compilação.

Este é um projeto comunitário, sem vínculo oficial com Electronic Arts, NBA ou Sony.
