# HeadHunter MCP → ChatGPT: OAuth и Render Free

Подготовлено 8 ноября 2026 г. Этот документ не запускает развёртывание. PR нельзя
сливать и Render нельзя запускать без отдельного подтверждения владельца.

## Что реализовано

**ChatGPT → защищённый `/mcp` на Render**, вход и выдача токенов — **Auth0**.
Отдельный OAuth-шлюз, база данных и хранение OAuth-сессий на Render не нужны.
Это OAuth resource server, а не самодельный сервер выдачи токенов. Для работы
нужен настроенный внешний Auth0 tenant; одних переменных Render недостаточно.

ChatGPT поддерживает Authorization Code + PKCE S256, discovery и заранее
зарегистрированный OAuth client. Здесь выбран именно этот вариант; DCR/CIMD
включать не требуется. Выбирайте **OAuth**, а не «без аутентификации» или смешанный
режим. Все запросы `/mcp`, включая initialize и tools/list, защищены.

Публичны только `/health` и документы discovery
`/.well-known/oauth-protected-resource/mcp` (также доступен корневой вариант).
Discovery содержит адреса и scopes, а не секреты и не данные hh.ru.

На каждом MCP-запросе сервер проверяет RS256-подпись по ключам настроенного
Auth0 tenant, точные issuer и audience, exp/iat/nbf, scope `mcp:tools`, OAuth client
и разрешённый `sub`. Срок access token — не более 3600 секунд (допуск часов 5 секунд).
Чужой аккаунт, даже зарегистрированный в том же Auth0, не получает доступа.
Недействительный/отсутствующий токен даёт 401; чужой пользователь/клиент или
недостаточный scope — 403. В OAuth-режиме нет обхода через MCP_SECRET_TOKEN.

## 1. Подготовить адрес сервиса, не запуская его

Выберите будущий адрес, например `https://hh-mcp-ВАШЕ-ИМЯ.onrender.com`.
Во всех следующих настройках замените пример на реальный адрес, который выделит
Render. Если имя занято или адрес изменился, синхронно обновите Auth0 API Identifier,
MCP_PUBLIC_URL и HH_ALLOWED_HOSTS. Адрес ниже — шаблон, не опубликованный сервер.

## 2. Настроить Auth0

Нужен аккаунт Auth0 и tenant. Используйте отдельный tenant для личного MCP,
чтобы его настройки не влияли на другие приложения. Создание и настройка
выполняются владельцем; реальные значения секретов не отправляйте в чат/GitHub.

1. **Applications → APIs → Create API**:
   - Name: `HeadHunter MCP`.
   - Identifier: `https://ВАШ-СЕРВИС.onrender.com/mcp` — точно, без завершающего `/`.
   - Signing Algorithm: **RS256**.
   - Access Token Profile: **Auth0** (содержит `azp`).
   - Token Expiration и Token Expiration for Browser Flows: **3600** секунд.
   - Permissions: добавьте `mcp:tools`, описание «Использовать инструменты HeadHunter».
   - Для обновления токенов включите **Allow Offline Access**.
   - В этом рецепте оставьте API RBAC выключенным: право владельца независимо
     проверяется по обязательному allowlist `sub`. Если включаете RBAC, отдельно
     назначьте владельцу роль с разрешением `mcp:tools`.
2. **Settings → Advanced → Settings**: включите
   **Resource Parameter Compatibility Profile** и
   **Include Issuer in Authorization Responses**. Первый связывает стандартный
   параметр `resource` с audience, второй защищает OAuth callback от подмены issuer.
   Не подменяйте это снятием проверки audience на MCP-сервере.
3. **Applications → Applications → Create Application → Regular Web Applications**:
   - Name: `ChatGPT HeadHunter MCP`.
   - Сохраните **Client ID**; **Client Secret** понадобится только в форме ChatGPT.
   - В **Advanced Settings → Grant Types** оставьте **Authorization Code** и
     **Refresh Token**. Password, Implicit и Client Credentials для этого подключения
     не нужны.
   - Token Endpoint Authentication Method: **Post** (`client_secret_post`).
   - Включите refresh token rotation, например с абсолютным сроком 30 дней и
     сроком неактивности 7 дней; по истечении потребуется войти повторно.
   - **Allowed Callback URLs**: при включённом issuer identification текущая
     документация ChatGPT указывает
     `https://chatgpt.com/connector_platform_oauth_redirect`.
     При настройке соединения сверьте его с **точным redirect URI**, показанным
     в управлении пользовательским MCP в ChatGPT, и добавьте именно этот URI.
     Некоторые соединения используют `https://chatgpt.com/connector/oauth/{callback_id}`:
     фигурные скобки не вставляйте, копируйте полный фактический адрес. Не используйте
     wildcard и не угадывайте callback по старым инструкциям для GPT Actions.
   - В Connections включите только выбранный способ входа.
4. **User Management → Users**: создайте личного пользователя (это отдельная
   учётная запись для входа в MCP, не обязательно ваш административный аккаунт Auth0).
   Скопируйте его **User ID**, например `auth0|...`, в `MCP_OAUTH_ALLOWED_SUBJECTS`.
   При социальной авторизации ID может начинаться с `google-oauth2|...`.
   Отключите самостоятельную регистрацию в используемом database connection, если
   она не нужна. Allowlist на сервере обязателен даже при отключённой регистрации.
5. Проверьте `https://ВАШ-TENANT.auth0.com/.well-known/openid-configuration`:
   - `issuer` должен точно совпадать с `MCP_OAUTH_ISSUER`, включая финальный `/`;
   - должны быть authorization_endpoint, token_endpoint, jwks_uri;
   - `code_challenge_methods_supported` должен содержать `S256`;
   - `token_endpoint_auth_methods_supported` должен содержать `client_secret_post`;
   - при включённом issuer identification проверьте
     `authorization_response_iss_parameter_supported: true`.
   Для Auth0 jwks_uri должен быть `https://ВАШ-TENANT.auth0.com/.well-known/jwks.json`.

Сервер не получает OAuth Client Secret: он проверяет публичные ключи Auth0.
Не нужно создавать секрет MCP для OAuth и не нужно передавать токены Auth0 в hh.ru.

## 3. Точные настройки Render — применять только после подтверждения

Не нажимайте создание/развёртывание сервиса во время согласования PR. Когда
владелец отдельно разрешит публикацию, создайте **Web Service**:

| Поле Render | Значение |
|---|---|
| Repository | `xzelaniss/hh-mcp` |
| Branch | `security/mcp-bearer-auth` для согласованной проверки PR; `main` только после разрешённого слияния |
| Language / Runtime | `Node` |
| Instance Type | `Free` |
| Root Directory | пусто (корень репозитория) |
| Build Command | `npm ci --include=dev && npm run build` |
| Start Command | `node dist/index.js --http` |
| Health Check Path | `/health` |
| Auto-Deploy | **Off / Disabled** |

Environment Variables (значения с `ВАШ` заменить, кавычки в UI не нужны):

| Имя | Значение |
|---|---|
| `NODE_VERSION` | `24` |
| `NODE_ENV` | `production` |
| `HOST` | `0.0.0.0` |
| `MCP_AUTH_MODE` | `oauth` |
| `MCP_PUBLIC_URL` | `https://ВАШ-СЕРВИС.onrender.com` — только origin, без `/mcp` |
| `MCP_OAUTH_ISSUER` | `https://ВАШ-TENANT.auth0.com/` — точный issuer с `/` |
| `MCP_OAUTH_CLIENT_ID` | Client ID приложения `ChatGPT HeadHunter MCP` из Auth0 |
| `MCP_OAUTH_ALLOWED_SUBJECTS` | ваш точный User ID из Auth0; при необходимости несколько через запятую |
| `HH_ALLOWED_HOSTS` | `ВАШ-СЕРВИС.onrender.com` — без схемы и пути |
| `HH_USER_AGENT` | своё имя приложения и контакт, например `my-hh-mcp/1.0 (me@example.com)` |
| `HH_ACCESS_TOKEN` | необязательно: секретный OAuth-токен hh.ru, нужен для резюме и `/me` |

`PORT` предоставляет Render, не задавайте `HTTP_PORT`. `HH_ALLOWED_ORIGINS` можно
не задавать: серверные запросы ChatGPT не требуют браузерного Origin. Если задаёте
его, перечислите только реально используемые Origin. HTTPS завершает Render,
приложение внутри слушает HTTP. Не отключайте проверку TLS к Auth0/hh.ru.

`MCP_SECRET_TOKEN` в этом рецепте не задаётся, в OAuth-режиме он не принимается.
OAuth Client Secret хранится в ChatGPT, не в Render. HH_ACCESS_TOKEN хранится в
секретных переменных Render и используется только для исходящих запросов hh.ru.
Самостоятельная загрузка `.env.local` не реализована; Render передаёт env напрямую.

Free Render засыпает после 15 минут без входящего трафика; запуск обычно занимает
около минуты. Первый запрос ChatGPT может завершиться тайм-аутом. После разрешённого
развёртывания откройте `/health`, дождитесь JSON и повторите подключение. Free-план
имеет квоты и может перезапускаться; постоянно доступный сервис не гарантируется.
OAuth-сессии/refresh tokens остаются у Auth0 и ChatGPT, а не на эфемерном диске Render.
Доступность функций и квоты Auth0 зависят от выбранного tenant/тарифа; отдельный
платный Render или PostgreSQL этому решению не требуется.

## 4. Поля «Добавить пользовательский сервер MCP» в ChatGPT

После отдельно разрешённого развёртывания:

| Поле ChatGPT | Что заполнить |
|---|---|
| Название | `HeadHunter` |
| Описание | `Поиск вакансий, работодателей и справочники HeadHunter` |
| URL сервера MCP | `https://ВАШ-СЕРВИС.onrender.com/mcp` |
| Аутентификация | **OAuth** |
| OAuth Client ID | Client ID приложения Auth0, тот же что `MCP_OAUTH_CLIENT_ID` |
| OAuth Client Secret | Client Secret этого приложения Auth0 |

Поля Client ID/Secret могут находиться в дополнительных настройках OAuth.
Это не MCP_SECRET_TOKEN и не HH_ACCESS_TOKEN. Если форма дополнительно запрашивает
Authorization URL, укажите `https://ВАШ-TENANT.auth0.com/authorize`; Token URL —
`https://ВАШ-TENANT.auth0.com/oauth/token`; scopes — `mcp:tools` (для долгой сессии
также `offline_access`; OIDC `openid email profile` разрешите в клиенте, если
они запрашиваются из discovery). Обычно эти адреса читаются автоматически.

Создайте подключение, сверьте фактический callback с Auth0, пройдите вход своим
разрешённым пользователем и подтвердите scope. Если ChatGPT предлагает способ
регистрации OAuth-клиента, используйте введённые статические client credentials;
DCR/CIMD для этого рецепта не нужны. После установки выберите HeadHunter в чате.

## 5. Приёмка после разрешённого развёртывания

1. GET `/health` без токена → 200, `tools: 19`.
2. GET `/.well-known/oauth-protected-resource/mcp` → 200; `resource` точно равен
   HTTPS URL MCP с `/mcp`, `authorization_servers` содержит точный Auth0 issuer.
3. POST `/mcp` без токена → 401 с `WWW-Authenticate`, содержащим `resource_metadata`.
4. Подключение ChatGPT проходит вход; список содержит 19 инструментов. Вызовите
   `search_vacancies` с простым запросом.
5. Другой пользователь Auth0 не должен получить доступ: 403. Ошибки scope тоже 403;
   неверный issuer/audience, подпись или истёкший токен — 401.

До публикации автоматические тесты используют временные ключи и имитацию ответов
Auth0/hh.ru. Проверяется в том числе реальный HTTP-сервер, initialize, tools/list
(19 инструментов), tools/call и отсутствие пересылки входящего токена в hh.ru.
Реальный OAuth-вход в ChatGPT/Auth0 не проверен: tenant и публичный сервис ещё
не создавались и не развёртывались. Это обязательный финальный этап приёмки,
а не обещание уже выполненного подключения.

При 401 не выбирайте «без аутентификации»: проверьте issuer, audience, ресурсный
профиль Auth0, exp/iat. При 403 проверьте `sub`, client ID и `mcp:tools`.
Ключи JWKS кэшируются до 10 минут; при невозможности загрузить нужный ключ запрос
отклоняется. Logout/revoke refresh token не аннулирует уже выданный JWT немедленно:
он может действовать до часа. Для срочного отключения пользователя удалите его `sub`
из allowlist и примените изменение окружения сервиса с отдельным разрешением владельца.

## Проверка зависимостей

Обновлены MCP SDK, Zod, JOSE и тестовый раннер. Для сборки нужен Node.js 22.12+
(на Render задайте 24); CI проверяет 22 и 24. `npm audit --omit=dev` после обновления
показывает **0 известных уязвимостей** рабочих зависимостей. Полный аудит также
проверен: остаются **8 предупреждений (7 moderate, 1 low)** в dev-цепочках
`typescript-eslint → minimatch` и `tsx/vite → esbuild`. High/critical нет.
Это инструменты разработки/сборки, сервер не запускает их HTTP dev-сервисы.
Принудительные несовместимые overrides для них не добавлялись; перед будущими
обновлениями повторите аудит. Отсутствие предупреждений не заменяет проверку
конфигурации Auth0 и финальный вход через ChatGPT.

## Источники

- [ChatGPT custom MCP](https://developers.openai.com/api/docs/guides/custom-mcp-server)
- [OAuth, PKCE, discovery и актуальные callback URI](https://developers.openai.com/plugins/build/auth)
- [Auth0: resource parameter и issuer identification](https://auth0.com/ai/docs/mcp/guides/resource-param-compatibility-profile)
- [Ограничения Render Free](https://render.com/docs/free)
